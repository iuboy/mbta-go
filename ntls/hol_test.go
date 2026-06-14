package ntls

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// slowSink 每个 batch 处理 sleep delay，用于放大单 batch 处理耗时、验证 worker 池并发收益。
// 计数收到的 batch 数（用于断言全部到达）。
type slowSink struct {
	delay  time.Duration
	events atomic.Int64
}

func (s *slowSink) OnSignalBatch(_ context.Context, _ string, batch *core.SignalBatch) error {
	time.Sleep(s.delay)
	s.events.Add(int64(len(batch.Signals)))
	return nil
}
func (s *slowSink) OnPressure(_ string) core.PressureState { return core.PressureNormal }

// TestHOL_BatchConcurrency 验证 readLoop 把 BATCH 派发到 worker 池并发处理：
// 单 batch 处理需 delay，发 defaultBatchWorkers+1 个小 batch 时，总耗时应显著小于
// 串行（(N)*delay），证明大 batch 不再队头阻塞后续帧。
func TestHOL_BatchConcurrency(t *testing.T) {
	const perBatchDelay = 80 * time.Millisecond
	const numBatches = defaultBatchWorkers + 2 // 多于 worker 数，分两批

	sink := &slowSink{delay: perBatchDelay}
	server, err := NewServer(ServerConfig{
		Address:      "127.0.0.1:0",
		SignCertFile: signCertFile,
		SignKeyFile:  signKeyFile,
		EncCertFile:  encCertFile,
		EncKeyFile:   encKeyFile,
		Auth:         core.NewStaticTokenValidator(map[string]string{"tok": "agent-1"}),
		Policy:       core.Policy{EnableHMACSHA256: true, EnableWindow: true},
		Sink:         sink,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srvCtx, srvCancel := context.WithCancel(context.Background())
	startErr := make(chan error, 1)
	go func() { startErr <- server.Start(srvCtx) }()
	var addr string
	for i := 0; i < 200; i++ {
		addr = server.Addr()
		if addr != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if addr == "" {
		srvCancel()
		t.Fatal("server did not start")
	}
	defer func() { srvCancel(); <-startErr }()

	client, err := NewClient(ClientConfig{
		Server: addr,
		Credentials: &ClientCredentials{
			SignCertFile: signCertFile, SignKeyFile: signKeyFile,
			EncCertFile: encCertFile, EncKeyFile: encKeyFile,
			InsecureSkipVerify: true,
		},
		AgentID: "agent-1",
		Token:   "tok",
		Capabilities: []string{core.CapCodecJSON, core.CapHMACSHA256, core.CapWindowFlowCtrl},
	})
	if err != nil {
		t.Fatal(err)
	}
	connCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Connect(connCtx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	batch := &core.SignalBatch{Signals: []*core.SignalRecord{{SignalType: "log", Body: "hol", TimeUnixMs: 1}}}

	start := time.Now()
	for i := 0; i < numBatches; i++ {
		if _, err := client.SendBatch(context.Background(), batch, "tag", "src"); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	// 等全部到达。
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if sink.events.Load() >= int64(numBatches) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	elapsed := time.Since(start)

	if sink.events.Load() < int64(numBatches) {
		t.Fatalf("only %d batches delivered, want %d", sink.events.Load(), numBatches)
	}
	// 串行基线：numBatches * perBatchDelay。并发后应远低于此。
	// 容忍 worker 池分批（ceil(numBatches/workers) * delay）+ 网络开销。
	serialBaseline := time.Duration(numBatches) * perBatchDelay
	if elapsed > serialBaseline/2 {
		t.Errorf("not concurrent: elapsed=%v, serial baseline=%v (want < %v)",
			elapsed, serialBaseline, serialBaseline/2)
	}
}
