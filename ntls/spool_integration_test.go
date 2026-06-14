package ntls

import (
	"context"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/spool"
)

// startServerWithSink 启动本地 ntls TLCP server，返回 (addr, sink, teardown)。
func startServerWithSink(t *testing.T) (string, *countSink, func()) {
	t.Helper()
	sink := &countSink{}
	server, err := NewServer(ServerConfig{
		Address:      "127.0.0.1:0",
		SignCertFile: signCertFile,
		SignKeyFile:  signKeyFile,
		EncCertFile:  encCertFile,
		EncKeyFile:   encKeyFile,
		Auth:         core.NewStaticTokenValidator(map[string]string{"tok": "agent-1"}),
		Policy: core.Policy{
			EnableHMACSHA256: true,
			EnableWindow:     true,
		},
		Sink: sink,
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
		select {
		case e := <-startErr:
			srvCancel()
			t.Fatalf("server start failed: %v", e)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if addr == "" {
		srvCancel()
		t.Fatal("server did not start listening in time")
	}
	return addr, sink, func() { srvCancel(); <-startErr }
}

// connectClient 用给定 SpoolDir 连接 ntls server。
func connectClient(t *testing.T, addr, spoolDir string) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{
		Server: addr,
		Credentials: &ClientCredentials{
			SignCertFile:       signCertFile,
			SignKeyFile:        signKeyFile,
			EncCertFile:        encCertFile,
			EncKeyFile:         encKeyFile,
			InsecureSkipVerify: true,
		},
		AgentID:  "agent-1",
		Token:    "tok",
		SpoolDir: spoolDir,
		Capabilities: []string{
			core.CapCodecJSON,
			core.CapHMACSHA256,
			core.CapWindowFlowCtrl,
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	connCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Connect(connCtx); err != nil {
		_ = client.Close()
		t.Fatalf("connect: %v", err)
	}
	return client
}

func waitForEvents(t *testing.T, sink *countSink, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if sink.events.Load() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %d events, got %d", want, sink.events.Load())
}

// TestSpool_ACKDeletesEntry 发送 batch → 收到 ACK → spool 条目应被删除。
func TestSpool_ACKDeletesEntry(t *testing.T) {
	dir := t.TempDir()
	addr, sink, td := startServerWithSink(t)
	defer td()

	client := connectClient(t, addr, dir)
	defer client.Close()

	batch := &core.SignalBatch{Signals: []*core.SignalRecord{
		{SignalType: "log", Body: "ntls-spool-test", TimeUnixMs: 1},
	}}
	if _, err := client.SendBatch(context.Background(), batch, "tag", "src"); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitForEvents(t, sink, 1, 3*time.Second)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if client.spool.Len() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("spool not empty after ACK: len=%d", client.spool.Len())
}

// TestSpool_CrashRetransmit 模拟崩溃恢复：seed 未 ACK batch 到 spool → 落盘 →
// 新 client 同 SpoolDir 连接 → drain 重发 → 服务端收到、ACK 后 spool 清空。
func TestSpool_CrashRetransmit(t *testing.T) {
	dir := t.TempDir()

	c1, err := NewClient(ClientConfig{
		Server:  "127.0.0.1:0", // 占位，不连接
		SpoolDir: dir,
	})
	if err != nil {
		t.Fatalf("new client1: %v", err)
	}
	sig := &core.SignalRecord{SignalType: "log", Body: "crashed-before-ack", TimeUnixMs: 1}
	recID := "rec-crash-1"
	if err := c1.spool.PutBatch([]spool.Record{{
		RecordID:        recID,
		AgentID:         "agent-1",
		Event:           sig,
		Tag:             "tag",
		Source:          "src",
		CreatedAtUnixMs: time.Now().UnixMilli(),
	}}, spool.Batch{
		Seq:             1,
		ChunkID:         "chunk-crash-1",
		RecordIDs:       []string{recID},
		CreatedAtUnixMs: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatalf("seed spool: %v", err)
	}
	if err := c1.Close(); err != nil {
		t.Fatalf("close client1: %v", err)
	}

	addr, sink, td := startServerWithSink(t)
	defer td()
	c2 := connectClient(t, addr, dir)
	defer c2.Close()

	waitForEvents(t, sink, 1, 3*time.Second)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c2.spool.Len() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("spool not empty after retransmit ACK: len=%d", c2.spool.Len())
}
