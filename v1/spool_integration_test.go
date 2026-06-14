package v1

import (
	"context"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/spool"
)

// startServerWithSink 启动本地 QUIC server，返回 (addr, sink, teardown)。
// 复用 setupE2E 的接线模式，但允许测试自管 client（spool 场景需自建 client）。
func startServerWithSink(t *testing.T) (string, *countSink, func()) {
	t.Helper()
	sink := &countSink{}
	server := NewServer(ServerConfig{
		Transport: QUICServerConfig{
			Address: "127.0.0.1:0",
			Credentials: &ServerCredentials{
				CertFile: certDir + "/server.crt",
				KeyFile:  certDir + "/server.key",
			},
			MaxIncomingStreams: 256,
		},
		Auth: core.NewStaticTokenValidator(map[string]string{"tok": "agent-1"}),
		Policy: core.Policy{
			EnableGzip:       true,
			EnableHMACSHA256: true,
			EnableWindow:     true,
		},
		Sink: sink,
	})
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
		case err := <-startErr:
			srvCancel()
			t.Fatalf("server start failed: %v", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if addr == "" {
		srvCancel()
		t.Fatal("server did not start listening in time")
	}
	teardown := func() {
		srvCancel()
		<-startErr
	}
	return addr, sink, teardown
}

// connectClient 用给定 SpoolDir 连接 server，返回就绪 client。
func connectClient(t *testing.T, addr, spoolDir string) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{
		Transport: QUICClientConfig{
			Server:      addr,
			Credentials: &ClientCredentials{InsecureSkipVerify: true},
		},
		AgentID:  "agent-1",
		Token:    "tok",
		SpoolDir: spoolDir,
		Capabilities: []string{
			core.CapCodecJSON,
			core.CapCompressGzip,
			core.CapHMACSHA256,
			core.CapWindowFlowCtrl,
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := client.Connect(context.Background()); err != nil {
		_ = client.Close()
		t.Fatalf("connect: %v", err)
	}
	return client
}

// waitForEvents 轮询 sink 直到收到 want 个事件或超时。
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
		{SignalType: "log", Body: "spool-test", TimeUnixMs: 1},
	}}
	if _, err := client.SendBatch(context.Background(), batch, "tag", "src"); err != nil {
		t.Fatalf("send: %v", err)
	}

	// 等 ACK 到达并处理（handleAck 同步删 spool）。
	waitForEvents(t, sink, 1, 3*time.Second)
	// 给 handleAck 一点时间执行 spool 删除（ACK 在 dispatch 前）。
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if client.spool.Len() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("spool not empty after ACK: len=%d", client.spool.Len())
}

// TestSpool_CrashRetransmit 模拟崩溃恢复：seed 一条未 ACK 的 batch 到 spool，
// 关闭 client1（flush 落盘）后用同 SpoolDir 新建 client2 连接 → drain 重发 → 服务端收到。
func TestSpool_CrashRetransmit(t *testing.T) {
	dir := t.TempDir()

	// client1：手动 seed spool（模拟"Put 后、ACK 前崩溃"），不 Connect，直接 Close 落盘。
	c1, err := NewClient(ClientConfig{
		Transport: QUICClientConfig{Server: "127.0.0.1:0"}, // 占位，不连接
		AgentID:   "agent-1",
		Token:     "tok",
		SpoolDir:  dir,
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
	if err := c1.Close(); err != nil { // flush 落盘
		t.Fatalf("close client1: %v", err)
	}

	// client2：同 SpoolDir，Connect 触发 drainSpoolAfterConnect 重发 seed 的 batch。
	addr, sink, td := startServerWithSink(t)
	defer td()
	c2 := connectClient(t, addr, dir)
	defer c2.Close()

	// 服务端应收到重发的 1 个事件。
	waitForEvents(t, sink, 1, 3*time.Second)

	// 重发 ACK 后原 spool 条目应被删除。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c2.spool.Len() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("spool not empty after retransmit ACK: len=%d", c2.spool.Len())
}
