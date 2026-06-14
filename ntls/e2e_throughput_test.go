package ntls

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// 端到端 ntls（TCP + TLCP）吞吐压测：真实 ntls Server + Client（testdata SM2 双证书，
// localhost），启用 HMAC-SHA256 + window 流控，测 SendBatch 全路径
// （marshal→HMAC→TLCP→server 解码→ACK）的稳态吞吐。
//
// 与 v1 QUIC 的差异：ntls 是单 TCP 连接、control/data 帧多路复用，无多流并发；
// 故此处只测单连接单发送者维度。TLCP 加密开销与 QUIC TLS 1.3 不同，预期绝对吞吐
// 低于 QUIC，但关注的是同一传输层下不同 batch 规模的相对曲线与稳态行为。

// setupE2E 启动一个本地 ntls Server 并连接一个 ntls Client，返回就绪的 client、计数 sink 与 teardown。
func setupE2E(b testing.TB, sink core.EventSink) (*Client, *countSink, func()) {
	b.Helper()

	if sink == nil {
		sink = &countSink{}
	}
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
		b.Fatalf("new server: %v", err)
	}

	srvCtx, srvCancel := context.WithCancel(context.Background())
	startErr := make(chan error, 1)
	go func() { startErr <- server.Start(srvCtx) }()

	// 轮询监听地址就绪。
	var addr string
	for i := 0; i < 200; i++ {
		addr = server.Addr()
		if addr != "" {
			break
		}
		select {
		case err := <-startErr:
			srvCancel()
			b.Fatalf("server start failed: %v", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if addr == "" {
		srvCancel()
		b.Fatal("server did not start listening in time")
	}

	client, err := NewClient(ClientConfig{
		Server: addr,
		Credentials: &ClientCredentials{
			SignCertFile:       signCertFile,
			SignKeyFile:        signKeyFile,
			EncCertFile:        encCertFile,
			EncKeyFile:         encKeyFile,
			InsecureSkipVerify: true,
		},
		AgentID: "agent-1",
		Token:   "tok",
		Capabilities: []string{
			core.CapCodecJSON,
			core.CapHMACSHA256,
			core.CapWindowFlowCtrl,
		},
	})
	if err != nil {
		srvCancel()
		b.Fatalf("new client: %v", err)
	}

	// Connect 用独立长生命周期 ctx：lifecycleCtx 从该 ctx 派生，驱动 readControlLoop 等
	// 后台 goroutine。若用可取消 ctx（WithTimeout + defer cancel），取消级联到 lifecycleCtx，
	// readControlLoop 握手后立即退出、无人读 ACK。
	connCtx, connCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := client.Connect(connCtx); err != nil {
		connCancel()
		srvCancel()
		b.Fatalf("connect: %v", err)
	}
	connCancel()

	teardown := func() {
		_ = client.Close()
		srvCancel()
		<-startErr // 等 server.Start 返回
	}
	return client, sink.(*countSink), teardown
}

// makeBatch 构造 n 个 log 信号的 SignalBatch，与 v1 bench 保持一致以便横向对比。
func makeBatch(n int) *core.SignalBatch {
	signals := make([]*core.SignalRecord, n)
	for i := range signals {
		signals[i] = &core.SignalRecord{
			SignalType: "log",
			EventID:    "evt",
			Body:       "benchmark log line",
			Attributes: map[string]any{"k": "v", "i": i},
		}
	}
	return &core.SignalBatch{Signals: signals}
}

// sendOrYield 发送一个 batch；遇窗口满让出调度重试（背压下稳态吞吐），其他错误 Fatal。
func sendOrYield(b *testing.B, client *Client, batch *core.SignalBatch) {
	for {
		_, err := client.SendBatch(context.Background(), batch, "tag", "src")
		if err == nil {
			return
		}
		if errors.Is(err, ErrWindowFull) {
			runtime.Gosched()
			continue
		}
		b.Fatalf("send: %v", err)
	}
}

// waitForDrain 等待客户端 inflight 清空（服务端已 ACK 全部已发 batch），让 ReportMetric
// 读到的 sink.events 准确，并使随后的 Close() drain 快速通过。
func waitForDrain(client *Client, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if client.pendingCount.Load() == 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// BenchmarkE2E_NTLS_SendBatch：单发送者，不同 batch 规模的端到端 ntls 吞吐。
// 报告 batch/s 与 events/s（服务端实际接收）。
func BenchmarkE2E_NTLS_SendBatch(b *testing.B) {
	for _, ev := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("events=%d", ev), func(b *testing.B) {
			client, sink, td := setupE2E(b, nil)
			defer td()
			batch := makeBatch(ev)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sendOrYield(b, client, batch)
			}
			b.StopTimer()
			waitForDrain(client, 10*time.Second)
			secs := b.Elapsed().Seconds()
			b.ReportMetric(float64(b.N)/secs, "batch/s")
			b.ReportMetric(float64(sink.events.Load())/secs, "events/s")
		})
	}
}
