package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// 端到端 QUIC 吞吐压测：真实 v1 Server + Client（testdata 自签证书，localhost QUIC），
// 启用 gzip + HMAC-SHA256 + window 流控，测 SendBatch 全路径（marshal→gzip→HMAC→QUIC→server
// 解码→ACK）的稳态吞吐与延迟。规模维度：单 batch 的 event 数、并发发送者数。

// certDir 是相对 v1 包测试目录的 testdata 证书路径。
const certDir = "../testdata/certificates"

// countSink 计数服务端实际收到的 events，用于报告真实送达吞吐（受 ACK/流控约束）。
type countSink struct {
	events atomic.Int64
}

func (s *countSink) OnSignalBatch(_ context.Context, _ string, batch *core.SignalBatch) error {
	s.events.Add(int64(len(batch.Signals)))
	return nil
}
func (s *countSink) OnPressure(_ string) core.PressureState { return core.PressureNormal }

// setupE2E 启动一个本地 v1 Server 并连接一个 v1 Client，返回就绪的 client、计数 sink 与 teardown。
// sink 为 nil 时使用 countSink（非 RawEventSink，走原路径）。
func setupE2E(b testing.TB, strategy string, streamCount int, sink core.EventSink) (*Client, core.EventSink, func()) {
	b.Helper()

	if sink == nil {
		sink = &countSink{}
	}
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
			RequireToken:     true,
			EnableGzip:       true,
			EnableHMACSHA256: true,
			EnableWindow:     true,
		},
		Sink: sink,
	})

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
		Transport: QUICClientConfig{
			Server:      addr,
			Credentials: &ClientCredentials{InsecureSkipVerify: true},
		},
		AgentID: "agent-1",
		Token:   "tok",
		Capabilities: []string{
			core.CapCodecJSON,
			core.CapCompressGzip,
			core.CapHMACSHA256,
			core.CapWindowFlowCtrl,
		},
		PickStrategy: strategy,
		StreamCount:  streamCount,
	})
	if err != nil {
		srvCancel()
		b.Fatalf("new client: %v", err)
	}

	// Connect 必须用独立的长生命周期 ctx：lifecycleCtx 会从该 ctx 派生，驱动 readControlLoop
	// 等后台 goroutine。若用会被取消的 ctx（如 WithTimeout + defer cancel），取消会级联到
	// lifecycleCtx，导致 readControlLoop 在握手后立即退出、无人读 ACK。
	if err := client.Connect(context.Background()); err != nil {
		srvCancel()
		b.Fatalf("connect: %v", err)
	}

	teardown := func() {
		_ = client.Close()
		srvCancel()
		<-startErr // 等 server.Start 返回
	}
	return client, sink, teardown
}

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

// sendOrYield 发送一个 batch；遇到窗口满则让出调度重试（背压下的稳态吞吐），其他错误 Fatal。
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

// waitForDrain 等待客户端 inflight 清空（服务端已 ACK 全部已发 batch）。
// 用途有二：(1) 让 ReportMetric 读到的 sink.events 准确（服务端已处理完）；
// (2) 让随后的 client.Close() 的 drain 快速通过，不卡满 30s 超时。
func waitForDrain(client *Client, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if client.pendingCount.Load() == 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// BenchmarkE2E_SendBatch：单发送者，不同 batch 规模的端到端吞吐。
// 报告 batch/s 与 events/s（服务端实际接收）。
func BenchmarkE2E_SendBatch(b *testing.B) {
	for _, ev := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("events=%d", ev), func(b *testing.B) {
			client, sink, td := setupE2E(b, "hash", 4, nil)
			defer td()
			batch := makeBatch(ev)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sendOrYield(b, client, batch)
			}
			b.StopTimer()
			waitForDrain(client, 5*time.Second)
			secs := b.Elapsed().Seconds()
			b.ReportMetric(float64(b.N)/secs, "batch/s")
			b.ReportMetric(float64(sink.(*countSink).events.Load())/secs, "events/s")
		})
	}
}

// BenchmarkE2E_Concurrent：多发送者并发，验证多流 + 缩小 sendMu 后的并行收益。
// 报告聚合 events/s。
func BenchmarkE2E_Concurrent(b *testing.B) {
	for _, p := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("senders=%d", p), func(b *testing.B) {
			client, sink, td := setupE2E(b, "hash", 4, nil)
			defer td()
			batch := makeBatch(1000)
			b.SetParallelism(p)
			b.ResetTimer()
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					sendOrYield(b, client, batch)
				}
			})
			b.StopTimer()
			waitForDrain(client, 5*time.Second)
			secs := b.Elapsed().Seconds()
			b.ReportMetric(float64(sink.(*countSink).events.Load())/secs, "events/s")
		})
	}
}

// BenchmarkE2E_SingleVsMultiStream：单流 vs 多流（hash）的吞吐对比，
// 直接量化 PickStrategy 多流优化在端到端场景的收益。
func BenchmarkE2E_SingleVsMultiStream(b *testing.B) {
	for _, sc := range []int{1, 4} {
		b.Run(fmt.Sprintf("streams=%d", sc), func(b *testing.B) {
			strategy := "hash"
			if sc == 1 {
				strategy = "single"
			}
			client, sink, td := setupE2E(b, strategy, sc, nil)
			defer td()
			batch := makeBatch(1000)
			b.SetParallelism(8)
			b.ResetTimer()
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					sendOrYield(b, client, batch)
				}
			})
			b.StopTimer()
			waitForDrain(client, 5*time.Second)
			secs := b.Elapsed().Seconds()
			b.ReportMetric(float64(sink.(*countSink).events.Load())/secs, "events/s")
		})
	}
}

// rawCountSink 实现 RawEventSink，服务端走快速路径（不解码 signalBatch）。
// 对比 countSink（原路径）可量化 RawEventSink 的 server 端解码省去收益。
type rawCountSink struct {
	events atomic.Int64
}

func (s *rawCountSink) OnRawBatch(_ context.Context, _ string, events int, _ json.RawMessage) (*core.RouteResult, error) {
	s.events.Add(int64(events))
	return &core.RouteResult{Status: core.ACKStatusAccepted}, nil
}
func (s *rawCountSink) OnSignalBatchWithResult(_ context.Context, _ string, batch *core.SignalBatch) (*core.RouteResult, error) {
	s.events.Add(int64(len(batch.Signals)))
	return &core.RouteResult{Status: core.ACKStatusAccepted}, nil
}
func (s *rawCountSink) OnSignalBatch(_ context.Context, _ string, batch *core.SignalBatch) error {
	s.events.Add(int64(len(batch.Signals)))
	return nil
}
func (s *rawCountSink) OnPressure(_ string) core.PressureState { return core.PressureNormal }

// BenchmarkE2E_RawSink：RawEventSink 快速路径（服务端跳过 signalBatch 解码）的端到端吞吐。
func BenchmarkE2E_RawSink(b *testing.B) {
	for _, ev := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("events=%d", ev), func(b *testing.B) {
			sink := &rawCountSink{}
			client, _, td := setupE2E(b, "hash", 4, sink)
			defer td()
			batch := makeBatch(ev)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sendOrYield(b, client, batch)
			}
			b.StopTimer()
			waitForDrain(client, 5*time.Second)
			secs := b.Elapsed().Seconds()
			b.ReportMetric(float64(b.N)/secs, "batch/s")
			b.ReportMetric(float64(sink.events.Load())/secs, "events/s")
		})
	}
}
