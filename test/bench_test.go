//go:build integration

package mbta_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	mbtago "github.com/iuboy/mbta-go"
	"github.com/iuboy/mbta-go/core"
	v1 "github.com/iuboy/mbta-go/v1"
)

// setupBenchServer 启动一个 v1 server 并返回（addr, cleanup）。
// 复用 integration_test.go 的 helper（同 package）。接受 testing.TB，bench/test 通用。
func setupBenchServer(tb testing.TB, sink core.EventSink) (*mbtago.Server, context.CancelFunc) {
	tb.Helper()
	tok, agentID := "bench-tok", "bench-agent"
	srv, err := mbtago.NewServer(
		mbtago.WithV1(v1.QUICServerConfig{
			Address: "127.0.0.1:0",
			Credentials: &v1.ServerCredentials{
				CertFile: "data/certificates/server.crt",
				KeyFile:  "data/certificates/server.key",
			},
		}),
		mbtago.WithEventSink(sink),
		mbtago.WithAuth(core.NewStaticTokenValidator(map[string]string{tok: agentID})),
	)
	if err != nil {
		tb.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()
	waitAddr(tb, srv)
	return srv, cancel
}

func benchConnect(tb testing.TB, addr string) *mbtago.Client {
	tb.Helper()
	c, err := mbtago.NewClient(
		mbtago.WithServer(addr),
		mbtago.WithAgent("bench-agent", "h", "bench-tok"),
		mbtago.WithV1Credentials(v1.ClientCredentials{InsecureSkipVerify: true}),
	)
	if err != nil {
		tb.Fatalf("NewClient: %v", err)
	}
	if err := c.Connect(context.Background()); err != nil {
		tb.Fatalf("Connect: %v", err)
	}
	return c
}

// BenchmarkE2E_V1_SendBatch 单连接端到端吞吐：握手后循环发小 batch。
// 测量 SendBatch 的稳态吞吐（不含握手开销）。
func BenchmarkE2E_V1_SendBatch(b *testing.B) {
	sink := &countingSink{}
	srv, cancel := setupBenchServer(b, sink)
	defer func() {
		cancel()
		_ = srv.Close()
	}()
	c := benchConnect(b, srv.Addr())
	defer c.Close()

	sb := smallBatch(1, 256)

	b.ResetTimer()
	b.SetBytes(256) // payload 字节数，让 bench 报 MB/s 吞吐
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.SendBatch(context.Background(), sb, "tag", "src"); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

// BenchmarkE2E_V1_SendBatch_LargeBatch 大 batch 吞吐：100 signals × 1KB body。
// 测量单连接处理大 payload 的吞吐（codec + envelope + 传输）。
func BenchmarkE2E_V1_SendBatch_LargeBatch(b *testing.B) {
	sink := &countingSink{}
	srv, cancel := setupBenchServer(b, sink)
	defer func() {
		cancel()
		_ = srv.Close()
	}()
	c := benchConnect(b, srv.Addr())
	defer c.Close()

	sb := smallBatch(100, 1024)

	b.ResetTimer()
	b.SetBytes(100 * 1024) // 100 events × 1KB
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.SendBatch(context.Background(), sb, "tag", "src"); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

// BenchmarkE2E_MultiConn_Throughput 多连接聚合吞吐：N=16 个 client 各自发 batch。
// 每次迭代并发向 16 个连接各发 1 batch，报告每轮（16 batch）耗时与 batch/sec。
// 验证多连接并发下的聚合吞吐能力。
func BenchmarkE2E_MultiConn_Throughput(b *testing.B) {
	const nConns = 16
	sink := &countingSink{}
	srv, cancel := setupBenchServer(b, sink)
	defer func() {
		cancel()
		_ = srv.Close()
	}()

	clients := make([]*mbtago.Client, nConns)
	for i := range clients {
		clients[i] = benchConnect(b, srv.Addr())
	}
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	sb := smallBatch(1, 256)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		// 并发向 nConns 个连接各发 1 batch（一轮 = nConns 个 batch）。
		var wg sync.WaitGroup
		var failed atomic.Bool
		for _, c := range clients {
			wg.Add(1)
			go func(c *mbtago.Client) {
				defer wg.Done()
				if _, err := c.SendBatch(context.Background(), sb, "tag", "src"); err != nil {
					failed.Store(true)
				}
			}(c)
		}
		wg.Wait()
		if failed.Load() {
			b.Fatal("SendBatch failed on one or more connections")
		}
	}
	b.StopTimer()
	// 每轮发了 nConns 个 batch，按此报告 batch/sec。
	b.ReportMetric(float64(nConns), "batch/op")
}

// BenchmarkE2E_ConnectionSetup 连接建立速率：每次迭代 Connect 一个新 client + 发 1 batch，
// 累积到滚动窗口（poolSize），窗口满时关闭最早建立的连接。
//
// 报告单次"连接建立 + 握手 + 1 batch"的耗时。拆除（Close with drain）移到
// b.StopTimer 之后统一进行——因为协议 Close 走 drain（默认超时较长），计入每次迭代
// 会让 benchmark 被 drain 等待主导，无法测出建立速率。
// 验证：若 fd/goroutine 泄漏，建立耗时随迭代数增长（窗口回收失效）。
func BenchmarkE2E_ConnectionSetup(b *testing.B) {
	const poolSize = 32 // 滚动窗口，限制并发连接数避免资源耗尽
	sink := &countingSink{}
	srv, cancel := setupBenchServer(b, sink)
	defer func() {
		cancel()
		_ = srv.Close()
	}()

	addr := srv.Addr()
	sb := smallBatch(1, 64)
	pool := make([]*mbtago.Client, 0, poolSize)
	closeAll := func() {
		for _, c := range pool {
			_ = c.Close()
		}
		pool = pool[:0]
	}
	defer closeAll()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		c := benchConnect(b, addr)
		if _, err := c.SendBatch(context.Background(), sb, "tag", "src"); err != nil {
			c.Close()
			b.Fatal(err)
		}
		pool = append(pool, c)
		// 窗口满：StopTimer 暂停计时，closeAll 关闭并清空 pool 内所有连接，
		// StartTimer 恢复。P7：旧注释"Close 留给 defer"与实际代码（此处 inline closeAll）矛盾，已更正。
		if len(pool) == poolSize {
			b.StopTimer()
			closeAll()
			b.StartTimer()
		}
	}
	b.StopTimer()
}
