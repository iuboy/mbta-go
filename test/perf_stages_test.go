//go:build integration

package mbta_test

import (
	"context"
	"testing"
	"time"

	mbtago "github.com/iuboy/mbta-go"
	v1 "github.com/iuboy/mbta-go/v1"
)

// TestPerf_StagedLatency 端到端各环节延迟分解：握手、首次 SendBatch（冷启动）、
// 稳态 SendBatch（N 次平均，含 ACK 往返）、Close。输出可读的延迟报告 + 吞吐量。
//
// 运行：go test -tags integration -run TestPerf_StagedLatency -v ./test/
// 用途：定位端到端延迟瓶颈（握手 vs 编码+envelope vs 传输+ACK 往返）。
func TestPerf_StagedLatency(t *testing.T) {
	sink := &countingSink{}
	srv, cancel := setupBenchServer(t, sink)
	defer func() {
		cancel()
		_ = srv.Close()
	}()
	addr := srv.Addr()

	// --- 阶段 1：握手（NewClient + Connect，含 QUIC 握手 + HELLO/AUTH）---
	handshakeStart := time.Now()
	c, err := mbtago.NewClient(
		mbtago.WithServer(addr),
		mbtago.WithAgent("bench-agent", "h", "bench-tok"),
		mbtago.WithV1Credentials(v1.ClientCredentials{InsecureSkipVerify: true}),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	handshakeLatency := time.Since(handshakeStart)
	defer c.Close()

	sb := smallBatch(1, 256)

	// --- 阶段 2：首次 SendBatch（冷启动，可能含首次 stream/codec 初始化）---
	coldStart := time.Now()
	if _, err := c.SendBatch(context.Background(), sb, "tag", "src"); err != nil {
		t.Fatalf("cold SendBatch: %v", err)
	}
	coldLatency := time.Since(coldStart)

	// --- 阶段 3：稳态 SendBatch（N 次平均，含完整 ACK 往返）---
	const steadyN = 1000
	steadyStart := time.Now()
	for i := 0; i < steadyN; i++ {
		if _, err := c.SendBatch(context.Background(), sb, "tag", "src"); err != nil {
			t.Fatalf("steady SendBatch %d: %v", i, err)
		}
	}
	steadyTotal := time.Since(steadyStart)
	steadyAvg := steadyTotal / steadyN

	// --- 阶段 4：Close（drain 等 pending ACK）---
	closeStart := time.Now()
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	closeLatency := time.Since(closeStart)

	// --- 报告 ---
	steadyThroughput := float64(steadyN) / steadyTotal.Seconds()
	payloadBytesPerBatch := 256 // smallBatch(1, 256) body
	steadyBytesPerSec := steadyThroughput * float64(payloadBytesPerBatch)

	t.Log("========== 端到端各环节延迟分解 ==========")
	t.Logf("握手 (NewClient+Connect, QUIC+HELLO/AUTH): %v", handshakeLatency)
	t.Logf("首次 SendBatch (冷启动):                   %v", coldLatency)
	t.Logf("稳态 SendBatch (×%d 平均, 含ACK往返):      %v", steadyN, steadyAvg)
	t.Logf("Close (drain 等 pending ACK):              %v", closeLatency)
	t.Log("---------- 吞吐量 ----------")
	t.Logf("稳态 batch 吞吐: %.0f batch/s", steadyThroughput)
	t.Logf("稳态 payload 吞吐: %.2f MB/s (%.0f KB/s)",
		steadyBytesPerSec/1024/1024, steadyBytesPerSec/1024)
	t.Logf("payload/batch: %d bytes", payloadBytesPerBatch)
	t.Log("==========================================")

	// 基本合理性断言（防止环境异常导致无意义数据）
	if steadyAvg > 100*time.Millisecond {
		t.Errorf("稳态延迟 %v 过高（>100ms），疑似环境问题或回归", steadyAvg)
	}
}

// TestPerf_LargeBatch_Throughput 大 batch（100 events × 1KB）端到端吞吐。
// 验证 codec/envelope/传输对大 payload 的处理能力，报 MB/s。
//
// 运行：go test -tags integration -run TestPerf_LargeBatch_Throughput -v ./test/
func TestPerf_LargeBatch_Throughput(t *testing.T) {
	sink := &countingSink{}
	srv, cancel := setupBenchServer(t, sink)
	defer func() {
		cancel()
		_ = srv.Close()
	}()

	c := benchConnect(t, srv.Addr())
	defer c.Close()

	const (
		nEvents   = 100
		bodyBytes = 1024
		nBatches  = 200
	)
	sb := smallBatch(nEvents, bodyBytes)
	payloadBytes := nEvents * bodyBytes // 近似（hex 翻倍，但量级一致）

	start := time.Now()
	for i := 0; i < nBatches; i++ {
		if _, err := c.SendBatch(context.Background(), sb, "tag", "src"); err != nil {
			t.Fatalf("SendBatch %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	totalPayloadMB := float64(nBatches*payloadBytes) / 1024 / 1024
	throughputMBps := totalPayloadMB / elapsed.Seconds()
	batchPerSec := float64(nBatches) / elapsed.Seconds()

	t.Log("========== 大 batch 端到端吞吐 ==========")
	t.Logf("batch 规格: %d events × %d bytes = %d bytes/batch", nEvents, bodyBytes, payloadBytes)
	t.Logf("总发送: %d batch = %.2f MB", nBatches, totalPayloadMB)
	t.Logf("耗时: %v", elapsed)
	t.Logf("吞吐: %.2f MB/s | %.0f batch/s", throughputMBps, batchPerSec)
	t.Logf("平均延迟/batch: %v", elapsed/nBatches)
	t.Log("=========================================")

	// 等待 sink 收齐（异步投递），验证无丢失。
	if !waitCount(sink, int64(nBatches), 5*time.Second) {
		t.Errorf("sink 收到 %d batch, want %d（异步投递丢失？）", sink.count.Load(), nBatches)
	}
}
