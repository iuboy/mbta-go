//go:build integration

package mbta_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	mbtago "github.com/iuboy/mbta-go"
	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
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

	// --- 导出结构化 JSON 报告（含核心环节延迟 + 端到端分解）---
	stages := measureCoreStages(t)
	report := PerfReport{
		E2E: E2EMetrics{
			HandshakeMs:     handshakeLatency.Seconds() * 1000,
			ColdSendMs:      coldLatency.Seconds() * 1000,
			SteadySendUs:    steadyAvg.Seconds() * 1e6,
			CloseMs:         closeLatency.Seconds() * 1000,
			BatchPerSec:     steadyThroughput,
			PayloadBytesPS:  steadyBytesPerSec,
			PayloadPerBatch: payloadBytesPerBatch,
		},
		Stages: stages,
	}
	if path, err := writePerfReport(report); err != nil {
		t.Errorf("write perf report: %v", err)
	} else {
		t.Logf("性能报告已导出: %s", path)
	}
}

// measureCoreStages 测量协议核心环节的延迟（envelope/cipher/negotiate），返回结构化
// 度量供 JSON 报告。每个环节跑 nPerStage 次取平均，数据自包含（无需跑 core bench）。
func measureCoreStages(t *testing.T) []StageMetric {
	t.Helper()
	const nPerStage = 500

	// 准备 envelope Build/Open 参数（INTL + GM，4KB payload）。
	payload := make([]byte, 4096)
	_, _ = rand.Read(payload)
	intlHMAC := make([]byte, core.HMACKeyLen(corepb.CipherSuite_CIPHER_SUITE_INTL))
	intlAEAD := make([]byte, core.AEADKeyLen(corepb.CipherSuite_CIPHER_SUITE_INTL))
	gmHMAC := make([]byte, core.HMACKeyLen(corepb.CipherSuite_CIPHER_SUITE_GM))
	gmAEAD := make([]byte, core.AEADKeyLen(corepb.CipherSuite_CIPHER_SUITE_GM))
	_, _ = rand.Read(intlHMAC)
	_, _ = rand.Read(intlAEAD)
	_, _ = rand.Read(gmHMAC)
	_, _ = rand.Read(gmAEAD)

	mkParams := func(cs corepb.CipherSuite, hmacKey, aeadKey []byte) core.BuildParams {
		return core.BuildParams{
			SessionID: []byte("s"), KeyID: "k", Seq: 1, Codec: corepb.Codec_CODEC_PROTO,
			Compression: corepb.Compression_COMPRESSION_NONE, CipherSuite: cs,
			DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
			MsgType:      corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
			HMACKey:      hmacKey, AEADKey: aeadKey, BatchPayload: payload, ChunkID: core.NewChunkID(),
		}
	}
	intlP := mkParams(corepb.CipherSuite_CIPHER_SUITE_INTL, intlHMAC, intlAEAD)
	gmP := mkParams(corepb.CipherSuite_CIPHER_SUITE_GM, gmHMAC, gmAEAD)
	intlEnv, _ := core.Build(intlP)
	gmEnv, _ := core.Build(gmP)

	var stages []StageMetric

	// Envelope Build/Open（INTL + GM）。
	stages = append(stages, avgStage("EnvelopeBuild/INTL_4KB", nPerStage, 4096, 0, func() {
		_, _ = core.Build(intlP)
	}))
	stages = append(stages, avgStage("EnvelopeBuild/GM_4KB", nPerStage, 4096, 0, func() {
		_, _ = core.Build(gmP)
	}))
	stages = append(stages, avgStage("EnvelopeOpen/INTL_4KB", nPerStage, 4096, 0, func() {
		_, _ = core.Open(intlEnv, intlHMAC, intlAEAD)
	}))
	stages = append(stages, avgStage("EnvelopeOpen/GM_4KB", nPerStage, 4096, 0, func() {
		_, _ = core.Open(gmEnv, gmHMAC, gmAEAD)
	}))

	// HMAC（INTL + GM）。
	intlH, _ := core.NewHMAC(corepb.CipherSuite_CIPHER_SUITE_INTL, intlHMAC)
	gmH, _ := core.NewHMAC(corepb.CipherSuite_CIPHER_SUITE_GM, gmHMAC)
	stages = append(stages, avgStage("HMAC/INTL_SHA256_4KB", nPerStage, 4096, 0, func() {
		intlH.Reset()
		intlH.Write(payload)
		_ = intlH.Sum(nil)
	}))
	stages = append(stages, avgStage("HMAC/GM_SM3_4KB", nPerStage, 4096, 0, func() {
		gmH.Reset()
		gmH.Write(payload)
		_ = gmH.Sum(nil)
	}))

	// Negotiate（典型 2 caps）。
	policy := core.DefaultPolicy(corepb.CipherSuite_CIPHER_SUITE_INTL)
	typicalCaps := []string{core.CapCodecProto, core.CapCSIntl}
	stages = append(stages, avgStage("Negotiate/typical_2caps", nPerStage, 0, 0, func() {
		_, _ = core.Negotiate(typicalCaps, policy)
	}))

	return stages
}

// avgStage 跑 n 次 op 取平均耗时，返回 StageMetric。payloadBytes>0 时计算 MB/s。
func avgStage(name string, n int, payloadBytes int, allocsPerOp float64, op func()) StageMetric {
	// 预热一次（消除首次初始化噪声）。
	op()
	start := time.Now()
	for i := 0; i < n; i++ {
		op()
	}
	elapsed := time.Since(start)
	nsPerOp := float64(elapsed.Nanoseconds()) / float64(n)
	mbPerSec := 0.0
	if payloadBytes > 0 && nsPerOp > 0 {
		mbPerSec = float64(payloadBytes) / nsPerOp * 1e3 // bytes/ns → MB/s
	}
	return StageMetric{Name: name, NsPerOp: nsPerOp, MBPerSec: mbPerSec, AllocsPerOp: allocsPerOp}
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

	// 导出大 batch 吞吐到 JSON 报告。
	report := PerfReport{
		LargeBatch: &LargeBatchRow{
			EventsPerBatch: nEvents,
			BodyBytes:      bodyBytes,
			NBatches:       nBatches,
			ThroughputMBps: throughputMBps,
			BatchPerSec:    batchPerSec,
			AvgLatencyMs:   elapsed.Seconds() * 1000 / float64(nBatches),
		},
	}
	if path, err := writePerfReport(report); err != nil {
		t.Errorf("write perf report: %v", err)
	} else {
		t.Logf("大 batch 报告已导出: %s", path)
	}
}
