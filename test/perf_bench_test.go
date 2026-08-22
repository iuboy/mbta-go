//go:build integration

package mbta_test

// perf_bench_test.go：结构化 JSON 性能报告导出（perf-<timestamp>.json）。
//
// TestPerfExport 用轻量定时循环（每环节 ~120ms，非 testing.B 全量跑）采集
// r3 各核心环节延迟 + E2E 吞吐/延迟，写入 test/results/perf-<毫秒时间戳>.json。
// CI 可归档、跨 commit 对比、绘图；自包含，不依赖 benchstat 等外部工具。
//
// 字段语义（r3）：
//   - stages：keyschedule（密钥日程）/ envelope（封装）/ frame（帧往返）/
//     credit（流控账本与准入窗）/ cipher（HMAC/AEAD 原语）各环节 ns/op；
//   - e2e：真实 QUIC 链路的握手、稳态吞吐与 RESULT 回调延迟；
//   - large_batch：100 signals × 1KB 大 batch 吞吐。

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"google.golang.org/protobuf/proto"
)

// --- 报告结构 ---

// PerfReport 是性能报告顶层结构，序列化为 JSON。
type PerfReport struct {
	Timestamp  string         `json:"timestamp"`  // RFC3339（毫秒），报告生成时刻
	GoVersion  string         `json:"go_version"` // runtime.Version()
	GOOS       string         `json:"goos"`
	GOARCH     string         `json:"goarch"`
	NumCPU     int            `json:"num_cpu"`
	Stages     []StageMetric  `json:"stages"`                // 核心环节延迟（r3 各阶段）
	E2E        E2EMetrics     `json:"e2e"`                   // 真实链路端到端指标
	LargeBatch *LargeBatchRow `json:"large_batch,omitempty"` // 大 batch 吞吐
}

// StageMetric 是单个核心环节的延迟度量（如 envelope_seal_4k_none_intl）。
type StageMetric struct {
	Name        string  `json:"name"`
	NsPerOp     float64 `json:"ns_per_op"`
	MBPerSec    float64 `json:"mb_per_sec,omitempty"`    // 有字节语义的环节才填
	AllocsPerOp float64 `json:"allocs_per_op,omitempty"` // 近似值（全局Mallocs差分）
}

// E2EMetrics 是 v1 QUIC 真实链路的端到端指标。
type E2EMetrics struct {
	HandshakeMs           float64 `json:"handshake_ms"`              // QUIC dial+1-RTT 握手全成本
	SteadySendBatchPerSec float64 `json:"steady_send_batch_per_sec"` // facade 稳态发送
	SteadySendMBPerSec    float64 `json:"steady_send_mb_per_sec"`    // 稳态吞吐（未压缩 batch wire 口径）
	ResultLatencyMs       float64 `json:"result_latency_ms"`         // SendBatch→RESULT(accepted) 回调
	PayloadPerBatch       int     `json:"payload_per_batch"`         // 每 batch 未压缩 wire 字节
}

// LargeBatchRow 是大 batch（100×1KB）端到端吞吐度量。
type LargeBatchRow struct {
	EventsPerBatch int     `json:"events_per_batch"`
	BodyBytes      int     `json:"body_bytes"`
	NBatches       int     `json:"n_batches"`
	ThroughputMBps float64 `json:"throughput_mb_ps"`
	BatchPerSec    float64 `json:"batch_per_sec"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
}

// --- 定时循环采集 ---

// stageResult 是 measureStage 的原始输出。
type stageResult struct {
	nsPerOp     float64
	mbPerSec    float64
	allocsPerOp float64
}

// measureStage 轻量定时循环：预热 64 次 → 计时至 ~120ms。
// bytesPerOp > 0 时同时报告 MB/s；allocs 为全局 Mallocs 差分近似
// （阶段测量先于任何服务端启动，并发污染可忽略）。
func measureStage(bytesPerOp int64, f func()) stageResult {
	for range 64 {
		f() // 预热（zstd 池/AES key schedule/编译热点）
	}
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	n := 0
	start := time.Now()
	for time.Since(start) < 120*time.Millisecond {
		f()
		n++
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&m2)
	if n == 0 {
		return stageResult{}
	}
	r := stageResult{
		nsPerOp:     float64(elapsed.Nanoseconds()) / float64(n),
		allocsPerOp: float64(m2.Mallocs-m1.Mallocs) / float64(n),
	}
	if bytesPerOp > 0 {
		r.mbPerSec = float64(bytesPerOp) * float64(n) / (1024 * 1024) / elapsed.Seconds()
	}
	return r
}

// --- 阶段采集（core 原语，全部走导出面）---

// perfHandshakeMaterial 预生成握手材料（子环节测量输入）。
type perfHandshakeMaterial struct {
	priv *core.EphemeralKey
	pub  []byte
}

func perfEphPair(t *testing.T, p corepb.Profile) (perfHandshakeMaterial, perfHandshakeMaterial) {
	t.Helper()
	c, pubC, err := core.GenerateEphemeral(p)
	if err != nil {
		t.Fatalf("generate client eph: %v", err)
	}
	s, pubS, err := core.GenerateEphemeral(p)
	if err != nil {
		t.Fatalf("generate server eph: %v", err)
	}
	return perfHandshakeMaterial{priv: c, pub: pubC}, perfHandshakeMaterial{priv: s, pub: pubS}
}

// perfKeysOnce 派生一份 intl 会话密钥（envelope 环节共用）。
func perfKeysOnce(t *testing.T) *core.SessionKeys {
	t.Helper()
	priv, pub, err := core.GenerateEphemeral(corepb.Profile_PROFILE_INTL)
	if err != nil {
		t.Fatalf("generate eph: %v", err)
	}
	zz, err := core.DeriveZZ(corepb.Profile_PROFILE_INTL, priv, pub)
	if err != nil {
		t.Fatalf("derive zz: %v", err)
	}
	keys, err := core.DeriveSessionKeys(corepb.Profile_PROFILE_INTL, zz, make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatalf("derive session keys: %v", err)
	}
	return keys
}

// perfLogBody 可压缩日志体（与 core/envelope_bench_test.go 同风格）。
func perfLogBody(size int) string {
	tpl := `service=checkout route=/api/v1/cart msg="add to cart" region=cn-north-1 host=pod-7f9c-`
	var sb strings.Builder
	for sb.Len() < size {
		sb.WriteString(tpl)
	}
	return sb.String()[:size]
}

// perfBatchWire 构造 nSignals 条 log、目标 total 字节的 Batch 编码。
func perfBatchWire(t *testing.T, total, nSignals int) []byte {
	t.Helper()
	bodySize := total/nSignals - 64
	if bodySize < 16 {
		bodySize = 16
	}
	signals := make([]*core.SignalRecord, nSignals)
	for i := range signals {
		signals[i] = &core.SignalRecord{
			SignalType: core.SignalTypeLog,
			TimeUnixMs: time.Now().UnixMilli(),
			Body:       perfLogBody(bodySize),
		}
	}
	payload, err := core.MarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, &core.SignalBatch{Signals: signals})
	if err != nil {
		t.Fatalf("marshal signal batch: %v", err)
	}
	bw, err := core.Encode(&core.Batch{Seq: 1, EventsCount: uint32(nSignals), Payload: payload})
	if err != nil {
		t.Fatalf("encode batch: %v", err)
	}
	return bw
}

// collectStages 采集全部核心环节指标（keyschedule/envelope/frame/credit/cipher）。
func collectStages(t *testing.T) []StageMetric {
	t.Helper()
	var out []StageMetric
	add := func(name string, bytesPerOp int64, f func()) {
		r := measureStage(bytesPerOp, f)
		out = append(out, StageMetric{Name: name, NsPerOp: r.nsPerOp,
			MBPerSec: r.mbPerSec, AllocsPerOp: r.allocsPerOp})
		t.Logf("stage %-36s %10.0f ns/op  %8.1f MB/s  %6.1f allocs/op",
			name, r.nsPerOp, r.mbPerSec, r.allocsPerOp)
	}

	// --- keyschedule ---
	for _, p := range []struct {
		name    string
		profile corepb.Profile
	}{{"intl", corepb.Profile_PROFILE_INTL}, {"gm", corepb.Profile_PROFILE_GM}} {
		add("keyschedule_handshake_"+p.name, 0, func() {
			// 完整日程：双侧 eph + ZZ + transcript + proof + derive（真实 1-RTT 全密码学成本）。
			privC, pubC, err := core.GenerateEphemeral(p.profile)
			if err != nil {
				t.Fatal(err)
			}
			privS, pubS, err := core.GenerateEphemeral(p.profile)
			if err != nil {
				t.Fatal(err)
			}
			hello := &core.Hello{Profile: p.profile, AgentId: "perf-agent-0001", ClientEph: pubC}
			thHello, err := core.TranscriptHello(p.profile, hello)
			if err != nil {
				t.Fatal(err)
			}
			proof := core.TokenProof(p.profile, "perf-token-0123456789", thHello)
			zz, err := core.DeriveZZ(p.profile, privC, pubS)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := core.DeriveSessionKeys(p.profile, zz, thHello, proof); err != nil {
				t.Fatal(err)
			}
			_ = privS
		})
	}

	intl := corepb.Profile_PROFILE_INTL
	cEph, sEph := perfEphPair(t, intl)
	hello := &core.Hello{Profile: intl, AgentId: "perf-agent-0001", ClientEph: cEph.pub}
	thHello, err := core.TranscriptHello(intl, hello)
	if err != nil {
		t.Fatalf("transcript hello: %v", err)
	}
	zz, err := core.DeriveZZ(intl, cEph.priv, sEph.pub)
	if err != nil {
		t.Fatalf("derive zz: %v", err)
	}
	proof := core.TokenProof(intl, "perf-token-0123456789", thHello)
	add("keyschedule_transcript_hello_intl", 0, func() {
		if _, err := core.TranscriptHello(intl, hello); err != nil {
			t.Fatal(err)
		}
	})
	add("keyschedule_token_proof_intl", 0, func() {
		_ = core.TokenProof(intl, "perf-token-0123456789", thHello)
	})
	add("keyschedule_derive_session_keys_intl", 0, func() {
		if _, err := core.DeriveSessionKeys(intl, zz, thHello, proof); err != nil {
			t.Fatal(err)
		}
	})

	// --- envelope（intl，4KB，NONE/ZSTD）---
	keys := perfKeysOnce(t)
	sessionID := []byte("perf-session-01")
	for _, tc := range []struct {
		name string
		comp corepb.Compression
	}{
		{"none", corepb.Compression_COMPRESSION_NONE},
		{"zstd", corepb.Compression_COMPRESSION_ZSTD},
	} {
		bw := perfBatchWire(t, 4*1024, 64)
		envWire, err := core.SealEnvelope(core.SealParams{
			FrameType: core.TypeBatch, SessionID: sessionID, Seq: 1,
			Compression: tc.comp, Keys: keys, BatchWire: bw,
		})
		if err != nil {
			t.Fatalf("seal (%s): %v", tc.name, err)
		}
		var env core.Envelope
		if err := proto.Unmarshal(envWire, &env); err != nil {
			t.Fatalf("unmarshal envelope: %v", err)
		}
		if got, err := core.OpenEnvelope(core.TypeBatch, sessionID, keys, nil, &env); err != nil || !bytes.Equal(got, bw) {
			t.Fatalf("envelope roundtrip (%s): err=%v", tc.name, err)
		}
		params := core.SealParams{
			FrameType: core.TypeBatch, SessionID: sessionID, Seq: 1,
			Compression: tc.comp, Keys: keys, BatchWire: bw,
		}
		add("envelope_seal_4k_"+tc.name+"_intl", int64(len(bw)), func() {
			if _, err := core.SealEnvelope(params); err != nil {
				t.Fatal(err)
			}
		})
		add("envelope_open_4k_"+tc.name+"_intl", int64(len(bw)), func() {
			if _, err := core.OpenEnvelope(core.TypeBatch, sessionID, keys, nil, &env); err != nil {
				t.Fatal(err)
			}
		})
	}

	// --- frame（1KB 往返）---
	framePayload := bytes.Repeat([]byte{0xA5}, 1024)
	add("frame_roundtrip_1k", 1024, func() {
		var buf bytes.Buffer
		if err := core.Write(&buf, core.TypeBatch, 0, framePayload); err != nil {
			t.Fatal(err)
		}
		if _, err := core.Read(&buf, core.DefaultLimits()); err != nil {
			t.Fatal(err)
		}
	})

	// --- credit ---
	ledger := core.NewCreditLedger(1<<20, 1<<30, 0, 0)
	deadline := time.Now().Add(time.Minute)
	var lSeq uint64
	add("credit_ledger_cycle", 0, func() {
		lSeq++
		if err := ledger.Consume(lSeq, 1024, "corr", deadline); err != nil {
			t.Fatal(err)
		}
		ledger.Terminal(lSeq)
		ledger.OnCredit(1, 1024)
	})

	cm := core.NewCreditManager(1<<30, 1<<40, 256)
	var wSeq uint64
	add("admission_sequential", 0, func() {
		wSeq++
		ar := cm.Admit(wSeq)
		if ar.Decision != core.AdmitAccept {
			t.Fatal("admit != accept")
		}
		if err := ar.Grant.Consume(1024); err != nil {
			t.Fatal(err)
		}
		ar.Grant.Settle(nil, corepb.ResultLevel_RESULT_LEVEL_DURABLE, 0, 0, 1024)
	})

	// 乱序阶段用独立窗口（顺序阶段已消费 seq 前缀，共用会让乱序 seq 落 < low 分支）。
	oooCM := core.NewCreditManager(1<<50, 1<<50, 256)
	const oooBlock = 64
	var oooBase, oooI uint64
	add("admission_out_of_order", 0, func() {
		if oooI == oooBlock {
			oooI = 0
			oooBase += oooBlock
		}
		seq := oooBase + 1 + (oooI*7)%oooBlock // stride=7 块内置换（seq 从 1 起）
		oooI++
		ar := oooCM.Admit(seq)
		if ar.Decision != core.AdmitAccept {
			t.Fatal("admit != accept")
		}
		if err := ar.Grant.Consume(1024); err != nil {
			t.Fatal(err)
		}
		ar.Grant.Settle(nil, corepb.ResultLevel_RESULT_LEVEL_DURABLE, 0, 0, 1024)
	})

	// --- cipher（4KB 直压，双 profile）---
	payload4k := make([]byte, 4096)
	if _, err := rand.Read(payload4k); err != nil {
		t.Fatalf("read rand: %v", err)
	}
	for _, tc := range []struct {
		name    string
		profile corepb.Profile
	}{{"sha256", corepb.Profile_PROFILE_INTL}, {"sm3", corepb.Profile_PROFILE_GM}} {
		key := make([]byte, core.HMACKeyLen(tc.profile))
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("read rand: %v", err)
		}
		h, err := core.NewHMAC(tc.profile, key)
		if err != nil {
			t.Fatalf("new hmac: %v", err)
		}
		add("hmac_"+tc.name+"_4k", 4096, func() {
			h.Reset()
			h.Write(payload4k)
			_ = h.Sum(nil)
		})
	}
	for _, tc := range []struct {
		name    string
		profile corepb.Profile
	}{{"aes256gcm", corepb.Profile_PROFILE_INTL}, {"sm4gcm", corepb.Profile_PROFILE_GM}} {
		key := make([]byte, core.AEADKeyLen(tc.profile))
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("read rand: %v", err)
		}
		a, err := core.NewAEAD(tc.profile, key)
		if err != nil {
			t.Fatalf("new aead: %v", err)
		}
		nonce := make([]byte, a.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			t.Fatalf("read rand: %v", err)
		}
		add("aead_seal_"+tc.name+"_4k", 4096, func() {
			_ = a.Seal(payload4k[:0], nonce, payload4k, nil)
		})
	}

	return out
}

// --- E2E 采集（真实 QUIC 链路，复用 bench_test.go 的 harness）---

// collectE2E 在 facade v1 server 上采集握手/稳态吞吐/RESULT 延迟。
func collectE2E(t *testing.T) (E2EMetrics, *LargeBatchRow) {
	t.Helper()
	addr, sink := startBenchServer(t)

	// 1) 握手延迟（raw harness：QUIC dial + 1-RTT + 密钥日程 + finished 校验）。
	const nHandshake = 10
	hsStart := time.Now()
	for range nHandshake {
		c, err := dialRawQUIC(context.Background(), addr, "bench-agent", "bench-tok")
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		if err := c.handshake(context.Background()); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		c.close()
	}
	handshakeMs := float64(time.Since(hsStart).Microseconds()) / float64(nHandshake) / 1000

	// 2) 稳态吞吐 + RESULT 延迟（facade 完整 client 栈，顺序 arm→send→wait）。
	client := benchFacadeClient(t, addr)
	probe := newResultLatencyProbe()
	client.SetResultHandler(probe.handler)
	sb := smallBatch(1, 256)

	// 每 batch 未压缩 wire 字节（吞吐口径）。
	sbPayload, err := core.MarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, sb)
	if err != nil {
		t.Fatalf("marshal signal batch: %v", err)
	}
	sbWire, err := core.Encode(&core.Batch{EventsCount: 1, Payload: sbPayload})
	if err != nil {
		t.Fatalf("encode batch: %v", err)
	}
	perBatch := len(sbWire)

	const nSteady = 1000
	latSum := time.Duration(0)
	steadyStart := time.Now()
	// lastSeq 跟踪连接级计数器实际值（连接上所有 SendBatch——含异步大 batch
	// 阶段——都推进它；arm 依赖预测，错位即回调永不命中）。
	var lastSeq uint64
	for range nSteady {
		probe.arm(lastSeq + 1)
		s, err := client.SendBatch(context.Background(), sb)
		if err != nil {
			t.Fatalf("SendBatch: %v", err)
		}
		if s != lastSeq+1 {
			t.Fatalf("SendBatch seq = %d, 探针预测 %d（连接级计数器错位）", s, lastSeq+1)
		}
		lastSeq = s
		d, ok := probe.waitTimeout(10 * time.Second)
		if !ok {
			t.Fatalf("RESULT for seq %d not observed within 10s", s)
		}
		latSum += d
	}
	steadyElapsed := time.Since(steadyStart)
	if !sink.waitCount(int64(nSteady), 10*time.Second) {
		t.Fatalf("sink count = %d, want %d", sink.count.Load(), nSteady)
	}

	e2e := E2EMetrics{
		HandshakeMs:           handshakeMs,
		SteadySendBatchPerSec: float64(nSteady) / steadyElapsed.Seconds(),
		SteadySendMBPerSec:    float64(perBatch*nSteady) / (1024 * 1024) / steadyElapsed.Seconds(),
		ResultLatencyMs:       float64(latSum.Microseconds()) / float64(nSteady) / 1000,
		PayloadPerBatch:       perBatch,
	}

	// 3) 大 batch（100×1KB）：异步吞吐 + 顺序采样延迟。
	lb := smallBatch(100, 1024)
	lbPayload, err := core.MarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, lb)
	if err != nil {
		t.Fatalf("marshal signal batch: %v", err)
	}
	lbWire, err := core.Encode(&core.Batch{EventsCount: 100, Payload: lbPayload})
	if err != nil {
		t.Fatalf("encode batch: %v", err)
	}
	const nLarge = 100
	lbStart := time.Now()
	for range nLarge {
		s, err := client.SendBatch(context.Background(), lb)
		if err != nil {
			t.Fatalf("SendBatch (large): %v", err)
		}
		lastSeq = s
	}
	lbElapsed := time.Since(lbStart)
	if !sink.waitCount(int64(nSteady+nLarge), 15*time.Second) {
		t.Fatalf("sink count = %d, want %d", sink.count.Load(), nSteady+nLarge)
	}
	// 顺序延迟采样（arm→send→wait，20 样本；seq 预测基于 lastSeq 实际值）。
	var lbLat time.Duration
	for range 20 {
		probe.arm(lastSeq + 1)
		s, err := client.SendBatch(context.Background(), lb)
		if err != nil {
			t.Fatalf("SendBatch (large latency): %v", err)
		}
		if s != lastSeq+1 {
			t.Fatalf("SendBatch (large latency) seq = %d, 探针预测 %d", s, lastSeq+1)
		}
		lastSeq = s
		d, ok := probe.waitTimeout(15 * time.Second)
		if !ok {
			t.Fatalf("RESULT (large latency) for seq %d not observed within 15s", s)
		}
		lbLat += d
	}

	large := &LargeBatchRow{
		EventsPerBatch: 100,
		BodyBytes:      1024,
		NBatches:       nLarge,
		ThroughputMBps: float64(len(lbWire)*nLarge) / (1024 * 1024) / lbElapsed.Seconds(),
		BatchPerSec:    float64(nLarge) / lbElapsed.Seconds(),
		AvgLatencyMs:   float64(lbLat.Microseconds()) / 20 / 1000,
	}
	return e2e, large
}

// --- 报告导出 ---

// writePerfReport 把报告写入 test/results/perf-<毫秒时间戳>.json（防覆盖），
// 返回写入路径。
func writePerfReport(r PerfReport) (string, error) {
	r.Timestamp = time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	r.GoVersion = runtime.Version()
	r.GOOS = runtime.GOOS
	r.GOARCH = runtime.GOARCH
	r.NumCPU = runtime.NumCPU()

	resultsDir := filepath.Join("results")
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir results: %w", err)
	}
	// 毫秒时间戳：同秒多次导出不互相覆盖。
	name := fmt.Sprintf("perf-%s.json", time.Now().Format("20060102-150405.000"))
	path := filepath.Join(resultsDir, name)

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	return path, nil
}

// TestPerfExport 采集各环节 + E2E 指标并导出 JSON 报告。
// 运行：go test -tags integration -run TestPerfExport -v ./test/
func TestPerfExport(t *testing.T) {
	if testing.Short() {
		t.Skip("perf export skipped in short mode")
	}

	stages := collectStages(t)
	e2e, large := collectE2E(t)

	path, err := writePerfReport(PerfReport{Stages: stages, E2E: e2e, LargeBatch: large})
	if err != nil {
		t.Fatalf("write perf report: %v", err)
	}

	t.Logf("e2e: handshake=%.2fms steady=%.0f batch/s (%.1f MB/s) result_latency=%.2fms",
		e2e.HandshakeMs, e2e.SteadySendBatchPerSec, e2e.SteadySendMBPerSec, e2e.ResultLatencyMs)
	t.Logf("large_batch(100x1KB): %.1f MB/s %.0f batch/s avg_latency=%.2fms",
		large.ThroughputMBps, large.BatchPerSec, large.AvgLatencyMs)
	t.Logf("perf report written: %s", path)

	// 基本合理性哨兵：数量级偏离说明实现回归（只报告不失败，趋势由 CI 对比 JSON 判定）。
	if e2e.HandshakeMs > 500 {
		t.Errorf("握手延迟 %.1fms 超过 500ms（数量级异常，检查密钥日程/QUIC 栈）", e2e.HandshakeMs)
	}
}
