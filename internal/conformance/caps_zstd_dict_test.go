package conformance

// caps_zstd_dict_test.go：zstd_dict 能力（服务端静态字典下发）。
//
//   - 配置字典 + 客户端协商 zstd_dict → HELLO_ACK 之后 DICT 帧（0x22）到达，
//     dict_id/dict 内容与策略一致；
//   - 客户端激活字典后 seal with dict → 服务端 open with dict 全链路
//     （RESULT accepted + sink 收到与原文一致的 payload）；
//   - 未配置字典时能力从 selected 剔除（fail-closed：无字典不协商）；
//   - 无字典却构造 ZSTD_DICT envelope → fail-closed 拒绝。
//
// 字典经键控注册表共享（连接级引用）：测试用 RegisterZstdDict 获取 codec，
// Seal/Open 显式传 Dict——多字典并存天然隔离，无需快照恢复。

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// testDictID 是测试字典标识（非 0 即可，客户端不解释）。
const testDictID uint32 = 0x5A5D1C7

// buildTestDict 构造 raw content dictionary（任意字节合法——zstd
// WithEncoderDictRaw/WithDecoderDictRaw 接受非训练格式的原始内容字典）：
// 用日志样语料填充，保证重复性 batch 有可匹配历史。
func buildTestDict() []byte {
	var b strings.Builder
	for i := range 256 {
		b.WriteString(`{"level":"info","service":"inventory-api","msg":"order updated","order_id":"ord-`)
		b.WriteString(strings.Repeat(string(rune('0'+i%10)), 6))
		b.WriteString(`","region":"cn-north-1","took_ms":`)
		b.WriteString(strings.Repeat(string(rune('0'+i%7)), 2))
		b.WriteString("}\n")
	}
	return []byte(b.String())
}

// dictCaps 是启用 zstd_dict 的协商配置。
func dictCaps() (server, client []string) {
	return []string{core.CapTraceContext, core.CapZstdDict},
		[]string{core.CapTraceContext, core.CapZstdDict}
}

// startDictEnv 完成带字典的握手，消费 DICT 帧并激活测试侧（客户端）字典。
func startDictEnv(t *testing.T) (*testEnv, *core.ZstdDict, *sinkCapture, *core.ZstdDictCodec) {
	t.Helper()
	server, client := dictCaps()
	sink := newSinkCapture()
	env := startEnv(t, envConfig{
		serverCaps: server, clientCaps: client,
		zstdDict: buildTestDict(), zstdDictID: testDictID,
		sink: sink.handler,
	})

	// HELLO_ACK 之后立即到达的 DICT 帧。
	f := ReadFrame(t, env.tr.Sent)
	if f.Header.Type != core.TypeDict {
		t.Fatalf("expected DICT frame after HELLO_ACK, got type 0x%02x", f.Header.Type)
	}
	var d core.ZstdDict
	if err := core.Decode(f.Payload, &d); err != nil {
		t.Fatalf("decode zstd dict: %v", err)
	}
	if d.GetDictId() != testDictID {
		t.Errorf("dict_id = %#x, want %#x", d.GetDictId(), testDictID)
	}
	if want := buildTestDict(); !bytes.Equal(d.GetDict(), want) {
		t.Errorf("dict content mismatch (%d vs %d bytes)", len(d.GetDict()), len(want))
	}
	// 客户端激活（模拟 CoreClient.handleDict 的效果）。
	codec, err := core.RegisterZstdDict(d.GetDictId(), d.GetDict())
	if err != nil {
		t.Fatalf("activate dict: %v", err)
	}
	return env, &d, sink, codec
}

// TestZstdDict_HandshakeDeliversDict 验证 DICT 帧到达 + dict_id/内容一致 +
// 字典在 core 层激活。
func TestZstdDict_HandshakeDeliversDict(t *testing.T) {
	_, d, _, codec := startDictEnv(t)
	if len(d.GetDict()) == 0 {
		t.Fatal("empty dict delivered")
	}
	if codec == nil {
		t.Fatal("dict codec not registered after activation")
	}
}

// TestZstdDict_FullChainSealWithDictOpenWithDict 验证 ZSTD_DICT 压缩 batch 的
// 全链路：客户端（带字典 encoder）seal → 服务端（配置字典 decoder）open →
// RESULT accepted + sink 收到与原文一致的 payload。
func TestZstdDict_FullChainSealWithDictOpenWithDict(t *testing.T) {
	// 重复性 batch（> 512B 启发阈值），内容与字典语料同构。
	payload := strings.Repeat(
		`{"level":"info","service":"inventory-api","msg":"order updated","order_id":"ord-000123","region":"cn-north-1"}`, 24)
	env, _, sink, codec := startDictEnv(t)

	plain := makeSignalBatch(t, 1, payload)
	if len(plain) <= 512 {
		t.Fatalf("fixture too small (%d bytes) to exercise dict path", len(plain))
	}

	batch := &core.Batch{Seq: 1, EventsCount: 1, Payload: plain}
	bw, err := core.Encode(batch)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := core.SealEnvelope(core.SealParams{
		FrameType: core.TypeBatch, SessionID: env.sessionID, Seq: 1,
		Compression: corepb.Compression_COMPRESSION_ZSTD_DICT,
		Keys:        env.keys, Dict: codec, BatchWire: bw, DualMACKey: env.keys.DualMACKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	env.tr.DataIn <- MakeFrame(core.TypeBatch, sealed)
	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED || r.GetCode() != core.CodeOK {
		t.Fatalf("result = %v/%d, want accepted/ok", r.GetLevel(), r.GetCode())
	}
	ev := sink.waitEvent(t, 1, 5*time.Second)
	if ev.Meta.Seq != 1 || ev.Meta.EventsCount != 1 {
		t.Errorf("sink meta = seq %d events %d, want 1/1", ev.Meta.Seq, ev.Meta.EventsCount)
	}
	if ev.Decoded == nil || len(ev.Decoded.Signals) != 1 || ev.Decoded.Signals[0].Body != payload {
		t.Error("sink payload mismatch after dict seal/open roundtrip")
	}
}

// TestZstdDict_CompressionRatio 验证字典压缩确实生效：对与字典语料同构的
// batch，ZSTD_DICT 输出密文小于 ZSTD（字典历史可匹配）。
func TestZstdDict_CompressionRatio(t *testing.T) {
	env, _, _, codec := startDictEnv(t)
	payload := strings.Repeat(
		`{"level":"info","service":"inventory-api","msg":"order updated","order_id":"ord-000123","region":"cn-north-1"}`, 16)
	bw, err := core.Encode(&core.Batch{Seq: 1, EventsCount: 1, Payload: makeSignalBatch(t, 1, payload)})
	if err != nil {
		t.Fatal(err)
	}
	sizeAt := func(comp corepb.Compression) int {
		p, err := core.SealEnvelope(core.SealParams{
			FrameType: core.TypeBatch, SessionID: env.sessionID, Seq: 1,
			Compression: comp, Keys: env.keys, Dict: codec, BatchWire: bw,
		})
		if err != nil {
			t.Fatal(err)
		}
		var e core.Envelope
		if err := core.Decode(p, &e); err != nil {
			t.Fatal(err)
		}
		return len(e.GetCiphertext())
	}
	dictSize, plainSize := sizeAt(corepb.Compression_COMPRESSION_ZSTD_DICT),
		sizeAt(corepb.Compression_COMPRESSION_ZSTD)
	if dictSize >= plainSize {
		t.Errorf("dict ciphertext %dB >= plain zstd %dB (dictionary not effective)", dictSize, plainSize)
	}
}

// TestZstdDict_CapStrippedWithoutDict 验证服务端未配置字典时，即使
// SupportedCapabilities 含 zstd_dict 也不协商（无字典可解，fail-closed 剔除）。
func TestZstdDict_CapStrippedWithoutDict(t *testing.T) {
	server, client := dictCaps()
	env := startEnv(t, envConfig{serverCaps: server, clientCaps: client}) // 无 zstdDict
	for _, c := range env.ack.GetSelectedCapabilities() {
		if c == core.CapZstdDict {
			t.Fatal("zstd_dict selected without configured dict (must be stripped)")
		}
	}
	// 也不应有 DICT 帧。
	if f, ok := NextFrame(env.tr.Sent, 500*time.Millisecond); ok {
		t.Fatalf("unexpected frame type 0x%02x after HELLO_ACK (no dict configured)", f.Header.Type)
	}
}

// TestZstdDict_NoDictActive_FailClosed 验证无字典进程构造/接收 ZSTD_DICT
// envelope 一律 fail-closed：seal 报 batch_invalid，open 报 envelope_open_failed。
func TestZstdDict_NoDictActive_FailClosed(t *testing.T) {
	// 清除注册表（测试隔离；结束后由后续测试的 Register 重建）。
	core.ResetZstdDicts()

	env := startEnv(t, envConfig{})
	batch := &core.Batch{Seq: 1, EventsCount: 1, Payload: makeSignalBatch(t, 1, "dict-less")}
	bw, err := core.Encode(batch)
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.SealEnvelope(core.SealParams{
		FrameType: core.TypeBatch, SessionID: env.sessionID, Seq: 1,
		Compression: corepb.Compression_COMPRESSION_ZSTD_DICT,
		Keys:        env.keys, BatchWire: bw,
	})
	if err == nil {
		t.Fatal("seal with ZSTD_DICT succeeded without active dict (must fail-closed)")
	}
	if core.CodeNumOf(err) != core.CodeBatchInvalid {
		t.Errorf("seal code = %d, want %d (batch_invalid)", core.CodeNumOf(err), core.CodeBatchInvalid)
	}

	var env0 core.Envelope
	env0.Seq = 1
	env0.Compression = corepb.Compression_COMPRESSION_ZSTD_DICT
	env0.Ciphertext = []byte("raw-ciphertext")
	if _, oerr := core.OpenEnvelope(core.TypeBatch, env.sessionID, env.keys, nil, &env0); oerr == nil {
		t.Fatal("open accepted ZSTD_DICT envelope without dict")
	} else if core.CodeNumOf(oerr) != core.CodeEnvelopeOpenFail {
		t.Errorf("open code = %d, want %d (envelope_open_failed)", core.CodeNumOf(oerr), core.CodeEnvelopeOpenFail)
	}
}
