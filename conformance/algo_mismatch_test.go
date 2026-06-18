package conformance

import (
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// buildMismatchedEnvelope 构造一个 BATCH envelope，但 Codec/CipherSuite/Compression
// 可被覆写为与协商结果不符的值，用于验证服务端算法一致性复核。
func buildMismatchedEnvelope(t *testing.T, keys *core.SessionKeys, cs corepb.CipherSuite,
	overrideCodec corepb.Codec, overrideCipher corepb.CipherSuite, overrideComp corepb.Compression) []byte {
	t.Helper()
	chunkID := core.NewChunkID()
	batchJSON := makeSignalBatch("algo-mismatch")
	batchMsg := &corepb.BatchMessage{
		Seq: 1, ChunkId: chunkID.Bytes(), EventsCount: 1, Batch: batchJSON,
	}
	bp, err := core.Encode(batchMsg)
	if err != nil {
		t.Fatalf("encode batch message: %v", err)
	}
	params := core.BuildParams{
		SessionID: []byte("session-1"), Seq: 1, ChunkID: chunkID,
		Codec: overrideCodec, Compression: overrideComp, CipherSuite: cs,
		DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
		MsgType:      corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
		HMACKey:      keys.HMACKey(), AEADKey: keys.AEADKey(), BatchPayload: bp,
	}
	env, err := core.Build(params)
	if err != nil {
		t.Fatalf("build envelope: %v", err)
	}
	// 覆写 envelope 的算法字段为与协商不符的值，模拟客户端注入未协商算法。
	env.Codec = overrideCodec
	if overrideCipher != cs {
		env.CipherSuite = overrideCipher
	}
	if overrideComp != corepb.Compression_COMPRESSION_NONE {
		env.Compression = overrideComp
	}
	ep, err := core.Encode(env)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	return ep
}

// TestCoreHandler_AlgoMismatch_Codec 验证 envelope 声明的 Codec 与协商结果不符时被 NACK。
// 回归 P1 修复：原先 verifyEnvelopeAlgo 只校验 Compression，codec 可被任意注入。
func TestCoreHandler_AlgoMismatch_Codec(t *testing.T) {
	tr, keys, cs := doHandshake(t, nil)
	// 协商结果 codec=PROTO（capability 仅含 codec_proto），注入 CODEC_JSON（未协商）。
	// Build 用 JSON 计算 HMAC（合法 MAC），故 HMAC 通过，到 algo 复核层
	// 因 env.Codec != 协商 codec 被拒——这正是 verifyEnvelopeAlgo 补齐 codec 校验要拦截的场景。
	ep := buildMismatchedEnvelope(t, keys, cs,
		corepb.Codec_CODEC_JSON, cs, corepb.Compression_COMPRESSION_NONE)
	tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, ep)

	resp := ReadFrame(t, tr.Sent)
	if resp.Header.Type != core.TypeNack {
		t.Fatalf("expected NACK for codec mismatch, got type %d", resp.Header.Type)
	}
	var n core.NackMessage
	if err := core.Decode(resp.Payload, &n); err != nil {
		t.Fatalf("decode nack: %v", err)
	}
	if n.GetCode() != protocol.CodeEnvelopeAlgoMismatch {
		t.Errorf("nack code = %q, want %s", n.GetCode(), protocol.CodeEnvelopeAlgoMismatch)
	}
}

// TestCoreHandler_AlgoMismatch_CipherSuite 验证 CipherSuite 篡改被拒绝。
//
// 注意：CipherSuite 是 HMAC canonical 输入的一部分，篡改它必然先触发 hmac_mismatch
// （HMAC 校验在 verifyEnvelopeAlgo 之前）。这是正确的纵深防御——无论被 hmac 层还是
// algo 层拦截，篡改的 envelope 都不会进入解密/解码路径。本测试断言「被拒绝」而非
// 特定错误码，兼容两层拦截。
func TestCoreHandler_AlgoMismatch_CipherSuite(t *testing.T) {
	tr, keys, cs := doHandshake(t, nil)
	// 协商 INTL，注入 GM（HMAC/AEAD 仍用 INTL 密钥，仅 envelope 字段造假）。
	ep := buildMismatchedEnvelope(t, keys, cs,
		corepb.Codec_CODEC_PROTO, corepb.CipherSuite_CIPHER_SUITE_GM, corepb.Compression_COMPRESSION_NONE)
	tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, ep)

	resp := ReadFrame(t, tr.Sent)
	if resp.Header.Type != core.TypeNack {
		t.Fatalf("expected NACK for cipher suite tampering, got type %d", resp.Header.Type)
	}
	var n core.NackMessage
	if err := core.Decode(resp.Payload, &n); err != nil {
		t.Fatalf("decode nack: %v", err)
	}
	// 合理拦截层：hmac_mismatch（篡改破坏 MAC）或 envelope_algo_mismatch（复核层）。
	if n.GetCode() != protocol.CodeEnvelopeAlgoMismatch && n.GetCode() != "hmac_mismatch" {
		t.Errorf("nack code = %q, want %s or hmac_mismatch", n.GetCode(), protocol.CodeEnvelopeAlgoMismatch)
	}
}

// TestCoreHandler_AlgoMismatch_Compression 验证 Compression 不符时仍被 NACK（原有逻辑，回归保护）。
func TestCoreHandler_AlgoMismatch_Compression(t *testing.T) {
	tr, keys, cs := doHandshake(t, nil)
	ep := buildMismatchedEnvelope(t, keys, cs,
		corepb.Codec_CODEC_PROTO, cs, corepb.Compression_COMPRESSION_ZSTD)
	tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, ep)

	resp := ReadFrame(t, tr.Sent)
	if resp.Header.Type != core.TypeNack {
		t.Fatalf("expected NACK for compression mismatch, got type %d", resp.Header.Type)
	}
	var n core.NackMessage
	if err := core.Decode(resp.Payload, &n); err != nil {
		t.Fatalf("decode nack: %v", err)
	}
	if n.GetCode() != protocol.CodeEnvelopeAlgoMismatch {
		t.Errorf("nack code = %q, want %s", n.GetCode(), protocol.CodeEnvelopeAlgoMismatch)
	}
}
