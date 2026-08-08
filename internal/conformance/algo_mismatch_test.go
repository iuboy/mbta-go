package conformance

import (
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/testutil"
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
		SessionID: []byte(testutil.RandString(8)), Seq: 1, ChunkID: chunkID,
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
	if n.GetCode() != core.ErrCodeEnvelopeAlgoMismatch.Code {
		t.Errorf("nack code = %q, want %s", n.GetCode(), core.ErrCodeEnvelopeAlgoMismatch.Code)
	}
}

// TestCoreHandler_AlgoMismatch_CipherSuite 验证 CipherSuite 篡改被拒绝。
// CipherSuite 属 HMAC canonical 输入，篡改会被 hmac_mismatch 或 algo_mismatch 拦截；本测试断言「被拒绝」。
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
	if n.GetCode() != core.ErrCodeEnvelopeAlgoMismatch.Code && n.GetCode() != core.ErrCodeHMACMismatch.Code {
		t.Errorf("nack code = %q, want %s or %s", n.GetCode(), core.ErrCodeEnvelopeAlgoMismatch.Code, core.ErrCodeHMACMismatch.Code)
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
	if n.GetCode() != core.ErrCodeEnvelopeAlgoMismatch.Code {
		t.Errorf("nack code = %q, want %s", n.GetCode(), core.ErrCodeEnvelopeAlgoMismatch.Code)
	}
}
