package conformance

import (
	"context"
	"sync/atomic"
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// countingSink 统计收到的 signal batch 数与事件数，用于验证非 proto codec 的解码成功。
type countingSink struct {
	count atomic.Int64
}

func (s *countingSink) OnSignalBatch(ctx context.Context, agentID string, sb *core.SignalBatch) error {
	s.count.Add(int64(len(sb.Signals)))
	return nil
}
func (s *countingSink) OnPressure(agentID string) core.PressureState { return core.PressureNormal }

// TestCoreHandler_CodecNegotiation_CBOR 验证 HELLO 协商 codec_cbor 后，
// 客户端发 CBOR 编码 batch，服务端能解码并路由到 sink（正向非 proto codec 端到端）。
func TestCoreHandler_CodecNegotiation_CBOR(t *testing.T) {
	testCodecNegotiation(t, "codec_cbor", corepb.Codec_CODEC_CBOR)
}

// TestCoreHandler_CodecNegotiation_JSON 验证 codec_json 的正向端到端路径。
func TestCoreHandler_CodecNegotiation_JSON(t *testing.T) {
	testCodecNegotiation(t, "codec_json", corepb.Codec_CODEC_JSON)
}

func testCodecNegotiation(t *testing.T, codecCap string, wantCodec corepb.Codec) {
	t.Helper()
	sink := &countingSink{}

	// 注入 sink 需要在握手前设置——通过临时改写 policy。由于 doHandshakeCodec 不接受
	// sink，这里用一个独立实现：先握手（sink=nil），再单独构造带 sink 的 handler 走 batch。
	// 更简洁的方式：扩展 doHandshakeCodec 接受 sink。为保持 helper 通用，这里直接内联。
	tr := NewFakeTransport(false)
	policy := core.Policy{
		SupportedCapabilities: []string{"codec_proto", "codec_cbor", "codec_json", "cs_intl"},
		DefaultCodec:          corepb.Codec_CODEC_PROTO,
		DefaultCompression:    corepb.Compression_COMPRESSION_NONE,
		CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
	}
	auth := core.NewStaticTokenValidator(map[string]string{"secret-token": "agent-1"})
	h := protocol.NewCoreHandler(tr, protocol.HandlerConfig{
		Auth: auth, Policy: policy, Sink: sink, ServerID: "srv-1",
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.Handle(ctx) }()

	// HELLO
	hello := &corepb.HelloMessage{
		AgentId:      "agent-1",
		FrameVersion: 1,
		Capabilities: []string{codecCap, "cs_intl"},
	}
	hp, err := core.Encode(hello)
	if err != nil {
		t.Fatalf("encode hello: %v", err)
	}
	tr.ControlIn <- MakeFrame(core.TypeHello, core.FlagControl, core.ChannelControl, hp)
	ackF := ReadFrame(t, tr.Sent)
	var ack core.HelloAckMessage
	if err := core.Decode(ackF.Payload, &ack); err != nil {
		t.Fatalf("decode hello_ack: %v", err)
	}
	if ack.GetCodec() != wantCodec {
		t.Fatalf("negotiated codec = %v, want %v", ack.GetCodec(), wantCodec)
	}
	cs := ack.GetCipherSuite()

	// AUTH
	authNonce := core.ComputeChallengeResponse("secret-token", string(ack.GetChallengeNonce()), cs)
	authMsg := &corepb.AuthMessage{
		Token: "secret-token", AgentId: "agent-1",
		SessionId: ack.GetSessionId(), AuthNonce: authNonce,
	}
	ap, _ := core.Encode(authMsg)
	tr.ControlIn <- MakeFrame(core.TypeAuth, core.FlagControl, core.ChannelControl, ap)
	okF := ReadFrame(t, tr.Sent)
	var ok core.AuthOKMessage
	if err := core.Decode(okF.Payload, &ok); err != nil {
		t.Fatalf("decode auth_ok: %v", err)
	}
	keys := core.NewSessionKeys(ok.GetKeyId(), cs, ok.GetHmacKey())
	keys.SetAEADKey(ok.GetAesKey())

	// 构造 BATCH：用协商的 codec 编码 SignalBatch
	chunkID := core.NewChunkID()
	sb := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log", Body: "cbor/json codec test", EventID: "e1"},
			{SignalType: "log", Body: "second event", EventID: "e2"},
		},
	}
	batchBytes, err := core.MarshalSignalBatchCodec(wantCodec, sb)
	if err != nil {
		t.Fatalf("marshal signal batch (%v): %v", wantCodec, err)
	}
	batchMsg := &corepb.BatchMessage{
		Seq: 1, ChunkId: chunkID.Bytes(), EventsCount: 2, Batch: batchBytes,
	}
	batchPayload, err := core.Encode(batchMsg)
	if err != nil {
		t.Fatalf("encode batch message: %v", err)
	}
	params := core.BuildParams{
		SessionID: ack.GetSessionId(), Seq: 1, ChunkID: chunkID,
		Codec: wantCodec, Compression: corepb.Compression_COMPRESSION_NONE, CipherSuite: cs,
		DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
		MsgType:      corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
		HMACKey:      keys.HMACKey(), AEADKey: keys.AEADKey(), BatchPayload: batchPayload,
	}
	env, err := core.Build(params)
	if err != nil {
		t.Fatalf("build envelope: %v", err)
	}
	envPayload, err := core.Encode(env)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload)

	// 期望 ACK（服务端成功解码 + 路由）
	resp := ReadFrame(t, tr.Sent)
	if resp.Header.Type != core.TypeAck {
		var n core.NackMessage
		_ = core.Decode(resp.Payload, &n)
		t.Fatalf("expected ACK for %v batch, got type %d (nack code=%s reason=%s)",
			wantCodec, resp.Header.Type, n.GetCode(), n.GetReason())
	}
	if got := sink.count.Load(); got != 2 {
		t.Errorf("sink received %d events, want 2 (decode + route succeeded)", got)
	}
}

// TestCoreHandler_CodecNegotiation_DefaultProtoStillWorks 验证客户端 offer 全部三种 codec
// 时，服务端按优先级选 proto（回归保护：确保引入 cbor/json 不破坏 proto baseline 默认）。
func TestCoreHandler_CodecNegotiation_DefaultProtoStillWorks(t *testing.T) {
	tr := NewFakeTransport(false)
	policy := core.Policy{
		SupportedCapabilities: []string{"codec_proto", "codec_cbor", "codec_json", "cs_intl"},
		DefaultCodec:          corepb.Codec_CODEC_PROTO,
		DefaultCompression:    corepb.Compression_COMPRESSION_NONE,
		CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
	}
	auth := core.NewStaticTokenValidator(map[string]string{"secret-token": "agent-1"})
	h := protocol.NewCoreHandler(tr, protocol.HandlerConfig{
		Auth: auth, Policy: policy, Sink: nil, ServerID: "srv-1",
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.Handle(ctx) }()

	hello := &corepb.HelloMessage{
		AgentId: "agent-1", FrameVersion: 1,
		// 客户端 offer 全部三种 codec，服务端应优先选 proto。
		Capabilities: []string{"codec_proto", "codec_cbor", "codec_json", "cs_intl"},
	}
	hp, _ := core.Encode(hello)
	tr.ControlIn <- MakeFrame(core.TypeHello, core.FlagControl, core.ChannelControl, hp)

	ackF := ReadFrame(t, tr.Sent)
	var ack core.HelloAckMessage
	if err := core.Decode(ackF.Payload, &ack); err != nil {
		t.Fatalf("decode hello_ack: %v", err)
	}
	if ack.GetCodec() != corepb.Codec_CODEC_PROTO {
		t.Errorf("negotiated codec = %v, want PROTO (proto > cbor > json priority)", ack.GetCodec())
	}
}
