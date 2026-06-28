package conformance

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// doHandshake 完成完整 HELLO/AUTH 握手，返回 transport / 会话密钥 / 协商套件。
// 供握手与 delivery 测试复用。
func doHandshake(t *testing.T, sink core.EventSink) (*FakeTransport, *core.SessionKeys, corepb.CipherSuite) {
	t.Helper()
	tr := NewFakeTransport(false)
	policy := core.Policy{
		SupportedCapabilities: []string{"codec_proto", "codec_proto", "comp_zstd", "cs_intl", "durable_ack", "partial_ack"},
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

	// --- HELLO ---
	hello := &corepb.HelloMessage{
		AgentId:      "agent-1",
		FrameVersion: 1,
		Capabilities: []string{"codec_proto", "cs_intl"},
	}
	hp, err := core.Encode(hello)
	if err != nil {
		t.Fatalf("encode hello: %v", err)
	}
	tr.ControlIn <- MakeFrame(core.TypeHello, core.FlagControl, core.ChannelControl, hp)

	ackF := ReadFrame(t, tr.Sent)
	if ackF.Header.Type == core.TypeError {
		var e core.ErrorMessage
		_ = core.Decode(ackF.Payload, &e)
		t.Fatalf("got ERROR after HELLO: code=%s reason=%s", e.GetCode(), e.GetReason())
	}
	if ackF.Header.Type != core.TypeHelloAck {
		t.Fatalf("expected HELLO_ACK, got type %d", ackF.Header.Type)
	}
	var ack core.HelloAckMessage
	if err := core.Decode(ackF.Payload, &ack); err != nil {
		t.Fatalf("decode hello_ack: %v", err)
	}
	cs := ack.GetCipherSuite()
	if cs != corepb.CipherSuite_CIPHER_SUITE_INTL {
		t.Errorf("cipher suite = %v, want INTL", cs)
	}
	if len(ack.GetChallengeNonce()) == 0 {
		t.Fatal("challenge_nonce empty")
	}

	// --- AUTH（challenge-response）---
	authNonce := core.ComputeChallengeResponse("secret-token", string(ack.GetChallengeNonce()), cs)
	authMsg := &corepb.AuthMessage{
		Token:     "secret-token",
		AgentId:   "agent-1",
		SessionId: ack.GetSessionId(),
		AuthNonce: authNonce,
	}
	ap, err := core.Encode(authMsg)
	if err != nil {
		t.Fatalf("encode auth: %v", err)
	}
	tr.ControlIn <- MakeFrame(core.TypeAuth, core.FlagControl, core.ChannelControl, ap)

	okF := ReadFrame(t, tr.Sent)
	if okF.Header.Type != core.TypeAuthOK {
		t.Fatalf("expected AUTH_OK, got type %d", okF.Header.Type)
	}
	var ok core.AuthOKMessage
	if err := core.Decode(okF.Payload, &ok); err != nil {
		t.Fatalf("decode auth_ok: %v", err)
	}
	keys := core.NewSessionKeys(ok.GetKeyId(), cs, ok.GetHmacKey())
	keys.SetAEADKey(ok.GetAesKey())
	return tr, keys, cs
}

// TestCoreHandler_Handshake 验证 HELLO→HELLO_ACK→AUTH→AUTH_OK 全链路 + capability 协商。
func TestCoreHandler_Handshake(t *testing.T) {
	_, keys, cs := doHandshake(t, nil)
	if cs != corepb.CipherSuite_CIPHER_SUITE_INTL {
		t.Errorf("cipher suite = %v, want INTL", cs)
	}
	if len(keys.HMACKey()) != core.HMACKeyLenIntl {
		t.Errorf("HMACKey len = %d, want %d", len(keys.HMACKey()), core.HMACKeyLenIntl)
	}
	if len(keys.AEADKey()) != core.AEADKeyLenIntl {
		t.Errorf("AEADKey len = %d, want %d", len(keys.AEADKey()), core.AEADKeyLenIntl)
	}
}

// TestCoreHandler_Delivery 验证 BATCH envelope → Open → route → ACK 全链路。
func TestCoreHandler_Delivery(t *testing.T) {
	tr, keys, cs := doHandshake(t, nil)

	// 构造 BATCH：SignalBatch(JSON) → BatchMessage(proto) → SecureEnvelope → 帧
	chunkID := core.NewChunkID()
	batchJSON := makeSignalBatch("hi")
	batchMsg := &corepb.BatchMessage{
		Seq:         1,
		ChunkId:     chunkID.Bytes(),
		EventsCount: 1,
		Batch:       batchJSON,
	}
	batchPayload, err := core.Encode(batchMsg)
	if err != nil {
		t.Fatalf("encode batch message: %v", err)
	}
	params := core.BuildParams{
		SessionID:    []byte("session-1"),
		Seq:          1,
		ChunkID:      chunkID,
		Codec:        corepb.Codec_CODEC_PROTO,
		Compression:  corepb.Compression_COMPRESSION_NONE,
		CipherSuite:  cs,
		DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
		MsgType:      corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
		HMACKey:      keys.HMACKey(),
		AEADKey:      keys.AEADKey(),
		BatchPayload: batchPayload,
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

	ackF := ReadFrame(t, tr.Sent)
	if ackF.Header.Type == core.TypeNack {
		var n core.NackMessage
		_ = core.Decode(ackF.Payload, &n)
		t.Fatalf("got NACK: code=%s reason=%s", n.GetCode(), n.GetReason())
	}
	if ackF.Header.Type != core.TypeAck {
		t.Fatalf("expected ACK, got type %d", ackF.Header.Type)
	}
	var ack core.AckMessage
	if err := core.Decode(ackF.Payload, &ack); err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if ack.GetSeq() != 1 {
		t.Errorf("ack seq = %d, want 1", ack.GetSeq())
	}
	if !bytes.Equal(ack.GetChunkId(), chunkID.Bytes()) {
		t.Errorf("ack chunk_id mismatch")
	}
}

// TestCoreHandler_ReplayDedup 验证重复 chunk_id 返回幂等 ACK（at-least-once）。
func TestCoreHandler_ReplayDedup(t *testing.T) {
	tr, keys, cs := doHandshake(t, nil)

	batchJSON := makeSignalBatch("hi")
	chunkID := core.NewChunkID()
	buildEnv := func() []byte {
		batchMsg := &corepb.BatchMessage{Seq: 1, ChunkId: chunkID.Bytes(), Batch: batchJSON}
		bp, _ := core.Encode(batchMsg)
		params := core.BuildParams{
			SessionID: []byte("s"), Seq: 1, ChunkID: chunkID,
			Codec: corepb.Codec_CODEC_PROTO, Compression: corepb.Compression_COMPRESSION_NONE,
			CipherSuite: cs, DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
			MsgType: corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
			HMACKey: keys.HMACKey(), AEADKey: keys.AEADKey(), BatchPayload: bp,
		}
		env, _ := core.Build(params)
		ep, _ := core.Encode(env)
		return ep
	}

	envPayload := buildEnv()
	tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload)
	ack1 := ReadFrame(t, tr.Sent) // 首次 ACK

	// 同 chunk_id 重发 → 幂等 ACK（不重复处理）
	tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload)
	ack2 := ReadFrame(t, tr.Sent)

	if ack1.Header.Type != core.TypeAck || ack2.Header.Type != core.TypeAck {
		t.Fatalf("expected both ACK; got %d, %d", ack1.Header.Type, ack2.Header.Type)
	}
}

// mockRawSink 实现 EventSink + RawEventSink，记录 OnRawBatch 投递（DATAGRAM 验证用）。
type mockRawSink struct {
	events atomic.Int64
}

func (s *mockRawSink) OnSignalBatch(_ context.Context, _ string, _ *core.SignalBatch) error {
	return nil
}
func (s *mockRawSink) OnSignalBatchWithResult(_ context.Context, _ string, _ *core.SignalBatch) (*core.RouteResult, error) {
	return &core.RouteResult{Status: core.ACKStatusAccepted}, nil
}
func (s *mockRawSink) OnPressure(_ string) core.PressureState { return core.PressureNormal }
func (s *mockRawSink) OnRawBatch(_ context.Context, _ string, eventsCount int, _ []byte) (*core.RouteResult, error) {
	s.events.Add(int64(eventsCount))
	return &core.RouteResult{Status: core.ACKStatusAccepted}, nil
}

// TestCoreHandler_Datagram 验证 unreliable DATAGRAM：processDatagram 投递到 RawEventSink，无 ACK（at-most-once）。
func TestCoreHandler_Datagram(t *testing.T) {
	sink := &mockRawSink{}
	tr, keys, cs := doHandshake(t, sink)

	chunkID := core.NewChunkID()
	dgMsg := &corepb.DatagramMessage{
		Seq:         1,
		ChunkId:     chunkID.Bytes(),
		EventsCount: 1,
		Batch:       makeSignalBatch("dg"),
	}
	dgPayload, err := core.Encode(dgMsg)
	if err != nil {
		t.Fatalf("encode datagram message: %v", err)
	}
	params := core.BuildParams{
		SessionID:    []byte("s"),
		Seq:          1,
		ChunkID:      chunkID,
		Codec:        corepb.Codec_CODEC_PROTO,
		Compression:  corepb.Compression_COMPRESSION_NONE,
		CipherSuite:  cs,
		DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_LOSSY,
		MsgType:      corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_DATAGRAM,
		HMACKey:      keys.HMACKey(),
		AEADKey:      keys.AEADKey(),
		BatchPayload: dgPayload,
	}
	env, err := core.Build(params)
	if err != nil {
		t.Fatalf("build envelope: %v", err)
	}
	envPayload, _ := core.Encode(env)

	tr.DataIn <- MakeFrame(core.TypeDatagram, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload)

	// DATAGRAM at-most-once：无 ACK 响应，仅投递到 sink。等待 processDatagram goroutine 完成。
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && sink.events.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := sink.events.Load(); got != 1 {
		t.Errorf("datagram events received = %d, want 1", got)
	}
}

// TestCoreHandler_EarlyData 验证 0-RTT resumption（core spec §11.6）：
// store.Put 模拟首次 AUTH_OK 颁发 ticket → 第二连接 HELLO 携带 ticket →
// CoreHandler 恢复 keys + earlyData → 0-RTT BATCH（AUTH 前）用 resumption keys → ACK。
func TestCoreHandler_EarlyData(t *testing.T) {
	store := core.NewSessionStore()
	resumptionKeys, _ := core.GenerateSessionKeys(corepb.CipherSuite_CIPHER_SUITE_INTL)
	ticket := core.NewTicket()
	store.Put(ticket, &core.SessionState{
		Keys:    resumptionKeys,
		AgentID: "agent-1",
		Expiry:  time.Now().Add(time.Hour),
	})

	tr := NewFakeTransport(false)
	policy := core.Policy{
		SupportedCapabilities: []string{"codec_proto", "cs_intl"},
		DefaultCodec:          corepb.Codec_CODEC_PROTO,
		DefaultCompression:    corepb.Compression_COMPRESSION_NONE,
		CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
	}
	h := protocol.NewCoreHandler(tr, protocol.HandlerConfig{
		Auth:         core.NewStaticTokenValidator(map[string]string{"t": "agent-1"}),
		Policy:       policy,
		ServerID:     "srv-1",
		SessionStore: store,
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.Handle(ctx) }()

	// HELLO 携带 ticket → handleHello 恢复 keys + earlyData
	hello := &corepb.HelloMessage{
		AgentId:       "agent-1",
		FrameVersion:  1,
		Capabilities:  []string{"codec_proto", "cs_intl"},
		SessionTicket: ticket,
	}
	hp, _ := core.Encode(hello)
	tr.ControlIn <- MakeFrame(core.TypeHello, core.FlagControl, core.ChannelControl, hp)

	ackF := ReadFrame(t, tr.Sent)
	if ackF.Header.Type != core.TypeHelloAck {
		t.Fatalf("expected HELLO_ACK, got type %d", ackF.Header.Type)
	}

	// 0-RTT BATCH（AUTH 前）：用 resumption keys 构建 envelope
	chunkID := core.NewChunkID()
	batchMsg := &corepb.BatchMessage{
		Seq:         1,
		ChunkId:     chunkID.Bytes(),
		EventsCount: 1,
		Batch:       makeSignalBatch("0rtt"),
	}
	batchPayload, _ := core.Encode(batchMsg)
	params := core.BuildParams{
		SessionID:    []byte("s"),
		Seq:          1,
		ChunkID:      chunkID,
		Codec:        corepb.Codec_CODEC_PROTO,
		Compression:  corepb.Compression_COMPRESSION_NONE,
		CipherSuite:  corepb.CipherSuite_CIPHER_SUITE_INTL,
		DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
		MsgType:      corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
		HMACKey:      resumptionKeys.HMACKey(),
		AEADKey:      resumptionKeys.AEADKey(),
		BatchPayload: batchPayload,
	}
	env, _ := core.Build(params)
	envPayload, _ := core.Encode(env)

	// dataLoop 应在 earlyData 后启动（AUTH 前），处理 0-RTT BATCH
	tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload)

	// 期望 ACK（processBatch 用 resumption keys VerifyMAC + Open）
	ackFrame := ReadFrame(t, tr.Sent)
	if ackFrame.Header.Type == core.TypeNack {
		var n core.NackMessage
		_ = core.Decode(ackFrame.Payload, &n)
		t.Fatalf("0-RTT BATCH got NACK: code=%s reason=%s", n.GetCode(), n.GetReason())
	}
	if ackFrame.Header.Type != core.TypeAck {
		t.Fatalf("expected ACK for 0-RTT BATCH, got type %d", ackFrame.Header.Type)
	}
}

// TestCoreHandler_UnknownCapabilityRejected 验证 §1.3 协商失败语义：
// 客户端宣告未注册的 stable capability → HELLO 返回 ERROR（不静默吞掉）。
func TestCoreHandler_UnknownCapabilityRejected(t *testing.T) {
	tr := NewFakeTransport(false)
	policy := core.Policy{
		SupportedCapabilities: []string{"codec_proto"},
		DefaultCodec:          corepb.Codec_CODEC_PROTO,
		DefaultCompression:    corepb.Compression_COMPRESSION_NONE,
		CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
	}
	h := protocol.NewCoreHandler(tr, protocol.HandlerConfig{
		Auth:   core.NewStaticTokenValidator(map[string]string{"t": "a"}),
		Policy: policy, ServerID: "srv-1",
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.Handle(ctx) }()

	// HELLO 携带一个未注册的 stable capability（"bogus_cap"）
	hello := &corepb.HelloMessage{
		AgentId:      "agent-1",
		FrameVersion: 1,
		Capabilities: []string{"codec_proto", "bogus_cap"},
	}
	hp, _ := core.Encode(hello)
	tr.ControlIn <- MakeFrame(core.TypeHello, core.FlagControl, core.ChannelControl, hp)

	resp := ReadFrame(t, tr.Sent)
	if resp.Header.Type != core.TypeError {
		t.Fatalf("expected ERROR for unknown capability, got type %d", resp.Header.Type)
	}
	var errMsg core.ErrorMessage
	_ = core.Decode(resp.Payload, &errMsg)
	if errMsg.GetReason() == "" {
		t.Error("ERROR reason should be non-empty")
	}
}

// TestCoreHandler_HmacTampered 验证 envelope HMAC 篡改 → NACK hmac_mismatch。
func TestCoreHandler_HmacTampered(t *testing.T) {
	tr, keys, cs := doHandshake(t, nil)
	chunkID := core.NewChunkID()
	batchMsg := &corepb.BatchMessage{Seq: 1, ChunkId: chunkID.Bytes(), EventsCount: 1, Batch: makeSignalBatch("x")}
	bp, _ := core.Encode(batchMsg)
	params := core.BuildParams{
		SessionID: []byte("s"), Seq: 1, ChunkID: chunkID,
		Codec: corepb.Codec_CODEC_PROTO, Compression: corepb.Compression_COMPRESSION_NONE,
		CipherSuite: cs, DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
		MsgType: corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
		HMACKey: keys.HMACKey(), AEADKey: keys.AEADKey(), BatchPayload: bp,
	}
	env, _ := core.Build(params)
	if len(env.Mac) > 0 {
		env.Mac[0] ^= 0xFF // 篡改 MAC
	}
	envPayload, _ := core.Encode(env)

	tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload)

	resp := ReadFrame(t, tr.Sent)
	if resp.Header.Type != core.TypeNack {
		t.Fatalf("expected NACK for tampered HMAC, got type %d", resp.Header.Type)
	}
	var nack core.NackMessage
	_ = core.Decode(resp.Payload, &nack)
	if nack.GetCode() != "hmac_mismatch" {
		t.Errorf("nack code = %q, want hmac_mismatch", nack.GetCode())
	}
}

// TestCoreHandler_BatchTooManyEvents 验证 EventsCount 超限 → NACK too_many_events。
func TestCoreHandler_BatchTooManyEvents(t *testing.T) {
	sink := &mockRawSink{}
	tr, keys, cs := doHandshake(t, sink)
	chunkID := core.NewChunkID()
	batchMsg := &corepb.BatchMessage{Seq: 1, ChunkId: chunkID.Bytes(), EventsCount: 10001, Batch: makeSignalBatch("x")}
	bp, _ := core.Encode(batchMsg)
	params := core.BuildParams{
		SessionID: []byte("s"), Seq: 1, ChunkID: chunkID,
		Codec: corepb.Codec_CODEC_PROTO, Compression: corepb.Compression_COMPRESSION_NONE,
		CipherSuite: cs, DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
		MsgType: corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
		HMACKey: keys.HMACKey(), AEADKey: keys.AEADKey(), BatchPayload: bp,
	}
	env, _ := core.Build(params)
	envPayload, _ := core.Encode(env)

	tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload)

	resp := ReadFrame(t, tr.Sent)
	if resp.Header.Type != core.TypeNack {
		t.Fatalf("expected NACK for too many events, got type %d", resp.Header.Type)
	}
	var nack core.NackMessage
	_ = core.Decode(resp.Payload, &nack)
	if nack.GetCode() != "too_many_events" {
		t.Errorf("nack code = %q, want too_many_events", nack.GetCode())
	}
}

// TestCoreHandler_PartialAckCapability 验证 partial_ack capability 协商 + 结构正确性。
func TestCoreHandler_PartialAckCapability(t *testing.T) {
	tr := NewFakeTransport(false)
	policy := core.Policy{
		SupportedCapabilities: []string{"codec_proto", "cs_intl", "partial_ack"},
		DefaultCodec:          corepb.Codec_CODEC_PROTO,
		DefaultCompression:    corepb.Compression_COMPRESSION_NONE,
		CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
	}
	h := protocol.NewCoreHandler(tr, protocol.HandlerConfig{
		Auth: core.NewStaticTokenValidator(map[string]string{"t": "a"}), Policy: policy, ServerID: "srv-1",
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.Handle(ctx) }()

	hello := &corepb.HelloMessage{AgentId: "a", FrameVersion: 1, Capabilities: []string{"codec_proto", "cs_intl", "partial_ack"}}
	hp, _ := core.Encode(hello)
	tr.ControlIn <- MakeFrame(core.TypeHello, core.FlagControl, core.ChannelControl, hp)

	ackF := ReadFrame(t, tr.Sent)
	var ack core.HelloAckMessage
	_ = core.Decode(ackF.Payload, &ack)

	found := false
	for _, c := range ack.GetSelectedCapabilities() {
		if c == "partial_ack" {
			found = true
		}
	}
	if !found {
		t.Error("partial_ack should be in selected capabilities when both sides support it")
	}
}

// makeSignalBatch creates a proto-encoded SignalBatch with one log signal.
func makeSignalBatch(body string) []byte {
	sb := &core.SignalBatch{
		Signals: []*core.SignalRecord{{SignalType: "log", Body: body}},
	}
	data, _ := core.MarshalSignalBatch(sb)
	return data
}

// validBatchTraceContext 返回合法 batch 级 TraceContext（供服务端 BATCH 构造复用）。
func validBatchTraceContext() *corepb.TraceContext {
	return &corepb.TraceContext{
		TraceId:    "0123456789abcdef0123456789abcdef",
		SpanId:     "0123456789abcdef",
		TraceFlags: 0x01,
	}
}

// buildBatchEnvelope 构造一个可靠 BATCH envelope（带可选 trace_context），注入 DataIn。
func buildBatchEnvelope(t *testing.T, tr *FakeTransport, keys *core.SessionKeys, cs corepb.CipherSuite,
	chunkID core.ChunkID, tc *corepb.TraceContext) {
	t.Helper()
	batchMsg := &corepb.BatchMessage{
		Seq: 1, ChunkId: chunkID.Bytes(), EventsCount: 1,
		Batch:        makeSignalBatch("hi"),
		TraceContext: tc,
	}
	bp, err := core.Encode(batchMsg)
	if err != nil {
		t.Fatalf("encode batch message: %v", err)
	}
	params := core.BuildParams{
		SessionID: []byte("s"), Seq: 1, ChunkID: chunkID,
		Codec: corepb.Codec_CODEC_PROTO, Compression: corepb.Compression_COMPRESSION_NONE,
		CipherSuite: cs, DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
		MsgType: corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
		HMACKey: keys.HMACKey(), AEADKey: keys.AEADKey(), BatchPayload: bp,
	}
	env, err := core.Build(params)
	if err != nil {
		t.Fatalf("build envelope: %v", err)
	}
	ep, err := core.Encode(env)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, ep)
}

// TestCoreHandler_BatchTraceContext_Accepted 验证带合法 trace_context 的 BATCH → ACK。
func TestCoreHandler_BatchTraceContext_Accepted(t *testing.T) {
	tr, keys, cs := doHandshake(t, nil)
	buildBatchEnvelope(t, tr, keys, cs, core.NewChunkID(), validBatchTraceContext())

	resp := ReadFrame(t, tr.Sent)
	if resp.Header.Type != core.TypeAck {
		var n core.NackMessage
		_ = core.Decode(resp.Payload, &n)
		t.Fatalf("expected ACK, got type %d (nack code=%s reason=%s)", resp.Header.Type, n.GetCode(), n.GetReason())
	}
}

// TestCoreHandler_BatchTraceContext_Rejected 验证非法 trace_context（全零 trace_id）→
// NACK batch_trace_context。
func TestCoreHandler_BatchTraceContext_Rejected(t *testing.T) {
	tr, keys, cs := doHandshake(t, nil)
	bad := validBatchTraceContext()
	bad.TraceId = "00000000000000000000000000000000"
	buildBatchEnvelope(t, tr, keys, cs, core.NewChunkID(), bad)

	resp := ReadFrame(t, tr.Sent)
	if resp.Header.Type != core.TypeNack {
		t.Fatalf("expected NACK for invalid trace_context, got type %d", resp.Header.Type)
	}
	var nack core.NackMessage
	_ = core.Decode(resp.Payload, &nack)
	if nack.GetCode() != "batch_trace_context" {
		t.Errorf("nack code = %q, want batch_trace_context", nack.GetCode())
	}
}

// traceSink 实现 EventSink + BatchTraceSink，记录透传的 batch 级 trace 上下文。
type traceSink struct {
	lastTC *core.TraceContext
	got    atomic.Bool
}

func (s *traceSink) OnSignalBatch(_ context.Context, _ string, _ *core.SignalBatch) error {
	return nil
}
func (s *traceSink) OnPressure(_ string) core.PressureState { return core.PressureNormal }
func (s *traceSink) OnBatchTraceContext(_ context.Context, _ string, tc *core.TraceContext) {
	s.lastTC = tc
	s.got.Store(true)
}

// TestCoreHandler_BatchTraceContext_SinkExposed 验证实现 BatchTraceSink 的 sink
// 收到 batch 级 trace 上下文旁路通知，且内容正确。
func TestCoreHandler_BatchTraceContext_SinkExposed(t *testing.T) {
	sink := &traceSink{}
	tr, keys, cs := doHandshake(t, sink)
	want := validBatchTraceContext()
	buildBatchEnvelope(t, tr, keys, cs, core.NewChunkID(), want)

	// 先读到 ACK（routeAndACK 先发 ACK 再 sink 通知，或顺序不定，两者都等）。
	_ = ReadFrame(t, tr.Sent)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !sink.got.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	if !sink.got.Load() {
		t.Fatal("BatchTraceSink.OnBatchTraceContext not invoked")
	}
	if sink.lastTC == nil || sink.lastTC.GetTraceId() != want.GetTraceId() {
		t.Errorf("trace_id = %v, want %q", sink.lastTC, want.GetTraceId())
	}
}

// captureSink 实现 EventSink（非 RawEventSink，强制走完整解码路径），捕获投递的 SignalBatch。
type captureSink struct {
	got   atomic.Bool
	batch *core.SignalBatch
}

func (s *captureSink) OnSignalBatch(_ context.Context, _ string, sb *core.SignalBatch) error {
	s.batch = sb
	s.got.Store(true)
	return nil
}
func (s *captureSink) OnPressure(_ string) core.PressureState { return core.PressureNormal }

// TestCoreHandler_MixedTraceBatch 验证 FIFO 混装场景：同一 batch 含多个不同 trace_id
// 的 span（多进程链），不设 batch 级 TraceContext，per-signal trace 字段在 proto 编解码
// 往返后完整保留。这是 batch 级 TraceContext 不适用时的正确用法（方案 A）。
func TestCoreHandler_MixedTraceBatch(t *testing.T) {
	sink := &captureSink{}
	tr, keys, cs := doHandshake(t, sink)

	// 两个 span 分属不同 trace_id（模拟 FIFO 混装多进程链）。
	sb := &core.SignalBatch{Signals: []*core.SignalRecord{
		{SignalType: "span", Name: "proc-A", TraceID: "11111111111111111111111111111111", SpanID: "aaaaaaaaaaaaaaaa"},
		{SignalType: "span", Name: "proc-B", TraceID: "22222222222222222222222222222222", SpanID: "bbbbbbbbbbbbbbbb"},
	}}
	batchBytes, err := core.MarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, sb)
	if err != nil {
		t.Fatalf("marshal signal batch: %v", err)
	}
	chunkID := core.NewChunkID()
	batchMsg := &corepb.BatchMessage{Seq: 1, ChunkId: chunkID.Bytes(), EventsCount: 2, Batch: batchBytes}
	bp, err := core.Encode(batchMsg)
	if err != nil {
		t.Fatalf("encode batch message: %v", err)
	}
	params := core.BuildParams{
		SessionID: []byte("s"), Seq: 1, ChunkID: chunkID,
		Codec: corepb.Codec_CODEC_PROTO, Compression: corepb.Compression_COMPRESSION_NONE,
		CipherSuite: cs, DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
		MsgType: corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
		HMACKey: keys.HMACKey(), AEADKey: keys.AEADKey(), BatchPayload: bp,
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

	// 校验通过 → ACK（混装合法，不应因多 trace 被 NACK）。
	resp := ReadFrame(t, tr.Sent)
	if resp.Header.Type != core.TypeAck {
		var n core.NackMessage
		_ = core.Decode(resp.Payload, &n)
		t.Fatalf("expected ACK for mixed-trace batch, got type %d (nack code=%s)", resp.Header.Type, n.GetCode())
	}

	// 等待 sink 收到完整解码的 SignalBatch。
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !sink.got.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	if !sink.got.Load() {
		t.Fatal("sink not invoked for mixed-trace batch")
	}

	// 断言：两个 signal 的 per-signal trace 字段在 proto 往返后完整保留且互不相同。
	got := sink.batch.Signals
	if len(got) != 2 {
		t.Fatalf("signals = %d, want 2", len(got))
	}
	if got[0].TraceID == got[1].TraceID {
		t.Errorf("trace_id not distinct across mixed signals: both %q", got[0].TraceID)
	}
	if got[0].TraceID != "11111111111111111111111111111111" || got[0].SpanID != "aaaaaaaaaaaaaaaa" {
		t.Errorf("signal[0] trace = (%q,%q), want preserved", got[0].TraceID, got[0].SpanID)
	}
	if got[1].TraceID != "22222222222222222222222222222222" || got[1].SpanID != "bbbbbbbbbbbbbbbb" {
		t.Errorf("signal[1] trace = (%q,%q), want preserved", got[1].TraceID, got[1].SpanID)
	}
}
