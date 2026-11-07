package conformance

// hardening_test.go：对抗性审查（2026-11）新增防线的 wire 级一致性。
//
//   - 握手帧尺寸先验拒（认证前解码放大窗口）与 HELLO.meta 条数上限；
//   - Batch.correlation 长度上限（in-flight 驻留与回显放大）；
//   - DGRAM 速率硬限与一切失败静默丢弃（spec §4.6）；
//   - 类型错域 → protocol_error 拆连；未知类型前向兼容跳过（spec §7.2/§12.1）；
//   - cbor 能力协商的整连接 CBOR 编码链路（spec §8.4）。

import (
	"strings"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/testutil"
)

// TestHandshake_OversizeHelloRejectedBeforeDecode 验证超过
// MaxHandshakeFrameBytes 的 HELLO 在解码前被拒（NAK bad_handshake_message）——
// proto.Unmarshal 对 map/repeated 无解码上限，尺寸先验拒把认证前放大窗口压到
// 常数级。oversize 载荷用超长 meta value 构造（wire 上合法编码，仅超尺寸）。
func TestHandshake_OversizeHelloRejectedBeforeDecode(t *testing.T) {
	cfg := envConfig{}
	cfg.normalize()
	env := startHandlerOnly(t, cfg)

	_, pub, err := core.GenerateEphemeral(cfg.profile)
	if err != nil {
		t.Fatal(err)
	}
	hello := &core.Hello{
		Profile:      cfg.profile,
		AgentId:      cfg.agentID,
		ClientEph:    pub,
		Meta:         map[string]string{"pad": strings.Repeat("p", core.MaxHandshakeFrameBytes)},
		TokenProof:   make([]byte, 32),
		Capabilities: []string{},
	}
	payload, err := core.Encode(hello)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) <= core.MaxHandshakeFrameBytes {
		t.Fatalf("test payload len = %d, want > %d（构造自检）", len(payload), core.MaxHandshakeFrameBytes)
	}
	env.tr.ControlIn <- MakeFrame(core.TypeHello, payload)

	nakF := ReadFrame(t, env.tr.Sent)
	if nakF.Header.Type != core.TypeHelloNak {
		t.Fatalf("expected HELLO_NAK for oversize HELLO, got type 0x%02x", nakF.Header.Type)
	}
	var nak core.HelloNak
	if err := core.Decode(nakF.Payload, &nak); err != nil {
		t.Fatal(err)
	}
	if nak.GetCode() != core.CodeBadHandshakeMessage {
		t.Errorf("nak code = %d (%s), want %d (bad_handshake_message)",
			nak.GetCode(), core.CodeName(nak.GetCode()), core.CodeBadHandshakeMessage)
	}
}

// TestHandshake_MetaEntriesCapped 验证 HELLO.meta 条数超限 → NAK
// bad_handshake_message（逐条长度校验不约束条数——map 解码放大）。
func TestHandshake_MetaEntriesCapped(t *testing.T) {
	cfg := envConfig{}
	cfg.normalize()
	env := startHandlerOnly(t, cfg)

	_, pub, err := core.GenerateEphemeral(cfg.profile)
	if err != nil {
		t.Fatal(err)
	}
	meta := make(map[string]string, core.MaxHelloMetaEntries+1)
	for i := range core.MaxHelloMetaEntries + 1 {
		meta["k"+testutil.RandString(4)+string(rune('a'+i%26))] = "v"
	}
	hello := &core.Hello{
		Profile:      cfg.profile,
		AgentId:      cfg.agentID,
		ClientEph:    pub,
		Meta:         meta,
		TokenProof:   make([]byte, 32),
		Capabilities: []string{},
	}
	payload, err := core.Encode(hello)
	if err != nil {
		t.Fatal(err)
	}
	env.tr.ControlIn <- MakeFrame(core.TypeHello, payload)

	nakF := ReadFrame(t, env.tr.Sent)
	if nakF.Header.Type != core.TypeHelloNak {
		t.Fatalf("expected HELLO_NAK for meta flood, got type 0x%02x", nakF.Header.Type)
	}
	var nak core.HelloNak
	if err := core.Decode(nakF.Payload, &nak); err != nil {
		t.Fatal(err)
	}
	if nak.GetCode() != core.CodeBadHandshakeMessage {
		t.Errorf("nak code = %d, want bad_handshake_message", nak.GetCode())
	}
}

// TestBatch_CorrelationLengthCapped 验证超限 correlation → RESULT
// rejected(batch_invalid)（in-flight slot 驻留与 Duplicate 回显放大防线）。
func TestBatch_CorrelationLengthCapped(t *testing.T) {
	env := startEnv(t, envConfig{})
	env.sendBatch(t, 1, "corr-too-long", strings.Repeat("c", core.MaxBatchCorrelationLen+1))

	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_REJECTED {
		t.Fatalf("result level = %v, want REJECTED", r.GetLevel())
	}
	if r.GetCode() != core.CodeBatchInvalid {
		t.Errorf("result code = %d (%s), want batch_invalid", r.GetCode(), core.CodeName(r.GetCode()))
	}
}

// TestDgram_RateLimitedSilentDrop 验证 DGRAM 速率硬限（令牌桶耗尽）与
// 畸形 payload 的一切失败静默丢弃：无 RESULT、无 ABORT、sink 零投递（§4.6）。
func TestDgram_RateLimitedSilentDrop(t *testing.T) {
	sink := newSinkCapture()
	// dgramRate=1：任何真实帧都远超每秒预算 → 全部丢弃。
	env := startEnv(t, envConfig{dgramRate: 1, sink: sink.handler})

	valid := env.sealDgram(t, 1, "rate-limited")
	env.tr.DataIn <- MakeFrame(core.TypeDgram, valid)
	env.tr.DataIn <- MakeFrame(core.TypeDgram, []byte("garbage-not-an-envelope"))

	// 静默窗口：无任何 wire 反馈、sink 零投递。
	if f, ok := NextFrame(env.tr.Sent, 300*time.Millisecond); ok {
		t.Fatalf("frame 0x%02x emitted for dropped DGRAM, want silence", f.Header.Type)
	}
	if sink.count() != 0 {
		t.Errorf("sink received %d events for dropped DGRAMs, want 0", sink.count())
	}
}

// sealDgram 封装一个 TypeDgram envelope（sealBatch 的 DGRAM 变体）。
func (e *testEnv) sealDgram(t *testing.T, seq uint64, body string) []byte {
	t.Helper()
	batch := &core.Batch{Seq: seq, EventsCount: 1, Payload: makeSignalBatch(t, 1, body)}
	bw, err := core.Encode(batch)
	if err != nil {
		t.Fatalf("encode batch: %v", err)
	}
	p, err := core.SealEnvelope(core.SealParams{
		FrameType: core.TypeDgram, SessionID: e.sessionID, Seq: seq,
		Compression: corepb.Compression_COMPRESSION_NONE, Keys: e.keys, BatchWire: bw,
		DualMACKey: e.keys.DualMACKey,
	})
	if err != nil {
		t.Fatalf("seal dgram: %v", err)
	}
	return p
}

// TestFrame_WrongDomainOnControlAborts 验证 data 域帧（TypeBatch）出现在
// control 通道 → ABORT(protocol_error) + Handle 以错误收场（spec §7.2
// 类型错域；此前静默跳过可被已认证对端用于无限期占用连接槽）。
func TestFrame_WrongDomainOnControlAborts(t *testing.T) {
	env := startEnv(t, envConfig{})
	env.tr.ControlIn <- MakeFrame(core.TypeBatch, []byte("data-domain-on-control"))

	f := AwaitFrame(t, env.tr.Sent, core.TypeAbort, 5*time.Second)
	var ab core.AbortMsg
	if err := core.Decode(f.Payload, &ab); err != nil {
		t.Fatal(err)
	}
	if ab.GetCode() != core.CodeProtocolError {
		t.Errorf("abort code = %d (%s), want protocol_error", ab.GetCode(), core.CodeName(ab.GetCode()))
	}
	select {
	case err := <-env.handleErr:
		if core.CodeNumOf(err) != core.CodeProtocolError {
			t.Errorf("handle err code = %d, want protocol_error", core.CodeNumOf(err))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return after wrong-domain frame")
	}
}

// TestFrame_WrongDomainOnDataAborts 验证 control 域帧（TypePing）出现在
// data 通道 → ABORT(protocol_error)（与 controlLoop 对称）。
func TestFrame_WrongDomainOnDataAborts(t *testing.T) {
	env := startEnv(t, envConfig{})
	env.tr.DataIn <- MakeFrame(core.TypePing, []byte{})

	f := AwaitFrame(t, env.tr.Sent, core.TypeAbort, 5*time.Second)
	var ab core.AbortMsg
	if err := core.Decode(f.Payload, &ab); err != nil {
		t.Fatal(err)
	}
	if ab.GetCode() != core.CodeProtocolError {
		t.Errorf("abort code = %d, want protocol_error", ab.GetCode())
	}
}

// TestFrame_UnknownTypesSkippedForwardCompat 验证未注册类型的前向兼容跳过
// （spec §12.1）：未知 control（0x5A）与未知 data（0x90 邻位 0x9E）类型帧
// 到达后连接存活——后续 PING 正常回 PONG。
func TestFrame_UnknownTypesSkippedForwardCompat(t *testing.T) {
	env := startEnv(t, envConfig{})
	env.tr.ControlIn <- MakeFrame(0x5A, []byte("unknown-control"))
	env.tr.DataIn <- MakeFrame(0x9E, []byte("unknown-data"))

	ping, err := core.Encode(&core.PingMsg{TimeUnixNs: 1, Nonce: []byte{0x01}})
	if err != nil {
		t.Fatal(err)
	}
	env.tr.ControlIn <- MakeFrame(core.TypePing, ping)

	pongF := AwaitFrame(t, env.tr.Sent, core.TypePong, 5*time.Second)
	var pong core.PongMsg
	if err := core.Decode(pongF.Payload, &pong); err != nil {
		t.Fatal(err)
	}
	if string(pong.GetNonce()) != "\x01" {
		t.Errorf("pong nonce = %x, want 01（连接在未知帧后存活）", pong.GetNonce())
	}
}

// TestCbor_FullChain 验证 cbor 能力协商的整连接链路（spec §8.4）：HELLO 携带
// cbor → selected 含 cbor → batch payload 以 CBOR 编码 seal/open → sink 收到
// 解码后的事件。
func TestCbor_FullChain(t *testing.T) {
	sink := newSinkCapture()
	env := startEnv(t, envConfig{
		serverCaps: []string{core.CapCbor, core.CapTraceContext},
		clientCaps: []string{core.CapCbor},
		sink:       sink.handler,
	})
	found := false
	for _, c := range env.ack.GetSelectedCapabilities() {
		if c == core.CapCbor {
			found = true
		}
	}
	if !found {
		t.Fatalf("selected_capabilities = %v, want cbor negotiated", env.ack.GetSelectedCapabilities())
	}

	sb := signalsOf(t, 2, "cbor-wire-body")
	payloadWire, err := core.MarshalSignalBatchCodec(corepb.Codec_CODEC_CBOR, sb)
	if err != nil {
		t.Fatalf("marshal cbor: %v", err)
	}
	batch := &core.Batch{Seq: 1, EventsCount: 2, Payload: payloadWire}
	bw, err := core.Encode(batch)
	if err != nil {
		t.Fatal(err)
	}
	envPayload, err := core.SealEnvelope(core.SealParams{
		FrameType: core.TypeBatch, SessionID: env.sessionID, Seq: 1,
		Compression: corepb.Compression_COMPRESSION_NONE, Keys: env.keys, BatchWire: bw,
		DualMACKey: env.keys.DualMACKey,
	})
	if err != nil {
		t.Fatalf("seal envelope: %v", err)
	}
	env.tr.DataIn <- MakeFrame(core.TypeBatch, envPayload)

	ev := sink.waitEvent(t, 1, 5*time.Second)
	if ev.Decoded == nil || len(ev.Decoded.Signals) != 2 {
		t.Fatalf("sink decoded = %+v, want 2 signals via cbor codec", ev.Decoded)
	}
	if b, _ := ev.Decoded.Signals[0].Body.(string); b != "cbor-wire-body" {
		t.Errorf("signal body = %q, want cbor-wire-body", b)
	}
	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED {
		t.Errorf("result level = %v, want accepted", r.GetLevel())
	}
}
