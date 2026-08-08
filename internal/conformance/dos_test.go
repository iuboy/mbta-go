package conformance

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/protocol"
	"github.com/iuboy/mbta-go/internal/testutil"
)

// dosSink 是 DoS 防护测试用的 sink：可控制 OnPressure 返回值与 OnSignalBatch 阻塞时长。
type dosSink struct {
	pressure atomic.Value // core.PressureState
	delay    time.Duration
	count    atomic.Int64
}

func newDoSSink() *dosSink {
	s := &dosSink{}
	s.pressure.Store(core.PressureNormal)
	return s
}

func (s *dosSink) OnSignalBatch(_ context.Context, _ string, _ *core.SignalBatch) error {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.count.Add(1)
	return nil
}
func (s *dosSink) OnPressure(_ string) core.PressureState {
	return s.pressure.Load().(core.PressureState)
}

// doHandshakeCfg 是 doHandshake 的变体，允许注入自定义 HandlerConfig（如 SinkTimeout）。
// 返回 transport、keys、cipherSuite、agentID（后者用于 chunkID 关联，此处测试不严格需要）。
func doHandshakeCfg(t *testing.T, cfg protocol.HandlerConfig) (*FakeTransport, *core.SessionKeys, corepb.CipherSuite) {
	t.Helper()
	tr := NewFakeTransport(false)
	tok, agentID := testutil.RandToken(), testutil.RandAgentID()
	// cfg.Policy 必须由调用方提供；若空则用默认测试 policy。
	if len(cfg.Policy.SupportedCapabilities) == 0 {
		cfg.Policy = core.Policy{
			SupportedCapabilities: []string{core.CapCodecProto, core.CapCSIntl},
			DefaultCodec:          corepb.Codec_CODEC_PROTO,
			DefaultCompression:    corepb.Compression_COMPRESSION_NONE,
			CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
		}
	}
	if cfg.Auth == nil {
		cfg.Auth = core.NewStaticTokenValidator(map[string]string{tok: agentID})
	} else {
		// 用调用方 Auth：tok/agentID 须匹配（此处用 testutil 构造一对）。
		cfg.Auth = core.NewStaticTokenValidator(map[string]string{tok: agentID})
	}
	if cfg.ServerID == "" {
		cfg.ServerID = "srv-" + testutil.RandString(4)
	}
	h := protocol.NewCoreHandler(tr, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.Handle(ctx) }()

	hello := &corepb.HelloMessage{AgentId: agentID, FrameVersion: 1, Capabilities: []string{core.CapCodecProto, core.CapCSIntl}}
	hp, _ := core.Encode(hello)
	tr.ControlIn <- MakeFrame(core.TypeHello, core.FlagControl, core.ChannelControl, hp)

	ackF := ReadFrame(t, tr.Sent)
	if ackF.Header.Type != core.TypeHelloAck {
		t.Fatalf("expected HELLO_ACK, got type %d", ackF.Header.Type)
	}
	var ack core.HelloAckMessage
	_ = core.Decode(ackF.Payload, &ack)
	cs := ack.GetCipherSuite()

	authNonce := core.ComputeChallengeResponse(tok, string(ack.GetChallengeNonce()), cs)
	authMsg := &corepb.AuthMessage{Token: tok, AgentId: agentID, SessionId: ack.GetSessionId(), AuthNonce: authNonce}
	ap, _ := core.Encode(authMsg)
	tr.ControlIn <- MakeFrame(core.TypeAuth, core.FlagControl, core.ChannelControl, ap)

	okF := ReadFrame(t, tr.Sent)
	if okF.Header.Type != core.TypeAuthOK {
		t.Fatalf("expected AUTH_OK, got type %d", okF.Header.Type)
	}
	var ok core.AuthOKMessage
	_ = core.Decode(okF.Payload, &ok)
	keys := core.NewSessionKeys(ok.GetKeyId(), cs, ok.GetHmacKey())
	keys.SetAEADKey(ok.GetAesKey())
	return tr, keys, cs
}

// buildDosBatchEnvelope 构造一个合法的 BATCH envelope 帧 payload（PROTO 编码，单 signal）。
// 与 handler_test.go 的 buildBatchEnvelope（含 trace）区分，本 helper 用于 DoS 测试的最小 batch。
func buildDosBatchEnvelope(t *testing.T, keys *core.SessionKeys, cs corepb.CipherSuite, seq uint64) []byte {
	t.Helper()
	chunkID := core.NewChunkID()
	sb := &core.SignalBatch{Signals: []*core.SignalRecord{{SignalType: "log", Body: testutil.RandPayloadString(8), EventID: testutil.RandEventID()}}}
	batchBytes, _ := core.MarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, sb)
	batchMsg := &corepb.BatchMessage{Seq: seq, ChunkId: chunkID.Bytes(), EventsCount: 1, Batch: batchBytes}
	batchPayload, _ := core.Encode(batchMsg)
	params := core.BuildParams{
		SessionID: []byte(testutil.RandString(8)), Seq: seq, ChunkID: chunkID,
		Codec: corepb.Codec_CODEC_PROTO, Compression: corepb.Compression_COMPRESSION_NONE, CipherSuite: cs,
		DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE, MsgType: corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
		HMACKey: keys.HMACKey(), AEADKey: keys.AEADKey(), BatchPayload: batchPayload,
	}
	env, err := core.Build(params)
	if err != nil {
		t.Fatalf("build envelope: %v", err)
	}
	envPayload, err := core.Encode(env)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	return envPayload
}

// TestDoS_SinkPressure_PreRouteThrottle 验证 B：sink 处于 critical 压力时，
// batch 在 route 前被 THROTTLE 拒绝（不进入 sink），防慢 sink 阻塞 handler goroutine。
func TestDoS_SinkPressure_PreRouteThrottle(t *testing.T) {
	sink := newDoSSink()
	tr, keys, cs := doHandshakeCfg(t, protocol.HandlerConfig{Sink: sink})

	// sink 设为 critical：新 batch 应被前置 THROTTLE。
	sink.pressure.Store(core.PressureCritical)
	envPayload := buildDosBatchEnvelope(t, keys, cs, 1)
	tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload)

	resp := ReadFrame(t, tr.Sent)
	if resp.Header.Type != core.TypeThrottle {
		t.Fatalf("expected THROTTLE under critical pressure, got type %d", resp.Header.Type)
	}
	if got := sink.count.Load(); got != 0 {
		t.Errorf("sink should not be called under critical pressure, got count=%d", got)
	}
}

// TestDoS_SinkTimeout 验证 A：sink 阻塞超过 SinkTimeout 时，handler goroutine 不永久挂起——
// routeAndACK 通过 goroutine 隔离 + select 超时，放弃 sink 结果并发 THROTTLE（让客户端重试）。
// 关键：即使 sink 用 time.Sleep 不响应 ctx，handler 也不被阻塞——select 不等 Sleep 完成。
func TestDoS_SinkTimeout(t *testing.T) {
	sink := newDoSSink()
	sink.delay = 2 * time.Second // sink 阻塞 2s（不响应 ctx，远超 SinkTimeout）
	tr, keys, cs := doHandshakeCfg(t, protocol.HandlerConfig{
		Sink:        sink,
		SinkTimeout: 200 * time.Millisecond,
	})

	start := time.Now()
	envPayload := buildDosBatchEnvelope(t, keys, cs, 1)
	tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload)

	// 应在 SinkTimeout 附近收到 THROTTLE（而非等满 sink 的 2s）。
	resp := ReadFrame(t, tr.Sent)
	elapsed := time.Since(start)
	if resp.Header.Type != core.TypeThrottle {
		t.Fatalf("expected THROTTLE after sink timeout, got type %d", resp.Header.Type)
	}
	// 应在 1s 内（远小于 sink 的 2s，证明 handler 未被 sink 阻塞）。
	if elapsed > 1*time.Second {
		t.Errorf("THROTTLE took %v, expected ~SinkTimeout (handler should not block on slow sink)", elapsed)
	}
}
