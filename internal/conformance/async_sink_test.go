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

// asyncDurableTestSink 实现 AsyncDurableSink：OnSignalBatchAsync 立即调 notifier.NotifyDurable
// （模拟"持久化瞬间完成"），用于验证异步 durable 升级路径。
// 统计 accepted（OnSignalBatchWithResult，走同步回退时不应被调）与 durable（NotifyDurable 触发）。
type asyncDurableTestSink struct {
	asyncCalls atomic.Int64
	syncCalls  atomic.Int64 // 同步路径调用计数（AsyncDurableSink 应为 0）
}

// EventSink 基础接口（AsyncDurableSink 经 DurableEventSink 继承）。
func (s *asyncDurableTestSink) OnSignalBatch(context.Context, string, *core.SignalBatch) error {
	s.syncCalls.Add(1)
	return nil
}
func (s *asyncDurableTestSink) OnPressure(string) core.PressureState { return core.PressureNormal }

// DurableEventSink（同步路径，AsyncDurableSink 实现后不应被调）。
func (s *asyncDurableTestSink) OnSignalBatchWithResult(context.Context, string, *core.SignalBatch) (*core.RouteResult, error) {
	s.syncCalls.Add(1)
	return &core.RouteResult{Status: core.ACKStatusAccepted}, nil
}

// AsyncDurableSink（异步路径）：立即持久化完成 → 调 notifier.NotifyDurable 发 durable 升级。
func (s *asyncDurableTestSink) OnSignalBatchAsync(_ context.Context, _ string, _ *core.SignalBatch, notifier core.DurableNotifier, seq uint64, chunkID []byte, eventsCount int) {
	s.asyncCalls.Add(1)
	// 模拟持久化瞬间完成：立即回调发 durable 升级帧。
	notifier.NotifyDurable(seq, chunkID, eventsCount)
}

// TestAsyncDurableSink_Upgrade 验证阶段 3：AsyncDurableSink 走异步路径——
// 服务端先发 ACK accepted（投队列立即回），sink 持久化后经 DurableNotifier 发 ACK durable 升级。
// 关键：同步路径（OnSignalBatchWithResult）不应被调用（asyncCalls>0, syncCalls=0）。
func TestAsyncDurableSink_Upgrade(t *testing.T) {
	sink := &asyncDurableTestSink{}
	// Policy 需声明 durable_ack（客户端协商后 useAckLevel=true），否则无法验证升级语义。
	cfg := protocol.HandlerConfig{
		Sink: sink,
		Policy: core.Policy{
			SupportedCapabilities: []string{core.CapCodecProto, core.CapCSIntl, core.CapDurableAck},
			DefaultCodec:          corepb.Codec_CODEC_PROTO,
			DefaultCompression:    corepb.Compression_COMPRESSION_NONE,
			CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
		},
	}
	tr, keys, cs := doHandshakeCfgWithPolicy(t, cfg, []string{core.CapCodecProto, core.CapCSIntl, core.CapDurableAck})

	envPayload := buildDosBatchEnvelope(t, keys, cs, 1)
	tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload)

	// 应收到两个 ACK：先 accepted（投队列立即发），后 durable（sink 持久化后 notifier 回调发）。
	var acksAccepted, acksDurable int
	deadline := time.Now().Add(3 * time.Second)
	for (acksAccepted+acksDurable) < 2 && time.Now().Before(deadline) {
		resp := ReadFrame(t, tr.Sent)
		if resp.Header.Type != core.TypeAck {
			t.Fatalf("expected ACK, got type %d", resp.Header.Type)
		}
		var ack core.AckMessage
		_ = core.Decode(resp.Payload, &ack)
		switch ack.GetAckMode() {
		case corepb.AckMode_ACK_MODE_ACCEPTED:
			acksAccepted++
		case corepb.AckMode_ACK_MODE_DURABLE:
			acksDurable++
		}
	}
	if acksAccepted != 1 {
		t.Errorf("accepted ACK count = %d, want 1", acksAccepted)
	}
	if acksDurable != 1 {
		t.Errorf("durable ACK count = %d, want 1 (upgrade via DurableNotifier)", acksDurable)
	}
	if sink.asyncCalls.Load() == 0 {
		t.Error("OnSignalBatchAsync should be called for AsyncDurableSink")
	}
	if sink.syncCalls.Load() != 0 {
		t.Errorf("sync path (OnSignalBatchWithResult/OnSignalBatch) called %d times, want 0", sink.syncCalls.Load())
	}
}

// doHandshakeCfgWithPolicy 是 doHandshakeCfg 的变体，允许指定客户端 HELLO 的 capabilities
// （用于协商 durable_ack，验证 useAckLevel 路径）。server cfg.Policy 必须已含对应 capability。
func doHandshakeCfgWithPolicy(t *testing.T, cfg protocol.HandlerConfig, clientCaps []string) (*FakeTransport, *core.SessionKeys, corepb.CipherSuite) {
	t.Helper()
	tr := NewFakeTransport(false)
	tok, agentID := testutil.RandToken(), testutil.RandAgentID()
	if cfg.Auth == nil {
		cfg.Auth = core.NewStaticTokenValidator(map[string]string{tok: agentID})
	} else {
		cfg.Auth = core.NewStaticTokenValidator(map[string]string{tok: agentID})
	}
	if cfg.ServerID == "" {
		cfg.ServerID = "srv-" + testutil.RandString(4)
	}
	h := protocol.NewCoreHandler(tr, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.Handle(ctx) }()

	hello := &corepb.HelloMessage{AgentId: agentID, FrameVersion: 1, Capabilities: clientCaps}
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
