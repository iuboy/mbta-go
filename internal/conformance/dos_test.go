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

// dosSink 是 DoS 防护测试用的 sink：可控制 OnPressure 返回值与 OnSignalBatch 阻塞。
// block 字段非 nil 时，OnSignalBatch 阻塞至 block 关闭（用于模拟慢/卡 sink 让队列堆积）。
type dosSink struct {
	pressure atomic.Value // core.PressureState
	delay    time.Duration
	block    chan struct{} // 非 nil 时 worker 阻塞至此 chan 关闭
	count    atomic.Int64
}

func newDoSSink() *dosSink {
	s := &dosSink{}
	s.pressure.Store(core.PressureNormal)
	return s
}

func (s *dosSink) OnSignalBatch(_ context.Context, _ string, _ *core.SignalBatch) error {
	if s.block != nil {
		// 阻塞至测试释放，或 3s 超时自解（防测试异常时 handler sinkWG.Wait 死锁）。
		select {
		case <-s.block:
		case <-time.After(3 * time.Second):
		}
	}
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
	tr := NewFakeTransport()
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

	authNonce := core.ComputeChallengeResponse(tok, agentID, string(ack.GetSessionId()), ack.GetChallengeNonce(), cs)
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

// TestDoS_SinkQueueFull_Throttle 验证阶段 1：普通 EventSink 异步投递队列满时，
// 发 THROTTLE（让客户端重试）。
// 用阻塞 sink（worker 卡住）+ 小队列（容量 1），并发投 5 帧让队列堆积，验证至少一个 THROTTLE。
func TestDoS_SinkQueueFull_Throttle(t *testing.T) {
	sink := newDoSSink()
	sink.block = make(chan struct{}) // worker 阻塞至此 chan 关闭
	tr, keys, cs := doHandshakeCfg(t, protocol.HandlerConfig{
		Sink:          sink,
		SinkQueueSize: 1, // 极小队列，worker 卡住时 1 个 batch 即满
	})
	// 测试结束时释放 block，让 handler 的 sinkWG.Wait() 不死锁。
	// （在读完响应后显式关闭，见下方；此处不 defer 以避免与 t.Cleanup cancel 的顺序竞态。）

	// 并发投足够多的帧（远超 worker 数 + 队列容量），让 worker 全部卡在 block 后
	// sinkQueue 堆积至满，后续帧 THROTTLE。worker 数 = runtime.NumCPU()（可能 ~10），
	// 队列容量 1，投 30 帧足以让队列满。
	const nFrames = 30
	for i := 1; i <= nFrames; i++ {
		envPayload := buildDosBatchEnvelope(t, keys, cs, uint64(i))
		tr.DataIn <- MakeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload)
	}

	// 读响应，统计 ACK/THROTTLE。读到第一个 THROTTLE 即证明队列满触发背压。
	acks, throttles := 0, 0
	deadline := time.Now().Add(5 * time.Second)
	for acks+throttles < nFrames && time.Now().Before(deadline) {
		resp := ReadFrame(t, tr.Sent)
		switch resp.Header.Type {
		case core.TypeAck:
			acks++
		case core.TypeThrottle:
			throttles++
		}
	}
	// 读完响应后释放 block，让阻塞的 worker 继续，handler 可干净退出。
	close(sink.block)
	if throttles == 0 {
		t.Errorf("expected at least one THROTTLE when sink queue full, got acks=%d throttles=%d", acks, throttles)
	}
}
