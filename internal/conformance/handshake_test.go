package conformance

// handshake_test.go：真实 1-RTT 握手 harness（全部协议级测试的基建）。
//
// 客户端侧不走 protocol.CoreClient（避免传输适配耦合），直接用 core 包原语
// 构造 HELLO（GenerateEphemeral/TranscriptHello/TokenProof），并独立完成
// ECDH→DeriveSessionKeys→finished 校验——这同时是 §16-9（transcript 跨实现
// canonical 一致性）的最强断言：测试侧密钥日程与服务端派生的密钥必须一致，
// 否则后续 Envelope 开箱全部失败。

import (
	"context"
	"crypto/hmac"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/protocol"
	"github.com/iuboy/mbta-go/internal/testutil"
)

// envConfig 是 startEnv 的可调参数（零值字段由 defaults 归一）。
type envConfig struct {
	profile corepb.Profile // 0 = PROFILE_INTL
	ackMode corepb.AckMode // 0 = ACK_MODE_ACCEPTED_ONLY

	// credit/limits（0 = 小额默认：4 批 / 1MB —— 攒批阈值=1，单批终态即触发 CREDIT，
	// 便于流控断言）。
	initialCreditBatches uint64
	initialCreditBytes   uint64
	maxFrameBytes        uint64
	maxBatchBytes        uint64

	serverCaps      []string // 服务端 SupportedCapabilities（nil = core.KnownCaps 全集）
	clientCaps      []string // HELLO.capabilities
	agentID         string   // 空 = 随机
	token           string   // 空 = 随机
	meta            map[string]string
	epochs          *protocol.EpochAllocator // nil = 独立分配器
	sink            core.BatchHandler        // nil = 无 sink（仅握手路径）
	sinkOpts        core.SinkOptions
	sinkDeadline    time.Duration
	sinkQueueSize   int   // 0 = 默认异步队列 256；负 = 同步调用
	sinkQueueMaxByt int64 // 0 = 默认 32MB

	// zstd_dict：服务端静态字典（配了且协商成功才发 DICT 帧）。
	zstdDict   []byte
	zstdDictID uint32

	// onSession：会话生命周期回调（nil = 不注入——契约允许，Handle 收尾
	// 的 DISCONNECTED 回调必须有 nil 守卫）。
	onSession core.OnSession
}

func (c *envConfig) normalize() {
	if c.profile == corepb.Profile_PROFILE_UNSPECIFIED {
		c.profile = corepb.Profile_PROFILE_INTL
	}
	if c.ackMode == corepb.AckMode_ACK_MODE_ENUM_UNSPECIFIED {
		c.ackMode = corepb.AckMode_ACK_MODE_ACCEPTED_ONLY
	}
	if c.initialCreditBatches == 0 {
		c.initialCreditBatches = 4
	}
	if c.initialCreditBytes == 0 {
		c.initialCreditBytes = 1 << 20
	}
	if c.maxFrameBytes == 0 {
		c.maxFrameBytes = core.MaxFrameBytes
	}
	if c.maxBatchBytes == 0 {
		c.maxBatchBytes = 8 << 20
	}
	if c.serverCaps == nil {
		c.serverCaps = []string{core.CapTraceContext, core.CapDatagram, core.CapCbor}
	}
	if c.agentID == "" {
		c.agentID = testutil.RandAgentID()
	}
	if c.token == "" {
		c.token = testutil.RandToken()
	}
	if c.sinkQueueMaxByt == 0 {
		c.sinkQueueMaxByt = 32 << 20
	}
}

// testEnv 是一次完整握手后的测试环境。
type testEnv struct {
	tr        *FakeTransport
	handler   *protocol.CoreHandler
	cfg       envConfig
	keys      *core.SessionKeys // 测试侧派生（与服务端一致——经 finished + Envelope 互验）
	ack       *core.HelloAck
	hello     *core.Hello
	thHello   []byte
	zz        []byte // ECDH 共享秘密（dual_integrity 追加派生用）
	sessionID []byte
	handleErr chan error // CoreHandler.Handle 的返回值
}

// envPolicy 由 envConfig 构造服务端策略（startEnv/startHandlerOnly 共用）。
func envPolicy(cfg envConfig) core.ServerPolicy {
	return core.ServerPolicy{
		Profile:               cfg.profile,
		SupportedCapabilities: cfg.serverCaps,
		AckMode:               cfg.ackMode,
		InitialCreditBatches:  cfg.initialCreditBatches,
		InitialCreditBytes:    cfg.initialCreditBytes,
		MaxFrameBytes:         cfg.maxFrameBytes,
		MaxBatchBytes:         cfg.maxBatchBytes,
		ZstdDict:              cfg.zstdDict,
		ZstdDictID:            cfg.zstdDictID,
	}
}

// startEnv 建立 FakeTransport + CoreHandler 并完成真实 1-RTT 握手。
func startEnv(t *testing.T, cfg envConfig) *testEnv {
	t.Helper()
	cfg.normalize()

	tr := NewFakeTransport()
	policy := envPolicy(cfg)
	h := protocol.NewCoreHandler(tr, protocol.HandlerConfig{
		Auth:              core.NewStaticTokenValidator(map[string]string{cfg.token: cfg.agentID}),
		Policy:            policy,
		ServerID:          "srv-" + testutil.RandString(4),
		Epochs:            cfg.epochs,
		SinkOpts:          cfg.sinkOpts,
		SinkHandler:       cfg.sink,
		SinkDeadline:      cfg.sinkDeadline,
		SinkQueueSize:     cfg.sinkQueueSize,
		SinkQueueMaxBytes: cfg.sinkQueueMaxByt,
		OnSession:         cfg.onSession,
	})

	ctx, cancel := context.WithCancel(context.Background())
	env := &testEnv{tr: tr, handler: h, cfg: cfg, handleErr: make(chan error, 1)}
	t.Cleanup(func() {
		cancel()
		_ = tr.Close()
		select {
		case <-env.handleErr:
		case <-time.After(5 * time.Second):
			t.Logf("handler did not exit within budget")
		}
	})
	go func() { env.handleErr <- h.Handle(ctx) }()

	// --- 客户端侧 HELLO（真实 eph + token_proof）---
	priv, pub, err := core.GenerateEphemeral(cfg.profile)
	if err != nil {
		t.Fatalf("generate ephemeral: %v", err)
	}
	hello := &core.Hello{
		Profile:      cfg.profile,
		AgentId:      cfg.agentID,
		Meta:         cfg.meta,
		Capabilities: cfg.clientCaps,
		ClientEph:    pub,
	}
	thHello, err := core.TranscriptHello(cfg.profile, hello)
	if err != nil {
		t.Fatalf("transcript hello: %v", err)
	}
	hello.TokenProof = core.TokenProof(cfg.profile, cfg.token, thHello)

	payload, err := core.Encode(hello)
	if err != nil {
		t.Fatalf("encode hello: %v", err)
	}
	tr.ControlIn <- MakeFrame(core.TypeHello, payload)

	// --- HELLO_ACK + 客户端独立密钥日程 ---
	ackF := ReadFrame(t, tr.Sent)
	if ackF.Header.Type != core.TypeHelloAck {
		t.Fatalf("expected HELLO_ACK, got type 0x%02x", ackF.Header.Type)
	}
	var ack core.HelloAck
	if err := core.Decode(ackF.Payload, &ack); err != nil {
		t.Fatalf("decode hello_ack: %v", err)
	}
	zz, err := core.DeriveZZ(cfg.profile, priv, ack.GetServerEph())
	if err != nil {
		t.Fatalf("derive zz: %v", err)
	}
	keys, err := core.DeriveSessionKeys(cfg.profile, zz, thHello, hello.TokenProof)
	if err != nil {
		t.Fatalf("derive session keys: %v", err)
	}
	// dual_integrity 协商启用 → 测试侧（客户端）同样追加派生（与服务端 handleHello
	// 对称），此后 sealBatch 自动附外层 mac。
	if slices.Contains(ack.GetSelectedCapabilities(), core.CapDualIntegrity) {
		dk, derr := core.DeriveDualMACKey(cfg.profile, zz, thHello, hello.TokenProof)
		if derr != nil {
			t.Fatalf("derive dual mac key: %v", derr)
		}
		keys.DualMACKey = dk
	}
	thFull, err := core.TranscriptFull(cfg.profile, hello, &ack)
	if err != nil {
		t.Fatalf("transcript full: %v", err)
	}
	if !hmac.Equal(core.FinishedMAC(keys, thFull), ack.GetFinished()) {
		t.Fatal("server finished MAC mismatch: server/client key schedule diverged")
	}

	env.keys = keys
	env.ack = &ack
	env.hello = hello
	env.thHello = thHello
	env.zz = zz
	env.sessionID = ack.GetSessionId()
	return env
}

// makeSignalBatch 构造 n 条 log signal 的 SignalBatch（proto 编码 payload）。
func makeSignalBatch(t *testing.T, n int, body string) []byte {
	t.Helper()
	signals := make([]*core.SignalRecord, n)
	for i := range signals {
		signals[i] = &core.SignalRecord{
			SignalType: core.SignalTypeLog,
			TimeUnixNs: time.Now().UnixNano(),
			Body:       body,
		}
	}
	wire, err := core.MarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO,
		&core.SignalBatch{Signals: signals})
	if err != nil {
		t.Fatalf("marshal signal batch: %v", err)
	}
	return wire
}

// sealBatch 用握手派生密钥封装一个 batch：seq 为 Envelope/Batch 共用序号，
// innerSeqOverride 非零时制造 Envelope.seq ≠ Batch.seq（负路径测试）。
func (e *testEnv) sealBatch(t *testing.T, seq uint64, body, corr string, innerSeqOverride uint64, comp corepb.Compression) []byte {
	t.Helper()
	inner := seq
	if innerSeqOverride != 0 {
		inner = innerSeqOverride
	}
	batch := &core.Batch{
		Seq:         inner,
		Correlation: corr,
		EventsCount: 1,
		Payload:     makeSignalBatch(t, 1, body),
	}
	bw, err := core.Encode(batch)
	if err != nil {
		t.Fatalf("encode batch: %v", err)
	}
	envPayload, err := core.SealEnvelope(core.SealParams{
		FrameType:   core.TypeBatch,
		SessionID:   e.sessionID,
		Seq:         seq,
		Compression: comp,
		Keys:        e.keys,
		BatchWire:   bw,
		DualMACKey:  e.keys.DualMACKey, // dual_integrity 协商时非 nil（startEnv 派生）
	})
	if err != nil {
		t.Fatalf("seal envelope: %v", err)
	}
	return envPayload
}

// sendBatch 发送一个 BATCH 帧并返回 envelope payload。
func (e *testEnv) sendBatch(t *testing.T, seq uint64, body, corr string) []byte {
	t.Helper()
	p := e.sealBatch(t, seq, body, corr, 0, corepb.Compression_COMPRESSION_NONE)
	e.tr.DataIn <- MakeFrame(core.TypeBatch, p)
	return p
}

// sinkCapture 记录 sink handler 收到的 batch（线程安全），done 由测试侧择机调用。
type sinkCapture struct {
	mu    sync.Mutex
	got   []core.BatchEvent
	dones []func(core.Outcome)
	recv  chan core.BatchEvent // 每次投递都发送（阻塞测试侧消费或带缓冲）
}

func newSinkCapture() *sinkCapture {
	return &sinkCapture{recv: make(chan core.BatchEvent, 128)}
}

func (s *sinkCapture) handler(_ context.Context, ev core.BatchEvent, done func(core.Outcome)) {
	s.mu.Lock()
	s.got = append(s.got, ev)
	s.dones = append(s.dones, done)
	s.mu.Unlock()
	s.recv <- ev
}

func (s *sinkCapture) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

func (s *sinkCapture) countSeq(seq uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, ev := range s.got {
		if ev.Meta.Seq == seq {
			n++
		}
	}
	return n
}

// waitEvent 等待第 n 次（1 起）投递。
func (s *sinkCapture) waitEvent(t *testing.T, n int, timeout time.Duration) core.BatchEvent { //nolint:unparam // 调用方统一 5s
	t.Helper()
	deadline := time.After(timeout)
	for s.count() < n {
		select {
		case <-s.recv:
		case <-deadline:
			t.Fatalf("timeout waiting for sink event #%d (got %d)", n, s.count())
			return core.BatchEvent{}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got[n-1]
}

func (s *sinkCapture) doneOf(seq uint64) func(core.Outcome) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.got) - 1; i >= 0; i-- {
		if s.got[i].Meta.Seq == seq {
			return s.dones[i]
		}
	}
	return nil
}

// callDone 对 seq 的最近一次投递调用 done（幂等契约由 makeDone 保证）。
func (s *sinkCapture) callDone(seq uint64, o core.Outcome) {
	if fn := s.doneOf(seq); fn != nil {
		fn(o)
	}
}

// === 握手测试 ===

// TestHandshake_Success_Intl 验证 intl 握手全字段（session/epoch/ack_mode/limits/
// credits/selected_caps/server_eph/finished/expiry）。
func TestHandshake_Success_Intl(t *testing.T) {
	env := startEnv(t, envConfig{clientCaps: []string{core.CapTraceContext, core.CapCbor}})
	ack := env.ack

	if n := len(ack.GetSessionId()); n != 16 {
		t.Errorf("session_id len = %d, want 16 (ChunkID)", n)
	}
	if ack.GetEpoch() < 1 {
		t.Errorf("epoch = %d, want >= 1 (server-assigned, 从 1 起)", ack.GetEpoch())
	}
	if ack.GetAckMode() != corepb.AckMode_ACK_MODE_ACCEPTED_ONLY {
		t.Errorf("ack_mode = %v, want ACCEPTED_ONLY (policy 声明)", ack.GetAckMode())
	}
	if got := ack.GetSelectedCapabilities(); len(got) != 2 || got[0] != core.CapTraceContext || got[1] != core.CapCbor {
		t.Errorf("selected_capabilities = %v, want [trace_context cbor]", got)
	}
	if ack.GetLimits().GetMaxFrameBytes() != core.MaxFrameBytes {
		t.Errorf("limits.max_frame_bytes = %d, want %d", ack.GetLimits().GetMaxFrameBytes(), core.MaxFrameBytes)
	}
	if ack.GetLimits().GetMaxBatchBytes() != 8<<20 {
		t.Errorf("limits.max_batch_bytes = %d, want %d", ack.GetLimits().GetMaxBatchBytes(), 8<<20)
	}
	if ack.GetCredits().GetBatches() != 4 || ack.GetCredits().GetBytes() != 1<<20 {
		t.Errorf("credits = %v, want {4, 1MiB}", ack.GetCredits())
	}
	if n := len(ack.GetServerEph()); n != core.EphemeralPubLen(corepb.Profile_PROFILE_INTL) {
		t.Errorf("server_eph len = %d, want %d (X25519)", n, core.EphemeralPubLen(corepb.Profile_PROFILE_INTL))
	}
	if n := len(ack.GetFinished()); n != core.HMACKeyLenIntl {
		t.Errorf("finished len = %d, want %d (HMAC-SHA256)", n, core.HMACKeyLenIntl)
	}
	if ack.GetExpiryUnix() <= time.Now().Unix() {
		t.Errorf("expiry_unix = %d, not in the future", ack.GetExpiryUnix())
	}
	// 密钥长度（§18-H3 split：intl L=104 = 32+32+32+4+4）。
	if len(env.keys.C2SKey) != core.AEADKeyLenIntl || len(env.keys.S2CKey) != core.AEADKeyLenIntl {
		t.Errorf("c2s/s2c key len = %d/%d, want %d", len(env.keys.C2SKey), len(env.keys.S2CKey), core.AEADKeyLenIntl)
	}
	if len(env.keys.HandshakeKey) != core.HMACKeyLenIntl {
		t.Errorf("handshake key len = %d, want %d", len(env.keys.HandshakeKey), core.HMACKeyLenIntl)
	}
}

// TestHandshake_Success_GM 验证 gm（SM2/SM3/SM4）握手与密钥日程。
func TestHandshake_Success_GM(t *testing.T) {
	env := startEnv(t, envConfig{profile: corepb.Profile_PROFILE_GM})
	ack := env.ack
	if n := len(ack.GetServerEph()); n != 65 {
		t.Errorf("server_eph len = %d, want 65 (SM2 非压缩 0x04‖X‖Y)", n)
	}
	if n := len(ack.GetFinished()); n != core.HMACKeyLenGM {
		t.Errorf("finished len = %d, want %d (HMAC-SM3)", n, core.HMACKeyLenGM)
	}
	// gm split：L=72 = 16+16+32+4+4（SM4-GCM 16B 密钥）。
	if len(env.keys.C2SKey) != core.AEADKeyLenGM {
		t.Errorf("c2s key len = %d, want %d (SM4)", len(env.keys.C2SKey), core.AEADKeyLenGM)
	}
	if len(env.keys.HandshakeKey) != core.HMACKeyLenGM {
		t.Errorf("handshake key len = %d, want %d", len(env.keys.HandshakeKey), core.HMACKeyLenGM)
	}
}

// TestHandshake_WrongToken_NAKAuthFailed 验证错误 token → NAK(auth_failed)（未认证
// 维度唯一码 + retryable），且 NAK 不拆连接——同连接上更正后的 HELLO 仍可成功。
func TestHandshake_WrongToken_NAKAuthFailed(t *testing.T) {
	cfg := envConfig{}
	cfg.normalize()
	env := startEnvWithToken(t, cfg, "wrong-token-000") // 握手本身注入坏 token

	nakF := ReadFrame(t, env.tr.Sent)
	if nakF.Header.Type != core.TypeHelloNak {
		t.Fatalf("expected HELLO_NAK, got type 0x%02x", nakF.Header.Type)
	}
	var nak core.HelloNak
	if err := core.Decode(nakF.Payload, &nak); err != nil {
		t.Fatalf("decode nak: %v", err)
	}
	if nak.GetCode() != core.CodeAuthFailed {
		t.Errorf("nak code = %d (%s), want %d (auth_failed)", nak.GetCode(), core.CodeName(nak.GetCode()), core.CodeAuthFailed)
	}
	if !nak.GetRetryable() {
		t.Error("nak retryable = false, want true（客户端应退避重试而非放弃）")
	}
	if nak.GetRetryHintMs() == 0 {
		t.Error("nak retry_hint_ms = 0, want non-zero")
	}

	// 同连接更正 token 重握手 → 成功（NAK 路径不返回错误、不拆传输）。
	_, pub, err := core.GenerateEphemeral(cfg.profile)
	if err != nil {
		t.Fatalf("generate ephemeral: %v", err)
	}
	hello := &core.Hello{Profile: cfg.profile, AgentId: cfg.agentID, ClientEph: pub}
	thHello, err := core.TranscriptHello(cfg.profile, hello)
	if err != nil {
		t.Fatalf("transcript hello: %v", err)
	}
	hello.TokenProof = core.TokenProof(cfg.profile, cfg.token, thHello)
	payload, err := core.Encode(hello)
	if err != nil {
		t.Fatalf("encode hello: %v", err)
	}
	env.tr.ControlIn <- MakeFrame(core.TypeHello, payload)
	ackF := ReadFrame(t, env.tr.Sent)
	if ackF.Header.Type != core.TypeHelloAck {
		t.Fatalf("corrected HELLO rejected: type 0x%02x (NAK 不应拆连接)", ackF.Header.Type)
	}
}

// TestHandshake_UnknownCapabilitiesFiltered 验证服务端只回交集：未知 capability
// 被静默过滤（不拒绝握手、不回显）。
func TestHandshake_UnknownCapabilitiesFiltered(t *testing.T) {
	env := startEnv(t, envConfig{clientCaps: []string{
		core.CapTraceContext, "x-experimental-unknown", "definitely-not-a-cap",
	}})
	got := env.ack.GetSelectedCapabilities()
	if len(got) != 1 || got[0] != core.CapTraceContext {
		t.Errorf("selected_capabilities = %v, want [trace_context]（未知能力被过滤）", got)
	}
}

// TestHandshake_DuplicateHello_Rejected 验证 Ready 后重复 HELLO → NAK
// (bad_handshake_message) 且连接以错误收场。
func TestHandshake_DuplicateHello_Rejected(t *testing.T) {
	env := startEnv(t, envConfig{})
	payload, err := core.Encode(env.hello)
	if err != nil {
		t.Fatalf("encode hello: %v", err)
	}
	env.tr.ControlIn <- MakeFrame(core.TypeHello, payload)

	nakF := ReadFrame(t, env.tr.Sent)
	if nakF.Header.Type != core.TypeHelloNak {
		t.Fatalf("expected HELLO_NAK for duplicate HELLO, got type 0x%02x", nakF.Header.Type)
	}
	var nak core.HelloNak
	if err := core.Decode(nakF.Payload, &nak); err != nil {
		t.Fatalf("decode nak: %v", err)
	}
	if nak.GetCode() != core.CodeBadHandshakeMessage {
		t.Errorf("nak code = %d (%s), want %d (bad_handshake_message)",
			nak.GetCode(), core.CodeName(nak.GetCode()), core.CodeBadHandshakeMessage)
	}
	select {
	case err := <-env.handleErr:
		if core.CodeNumOf(err) != core.CodeBadHandshakeMessage {
			t.Errorf("handle err code = %d, want %d", core.CodeNumOf(err), core.CodeBadHandshakeMessage)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return after duplicate HELLO")
	}
}

// TestHandshake_BadEphLength_NAK 验证 client_eph 长度非法 → NAK(hello_eph_invalid)。
func TestHandshake_BadEphLength_NAK(t *testing.T) {
	cfg := envConfig{}
	cfg.normalize()
	hello := &core.Hello{
		Profile:   cfg.profile,
		AgentId:   cfg.agentID,
		ClientEph: make([]byte, core.EphemeralPubLen(cfg.profile)-1), // 长度错
	}
	thHello, err := core.TranscriptHello(cfg.profile, hello)
	if err != nil {
		t.Fatalf("transcript hello: %v", err)
	}
	hello.TokenProof = core.TokenProof(cfg.profile, cfg.token, thHello)

	env := startHandlerOnly(t, cfg)
	payload, err := core.Encode(hello)
	if err != nil {
		t.Fatalf("encode hello: %v", err)
	}
	env.tr.ControlIn <- MakeFrame(core.TypeHello, payload)

	nakF := ReadFrame(t, env.tr.Sent)
	if nakF.Header.Type != core.TypeHelloNak {
		t.Fatalf("expected HELLO_NAK, got type 0x%02x", nakF.Header.Type)
	}
	var nak core.HelloNak
	if err := core.Decode(nakF.Payload, &nak); err != nil {
		t.Fatalf("decode nak: %v", err)
	}
	if nak.GetCode() != core.CodeHelloEphInvalid {
		t.Errorf("nak code = %d (%s), want %d (hello_eph_invalid)",
			nak.GetCode(), core.CodeName(nak.GetCode()), core.CodeHelloEphInvalid)
	}
}

// TestHandshake_EpochAllocator_Monotonic 验证 epoch 服务端分配且同 agent 跨连接
// 单调递增（共享 EpochAllocator；无票据重连同样获得更高 epoch——§16-7）。
func TestHandshake_EpochAllocator_Monotonic(t *testing.T) {
	epochs := &protocol.EpochAllocator{}
	agent := testutil.RandAgentID()

	var first uint64
	for i := range 3 {
		cfg := envConfig{epochs: epochs, agentID: agent}
		env := startEnv(t, cfg)
		got := env.ack.GetEpoch()
		if got < 1 {
			t.Fatalf("handshake %d: epoch = %d, want >= 1", i, got)
		}
		if i == 0 {
			first = got
		} else if got != first+uint64(i) {
			t.Fatalf("handshake %d: epoch = %d, want %d (单调递增)", i, got, first+uint64(i))
		}
	}
}

// startHandlerOnly 只建 handler 不做握手（负路径测试自行注入畸形 HELLO）。
func startHandlerOnly(t *testing.T, cfg envConfig) *testEnv {
	t.Helper()
	cfg.normalize()
	tr := NewFakeTransport()
	h := protocol.NewCoreHandler(tr, protocol.HandlerConfig{
		Auth:              core.NewStaticTokenValidator(map[string]string{cfg.token: cfg.agentID}),
		Policy:            envPolicy(cfg),
		ServerID:          "srv-" + testutil.RandString(4),
		Epochs:            cfg.epochs,
		SinkOpts:          cfg.sinkOpts,
		SinkHandler:       cfg.sink,
		SinkDeadline:      cfg.sinkDeadline,
		SinkQueueSize:     cfg.sinkQueueSize,
		SinkQueueMaxBytes: cfg.sinkQueueMaxByt,
		OnSession:         cfg.onSession,
	})
	ctx, cancel := context.WithCancel(context.Background())
	env := &testEnv{tr: tr, handler: h, cfg: cfg, handleErr: make(chan error, 1)}
	t.Cleanup(func() {
		cancel()
		_ = tr.Close()
		select {
		case <-env.handleErr:
		case <-time.After(5 * time.Second):
		}
	})
	go func() { env.handleErr <- h.Handle(ctx) }()
	return env
}

// startEnvWithToken 以指定 token（可与注册 token 不同）完成握手尝试，返回环境。
// 坏 token 场景下握手必然失败（NAK），env.keys/ack 为 nil——仅供 NAK 断言用。
func startEnvWithToken(t *testing.T, cfg envConfig, helloToken string) *testEnv {
	t.Helper()
	cfg.normalize()
	env := startHandlerOnly(t, cfg)

	_, pub, err := core.GenerateEphemeral(cfg.profile)
	if err != nil {
		t.Fatalf("generate ephemeral: %v", err)
	}
	hello := &core.Hello{Profile: cfg.profile, AgentId: cfg.agentID, ClientEph: pub}
	thHello, err := core.TranscriptHello(cfg.profile, hello)
	if err != nil {
		t.Fatalf("transcript hello: %v", err)
	}
	hello.TokenProof = core.TokenProof(cfg.profile, helloToken, thHello)
	payload, err := core.Encode(hello)
	if err != nil {
		t.Fatalf("encode hello: %v", err)
	}
	env.tr.ControlIn <- MakeFrame(core.TypeHello, payload)
	env.hello = hello
	env.thHello = thHello
	return env
}
