package protocol

// client.go：客户端协议核心（r3）。1-RTT 握手、credit 账本（模型 B）、
// RESULT/CREDIT 处理、lifecycle（Closed 一等出边）。

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// ackQueueSize 限定结果回调队列容量（慢回调不阻塞 control loop）。
const ackQueueSize = 1024

// CoreClientConfig 是客户端配置。
type CoreClientConfig struct {
	AgentID      string
	Meta         map[string]string
	Token        string
	Capabilities []string
	Profile      corepb.Profile
	Metrics      core.Metrics
	DrainTimeout time.Duration
	AckTimeout   time.Duration // RESULT 等待上限（0 = 5min；超时标记失败通知应用）
}

// CoreClient 是客户端协议核心。
type CoreClient struct {
	// tr 经 atomic.Pointer 发布：SetTransport（Handshake 前由 binding 调用）与
	// close/fatalTeardown（用户可并发触发）存在无同步交错——此前裸字段是数据
	// 竞态（-race 可复现）。Handshake 前 MUST 完成注入，注入后运行期不再替换。
	tr      atomic.Pointer[ClientTransport]
	cfg     CoreClientConfig
	metrics core.Metrics
	sm      *core.StateMachine

	agentID   string
	sessionID atomic.Value // []byte
	expiry    atomic.Int64 // HELLO_ACK.expiry_unix（SendBatch 前置检查）
	closed    atomic.Bool

	seq     *core.SeqGenerator
	ledger  atomic.Pointer[core.CreditLedger]
	keys    atomic.Pointer[core.SessionKeys]
	negCaps atomic.Value                       // []string
	codec   atomic.Value                       // corepb.Codec
	limits  atomic.Value                       // *corepb.Limits
	ackMode atomic.Value                       // corepb.AckMode（drain 终态判定：durable 模式下 accepted 为中间态）
	zdict   atomic.Pointer[core.ZstdDictCodec] // zstd_dict：连接持有的字典 codec（DICT 帧后非 nil）

	resultHandler    atomic.Pointer[func(seq uint64, level string, code uint32, correlation string)]
	redirectHandler  atomic.Pointer[func(ctx context.Context, payload []byte)]
	redirectInflight atomic.Bool
	commandHandler   atomic.Pointer[CommandHandler]
	// commandSlots 限流命令回调的并发 goroutine 数（恶意/被攻陷服务端命令洪水
	// 防线），NewCoreClient 初始化。
	commandSlots chan struct{}
	seenCmdMu    sync.Mutex
	seenCommands map[string]struct{}
	seenCmdOrder []string // seenCommands 的到达序（环形淘汰最旧，见 markSeenCommand）

	sendMu sync.Mutex

	// lifecycle 字段组由 lifecycleMu 保护：startLifecycle 写入与
	// teardownPhase/waitGoroutines 的读取存在并发交错（直连 binding 时 Connect
	// 与用户 Close 可并发）——此前裸字段是 -race 可检出的数据竞态。
	lifecycleMu     sync.Mutex
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	ackDone         chan struct{}
	heartbeatDone   chan struct{}
	reaperDone      chan struct{}
	ackQueue        chan resultNotify
	ackWorkerDone   chan struct{}

	drainCh       chan struct{}
	closeOnce     sync.Once
	lifecycleOnce sync.Once // StartLifecycle 幂等：二次调用不得替换字段（旧 goroutine 的 ctx 将永不取消）
	connErr       error

	readControlFn   func(context.Context)
	heartbeatLoopFn func(context.Context)
}

type resultNotify struct {
	seq         uint64
	level       string
	code        uint32
	correlation string
}

// NewCoreClient 创建客户端核心。
func NewCoreClient(tr ClientTransport, cfg CoreClientConfig) *CoreClient {
	if isNilMetrics(cfg.Metrics) {
		cfg.Metrics = core.NoOpMetrics{}
	}
	if cfg.AckTimeout == 0 {
		cfg.AckTimeout = 5 * time.Minute
	}
	meta := cfg.Meta
	if meta == nil {
		meta = map[string]string{}
	}
	cfg.Meta = meta
	cc := &CoreClient{
		cfg:          cfg,
		metrics:      cfg.Metrics,
		sm:           core.NewStateMachine(),
		seq:          core.NewSeqGenerator(),
		agentID:      cfg.AgentID,
		drainCh:      make(chan struct{}, 1),
		commandSlots: make(chan struct{}, maxCommandHandlers),
	}
	if tr != nil {
		cc.tr.Store(&tr)
	}
	return cc
}

// SetTransport 注入客户端传输（binding 在 dial 成功后的 setupTransport 阶段调用）。
// NewClientCore 构造 CoreClient 时传输尚未建立（先做纯配置校验），Handshake 前
// MUST 完成注入——之后 lifecycle goroutine 并发读 tr，不再允许替换。
func (c *CoreClient) SetTransport(tr ClientTransport) { c.tr.Store(&tr) }

// transport 返回当前传输（nil = 未注入）。
func (c *CoreClient) transport() ClientTransport {
	if p := c.tr.Load(); p != nil {
		return *p
	}
	return nil
}

// --- 握手（1 RTT）---

// Handshake 发送 HELLO 并处理 HELLO_ACK/NAK。成功后进入 Ready（StartLifecycle 由
// binding 在此之后调用——lifecycle goroutine 启动前握手已完成，无 0-RTT 时序问题）。
func (c *CoreClient) Handshake(ctx context.Context) error {
	tr := c.transport()
	if tr == nil {
		return core.NewError(core.ErrCodeConfig, "transport not injected (binding must call SetTransport before Handshake)")
	}
	priv, pub, err := core.GenerateEphemeral(c.cfg.Profile)
	if err != nil {
		return err
	}
	hello := &core.Hello{
		Profile:      c.cfg.Profile,
		AgentId:      c.cfg.AgentID,
		Meta:         c.cfg.Meta,
		Capabilities: c.cfg.Capabilities,
		ClientEph:    pub,
	}
	thHello, err := core.TranscriptHello(c.cfg.Profile, hello)
	if err != nil {
		return err
	}
	hello.TokenProof = core.TokenProof(c.cfg.Profile, c.cfg.Token, thHello)

	payload, err := core.Encode(hello)
	if err != nil {
		return core.WrapError(core.ErrCodeHandshake, "marshal hello", err)
	}
	if err := tr.WriteFrame(ctx, core.TypeHello, payload); err != nil {
		return core.WrapError(core.ErrCodeHandshake, "write hello", err)
	}

	f, err := tr.ReadFrame(ctx)
	if err != nil {
		return core.WrapError(core.ErrCodeHandshake, "read hello_ack", err)
	}
	switch f.Header.Type {
	case core.TypeHelloNak:
		var nak core.HelloNak
		if derr := core.Decode(f.Payload, &nak); derr != nil {
			return core.WrapError(core.ErrCodeHandshake, "decode nak", derr)
		}
		return core.NewError(core.ErrCodeAuthFailed,
			"handshake rejected: "+core.CodeName(nak.GetCode())+" (retryable="+boolStr(nak.GetRetryable())+")")
	case core.TypeHelloAck:
		// 尺寸先验拒先于 Decode（恶意/受损服务端防线，与服务端 handleHello 对称）：
		// HELLO_ACK 天然小上界（core.MaxHandshakeFrameBytes），超额帧在
		// proto.Unmarshal 分配 selected_capabilities 等列表前拒绝。
		if len(f.Payload) > core.MaxHandshakeFrameBytes {
			return core.NewError(core.ErrCodeBadHandshake,
				"hello_ack frame exceeds handshake limit")
		}
		var ack core.HelloAck
		if derr := core.Decode(f.Payload, &ack); derr != nil {
			return core.WrapError(core.ErrCodeHandshake, "decode hello_ack", derr)
		}
		if verr := core.ValidateHelloAck(&ack); verr != nil {
			return verr
		}
		// ECDH + 密钥派生 + finished 验证（服务端密钥确认）。
		keys, kerr := c.deriveKeys(priv, &ack, thHello, hello.TokenProof)
		if kerr != nil {
			return kerr
		}
		thFull, terr := core.TranscriptFull(c.cfg.Profile, hello, &ack)
		if terr != nil {
			return terr
		}
		if !hmacEqual(core.FinishedMAC(keys, thFull), ack.GetFinished()) {
			return core.NewError(core.ErrCodeAuthFailed, "server finished MAC mismatch")
		}
		c.keys.Store(keys)
		c.sessionID.Store(ack.GetSessionId())
		c.negCaps.Store(ack.GetSelectedCapabilities())
		c.codec.Store(core.CodecFor(ack.GetSelectedCapabilities()))
		c.limits.Store(ack.GetLimits())
		c.ackMode.Store(ack.GetAckMode())
		c.ledger.Store(core.NewCreditLedger(
			int64(ack.GetCredits().GetBatches()), int64(ack.GetCredits().GetBytes()), 0, 0))
		c.expiry.Store(ack.GetExpiryUnix())
		// 协商帧上限接入后续读取（clamp 到本地 16MB 硬顶，防恶意服务端放大攻击面）。
		if fl, ok := tr.(FrameLimitSetter); ok && ack.GetLimits().GetMaxFrameBytes() > 0 {
			fl.SetFrameLimit(min(ack.GetLimits().GetMaxFrameBytes(), core.MaxFrameBytes))
		}
		if err := c.sm.Transition(core.StateReady); err != nil {
			return core.WrapError(core.ErrCodeSession, "transition ready", err)
		}
		if am, ok := tr.(AuthMarker); ok {
			am.MarkAuthed()
		}
		slog.Info("handshake completed", "agent", core.SanitizeForLog(c.agentID),
			"session", string(ack.GetSessionId()), "epoch", ack.GetEpoch(),
			"ack_mode", ack.GetAckMode().String())
		return nil
	default:
		return core.NewError(core.ErrCodeHandshake, "unexpected frame during handshake")
	}
}

// deriveKeys 完成客户端侧 ECDH 与会话密钥派生：ECDH 共享密钥 →
// core.DeriveSessionKeysWithCaps（dual_integrity 协商选中时内部追加
// DeriveDualMACKey 填充 SessionKeys.DualMACKey，与服务端 handleHello 对称驱动；
// 未协商时保持 nil）。
func (c *CoreClient) deriveKeys(priv *core.EphemeralKey, ack *core.HelloAck, thHello, tokenProof []byte) (*core.SessionKeys, error) {
	zz, err := core.DeriveZZ(c.cfg.Profile, priv, ack.GetServerEph())
	if err != nil {
		return nil, err
	}
	keys, kerr := core.DeriveSessionKeysWithCaps(c.cfg.Profile, zz, thHello, tokenProof, ack.GetSelectedCapabilities())
	// ECDH 共享密钥用后即清零（与服务端 deriveServerKeys 对称；zz 此后无使用方）。
	for i := range zz {
		zz[i] = 0
	}
	return keys, kerr
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// --- 发送 ---

// 压缩启发阈值（r3 客户端补全项；接收端四算法 + ZSTD_DICT 全支持，发送端逐帧自选）：
//   - 字典路径（zstd_dict 协商且 DICT 已到达）> 512B 启用——小批字典加载/匹配
//     开销高于压缩收益；
//   - 非字典路径 ≥ 4096B 选 ZSTD——小批压缩收益低于 CPU 成本。
const (
	dictCompressMinBytes = 512
	zstdCompressMinBytes = 4096
)

// pickCompression 按协商与 batch wire 尺寸选择压缩算法（字典路径优先）。
func (c *CoreClient) pickCompression(batchWireLen int) corepb.Compression {
	if batchWireLen > dictCompressMinBytes && c.zdict.Load() != nil &&
		slices.Contains(c.SelectedCapabilities(), core.CapZstdDict) {
		return corepb.Compression_COMPRESSION_ZSTD_DICT
	}
	if batchWireLen >= zstdCompressMinBytes {
		return corepb.Compression_COMPRESSION_ZSTD
	}
	return corepb.Compression_COMPRESSION_NONE
}

// encodeAndSeal 在 sendMu 临界区内完成：状态/过期检查 → seq 分配（单一计数器，
// BATCH/DGRAM 共享）→ Batch 编码 → 压缩启发 → Envelope 封装（dual_integrity
// 协商启用时附外层 mac）。credit 消耗由可靠路径调用方在同一临界区续做。
func (c *CoreClient) encodeAndSeal(sb *core.SignalBatch, sc *core.SendConfig, frameType uint8) ([]byte, uint64, error) {
	if c.sm.State() != core.StateReady {
		return nil, 0, core.NewError(core.ErrCodeSession, "not ready")
	}
	if exp := c.expiry.Load(); exp > 0 && time.Now().Unix() > exp {
		return nil, 0, core.NewError(core.ErrCodeServerDraining, "session expired, reconnect required")
	}
	codec := corepb.Codec_CODEC_PROTO
	if v, ok := c.codec.Load().(corepb.Codec); ok {
		codec = v
	}
	batchWire, err := core.MarshalSignalBatchCodec(codec, sb)
	if err != nil {
		return nil, 0, core.WrapError(core.ErrCodeBatch, "marshal signal batch", err)
	}
	seq := c.seq.Next()
	batch := &core.Batch{Seq: seq, EventsCount: uint32(len(sb.Signals)), Payload: batchWire}
	if sc.TraceContext != nil {
		batch.Trace = sc.TraceContext
	}
	bw, err := core.Encode(batch)
	if err != nil {
		return nil, 0, core.WrapError(core.ErrCodeBatch, "encode batch", err)
	}
	keys := c.sessionKeys()
	if keys == nil {
		return nil, 0, core.NewError(core.ErrCodeSession, "handshake incomplete")
	}
	envPayload, err := core.SealEnvelope(core.SealParams{
		FrameType: frameType, SessionID: c.getSessionID(), Seq: seq,
		Compression: c.pickCompression(len(bw)), Keys: keys, Dict: c.zdict.Load(), BatchWire: bw,
		DualMACKey: keys.DualMACKey,
	})
	if err != nil {
		return nil, 0, err
	}
	return envPayload, seq, nil
}

// SendBatch 发送一个 SignalBatch（可靠路径），返回分配的 seq。
func (c *CoreClient) SendBatch(ctx context.Context, sb *core.SignalBatch, opts ...core.SendOption) (uint64, error) {
	if sb == nil {
		return 0, core.NewError(core.ErrCodeBatch, "batch must not be nil")
	}
	sc := core.ApplySendOptions(opts)

	c.sendMu.Lock()
	envPayload, seq, err := c.encodeAndSeal(sb, &sc, core.TypeBatch)
	if err != nil {
		c.sendMu.Unlock()
		return 0, err
	}
	// credit 消耗与 seq 分配同一临界区（Peek 序号语义的 r3 等价物）。
	ledger := c.ledger.Load()
	if ledger == nil {
		c.sendMu.Unlock()
		return 0, core.NewError(core.ErrCodeSession, "handshake incomplete")
	}
	if cerr := ledger.Consume(seq, int64(len(envPayload)), "", time.Now().Add(c.cfg.AckTimeout)); cerr != nil {
		c.sendMu.Unlock()
		return 0, cerr
	}
	c.sendMu.Unlock()

	if werr := c.transport().WriteFrame(ctx, core.TypeBatch, envPayload); werr != nil {
		// 写失败 Rollback：服务端从未收到该帧、不会为此返还 CREDIT——
		// 不补偿即单向泄漏（镜像缺陷曾在服务端 sem-full 路径存在）。
		ledger.Rollback(seq)
		return 0, core.WrapError(core.ErrCodeBatch, "write batch", werr)
	}
	c.metrics.BatchesSent().Inc()
	return seq, nil
}

// SendDatagram 以不可靠通道发送一个 SignalBatch（at-most-once），返回分配的 seq。
//
// 前置：协商含 datagram 能力且传输实际提供不可靠通道（QUIC DATAGRAM，两侧
// 启用扩展）。二者任一不满足即降级走可靠 SendBatch 路径（消耗 credit、有
// RESULT 反馈，语义与直接调用 SendBatch 完全一致）。
//
// DGRAM 豁免 credit（不 Consume 账本，只分配 seq——与 BATCH 共享单一计数器，
// 跨通道 nonce 复用在构造上不可表达）；Envelope AD 绑定 TypeDgram，服务端
// processDatagram 以同一帧类型开启。服务端对一切失败静默丢弃（at-most-once）；
// 本侧发送失败（如超出 QUIC DATAGRAM 尺寸上限）原样返回错误由调用方决策。
func (c *CoreClient) SendDatagram(ctx context.Context, sb *core.SignalBatch, opts ...core.SendOption) (uint64, error) {
	if sb == nil {
		return 0, core.NewError(core.ErrCodeBatch, "batch must not be nil")
	}
	dt, ok := c.transport().(ClientDatagramTransport)
	if !ok || !dt.SupportsDatagram() || !slices.Contains(c.SelectedCapabilities(), core.CapDatagram) {
		return c.SendBatch(ctx, sb, opts...) // 降级：可靠路径
	}
	sc := core.ApplySendOptions(opts)

	c.sendMu.Lock()
	envPayload, seq, err := c.encodeAndSeal(sb, &sc, core.TypeDgram)
	c.sendMu.Unlock()
	if err != nil {
		return 0, err
	}
	if derr := dt.SendDatagram(ctx, envPayload); derr != nil {
		return 0, core.WrapError(core.ErrCodeBatch, "send datagram", derr)
	}
	c.metrics.BatchesSent().Inc()
	return seq, nil
}

func (c *CoreClient) sessionKeys() *core.SessionKeys { return c.keys.Load() }

func (c *CoreClient) getSessionID() []byte {
	if v := c.sessionID.Load(); v != nil {
		return v.([]byte)
	}
	return nil
}

// --- lifecycle ---

// SetResultHandler 注册结果回调（accepted/durable/rejected/released）。
func (c *CoreClient) SetResultHandler(h func(seq uint64, level string, code uint32, correlation string)) {
	c.resultHandler.Store(&h)
}

// SetRedirectHandler 注册 REDIRECT 回调（ctx 带 30s 超时）。
func (c *CoreClient) SetRedirectHandler(h func(ctx context.Context, payload []byte)) {
	c.redirectHandler.Store(&h)
}

// SetReadControlLoop 注入 control 读循环（binding 提供；StartLifecycle 把它启动为
// 后台 goroutine。nil = binding 自行驱动读路径，lifecycle 不再代启）。
func (c *CoreClient) SetReadControlLoop(fn func(context.Context)) { c.readControlFn = fn }

// SetHeartbeatLoop 注入心跳循环（binding 提供；启动方式同 SetReadControlLoop。
// nil = 无应用层心跳，HeartbeatEnabled 据此报告）。
func (c *CoreClient) SetHeartbeatLoop(fn func(context.Context)) { c.heartbeatLoopFn = fn }

// HeartbeatEnabled 报告 binding 是否注入了应用层心跳。诊断/回归面：
// QUIC binding 漏注入时连接仍能工作，但空闲会话会被 control 读超时
// 周期性断连（生产实测每 5 分钟 disconnect→handshake），问题只在线上
// 显形——binding 测试用它做注入存在性断言。
func (c *CoreClient) HeartbeatEnabled() bool { return c.heartbeatLoopFn != nil }

// StartLifecycle 启动后台 goroutine（拒绝在已关闭实例上启动；Once 保证幂等——
// 二次调用会替换 lifecycleCtx/ackQueue 等字段，旧 goroutine 的 ctx 永不取消而
// 泄漏，review F13 裁决）。closed 检查在 startLifecycle 的 lifecycleMu 临界区内
// 复查：与并发 Close 的交错由锁收口，任一顺序都不逃逸 goroutine。
func (c *CoreClient) StartLifecycle() {
	if c.closed.Load() {
		slog.Warn("StartLifecycle on closed client ignored")
		return
	}
	c.lifecycleOnce.Do(c.startLifecycle)
}

func (c *CoreClient) startLifecycle() {
	// closed 复查与字段写入同锁收口：Close/fatalTeardown 置位 closed 后本函数
	// 不再启动任何 goroutine（否则新 lifecycleCtx 无人取消、goroutine 逃逸）。
	// 先行完成的 Close 读到 nil channel 直接跳过等待——两序皆收敛。
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed.Load() {
		return
	}
	c.lifecycleCtx, c.lifecycleCancel = context.WithCancel(context.Background())
	c.ackDone = make(chan struct{})
	c.heartbeatDone = make(chan struct{})
	c.reaperDone = make(chan struct{})
	c.ackQueue = make(chan resultNotify, ackQueueSize)
	c.ackWorkerDone = make(chan struct{})
	if c.readControlFn != nil {
		fn := c.readControlFn
		go func() { defer close(c.ackDone); fn(c.lifecycleCtx) }()
	} else {
		close(c.ackDone)
	}
	if c.heartbeatLoopFn != nil {
		fn := c.heartbeatLoopFn
		go func() { defer close(c.heartbeatDone); fn(c.lifecycleCtx) }()
	} else {
		close(c.heartbeatDone)
	}
	go func() { defer close(c.reaperDone); c.AckReaperLoop(c.lifecycleCtx) }()
	go func() { defer close(c.ackWorkerDone); c.runResultWorker(c.lifecycleCtx) }()
}

// Close 幂等关闭。
func (c *CoreClient) Close() error {
	c.closeOnce.Do(c.close)
	return c.connErr
}

// close 是用户侧终态（发 CLOSE → drain → teardown）。
// 与 fatalTeardown 共享 teardownPhase 序列——两条路径的未来演化（新增清理步骤）
// 只需改一处。
func (c *CoreClient) close() {
	c.closed.Store(true)
	closeMsg := &core.CloseMsg{Reason: "client closing"}
	if payload, err := core.Encode(closeMsg); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if tr := c.transport(); tr != nil {
			if err := tr.WriteFrame(ctx, core.TypeClose, payload); err != nil {
				slog.Debug("write close frame", "error", err)
			}
		}
		cancel()
	}
	if err := c.sm.Transition(core.StateDraining); err == nil {
		c.drain() // Draining 进入成功才等排空；失败（非 Ready 出发）直接收敛
	}
	c.teardownPhase("user close")
	if tr := c.transport(); tr != nil {
		c.connErr = tr.CloseConn()
	}
	c.waitGoroutines()
}

// drain 等待全部已发 seq 终态（计数谓词）或 DrainTimeout。
func (c *CoreClient) drain() {
	timeout := c.cfg.DrainTimeout
	if timeout <= 0 {
		timeout = core.DefaultDrainTimeout
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	l := c.ledger.Load()
	if l == nil {
		return
	}
	for !l.Drained() {
		select {
		case <-deadline.C:
			slog.Warn("drain timeout, force-closing", "pending", l.Pending())
			return
		case <-c.drainCh:
		}
	}
}

func (c *CoreClient) notifyDrainIfEmpty() {
	if l := c.ledger.Load(); l != nil && l.Drained() {
		select {
		case c.drainCh <- struct{}{}:
		default:
		}
	}
}

// waitGoroutines 等待 lifecycle goroutine（每通道 5s 预算）。
// 通道快照在 lifecycleMu 下读取——与 startLifecycle 的写入（若 Close 先行完成则
// 通道仍为 nil，跳过等待；startLifecycle 侧的 closed 复查保证不会事后启动）互斥。
func (c *CoreClient) waitGoroutines() {
	const budget = 5 * time.Second
	c.lifecycleMu.Lock()
	chs := []chan struct{}{c.ackDone, c.heartbeatDone, c.reaperDone, c.ackWorkerDone}
	c.lifecycleMu.Unlock()
	for _, ch := range chs {
		if ch == nil {
			continue
		}
		select {
		case <-ch:
		case <-time.After(budget):
			slog.Warn("goroutine did not exit within budget")
		}
	}
}

// State 返回状态机状态。
func (c *CoreClient) State() core.State { return c.sm.State() }

// IsClosed 报告生命周期是否已终结。
func (c *CoreClient) IsClosed() bool { return c.closed.Load() }

// OverrideExpiry 覆写会话过期时刻（Unix 秒）。测试专用：模拟会话超时
// （生产 expiry 由 HELLO_ACK 权威下发，运行期不可变）。构造期注入比方法覆写
// 更难误用，但 conformance 需要握手后再操纵时序——保留为唯一测试钩子，
// doc 明示禁用于生产。
func (c *CoreClient) OverrideExpiry(unix int64) { c.expiry.Store(unix) }

// SessionID 返回会话 ID 文本。
func (c *CoreClient) SessionID() string {
	sid := c.getSessionID()
	if len(sid) == 0 {
		return ""
	}
	if cid, err := core.ChunkIDFromBytes(sid); err == nil {
		return cid.String()
	}
	return ""
}

// SelectedCapabilities 返回协商结果。
func (c *CoreClient) SelectedCapabilities() []string {
	if v := c.negCaps.Load(); v != nil {
		return v.([]string)
	}
	return nil
}

// ackModeLoad 返回握手协商的 ack_mode（握手前零值 ACCEPTED_ONLY——此时
// accepted 即终态，drain 判定不等待 durable）。
func (c *CoreClient) ackModeLoad() corepb.AckMode {
	if v := c.ackMode.Load(); v != nil {
		return v.(corepb.AckMode)
	}
	return corepb.AckMode_ACK_MODE_ACCEPTED_ONLY
}

// DictActive 报告 zstd 字典是否已到达并激活（DICT 帧处理后为 true）。
func (c *CoreClient) DictActive() bool { return c.zdict.Load() != nil }

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// teardownPhase 是收敛序列的公共尾部（幂等；close 与 fatalTeardown 共用）：
// 取消 lifecycle → 状态收敛 Closed → 清账本 → 唤醒 drain。连接关闭与
// goroutine 等待由调用方收尾（close 全量执行；fatalTeardown 即时关闭）。
func (c *CoreClient) teardownPhase(cause string) {
	// cause 仅作观测：close 路径传 "user close"，fatalTeardown 另在收尾时
	// 以 Info 级记录。此处置 Debug 保证两条路径的根因都有痕可查。
	slog.Debug("session teardown", "cause", cause, "session", c.SessionID())
	c.lifecycleMu.Lock()
	cancel := c.lifecycleCancel
	c.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.sm.ForceClosed()
	if l := c.ledger.Load(); l != nil {
		l.Reset()
	}
	select {
	case c.drainCh <- struct{}{}:
	default:
	}
}
