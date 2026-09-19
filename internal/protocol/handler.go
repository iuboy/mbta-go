package protocol

// handler.go：服务端协议核心（r3）。1-RTT 握手、RESULT/CREDIT、服务端 reaper、
// 集合制去重准入、credit 守恒（模型 B）、sink 契约。

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// 常量（继承 v1 防御值 + r3 裁决默认值，docs/v2-design.md §18-H5）。
const (
	maxConcurrentQuicDataFrames = 64
	maxConcurrentTCPBatches     = 8
	dgramConcurrencySlots       = 64

	maxDrainTimeout = 30 * time.Second
	minDrainTimeout = 1 * time.Second

	creditFlushInterval = 100 * time.Millisecond

	maxBatchEvents   = 10000
	stuckInflightAge = 60 * time.Second // 服务端 reaper 的 inflight 超时

	defaultSinkQueueSize     = 256
	defaultSinkQueueMaxBytes = int64(32 << 20)
)

// EpochAllocator 按 agent 单调分配连接纪元（服务端级共享；r2 审查裁决：
// epoch 必须服务端分配，否则票据丢失后 agent 被围栏死锁）。
type EpochAllocator struct {
	mu     sync.Mutex
	epochs map[string]uint64
}

// Next 返回 agent 的下一个 epoch（从 1 起）。
func (e *EpochAllocator) Next(agentID string) uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.epochs == nil {
		e.epochs = make(map[string]uint64)
	}
	e.epochs[agentID]++
	return e.epochs[agentID]
}

// HandlerConfig 是 CoreHandler 配置。
type HandlerConfig struct {
	Auth              core.TokenValidator
	Policy            core.ServerPolicy
	Metrics           core.Metrics
	ServerID          string
	RedirectChecker   core.RedirectChecker
	OnSession         core.OnSession
	Epochs            *EpochAllocator // nil = 每连接自增（测试）；生产共享一份
	SinkOpts          core.SinkOptions
	SinkHandler       core.BatchHandler // nil = 丢弃（仅握手测试）
	SinkDeadline      time.Duration     // 0 = core.DefaultSinkDeadline
	SinkQueueSize     int               // 0 = 256；负 = 同步调用（测试）
	SinkQueueMaxBytes int64             // 0 = 32MB；负 = 不限
	// Zdict 是 zstd_dict 字典 codec（构造期从 Policy 注册；nil=未配置）。
	Zdict    *core.ZstdDictCodec
	Commands *CommandRegistry
}

// CoreHandler 是服务端协议状态机核心。
type CoreHandler struct {
	tr     Transport
	config HandlerConfig

	sm          *core.ServerMachine
	metrics     core.Metrics
	agentID     string
	sessionID   []byte
	handshakeMu sync.RWMutex
	authed      atomic.Bool
	expiresAt   atomic.Int64

	keys    atomic.Pointer[core.SessionKeys]
	negCaps atomic.Value // []string selected capabilities
	codec   atomic.Value // corepb.Codec

	// credit 模型 B（服务端权威）。
	credit        *core.CreditManager // 准入/去重/守恒单一真相（根治版：grant 令牌化）
	flushArmed    atomic.Bool         // 懒 flush：首个 Settle 后 arm 一次 100ms 定时器（无常驻 tick
	dgramTokens   chan struct{}       // datagram 并发槽
	dgramBucketMu sync.Mutex
	dgramRate     int64 // bytes/s；0 = 不限
	dgramAvail    int64
	dgramLast     time.Time

	epoch uint64

	dataOnce       sync.Once
	dataWG         sync.WaitGroup
	batchSem       chan struct{}
	cancelDataLoop context.CancelFunc

	// sink 队列（继承 v1 加固：双限界/排空超时/panic 契约）。
	sinkStart       sync.Once // 懒启动 sink worker（首个成功入队触发）
	sinkQueue       chan sinkTask
	sinkDone        chan struct{}
	sinkWG          sync.WaitGroup
	sinkQueuedBytes atomic.Int64
	sinkMaxBytes    int64
	sinkDeadline    time.Duration

	closeTimeout time.Duration

	sinkCtx context.Context
}

// NewCoreHandler 创建 handler。
func NewCoreHandler(tr Transport, cfg HandlerConfig) *CoreHandler {
	sem := maxConcurrentQuicDataFrames
	if tr.Multiplexing() == MultiplexTCPSingleConn {
		sem = maxConcurrentTCPBatches
	}
	if isNilMetrics(cfg.Metrics) {
		cfg.Metrics = core.NoOpMetrics{}
	}
	if cfg.Epochs == nil {
		cfg.Epochs = &EpochAllocator{}
	}
	var zdict *core.ZstdDictCodec
	if len(cfg.Policy.ZstdDict) > 0 && cfg.Policy.ZstdDictID != 0 {
		zc, zerr := core.RegisterZstdDict(cfg.Policy.ZstdDictID, cfg.Policy.ZstdDict)
		if zerr != nil {
			slog.Error("zstd dict register failed; zstd_dict disabled", "error", zerr)
		} else {
			zdict = zc
		}
	}
	cfg.Zdict = zdict
	h := &CoreHandler{
		tr:          tr,
		config:      cfg,
		sm:          core.NewServerMachine(),
		metrics:     cfg.Metrics,
		batchSem:    make(chan struct{}, sem),
		credit:      core.NewCreditManager(int64(cfg.Policy.InitialCreditBatches), int64(cfg.Policy.InitialCreditBytes), 256),
		dgramTokens: make(chan struct{}, dgramConcurrencySlots),
		dgramRate:   cfg.Policy.DatagramRateBytes,
	}
	h.sinkDeadline = cfg.SinkDeadline
	if h.sinkDeadline == 0 {
		h.sinkDeadline = core.DefaultSinkDeadline
	}
	h.initSinkQueue()
	return h
}

// Handle 运行连接生命周期。
func (h *CoreHandler) Handle(ctx context.Context) error {
	sinkCtx, sinkCancel := context.WithCancel(ctx)
	h.sinkCtx = sinkCtx
	defer sinkCancel()

	defer func() {
		// 命令注册表注销独立于 OnSession：必须无条件发生于已认证连接
		// （防止幽灵路由）。重连竞态由 unregister 的指向检查保护。
		if h.config.Commands != nil && h.authed.Load() {
			h.config.Commands.unregister(h.getAgentID(), h)
		}
		if h.config.OnSession != nil {
			h.config.OnSession(core.SessionEvent{
				Type:       core.SessionDisconnected,
				AgentID:    h.getAgentID(),
				SessionID:  string(h.getSessionID()),
				RemoteAddr: h.tr.RemoteAddr(),
			})
		}
	}()

	err := h.controlLoop(ctx)

	// data drain（有界）。
	drainTimeout := h.closeTimeout
	if drainTimeout == 0 {
		drainTimeout = 5 * time.Second
	}
	if h.cancelDataLoop != nil {
		h.cancelDataLoop()
	}
	done := make(chan struct{})
	go func() { h.dataWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(drainTimeout):
		slog.Warn("data goroutines did not exit in drain timeout; abandoning", "session", string(h.getSessionID()))
	}

	// 服务端排空：对放弃的 inflight 项发 released（禁止沉默——否则客户端白等满超时）。
	h.releaseStuck(ctx, core.CodeServerDraining, 0)

	// sink 排空（有界）：超时取消 sinkCtx 放弃等待（防卡死 sink 钉死 connSem 槽位）。
	if h.sinkQueue != nil {
		close(h.sinkDone)
		drained := make(chan struct{})
		go func() { h.sinkWG.Wait(); close(drained) }()
		select {
		case <-drained:
		case <-time.After(drainTimeout):
			sinkCancel()
			slog.Warn("sink workers did not drain; abandoning", "session", string(h.getSessionID()))
		}
	}
	return err
}

// controlLoop 处理控制帧。
func (h *CoreHandler) controlLoop(ctx context.Context) error {
	// 服务端 reaper：inflight 超时 → released + credit 回收。
	reapStop := make(chan struct{})
	defer close(reapStop)
	go h.reaper(ctx, reapStop)

	for {
		f, err := h.tr.RecvControlFrame(ctx)
		if err != nil {
			return core.WrapError(core.ErrCodeProtocolError, "read control frame", err)
		}
		switch f.Header.Type {
		case core.TypeHello:
			if h.sm.State() != core.ServerStateHandshaking {
				h.sendNak(ctx, core.CodeBadHandshakeMessage, false, 0)
				return core.NewError(core.ErrCodeBadHandshake, "HELLO after handshake")
			}
			if err := h.handleHello(ctx, f.Payload); err != nil {
				return err
			}
			if h.sm.State() == core.ServerStateReady {
				h.dataOnce.Do(func() {
					dataCtx, cancel := context.WithCancel(ctx)
					h.cancelDataLoop = cancel
					h.dataWG.Add(1)
					go func() {
						defer h.dataWG.Done()
						defer func() {
							if r := recover(); r != nil {
								slog.Warn("dataLoop panicked", "panic", r)
							}
						}()
						h.dataLoop(dataCtx)
					}()
				})
			}
		case core.TypePing:
			h.handlePing(ctx, f.Payload)
		case core.TypeCommandAck:
			var ack corepb.ControlCommandAck
			if err := core.Decode(f.Payload, &ack); err != nil {
				slog.Warn("decode command ack failed", "error", err)
			} else {
				h.resolveAck(&ack)
			}
		case core.TypeClose:
			h.handleClose(f.Payload)
			return nil
		case core.TypeAbort:
			slog.Info("client aborted", "session", string(h.getSessionID()))
			return nil
		default:
			// TCP binding 已按 type 高位分流、QUIC control stream 只承载 control 帧，
			// 此分支正常不可达——纯防御。
			slog.Debug("unexpected frame on control channel; skipping", "type", f.Header.Type)
		}
	}
}

// handleHello 执行 1-RTT 握手（r3 §5.1）：
// 解码校验 → token_proof 验证 → eph/ECDH → 派生 → HELLO_ACK。
func (h *CoreHandler) handleHello(ctx context.Context, payload []byte) error {
	var hello core.Hello
	if err := core.Decode(payload, &hello); err != nil {
		h.sendNak(ctx, core.CodeBadHandshakeMessage, false, 0)
		return core.WrapError(core.ErrCodeBadHandshake, "decode hello", err)
	}
	if err := core.ValidateHello(&hello); err != nil {
		slog.Debug("HELLO validation failed", "error", err)
		code := core.CodeBadHandshakeMessage
		if core.CodeNumOf(err) == core.CodeUnsupportedProfile || core.CodeNumOf(err) == core.CodeHelloEphInvalid {
			code = core.CodeNumOf(err)
		}
		h.sendNak(ctx, code, false, 0)
		return err
	}

	// profile 与服务端策略一致性校验：profile 绑定整套密码组合（ECDH/KDF/AEAD），
	// 服务端只按自己策略声明的 profile 派生密钥——客户端声明其他已注册 profile 时
	// NAK（防算法不匹配导致密钥日程两侧发散）。
	if hello.GetProfile() != h.config.Policy.Profile {
		slog.Debug("profile mismatch", "client", core.ProfileName(hello.GetProfile()),
			"policy", core.ProfileName(h.config.Policy.Profile))
		h.sendNak(ctx, core.CodeUnsupportedProfile, false, 0)
		return core.NewError(core.ErrCodeUnsupportedProfile,
			"profile mismatch: client="+core.ProfileName(hello.GetProfile())+
				" policy="+core.ProfileName(h.config.Policy.Profile))
	}

	// 能力协商。zstd_dict 守卫：未配置字典时从交集剔除（否则客户端会以为字典
	// 可用而选 ZSTD_DICT 压缩，服务端却无字典可解——fail-closed 而非事后拒绝）。
	selected := h.config.Policy.Negotiate(hello.GetCapabilities())
	if len(h.config.Policy.ZstdDict) == 0 {
		selected = slices.DeleteFunc(selected, func(c string) bool { return c == core.CapZstdDict })
	}
	h.negCaps.Store(selected)
	h.codec.Store(core.CodecFor(selected))

	// token_proof 验证（先于任何密钥派生——防仅持票据者注入）。
	thHello, err := core.TranscriptHello(hello.GetProfile(), &hello)
	if err != nil {
		h.sendNak(ctx, core.CodeInternal, false, 0)
		return err
	}
	if verr := core.VerifyTokenProof(h.config.Auth, hello.GetProfile(), hello.GetAgentId(), thHello, hello.GetTokenProof()); verr != nil {
		// 候选诊断字段：candidates 数量/首候选前缀直接区分「候选缺失
		//（服务端未纳管该 token 类别）」与「候选在但证明不匹配」两类故障。
		cands, _ := h.config.Auth.ResolveToken(hello.GetAgentId())
		slog.Warn("token proof verification failed", "agent", core.SanitizeForLog(hello.GetAgentId()),
			"candidates", len(cands), "first_prefix", func() string {
				if len(cands) > 0 && len(cands[0]) > 8 {
					return cands[0][:8]
				}
				return ""
			}(), "hello_caps", fmt.Sprint(hello.GetCapabilities()))
		h.sendNak(ctx, core.CodeAuthFailed, true, 1000) // 单一代码 + retryable + 退避提示
		return nil                                      //nolint:nilerr // 握手失败不拆传输层（NAK 已回）
	}

	// ECDH + 密钥派生。
	clientPub := hello.GetClientEph()
	priv, _, gerr := core.GenerateEphemeral(hello.GetProfile())
	if gerr != nil {
		h.sendNak(ctx, core.CodeInternal, false, 0)
		return gerr
	}
	zz, derr := core.DeriveZZ(hello.GetProfile(), priv, clientPub)
	if derr != nil {
		h.sendNak(ctx, core.CodeHelloEphInvalid, false, 0)
		return derr
	}
	keys, kerr := core.DeriveSessionKeysWithCaps(hello.GetProfile(), zz, thHello, hello.GetTokenProof(), selected)
	if kerr != nil {
		h.sendNak(ctx, core.CodeInternal, false, 0)
		return kerr
	}
	h.keys.Store(keys)

	// 会话状态。
	h.handshakeMu.Lock()
	h.agentID = hello.GetAgentId()
	h.sessionID = core.NewChunkID().Bytes()
	h.handshakeMu.Unlock()
	h.epoch = h.config.Epochs.Next(hello.GetAgentId())
	h.expiresAt.Store(time.Now().Add(core.DefaultSessionTTL).Unix())

	// 构造 HELLO_ACK（finished 覆盖全部服务端声明）。
	ack := &core.HelloAck{
		SessionId:            h.getSessionID(),
		Epoch:                h.epoch,
		AckMode:              h.config.Policy.AckMode,
		SelectedCapabilities: selected,
		Limits: &corepb.Limits{
			MaxFrameBytes: h.config.Policy.MaxFrameBytes,
			MaxBatchBytes: h.config.Policy.MaxBatchBytes,
		},
		Credits: &corepb.Credits{
			Batches: h.config.Policy.InitialCreditBatches,
			Bytes:   h.config.Policy.InitialCreditBytes,
		},
		ServerEph:  ephPub(priv),
		ExpiryUnix: h.expiresAt.Load(),
	}
	thFull, terr := core.TranscriptFull(hello.GetProfile(), &hello, ack)
	if terr != nil {
		h.sendNak(ctx, core.CodeInternal, false, 0)
		return terr
	}
	ack.Finished = core.FinishedMAC(keys, thFull)

	ackPayload, aerr := core.Encode(ack)
	if aerr != nil {
		return core.WrapError(core.ErrCodeInternal, "marshal hello_ack", aerr)
	}
	if serr := SendControlFrame(ctx, h.tr, core.TypeHelloAck, ackPayload); serr != nil {
		return core.WrapError(core.ErrCodeProtocolError, "write hello_ack", serr)
	}

	// zstd_dict：字典配置且协商选中 → HELLO_ACK 之后立即下发 DICT 帧（边界
	// 声明见 maybeSendDict）。
	if err := h.maybeSendDict(ctx, selected); err != nil {
		return err
	}

	if terr := h.sm.Transition(core.ServerStateReady); terr != nil {
		return core.WrapError(core.ErrCodeProtocolError, "transition READY", terr)
	}
	h.authed.Store(true)
	if am, ok := h.tr.(AuthMarker); ok {
		am.MarkAuthed()
	}
	// 控制命令通道注册：READY 即登记，使 OnSession(CONNECTED) 的接收方
	// 立即可向该 agent 下发命令。仅当注册表注入且协商了能力。
	h.registerCommandChannel(hello.GetAgentId())

	slog.Info("handshake completed", "agent", core.SanitizeForLog(hello.GetAgentId()),
		"session", string(h.getSessionID()), "epoch", h.epoch, "profile", core.ProfileName(hello.GetProfile()))

	if h.config.OnSession != nil {
		h.config.OnSession(core.SessionEvent{
			Type:       core.SessionConnected,
			AgentID:    hello.GetAgentId(),
			SessionID:  string(h.getSessionID()),
			RemoteAddr: h.tr.RemoteAddr(),
		})
	}

	// HA 重定向：握手完成后任意时刻可发；发出后关闭连接。
	if h.config.RedirectChecker != nil {
		if info, redirect := h.config.RedirectChecker(ctx); redirect {
			if core.ValidateHostPort(info.LeaderAddr) == nil {
				rp, _ := core.Encode(&core.Redirect{LeaderAddr: info.LeaderAddr, LeaderId: info.LeaderID})
				if serr := SendControlFrame(ctx, h.tr, core.TypeRedirect, rp); serr != nil {
					slog.Warn("send redirect failed", "error", serr)
				}
				return core.NewError(core.ErrCodeProtocolError, "client redirected")
			}
			slog.Warn("redirect address invalid; ignoring", "addr", core.SanitizeForLog(info.LeaderAddr))
		}
	}
	h.metrics.AuthSuccess().Inc()
	return nil
}

// ephPub 返回临时公钥 wire 字节（持有者自身）。
func ephPub(k *core.EphemeralKey) []byte {
	pub, err := k.PubBytes()
	if err != nil {
		return nil
	}
	return pub
}

// maybeSendDict 在 zstd_dict 协商选中时下发 DICT 帧并注册服务端解压字典；
// 未选中时为 no-op。边界声明，即 r3 裁决与 v2-design §15.2 的差异：字典内容
// 不入 transcript——HELLO_ACK 的 finished 已签发后无法追加入链。字典经传输层
// AEAD（TLS/TLCP）通道保护；字典被篡改最坏导致解压失败，属 fail-closed，
// 无安全降级。
func (h *CoreHandler) maybeSendDict(ctx context.Context, selected []string) error {
	if !slices.Contains(selected, core.CapZstdDict) {
		return nil
	}
	dict := h.config.Policy.ZstdDict
	id := h.config.Policy.ZstdDictID
	if len(dict) == 0 || id == 0 {
		return nil // 防御：协商守卫已剔除，正常不可达
	}
	payload, err := core.Encode(&core.ZstdDict{DictId: id, Dict: dict})
	if err != nil {
		return core.WrapError(core.ErrCodeInternal, "encode dict", err)
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeDict, payload); err != nil {
		return core.WrapError(core.ErrCodeProtocolError, "write dict", err)
	}
	return nil
}

// registerCommandChannel 在握手 READY 后登记控制命令通道（能力协商通过
// 才注册；未协商时告警，便于观察混合舰队中旧 agent 的覆盖情况）。
func (h *CoreHandler) registerCommandChannel(agentID string) {
	if h.config.Commands == nil {
		return
	}
	if !h.hasCapability(core.CapControlCommands) {
		slog.Warn("command capability not negotiated",
			"agent", core.SanitizeForLog(agentID),
			"selected", fmt.Sprint(h.negCaps.Load()))
		return
	}
	h.config.Commands.register(agentID, h)
	slog.Info("command channel registered", "agent", core.SanitizeForLog(agentID))
}

// hasCapability 报告该连接是否协商了指定能力（control_commands 门控用）。
func (h *CoreHandler) hasCapability(capability string) bool {
	v := h.negCaps.Load()
	if v == nil {
		return false
	}
	caps, ok := v.([]string)
	if !ok {
		return false
	}
	return slices.Contains(caps, capability)
}

// sendCommand 下发一条运维命令帧（COMMAND 0x23）。仅内部使用——外部经
// CommandRegistry.SendCommand（含能力门控 + ACK 等待）。
func (h *CoreHandler) sendCommand(cmd *corepb.ControlCommand) error {
	payload, err := core.Encode(cmd)
	if err != nil {
		return core.WrapError(core.ErrCodeInternal, "encode command", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return SendControlFrame(ctx, h.tr, core.TypeCommand, payload)
}

// resolveAck 将命令应答分发给等待中的发送方（controlLoop COMMAND_ACK case
// 调用）。等待管道的单一真相在 CommandRegistry.pending——handler 侧不持有
// 第二套（此前双管道导致 ACK 永远无人等待，测试暴露后修正）。
func (h *CoreHandler) resolveAck(ack *corepb.ControlCommandAck) {
	if h.config.Commands != nil {
		h.config.Commands.resolve(ack)
	}
}

// isNilMetrics 拦截 typed-nil（nil 的 *core.MBTAMetrics 赋入接口）。
func isNilMetrics(m core.Metrics) bool {
	if m == nil {
		return true
	}
	rv := reflect.ValueOf(m)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}

func (h *CoreHandler) getAgentID() string {
	h.handshakeMu.RLock()
	defer h.handshakeMu.RUnlock()
	return h.agentID
}

func (h *CoreHandler) getSessionID() []byte {
	h.handshakeMu.RLock()
	defer h.handshakeMu.RUnlock()
	return h.sessionID
}

// handlePing 回 PONG（双 binding 客户端均注入心跳，见 v1/ntls NewClient）。
func (h *CoreHandler) handlePing(ctx context.Context, payload []byte) {
	var ping core.PingMsg
	if err := core.Decode(payload, &ping); err != nil {
		return
	}
	pong := &core.PongMsg{TimeUnixMs: ping.GetTimeUnixMs(), Nonce: ping.GetNonce(), Status: "ok"}
	p, err := core.Encode(pong)
	if err != nil {
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypePong, p); err != nil {
		slog.Debug("write pong failed", "error", err)
	}
}

// handleClose 处理 CLOSE：clamp drain 超时 [1s, 30s]。
func (h *CoreHandler) handleClose(payload []byte) {
	var c core.CloseMsg
	if derr := core.Decode(payload, &c); derr != nil {
		slog.Warn("failed to decode close", "error", derr)
	}
	if t := c.GetDrainTimeoutMs(); t > 0 {
		d := time.Duration(t) * time.Millisecond
		if d > maxDrainTimeout {
			d = maxDrainTimeout
		}
		if d < minDrainTimeout {
			d = minDrainTimeout
		}
		h.closeTimeout = d
	}
	// Ready→Draining：显式进入排空态（此后新 seq → released(server_draining)）。
	if err := h.sm.Transition(core.ServerStateDraining); err != nil {
		slog.Debug("draining transition skipped", "error", err)
	}
}

// sendNak 发送握手拒绝（未认证维度单一代码；detail 不透传）。
func (h *CoreHandler) sendNak(ctx context.Context, code uint32, retryable bool, retryMs uint32) {
	na := &core.HelloNak{Code: code, Retryable: retryable, RetryHintMs: retryMs}
	p, err := core.Encode(na)
	if err != nil {
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeHelloNak, p); err != nil {
		slog.Debug("write hello_nak failed", "error", err)
	}
}

// dataLoop 读数据帧并发处理（batchSem 限流；DGRAM 走并发槽 + 令牌桶）。
func (h *CoreHandler) dataLoop(ctx context.Context) {
	for {
		f, err := h.tr.RecvDataFrame(ctx)
		if err != nil {
			slog.Debug("data stream ended", "error", err)
			return
		}
		switch f.Header.Type {
		case core.TypeBatch:
			select {
			case h.batchSem <- struct{}{}:
				h.dataWG.Add(1)
				go func(pf core.Frame) {
					defer func() { <-h.batchSem; h.dataWG.Done() }()
					defer func() {
						if r := recover(); r != nil {
							slog.Warn("processBatch panicked", "panic", r)
						}
					}()
					h.processBatch(ctx, pf.Payload)
				}(f)
			default:
				// 并发满：grant 化直拒——占位+扣额度+Settle(released) 原子完成，
				// credit 守恒与终态环记录不可漏（历史缺陷：直发 RESULT 不经 terminal，
				// 客户端额度单向泄漏）。
				h.rejectAtCapacity(ctx, f.Payload)
			}
		case core.TypeDgram:
			select {
			case h.dgramTokens <- struct{}{}:
				h.dataWG.Add(1)
				go func(pf core.Frame) {
					defer func() { <-h.dgramTokens; h.dataWG.Done() }()
					defer func() {
						if r := recover(); r != nil {
							slog.Warn("processDatagram panicked", "panic", r)
						}
					}()
					h.processDatagram(ctx, pf.Payload)
				}(f)
			default:
				slog.Debug("datagram dropped: concurrency slots full")
			}
		default:
			slog.Debug("unexpected data type; skipping", "type", f.Header.Type)
		}
	}
}

// reaper：服务端闭环。两职责：
//   - inflight 超时回收（stuckInflightAge）→ released + 额度回收；
//   - CREDIT 定时攒批发 放（creditFlushInterval）：低吞吐连接上回收量长期达不到
//     阈值（初始窗/4）时，客户端额度被拖死——定时器兜底任何 >0 的回收量。
//     同时消除"服务端阈值 > 客户端钳制"配置组合下的饿死路径。
func (h *CoreHandler) reaper(ctx context.Context, stop <-chan struct{}) {
	reap := time.NewTicker(core.DefaultReapInterval)
	defer reap.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-reap.C:
			h.releaseStuck(ctx, core.CodeInternal, stuckInflightAge)
		}
	}
}
