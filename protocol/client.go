// Package protocol 实现 MBTA server/client 的共享协议核心。
package protocol

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// ClientTransport 抽象客户端侧的传输差异（v1 QUIC 多流 vs ntls 单 TCP 连接）。
//
// 与服务端 Transport 接口（RecvControlFrame/RecvDataFrame 双读路径）不同，
// 客户端只有一个读路径（readControlLoop 收 ACK/NACK/WINDOW/THROTTLE/PING/CLOSE），
// 故 ReadFrame 提供单一阻塞读原语。写侧用 ctx 区分 control（不超时）与 data（受 ctx 约束）。
//
// 各 binding 负责内部的写串行化：
//   - v1: control 帧走 controlMu+controlStr，data 帧走 picker+per-stream mu；
//   - ntls: 所有帧走 writeMu+单 conn。
type ClientTransport interface {
	// ReadFrame 阻塞读下一帧（HELLO_ACK / AUTH_OK / ACK / NACK / WINDOW / THROTTLE / PING / CLOSE）。
	ReadFrame() (core.Frame, error)

	// WriteFrame 写一帧。ctx 仅约束 data 通道（ChannelData）的写超时；
	// control 通道（ChannelControl）调用方通常传 context.Background()。
	// channel 区分控制/数据，binding 内部按 channel 路由到不同写路径。
	WriteFrame(ctx context.Context, typ uint8, flags, channel uint8, payload []byte) error

	// CloseConn 关闭底层连接。v1: CloseWithError(0,...)；ntls: conn.Close()。
	CloseConn() error
}

// CoreClientConfig 是 CoreClient 的公共配置（传输无关字段）。
// 各 binding 的 ClientConfig 内嵌或包装此结构，附加传输专属字段。
type CoreClientConfig struct {
	AgentID      string
	Hostname     string
	Token        string
	Capabilities []string // 客户端能力（HELLO 携带，与服务端协商）
}

// ackTask 是排队等待执行的用户 ACK/NACK 回调。
type ackTask struct {
	chunkID string
	mode    string
}

// ackQueueSize 限定 ACK 回调队列容量。满时 dispatchACK 丢弃回调（记录日志）
// 而非阻塞 control loop。
const ackQueueSize = 1024

// CoreClient 收敛 v1/ntls 客户端共享的协议逻辑：状态机、ACK worker、
// ackReaper、drain、heartbeat、inflight/window/throttle/pendingAcks、生命周期管理。
//
// 与服务端 CoreHandler 对称——两者都仅依赖 Transport 接口，不感知具体传输。
// v1.Client / ntls.Client 持有 *CoreClient 并提供 ClientTransport 实现，
// 自身仅保留传输适配（Dial/openStreams/writeMu/controlStr 等）。
//
// 可靠投递语义：CoreClient 仅在内存追踪已发送未 ACK 的 batch（pendingAcks/inflight）。
// 进程崩溃/重连后未 ACK 的 batch 会丢失——持久化与重发由调用方负责。
type CoreClient struct {
	tr  ClientTransport
	cfg CoreClientConfig
	sm  *core.StateMachine

	// 协商结果与密钥（握手后填充）
	negotiated     *core.NegotiateResult
	keys           *core.SessionKeys
	sessionID      []byte
	challengeNonce []byte    // server challenge from HELLO_ACK
	expiresAt      time.Time // 会话过期时间，从 AUTH_OK 获取

	// 发送追踪
	seq      *core.SeqGenerator
	inflight *core.Inflight
	window   *core.Window
	throttle *core.ThrottleState

	// sendMu 保护「window 检查 + 取 seq/chunkID + inflight/pending 登记」，
	// 保证并发 SendBatch 不会同时通过窗口后超限。重的 CPU 工作（marshal/Build/写）在锁外。
	sendMu sync.Mutex

	// pendingAcks 追踪 chunk_id -> batch info 用于 ACK 关联。
	pendingAcks  sync.Map     // chunkID -> *pendingBatch
	pendingCount atomic.Int64 // 与 pendingAcks 同步增减，notifyDrainIfEmpty 免 Range 扫描

	// ackHandler 在收到 ACK 时回调，接收 (chunkID, ackMode)。
	ackHandler atomic.Pointer[func(chunkID, ackMode string)]

	ackTimeout        time.Duration // max time to wait for ACK (default 5 min)
	heartbeatInterval time.Duration // PING 发送间隔（从 HELLO_ACK 获取，默认 30s）

	// lifecycleCtx 驱动所有后台 goroutine，独立于 Connect 调用方 ctx，
	// 避免 WithTimeout + defer cancel 级联停掉后台 goroutine。
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	// done channel 在对应 goroutine 退出时关闭，Close() 等待它们以确保无 goroutine 跨越 Close。
	ackDone       chan struct{}
	reaperDone    chan struct{}
	heartbeatDone chan struct{}

	// ackQueue 串行化用户 ACK/NACK 回调到一个 worker，慢回调不阻塞 readControlLoop。
	ackQueue      chan ackTask
	ackWorkerDone chan struct{}

	drainCh   chan struct{} // drain 时 pendingAcks 归零通知
	closeOnce sync.Once     // 使 Close 幂等
	connErr   error         // closeOnce.Do 内捕获，作为 Close() 返回值

	// 可注入钩子（binding 提供）：
	onAuthed        func(context.Context)         // AUTH_OK 后调用（v1: SetAuthed）；nil=no-op
	heartbeatLoopFn func(context.Context)         // 心跳循环（PING 写依赖 transport）；nil=不启心跳
	readControlFn   func(context.Context)         // readControlLoop（control 帧分发依赖 binding handle*）
}

// pendingBatch 记录一个待 ACK 的 batch 元信息。
type pendingBatch struct {
	Seq      uint64
	Events   int
	Bytes    int64
	SentAt   time.Time
	Deadline time.Time // 此 batch 若无 ACK 的超时时刻
}

// NewCoreClient 创建共享协议核心。tr 由各 binding 提供。
func NewCoreClient(tr ClientTransport, cfg CoreClientConfig) *CoreClient {
	return &CoreClient{
		tr:        tr,
		cfg:       cfg,
		sm:        core.NewStateMachine(),
		seq:       core.NewSeqGenerator(),
		inflight:  &core.Inflight{},
		window:    core.NewWindow(100, 10000, 16*1024*1024),
		throttle:  &core.ThrottleState{},
		ackTimeout: 5 * time.Minute,
		drainCh:   make(chan struct{}, 1),
	}
}

// SetACKHandler registers a callback invoked when the server acknowledges a batch.
func (c *CoreClient) SetACKHandler(h func(chunkID, ackMode string)) {
	c.ackHandler.Store(&h)
}

func (c *CoreClient) loadACKHandler() func(chunkID, ackMode string) {
	if p := c.ackHandler.Load(); p != nil {
		return *p
	}
	return nil
}

// dispatchACK 入队用户 ACK/NACK 回调异步执行。永不阻塞：队列满时丢弃回调（warn）。
// 仅回调通知丢失——pendingAcks/inflight 在 handleAck/handleNack 同步更新，
// ackReaper 仍会回收未 ACK batch 的 inflight。
func (c *CoreClient) dispatchACK(chunkID, mode string) {
	select {
	case c.ackQueue <- ackTask{chunkID: chunkID, mode: mode}:
	default:
		slog.Warn("ack callback queue full, dropping callback",
			"chunk", chunkID, "mode", mode)
	}
}

// runACKWorker 消费 ackTask 并在单 goroutine 上调用已注册 handler，保持 ACK 到达顺序。
// 关闭时先排空队列，使已入队回调仍能投递。
func (c *CoreClient) runACKWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case t := <-c.ackQueue:
					c.invokeACKHandler(t)
				default:
					return
				}
			}
		case t := <-c.ackQueue:
			c.invokeACKHandler(t)
		}
	}
}

// invokeACKHandler 每次新鲜加载 handler，使 SetACKHandler 更新立即生效。
func (c *CoreClient) invokeACKHandler(t ackTask) {
	if h := c.loadACKHandler(); h != nil {
		h(t.chunkID, t.mode)
	}
}

// ackReaper 周期回收超时未 ACK 的 batch 的 inflight 配额（30s ticker）。
// 防止对端永不 ACK 时 inflight 永久占用窗口。
func (c *CoreClient) ackReaper(ctx context.Context) {
	const reaperInterval = 30 * time.Second
	ticker := time.NewTicker(reaperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			c.pendingAcks.Range(func(key, val any) bool {
				pb, ok := val.(*pendingBatch)
				if !ok {
					return true
				}
				if now.After(pb.Deadline) {
					c.pendingAcks.Delete(key)
					c.pendingCount.Add(-1)
					c.inflight.Remove(pb.Events, pb.Bytes)
					slog.Warn("reaped expired unacked batch",
						"chunk", key, "seq", pb.Seq, "age", now.Sub(pb.SentAt).Round(time.Second))
					c.notifyDrainIfEmpty()
				}
				return true
			})
		}
	}
}

// notifyDrainIfEmpty 在 drain 状态且 pendingAcks 归零时通知 close 的 drain 循环。
// 非阻塞：drainCh 容量 1，重复通知无妨。
func (c *CoreClient) notifyDrainIfEmpty() {
	if c.pendingCount.Load() == 0 {
		select {
		case c.drainCh <- struct{}{}:
		default:
		}
	}
}

// countPendingAcks 返回当前待 ACK 的 batch 数（用于 close 日志）。
func (c *CoreClient) countPendingAcks() int {
	return int(c.pendingCount.Load())
}

// waitGoroutines 等待所有后台 goroutine 退出或超时（5s），防止 Close 无限挂起。
func (c *CoreClient) waitGoroutines() {
	const waitTimeout = 5 * time.Second
	deadline := time.NewTimer(waitTimeout)
	defer deadline.Stop()
	for _, ch := range []<-chan struct{}{c.ackDone, c.reaperDone, c.heartbeatDone, c.ackWorkerDone} {
		select {
		case <-ch:
		case <-deadline.C:
			slog.Warn("goroutine wait timeout, proceeding with close")
			return
		}
	}
}

// Close sends a CLOSE frame, drains pending ACKs, and shuts down.
// Idempotent: subsequent calls return the error from the first close.
func (c *CoreClient) Close() error {
	c.closeOnce.Do(c.close)
	return c.connErr
}

// close 执行实际关闭（仅运行一次）。
func (c *CoreClient) close() {
	// 1. 发 CLOSE 帧（goroutine 仍存活，使 server 得知客户端关闭）。
	closeMsg := &corepb.CloseMessage{Code: "shutdown", Reason: "client closing"}
	if payload, err := core.Encode(closeMsg); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := c.tr.WriteFrame(ctx, core.TypeClose, core.FlagControl, core.ChannelControl, payload); err != nil {
			slog.Warn("write close frame", "error", err)
		}
		cancel()
	}

	// 2. 进入 Draining。
	if err := c.sm.Transition(core.StateDraining); err != nil {
		slog.Debug("drain transition skipped", "error", err)
	}

	// 3. 等待 drain。readControlLoop 仍运行，handleAck 持续触发 notifyDrainIfEmpty。
	if c.sm.State() == core.StateDraining {
		drainDeadline := time.NewTimer(core.DefaultDrainTimeout)
		for c.sm.State() == core.StateDraining {
			select {
			case <-drainDeadline.C:
				slog.Warn("drain timeout exceeded, force-closing",
					"pending", c.countPendingAcks())
				_ = c.sm.Transition(core.StateClosed)
			case <-c.drainCh:
				_ = c.sm.Transition(core.StateClosed)
			}
		}
		drainDeadline.Stop()
	}

	// 4. 取消所有后台 goroutine。
	if c.lifecycleCancel != nil {
		c.lifecycleCancel()
	}
	// 5. 关闭连接（transport 负责）。
	if c.tr != nil {
		c.connErr = c.tr.CloseConn()
	}
	// 6. 等待 goroutine 实际退出。
	c.waitGoroutines()

	// 7. 清理 pending ACKs 释放引用。
	c.pendingAcks.Range(func(key, _ any) bool {
		c.pendingAcks.Delete(key)
		return true
	})
	c.pendingCount.Store(0)

	// 8. 清零密钥（sendMu 保证无并发 SendBatch 读取）。
	c.sendMu.Lock()
	c.inflight.Reset()
	if c.keys != nil {
		for i := range c.keys.HMACKey {
			c.keys.HMACKey[i] = 0
		}
		for i := range c.keys.AEADKey {
			c.keys.AEADKey[i] = 0
		}
		c.keys = nil
	}
	c.sendMu.Unlock()
}

// State 返回当前连接状态（供外部查询）。
func (c *CoreClient) State() core.State {
	return c.sm.State()
}

// SessionID 返回握手后分配的会话 ID（十六进制）。
func (c *CoreClient) SessionID() string {
	if len(c.sessionID) == 0 {
		return ""
	}
	if cid, err := core.ChunkIDFromBytes(c.sessionID); err == nil {
		return cid.String()
	}
	return ""
}

// StartLifecycle 初始化后台 goroutine 上下文与 done channel，启动 4 个 goroutine。
// 各 binding 的 Connect 在握手成功后调用此方法。readControlFn / heartbeatLoopFn
// 由 binding 通过 SetReadControlLoop / SetHeartbeatLoop 注入（control 帧分发与
// PING 写依赖 binding 的 handle* / transport）。
func (c *CoreClient) StartLifecycle() {
	c.lifecycleCtx, c.lifecycleCancel = context.WithCancel(context.Background())
	c.ackDone = make(chan struct{})
	c.reaperDone = make(chan struct{})
	c.heartbeatDone = make(chan struct{})
	c.ackQueue = make(chan ackTask, ackQueueSize)
	c.ackWorkerDone = make(chan struct{})

	if c.readControlFn != nil {
		fn := c.readControlFn
		go func() { defer close(c.ackDone); fn(c.lifecycleCtx) }()
	}
	if c.heartbeatLoopFn != nil {
		fn := c.heartbeatLoopFn
		go func() { defer close(c.heartbeatDone); fn(c.lifecycleCtx) }()
	}
	go func() { defer close(c.reaperDone); c.ackReaper(c.lifecycleCtx) }()
	go func() { defer close(c.ackWorkerDone); c.runACKWorker(c.lifecycleCtx) }()
}

// SetHeartbeatLoop 注入心跳循环实现（binding 提供，PING 写走 transport）。
// 必须在 StartLifecycle 前调用。
func (c *CoreClient) SetHeartbeatLoop(fn func(context.Context)) {
	c.heartbeatLoopFn = fn
}

// SetReadControlLoop 注入 control 帧读循环（binding 提供 handleAck/Nack 等）。
// 必须在 StartLifecycle 前调用。
func (c *CoreClient) SetReadControlLoop(fn func(context.Context)) {
	c.readControlFn = fn
}

// SetOnAuthed 注入 AUTH_OK 后置钩子（v1 binding 用于 SetAuthed(true)）。
func (c *CoreClient) SetOnAuthed(fn func(context.Context)) {
	c.onAuthed = fn
}

// --- binding 在 Connect 中调用的状态设置方法 ---

// SetTransport 设置/替换传输实现。Connect 拨号成功后由 binding 调用。
func (c *CoreClient) SetTransport(tr ClientTransport) {
	c.tr = tr
}

// SetSessionID 设置握手后分配的会话 ID。
func (c *CoreClient) SetSessionID(id []byte) {
	c.sessionID = id
}

// UpdateWindow 更新流控窗口（从 HELLO_ACK 的 initial_window）。
func (c *CoreClient) UpdateWindow(batches, events int, bytes int64) {
	c.window.Update(batches, events, bytes)
}

// SetHeartbeatInterval 设置 PING 间隔（从 HELLO_ACK 或默认 30s）。
func (c *CoreClient) SetHeartbeatInterval(d time.Duration) {
	c.heartbeatInterval = d
}

// SmTransition 暴露状态机转换给 binding（Connect 流程需要）。
func (c *CoreClient) SmTransition(state core.State) error {
	return c.sm.Transition(state)
}

// SmTransitionConnecting 是 Connecting 转换的便捷方法。
func (c *CoreClient) SmTransitionConnecting() error {
	return c.sm.Transition(core.StateConnecting)
}

// --- 握手（sendHello / recvHelloAck / sendAuth / recvAuthResult）---
// 这些方法原在 v1/handshake.go 与 ntls/handshake.go 中逐字重复，现已下沉。
// 读写均经 c.tr（ClientTransport），消除对 controlStr/conn 的直接依赖。

// SendHello 发送 HELLO（core spec §9.5）。
func (c *CoreClient) SendHello() error {
	hello := &corepb.HelloMessage{
		AgentId:       c.cfg.AgentID,
		Hostname:      c.cfg.Hostname,
		FrameVersion:  1,
		AgentVersion:  "0.1.0",
		Capabilities:  c.cfg.Capabilities,
		InstanceId:    core.NewChunkID().String(),
		StartedAtUnix: time.Now().Unix(),
	}
	payload, err := core.Encode(hello)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal hello", err)
	}
	if err := c.tr.WriteFrame(context.Background(), core.TypeHello, core.FlagControl, core.ChannelControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateHelloSent); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to HELLO_SENT", err)
	}
	return nil
}

// RecvHelloAck 接收 HELLO_ACK，存储协商结果与 challenge nonce。
func (c *CoreClient) RecvHelloAck() (*core.HelloAckMessage, error) {
	f, err := c.tr.ReadFrame()
	if err != nil {
		return nil, err
	}
	if f.Header.Type == core.TypeError {
		var errMsg core.ErrorMessage
		_ = core.Decode(f.Payload, &errMsg)
		return nil, core.NewError(core.NumHandshake, core.CodeHandshake, fmt.Sprintf("server error: %s", errMsg.GetReason()))
	}
	if f.Header.Type != core.TypeHelloAck {
		return nil, core.NewError(core.NumProtocol, core.CodeProtocol, fmt.Sprintf("expected HELLO_ACK, got 0x%02x", f.Header.Type))
	}

	var ack core.HelloAckMessage
	if err := core.Decode(f.Payload, &ack); err != nil {
		return nil, err
	}

	c.negotiated = &core.NegotiateResult{
		SelectedCapabilities: ack.GetSelectedCapabilities(),
		Codec:                ack.GetCodec(),
		Compression:          ack.GetCompression(),
		CipherSuite:          ack.GetCipherSuite(),
	}
	c.challengeNonce = ack.GetChallengeNonce()

	if len(c.challengeNonce) == 0 {
		return nil, core.NewError(core.NumHandshake, core.CodeHandshake, "server did not provide challenge_nonce in HELLO_ACK")
	}
	return &ack, nil
}

// SendAuth 发送 AUTH（challenge-response）。
func (c *CoreClient) SendAuth() error {
	if len(c.challengeNonce) == 0 {
		return core.NewError(core.NumAuth, core.CodeAuth, "server did not provide challenge_nonce in HELLO_ACK, cannot authenticate")
	}

	auth := c.buildAuthMessage()
	payload, err := core.Encode(auth)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal auth", err)
	}
	if err := c.tr.WriteFrame(context.Background(), core.TypeAuth, core.FlagControl, core.ChannelControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateAuthSent); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to AUTH_SENT", err)
	}
	return nil
}

// buildAuthMessage 构造 AUTH 帧：Token + 基于 challenge 的 HMAC 应答（按协商 CipherSuite）。
func (c *CoreClient) buildAuthMessage() *corepb.AuthMessage {
	cs := corepb.CipherSuite_CIPHER_SUITE_INTL
	if c.negotiated != nil {
		cs = c.negotiated.CipherSuite
	}
	return &corepb.AuthMessage{
		Token:     c.cfg.Token,
		AgentId:   c.cfg.AgentID,
		SessionId: c.sessionID,
		AuthNonce: core.ComputeChallengeResponse(c.cfg.Token, string(c.challengeNonce), cs),
	}
}

// RecvAuthResult 接收 AUTH_OK / AUTH_FAIL。AUTH_OK 后调用 onAuthed 钩子（v1 binding
// 用于 SetAuthed 开放 data stream 门禁；ntls binding 不设置此钩子）。
func (c *CoreClient) RecvAuthResult() error {
	f, err := c.tr.ReadFrame()
	if err != nil {
		return err
	}

	switch f.Header.Type {
	case core.TypeAuthOK:
		var okMsg core.AuthOKMessage
		if err := core.Decode(f.Payload, &okMsg); err != nil {
			return err
		}

		cs := okMsg.GetCipherSuite()
		c.keys = &core.SessionKeys{
			KeyID:       okMsg.GetKeyId(),
			CipherSuite: cs,
			HMACKey:     okMsg.GetHmacKey(),
		}
		// AEAD 密钥按套件下发字段（intl=AesKey, gm=Sm4Key）。
		if cs == corepb.CipherSuite_CIPHER_SUITE_INTL {
			c.keys.AEADKey = okMsg.GetAesKey()
		} else {
			c.keys.AEADKey = okMsg.GetSm4Key()
		}

		if okMsg.GetExpiresAtUnix() > 0 {
			c.expiresAt = time.Unix(okMsg.GetExpiresAtUnix(), 0)
		}

		if c.onAuthed != nil {
			c.onAuthed(context.Background())
		}
		if err := c.sm.Transition(core.StateReady); err != nil {
			return core.WrapError(core.NumSession, core.CodeSession, "transition to READY", err)
		}
		return nil

	case core.TypeAuthFail:
		var failMsg core.AuthFailMessage
		if uerr := core.Decode(f.Payload, &failMsg); uerr != nil {
			slog.Debug("failed to decode auth_fail frame", "error", uerr)
		}
		return core.NewError(core.NumAuth, core.CodeAuth, fmt.Sprintf("auth failed: %s (%s)", failMsg.GetReason(), failMsg.GetCode()))

	default:
		return core.NewError(core.NumProtocol, core.CodeProtocol, fmt.Sprintf("expected AUTH_OK/FAIL, got 0x%02x", f.Header.Type))
	}
}

// --- 批次发送 ---

// SendBatch 发送一个 SignalBatch。返回分配的 chunkID 用于 ACK 关联。
//
// 锁粒度：sendMu 仅保护「window 检查 + 取 seq/chunkID + inflight/pending 登记」，
// 重的 CPU 工作（marshal/Build/网络写）全部在锁外，使多调用方可跨 batch 并行利用多核。
func (c *CoreClient) SendBatch(ctx context.Context, signalBatch *core.SignalBatch, tag, source string) (string, error) {
	if signalBatch == nil {
		return "", core.NewError(core.NumBatch, core.CodeBatch, "batch must not be nil")
	}

	// --- 锁外：无状态前置检查 + marshal SignalBatch ---
	if c.sm.State() != core.StateReady {
		return "", fmt.Errorf("not ready, state=%s", c.sm.State())
	}
	if c.throttle.Active() {
		return "", fmt.Errorf("throttled, retry after %v", c.throttle.WaitDuration())
	}

	batchJSON, err := core.MarshalSignalBatch(signalBatch)
	if err != nil {
		return "", core.WrapError(core.NumBatch, core.CodeBatch, "marshal signal batch", err)
	}
	batchEvents := len(signalBatch.Signals)

	// --- 锁内：取 seq/chunkID、窗口检查、inflight/pending 登记 ---
	seq, chunkID, batchPayload, err := c.reserveInflight(tag, source, batchJSON, batchEvents)
	if err != nil {
		return "", err
	}
	batchBytes := int64(len(batchPayload))

	// --- 锁外：Build envelope（gzip+HMAC）+ marshal env + 网络写 ---
	if writeErr := c.buildAndSend(ctx, seq, chunkID, tag, source, batchPayload); writeErr != nil {
		c.inflight.Remove(batchEvents, batchBytes)
		if _, ok := c.pendingAcks.LoadAndDelete(chunkID.String()); ok {
			c.pendingCount.Add(-1)
		}
		return "", writeErr
	}

	slog.Debug("batch sent", "seq", seq, "chunk", chunkID.String(), "events", batchEvents)
	return chunkID.String(), nil
}

// reserveInflight 在 sendMu 保护下原子完成：取 seq/chunkID、构造 BatchMessage proto、
// 窗口检查、inflight/pending 登记。
func (c *CoreClient) reserveInflight(tag, source string, batchJSON []byte, batchEvents int) (uint64, core.ChunkID, []byte, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	seq := c.seq.Next()
	chunkID := core.NewChunkID()

	batchMsg := &corepb.BatchMessage{Seq: seq, ChunkId: chunkID.Bytes(), Tag: tag, Source: source}
	if batchEvents > 0 {
		batchMsg.EventsCount = int32(batchEvents)
	}
	batchMsg.Batch = batchJSON
	batchPayload, err := core.Encode(batchMsg)
	if err != nil {
		return 0, core.ChunkID{}, nil, core.WrapError(core.NumBatch, core.CodeBatch, "encode batch message", err)
	}
	batchBytes := int64(len(batchPayload))

	if !c.window.CanSend(c.inflight, batchEvents, batchBytes) {
		return 0, core.ChunkID{}, nil, core.NewError(core.NumBatch, core.CodeBatch, "window full")
	}
	c.inflight.Add(batchEvents, batchBytes)

	chunkIDText := chunkID.String()
	c.pendingAcks.Store(chunkIDText, &pendingBatch{
		Seq:      seq,
		Events:   batchEvents,
		Bytes:    batchBytes,
		SentAt:   time.Now(),
		Deadline: time.Now().Add(c.ackTimeout),
	})
	c.pendingCount.Add(1)

	return seq, chunkID, batchPayload, nil
}

// buildAndSend 在锁外完成 envelope 构建（gzip+HMAC）、envelope marshal 与网络写。
// BATCH 写经 c.tr.WriteFrame（v1 走 picker 多流，ntls 走单连接），由 binding 实现。
func (c *CoreClient) buildAndSend(ctx context.Context, seq uint64, chunkID core.ChunkID, tag, source string, batchPayload []byte) error {
	cs := corepb.CipherSuite_CIPHER_SUITE_INTL
	codec := corepb.Codec_CODEC_PROTO
	comp := corepb.Compression_COMPRESSION_NONE
	if c.negotiated != nil {
		cs = c.negotiated.CipherSuite
		codec = c.negotiated.Codec
		comp = c.negotiated.Compression
	}
	params := core.BuildParams{
		SessionID:    c.sessionID,
		Seq:          seq,
		ChunkID:      chunkID,
		Codec:        codec,
		Compression:  comp,
		CipherSuite:  cs,
		DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
		MsgType:      corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
	}
	if c.keys != nil {
		params.KeyID = c.keys.KeyID
		params.HMACKey = c.keys.HMACKey
		params.AEADKey = c.keys.AEADKey
	}
	params.BatchPayload = batchPayload
	env, err := core.Build(params)
	if err != nil {
		return core.WrapError(core.NumBatch, core.CodeBatch, "build envelope", err)
	}
	envPayload, err := core.Encode(env)
	if err != nil {
		return core.WrapError(core.NumBatch, core.CodeBatch, "encode envelope", err)
	}

	if err := c.tr.WriteFrame(ctx, core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload); err != nil {
		return core.WrapError(core.NumBatch, core.CodeBatch, "write batch", err)
	}
	return nil
}

// --- control 帧处理（readControlLoop / handleAck / handleNack / handleWindow / handleThrottle / handlePing）---
// 这些方法原在 v1/control.go 与 ntls/control.go 中重复。PONG 写经 c.tr.WriteFrame。

// ReadControlLoop 读 control 帧并分发。由 StartLifecycle 启动为后台 goroutine。
// 注意：此方法作为默认 readControlFn，binding 通过 SetReadControlLoop 注入时
// 可包装此方法（当前 binding 直接使用此默认实现）。
func (c *CoreClient) ReadControlLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		f, err := c.tr.ReadFrame()
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("control loop read error", "error", err)
			}
			return
		}

		switch f.Header.Type {
		case core.TypeAck:
			c.handleAck(f.Payload)
		case core.TypeNack:
			c.handleNack(f.Payload)
		case core.TypePartialAck:
			// future
		case core.TypeWindow:
			c.handleWindow(f.Payload)
		case core.TypeThrottle:
			c.handleThrottle(f.Payload)
		case core.TypeClose:
			slog.Info("server sent close")
			return
		case core.TypePing:
			c.handlePing(f.Payload)
		case core.TypeError:
			var errMsg core.ErrorMessage
			if err := core.Decode(f.Payload, &errMsg); err != nil {
				slog.Debug("invalid error payload", "error", err)
			} else {
				slog.Warn("server error", "code", errMsg.GetCode(), "reason", core.SanitizeForLog(errMsg.GetReason()), "fatal", errMsg.GetFatal())
				if errMsg.GetFatal() {
					return
				}
			}
		}
	}
}

// handleAck 处理 ACK：清除 inflight，回调。
func (c *CoreClient) handleAck(payload []byte) {
	var ack core.AckMessage
	if err := core.Decode(payload, &ack); err != nil {
		slog.Debug("invalid ack payload", "error", err)
		return
	}

	chunkID := ulidText(ack.GetChunkId())
	if val, ok := c.pendingAcks.LoadAndDelete(chunkID); ok {
		c.pendingCount.Add(-1)
		if pb, ok := val.(*pendingBatch); ok {
			c.inflight.Remove(pb.Events, pb.Bytes)
		}
	}

	c.dispatchACK(chunkID, ackModeString(ack.GetAckMode()))
	c.notifyDrainIfEmpty()

	slog.Debug("ack received", "seq", ack.GetSeq(), "chunk", chunkID, "count", ack.GetCount(), "mode", ackModeString(ack.GetAckMode()))
}

// handleNack 处理 NACK：清除 inflight。
func (c *CoreClient) handleNack(payload []byte) {
	var nack core.NackMessage
	if err := core.Decode(payload, &nack); err != nil {
		slog.Debug("invalid nack payload", "error", err)
		return
	}

	chunkID := ulidText(nack.GetChunkId())
	if val, ok := c.pendingAcks.LoadAndDelete(chunkID); ok {
		c.pendingCount.Add(-1)
		if pb, ok := val.(*pendingBatch); ok {
			c.inflight.Remove(pb.Events, pb.Bytes)
		}
	}

	c.dispatchACK(chunkID, "nack")
	c.notifyDrainIfEmpty()

	slog.Warn("nack received", "seq", nack.GetSeq(), "code", nack.GetCode(), "reason", core.SanitizeForLog(nack.GetReason()), "retryable", nack.GetRetryable())
}

func (c *CoreClient) handleWindow(payload []byte) {
	var win core.WindowMessage
	if err := core.Decode(payload, &win); err != nil {
		slog.Debug("invalid window payload", "error", err)
		return
	}
	c.window.Update(int(win.GetMaxInflightBatches()), int(win.GetMaxInflightEvents()), win.GetMaxInflightBytes())
	slog.Debug("window updated", "batches", win.GetMaxInflightBatches(), "events", win.GetMaxInflightEvents())
}

func (c *CoreClient) handleThrottle(payload []byte) {
	var throt core.ThrottleMessage
	if err := core.Decode(payload, &throt); err != nil {
		slog.Debug("invalid throttle payload", "error", err)
		return
	}
	c.throttle.Apply(int(throt.GetRetryDelayMs()))
	slog.Info("throttled", "delay_ms", throt.GetRetryDelayMs(), "reason", core.SanitizeForLog(throt.GetReason()))
}

func (c *CoreClient) handlePing(payload []byte) {
	var ping core.PingMessage
	if err := core.Decode(payload, &ping); err != nil {
		slog.Debug("invalid ping payload", "error", err)
		return
	}

	pong := &corepb.PongMessage{TimeUnixMs: ping.GetTimeUnixMs(), Nonce: ping.GetNonce(), Status: "ok"}
	pongPayload, err := core.Encode(pong)
	if err != nil {
		slog.Warn("marshal pong failed", "error", err)
		return
	}
	if err := c.tr.WriteFrame(context.Background(), core.TypePong, core.FlagControl, core.ChannelControl, pongPayload); err != nil {
		slog.Warn("write pong failed", "error", err)
	}
}

// --- 心跳 ---

// HeartbeatLoop 周期发送 PING 保活。由 binding 通过 SetHeartbeatLoop 注入
// （或直接使用此默认实现，因 PING 写已走 c.tr.WriteFrame）。
func (c *CoreClient) HeartbeatLoop(ctx context.Context) {
	if c.heartbeatInterval <= 0 {
		return
	}
	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ping := &corepb.PingMessage{TimeUnixMs: time.Now().UnixMilli(), Nonce: core.NewChunkID().String()}
			payload, err := core.Encode(ping)
			if err != nil {
				slog.Debug("marshal ping failed", "error", err)
				continue
			}
			if err := c.tr.WriteFrame(context.Background(), core.TypePing, core.FlagControl, core.ChannelControl, payload); err != nil {
				slog.Warn("write ping failed", "error", err)
				return
			}
		}
	}
}

// --- 辅助函数（原 v1/control.go 与 ntls/control.go 重复的包级函数）---

// ackModeString 把 corepb.AckMode 转为回调期望的字符串（"durable"/"accepted"）。
func ackModeString(m corepb.AckMode) string {
	if m == corepb.AckMode_ACK_MODE_DURABLE {
		return "durable"
	}
	return "accepted"
}

// ulidText 把 wire chunk_id（ULID 16B）转为文本，匹配 pendingAcks key。
func ulidText(chunkID []byte) string {
	if c, err := core.ChunkIDFromBytes(chunkID); err == nil {
		return c.String()
	}
	return string(chunkID)
}
