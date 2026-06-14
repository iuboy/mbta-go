package ntls

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/iuboy/mbta-go/core"
)

// Client 是 MBTA-NTLS 客户端：单 TCP（TLCP）连接上多路复用 control/data 帧。
//
// 与 v1（QUIC 多流）的核心区别：
//   - 无独立 control/data stream，所有帧复用同一 net.Conn。
//   - writeMu 串行化所有写（HELLO/AUTH/BATCH/PING/CLOSE/PONG），替代 v1 的 controlMu + picker。
type Client struct {
	config     ClientConfig
	conn       net.Conn // 单 TCP（TLCP）连接
	sm         *core.StateMachine
	negotiated *core.NegotiateResult
	keys       *core.SessionKeys
	seq        *core.SeqGenerator
	inflight   *core.Inflight
	window     *core.Window
	throttle   *core.ThrottleState
	sessionID  string

	challengeNonce string    // server challenge from HELLO_ACK
	expiresAt      time.Time // 会话过期时间，从 AUTH_OK 的 expires_at_unix 获取

	// writeMu 串行化单连接上的所有写帧操作（HELLO/AUTH/BATCH/PING/PONG/CLOSE），
	// 替代 v1 的 controlMu（仅保护 controlStr）+ StreamPicker（多流并发）。
	writeMu sync.Mutex

	// sendMu 保护「window 检查 + 取 seq/chunkID + inflight/pending 登记」这一小段，
	// 保证并发调用不会同时通过窗口后超限。重的 CPU 工作（marshal、Build、网络写）在锁外。
	sendMu sync.Mutex

	// pendingAcks tracks chunk_id -> batch info for ACK correlation.
	pendingAcks  sync.Map     // chunkID -> pendingBatch
	pendingCount atomic.Int64 // 与 pendingAcks 同步增减，notifyDrainIfEmpty 用它免 Range 扫描

	// ackHandler is called when an ACK is received from the server.
	// The handler receives the chunkID and ack_mode (e.g. "durable", "accepted").
	ackHandler atomic.Pointer[func(chunkID, ackMode string)]

	ackTimeout        time.Duration // max time to wait for ACK (default 5 min)
	heartbeatInterval time.Duration // PING 发送间隔（从 HELLO_ACK 获取，默认 30s）

	// lifecycleCtx drives all background goroutines (readControlLoop, ackReaper,
	// heartbeatLoop). 独立于 Connect 调用方的 ctx，避免 WithTimeout + defer cancel
	// 误停后台 goroutine；client 生命周期由 Close() 终结。
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	// ackDone/reaperDone/heartbeatDone 在对应 goroutine 退出时关闭，
	// Close() 等待它们以确保无 goroutine 跨越 Close 存活。
	ackDone       chan struct{}
	reaperDone    chan struct{}
	heartbeatDone chan struct{}

	// ackQueue 串行化用户 ACK/NACK 回调到一个 worker，慢回调不会头阻 readControlLoop。
	// dispatchACK 非阻塞；队列满时丢弃回调（ackReaper 仍会回收 inflight）。
	ackQueue      chan ackTask
	ackWorkerDone chan struct{}

	drainCh   chan struct{} // drain 时 pendingAcks 归零时通知
	closeOnce sync.Once     // 使 Close 幂等
	connErr   error         // closeOnce.Do 内捕获，作为 Close() 返回值
}

// pendingBatch 记录一个待 ACK 的 batch 元信息。
type pendingBatch struct {
	Seq      uint64
	Events   int
	Bytes    int64
	SentAt   time.Time
	Deadline time.Time // 此 batch 若无 ACK 的超时时刻
}

// ackTask 是排队等待执行的用户 ACK/NACK 回调。
type ackTask struct {
	chunkID string
	mode    string
}

// ackQueueSize 限定 ACK 回调队列容量。满时 dispatchACK 丢弃回调（记录日志）
// 而非阻塞 control loop。
const ackQueueSize = 1024

// NewClient 创建一个 MBTA-NTLS 客户端。
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Server == "" {
		return nil, core.NewError(core.NumCredential, core.CodeCredential, "server address required")
	}
	c := &Client{
		config:     cfg,
		sm:         core.NewStateMachine(),
		seq:        core.NewSeqGenerator(),
		inflight:   &core.Inflight{},
		window:     core.NewWindow(100, 10000, 16*1024*1024),
		throttle:   &core.ThrottleState{},
		ackTimeout: 5 * time.Minute,
		drainCh:    make(chan struct{}, 1),
	}
	return c, nil
}

// Connect 拨号并完成 HELLO/AUTH 握手。
//
// ctx 仅控制握手阶段（Dial、HELLO/AUTH）的超时与取消——可用 context.WithTimeout
// 限定握手时长。握手成功后，client 的后台 goroutine 运行在独立的 lifecycle ctx 上，
// 不随 ctx 取消而退出；client 生命周期由 Close() 终结。
//
// ntls 与 v1 区别：单 TCP 连接，无 OpenControlStream/OpenDataStream。
func (c *Client) Connect(ctx context.Context) error {
	// Dial TLCP over TCP.
	if err := c.sm.Transition(core.StateConnecting); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to CONNECTING", err)
	}

	conn, err := Dial(ctx, &c.config)
	if err != nil {
		return core.WrapError(core.NumTransport, core.CodeTransport, "dial", err)
	}
	c.conn = conn

	// ntls 单 TCP 连接：无独立 control stream 需要打开，但状态机仍要求
	// Connecting -> ControlStreamOpen -> HelloSent 的路径（见 core session transitions）。
	if err := c.sm.Transition(core.StateControlStreamOpen); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to CONTROL_STREAM_OPEN", err)
	}

	// Send HELLO
	if err := c.sendHello(); err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "hello", err)
	}

	// Receive HELLO_ACK
	helloAck, err := c.recvHelloAck()
	if err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "hello_ack", err)
	}

	c.sessionID = helloAck.SessionID
	if err := c.sm.Transition(core.StateHelloAcked); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to HELLO_ACKED", err)
	}

	// Update window from HELLO_ACK
	c.window.Update(
		helloAck.InitialWindow.MaxInflightBatches,
		helloAck.InitialWindow.MaxInflightEvents,
		helloAck.InitialWindow.MaxInflightBytes,
	)

	// Store heartbeat interval from server
	if helloAck.HeartbeatIntervalSec > 0 {
		c.heartbeatInterval = time.Duration(helloAck.HeartbeatIntervalSec) * time.Second
	} else {
		c.heartbeatInterval = 30 * time.Second
	}

	// Send AUTH
	if err := c.sendAuth(); err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "auth", err)
	}

	// Receive AUTH_OK/FAIL
	if err := c.recvAuthResult(); err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "auth_result", err)
	}

	// lifecycleCtx 独立于 caller ctx，避免 WithTimeout+defer cancel 级联停掉后台 goroutine。
	c.lifecycleCtx, c.lifecycleCancel = context.WithCancel(context.Background())
	c.ackDone = make(chan struct{})
	c.reaperDone = make(chan struct{})
	c.heartbeatDone = make(chan struct{})
	c.ackQueue = make(chan ackTask, ackQueueSize)
	c.ackWorkerDone = make(chan struct{})

	// readControlLoop 处理 ACK/NACK/window/throttle；每个 goroutine 退出时关闭 done channel。
	go func() { defer close(c.ackDone); c.readControlLoop(c.lifecycleCtx) }()
	go func() { defer close(c.reaperDone); c.ackReaper(c.lifecycleCtx) }()
	go func() { defer close(c.heartbeatDone); c.heartbeatLoop(c.lifecycleCtx) }()
	// runACKWorker 消费 ackQueue，使慢回调不阻塞 control loop。
	go func() { defer close(c.ackWorkerDone); c.runACKWorker(c.lifecycleCtx) }()

	// ntls 无 openDataStreams：所有 batch 帧直接通过 c.writeFrame 写入同一连接。

	slog.Info("MBTA-NTLS client connected", "agent", c.config.AgentID, "session", c.sessionID)
	return nil
}

// writeFrame 在 writeMu 保护下向单 TCP 连接写一帧。
// ntls 中所有写（HELLO/AUTH/BATCH/PING/PONG/CLOSE）都走此函数，保证帧级原子性。
func (c *Client) writeFrame(typ uint16, flags byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return core.Write(c.conn, typ, flags, payload)
}

// SendBatch 通过 MBTA-NTLS 协议发送一个 SignalBatch。
// 返回分配给该 batch 的 chunkID（用于 ACK 关联），或错误。
//
// 锁粒度：sendMu 仅保护「window 检查 + 取 seq/chunkID + inflight/pending 登记」，
// 重的 CPU 工作（marshal、gzip+HMAC Build、网络写）全部在锁外，使多调用方可并行利用多核。
func (c *Client) SendBatch(ctx context.Context, signalBatch *core.SignalBatch, tag, source string) (string, error) {
	if signalBatch == nil {
		return "", core.NewError(core.NumBatch, core.CodeBatch, "batch must not be nil")
	}

	// --- 锁外：无状态前置检查 + marshal SignalBatch（CPU 密集，可并行）---
	if c.sm.State() != core.StateReady {
		return "", fmt.Errorf("%w, state=%s", ErrNotReady, c.sm.State())
	}
	if c.throttle.Active() {
		return "", fmt.Errorf("%w, retry after %v", ErrThrottled, c.throttle.WaitDuration())
	}

	batchJSON, err := core.FastMarshal(signalBatch)
	if err != nil {
		return "", core.WrapError(core.NumBatch, core.CodeBatch, "marshal signal batch", err)
	}
	batchEvents := len(signalBatch.Signals)

	// --- 锁内：取 seq/chunkID、构造 batch wrapper、窗口检查、inflight/pending 登记 ---
	seq, chunkID, batchPayload, err := c.reserveInflight(tag, source, batchJSON, batchEvents)
	if err != nil {
		return "", err
	}
	batchBytes := int64(len(batchPayload))

	// --- 锁外：Build envelope（gzip+HMAC）+ marshal env + 网络写 ---
	if writeErr := c.buildAndSend(seq, chunkID, tag, source, batchPayload); writeErr != nil {
		// 写失败：回滚已登记的 inflight/pending，避免窗口被永久占用。
		c.inflight.Remove(batchEvents, batchBytes)
		if _, ok := c.pendingAcks.LoadAndDelete(chunkID); ok {
			c.pendingCount.Add(-1)
		}
		return "", writeErr
	}

	slog.Debug("batch sent", "seq", seq, "chunk", chunkID, "events", batchEvents)
	return chunkID, nil
}

// reserveInflight 在 sendMu 保护下原子完成：取 seq/chunkID、构造 batch wrapper
// （手写，避免 json.Marshal 对 RawMessage 的 compact 扫描）、窗口检查、inflight 与 pending 登记。
// 返回 seq、chunkID 与构造好的 batchPayload（供 buildAndSend 直接 Build，避免重复 marshal）。
func (c *Client) reserveInflight(tag, source string, batchJSON []byte, batchEvents int) (uint64, string, []byte, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	seq := c.seq.Next()
	chunkID := uuid.Must(uuid.NewV7()).String()

	batchPayload := buildBatchPayload(seq, chunkID, tag, source, batchEvents, batchJSON)
	batchBytes := int64(len(batchPayload))

	// 窗口检查与 inflight 登记同处一个临界区，防止并发调用双双通过后超限。
	if !c.window.CanSend(c.inflight, batchEvents, batchBytes) {
		return 0, "", nil, ErrWindowFull
	}
	c.inflight.Add(batchEvents, batchBytes)
	c.pendingAcks.Store(chunkID, &pendingBatch{
		Seq:      seq,
		Events:   batchEvents,
		Bytes:    batchBytes,
		SentAt:   time.Now(),
		Deadline: time.Now().Add(c.ackTimeout),
	})
	c.pendingCount.Add(1)

	return seq, chunkID, batchPayload, nil
}

// buildBatchPayload 手写 BatchMessage 的 JSON，避免 json.Marshal 对 RawMessage
// （整个 signalBatch JSON）做 O(n) compact 扫描。字段顺序与 json tag 一致，
// Tag/Source 的 omitempty 用空串判断，字符串字段用 strconv.AppendQuote 保证 escape
// 与 encoding/json 一致，server 端 json.Unmarshal 完全兼容。
// eventsCount 写入 events_count 字段，供服务端 RawEventSink 快速路径省去解码。
func buildBatchPayload(seq uint64, chunkID, tag, source string, eventsCount int, batchJSON []byte) []byte {
	buf := make([]byte, 0, 160+len(batchJSON))
	buf = append(buf, `{"seq":`...)
	buf = strconv.AppendUint(buf, seq, 10)
	buf = append(buf, `,"chunk_id":`...)
	buf = strconv.AppendQuote(buf, chunkID)
	if tag != "" {
		buf = append(buf, `,"tag":`...)
		buf = strconv.AppendQuote(buf, tag)
	}
	if source != "" {
		buf = append(buf, `,"source":`...)
		buf = strconv.AppendQuote(buf, source)
	}
	if eventsCount > 0 {
		buf = append(buf, `,"events_count":`...)
		buf = strconv.AppendInt(buf, int64(eventsCount), 10)
	}
	buf = append(buf, `,"batch":`...)
	buf = append(buf, batchJSON...)
	buf = append(buf, '}')
	return buf
}

// buildAndSend 在锁外完成 envelope 构建（gzip+HMAC）、envelope marshal 与网络写。
// batchPayload 由 reserveInflight 已构造（手写），此处直接 Build，不再重复 marshal。
//
// ntls 与 v1 区别：写 BATCH 帧走 c.writeFrame（单连接 + writeMu），
// 替代 v1 的 c.picker.Pick(batch) + core.Write(ds, ...)（多流分发）。
func (c *Client) buildAndSend(seq uint64, chunkID, tag, source string, batchPayload []byte) error {
	params := core.Params{
		SessionID:   c.sessionID,
		Seq:         seq,
		ChunkID:     chunkID,
		Codec:       "json",
		Compression: "none",
		Encryption:  "none",
		HMACAlgo:    "none",
	}
	if c.negotiated != nil {
		params.Codec = c.negotiated.Codec
		params.Compression = c.negotiated.Compression
		params.Encryption = c.negotiated.Encryption
		params.HMACAlgo = c.negotiated.HMACAlgo
	}
	if c.keys != nil {
		params.KeyID = c.keys.KeyID
		params.HMACKey = c.keys.HMACKey
		params.SM4Key = c.keys.SM4Key
	}

	env, err := core.Build(params, batchPayload)
	if err != nil {
		return core.WrapError(core.NumEnvelope, core.CodeEnvelope, "build envelope", err)
	}
	envPayload, err := core.FastMarshal(env)
	if err != nil {
		return core.WrapError(core.NumEnvelope, core.CodeEnvelope, "marshal envelope", err)
	}

	// ntls：单 TCP 连接，直接写 BATCH 帧（envelope + data 标志），无流分发。
	if err := c.writeFrame(core.TypeBatch, core.FlagEnvelope|core.FlagData, envPayload); err != nil {
		return core.WrapError(core.NumBatch, core.CodeBatch, "write batch", err)
	}
	return nil
}

// SetACKHandler 注册一个回调，在服务端确认（或拒绝）一个 batch 时被调用。
// handler 收到 (chunkID, ackMode)，ackMode 例如 "durable"、"accepted"、"nack"。
func (c *Client) SetACKHandler(h func(chunkID, ackMode string)) {
	c.ackHandler.Store(&h)
}

func (c *Client) loadACKHandler() func(chunkID, ackMode string) {
	if p := c.ackHandler.Load(); p != nil {
		return *p
	}
	return nil
}

// dispatchACK 把用户 ACK/NACK 回调排队，由 runACKWorker 异步执行。
// 永不阻塞：队列满会拖住 control loop，故丢弃回调并告警。仅回调丢失——
// pendingAcks/inflight 仍在 handleAck/handleNack 中同步更新，
// 未收到 ACK 的 batch 由 ackReaper 回收 inflight。
func (c *Client) dispatchACK(chunkID, mode string) {
	select {
	case c.ackQueue <- ackTask{chunkID: chunkID, mode: mode}:
	default:
		slog.Warn("ack callback queue full, dropping callback",
			"chunk", chunkID, "mode", mode)
	}
}

// runACKWorker 消费 ackTask 并在单个 goroutine 上调用注册的 handler，
// 保持 ACK 到达顺序（对可靠投递重要）。关闭时先排空队列，使已入队的回调仍被投递。
func (c *Client) runACKWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			// Best-effort drain: deliver already-enqueued callbacks before exit.
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

// invokeACKHandler 对一个 task 执行当前注册的 handler。每次都重新加载 handler，
// 使 SetACKHandler 的更新立即生效。
func (c *Client) invokeACKHandler(t ackTask) {
	if h := c.loadACKHandler(); h != nil {
		h(t.chunkID, t.mode)
	}
}

// Close 发送 CLOSE 帧、排空待 ACK 的 batch、关闭连接。
// 幂等：后续调用返回首次关闭的错误。
//
// 生命周期（旧实现提前取消所有 goroutine，会饿死 drain 循环——
// ACK 不再被处理，30s drain 超时必然触发）：
//  1. 后台 goroutine 仍存活时先发 CLOSE 帧。
//  2. 切换到 Draining，等待 pending ACK 归零
//     （readControlLoop + ackReaper 仍在运行，处理最后的 ACK）。
//  3. 取消 goroutine 并等待退出。
//  4. 清理状态并关闭连接。
func (c *Client) Close() error {
	c.closeOnce.Do(c.close)
	return c.connErr
}

// close 执行实际关闭。通过 closeOnce 仅运行一次。
//
// ntls 与 v1 区别：写 CLOSE 帧走 c.writeFrame（writeMu 保护单连接），
// 替代 v1 的 c.controlMu.Lock() + core.Write(c.controlStr, ...)。
// 连接关闭用 c.conn.Close()（net.Conn），替代 v1 的 c.conn.CloseWithError(0, ...)。
func (c *Client) close() {
	// 1. Send CLOSE frame before cancelling so the server learns we're done.
	if c.conn != nil {
		closeMsg := core.CloseMessage{Code: "shutdown", Reason: "client closing"}
		if payload, err := core.FastMarshal(closeMsg); err == nil {
			if err := c.writeFrame(core.TypeClose, core.FlagControl, payload); err != nil {
				slog.Warn("write close frame", "error", err)
			}
		}
	}

	// 2. Transition to Draining state.
	if err := c.sm.Transition(core.StateDraining); err != nil {
		slog.Debug("drain transition skipped", "error", err)
	}

	// 3. Wait for drain. readControlLoop is still running, so handleAck keeps
	// firing notifyDrainIfEmpty → drainCh signals as pendingAcks hits zero.
	// If the timeout fires first (no ACK for some batch), force-close.
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

	// 4. Cancel all background goroutines.
	if c.lifecycleCancel != nil {
		c.lifecycleCancel()
	}
	// Close the connection first so a readControlLoop blocked in core.Read
	// unblocks (the read errors out) and can observe the cancellation.
	if c.conn != nil {
		c.connErr = c.conn.Close()
	}
	// 5. Wait for goroutines to actually exit (bounded — see waitGoroutines).
	c.waitGoroutines()

	// 6. Clear pending ACKs to release references.
	c.pendingAcks.Range(func(key, _ any) bool {
		c.pendingAcks.Delete(key)
		return true
	})
	c.pendingCount.Store(0) // 此刻 readControlLoop/ackReaper 已退出，无并发

	// 7. Acquire sendMu so the field clearing below cannot race a concurrent
	// SendBatch. A SendBatch that already passed its StateReady check may
	// still be reading c.keys under sendMu; once we hold the lock it has
	// finished, and since the state machine is past Ready any later
	// SendBatch returns ErrNotReady before touching these fields.
	c.sendMu.Lock()
	// Reset inflight counters so stale state does not block future sends.
	c.inflight.Reset()

	// Clear sensitive material from memory.
	c.config.Token = ""
	if c.keys != nil {
		for i := range c.keys.HMACKey {
			c.keys.HMACKey[i] = 0
		}
		for i := range c.keys.SM4Key {
			c.keys.SM4Key[i] = 0
		}
		c.keys = nil
	}
	c.sendMu.Unlock()
}

// waitGoroutines 阻塞直到所有后台 goroutine 退出或等待超时。
// 超时为 Close 设上限，防止某个 goroutine 卡在不可中断的读取上无限挂起。
func (c *Client) waitGoroutines() {
	const waitTimeout = 5 * time.Second
	deadline := time.NewTimer(waitTimeout)
	defer deadline.Stop()
	for _, done := range []chan struct{}{c.ackDone, c.reaperDone, c.heartbeatDone, c.ackWorkerDone} {
		if done == nil {
			continue
		}
		select {
		case <-done:
		case <-deadline.C:
			slog.Warn("background goroutine did not exit within timeout",
				"timeout", waitTimeout)
			return
		}
	}
}

// countPendingAcks 返回等待 ACK 的 batch 数。仅用于 drain 超时日志诊断。
func (c *Client) countPendingAcks() int {
	n := 0
	c.pendingAcks.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// SessionID 返回当前会话 ID。
func (c *Client) SessionID() string {
	return c.sessionID
}

// State 返回当前 client 状态。
func (c *Client) State() core.State {
	return c.sm.State()
}

// ackReaper 周期性扫描 pendingAcks，移除已超时的条目，回收的 inflight 槽位允许发送新 batch。
func (c *Client) ackReaper(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
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
				if !pb.Deadline.IsZero() && now.After(pb.Deadline) {
					c.pendingAcks.Delete(key)
					c.pendingCount.Add(-1)
					c.inflight.Remove(pb.Events, pb.Bytes)
					slog.Warn("reaped expired pending ACK",
						"chunk", key,
						"seq", pb.Seq,
						"age", now.Sub(pb.SentAt).Round(time.Second))
				}
				return true
			})
			c.notifyDrainIfEmpty()
		}
	}
}

// notifyDrainIfEmpty 当无 pending ACK 时通知 drain channel。
// 读 pendingCount 原子值判断空，免去每次 ACK/NACK 的 sync.Map.Range 扫描。
func (c *Client) notifyDrainIfEmpty() {
	if c.pendingCount.Load() == 0 {
		select {
		case c.drainCh <- struct{}{}:
		default: // already signaled, no need to block
		}
	}
}

// heartbeatLoop 周期性发送 PING 帧保活。
// 间隔在 HELLO_ACK 中与服务端协商（默认 30s）。
//
// ntls 写 PING 走 c.writeFrame（writeMu 保护），替代 v1 的 controlMu + controlStr。
func (c *Client) heartbeatLoop(ctx context.Context) {
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
			ping := core.PingMessage{
				TimeUnixMs: time.Now().UnixMilli(),
				Nonce:      uuid.Must(uuid.NewV7()).String(),
			}
			payload, err := core.FastMarshal(ping)
			if err != nil {
				slog.Debug("marshal ping failed", "error", err)
				continue
			}
			if err := c.writeFrame(core.TypePing, core.FlagControl, payload); err != nil {
				slog.Warn("write ping failed", "error", err)
				return
			}
		}
	}
}
