package v1

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/quic-go/quic-go"
)

// ClientConfig holds configuration for an MBTA client.
type ClientConfig struct {
	Transport    QUICClientConfig // QUIC connection settings
	AgentID      string           // unique agent identifier
	Hostname     string           // agent hostname (sent in HELLO)
	Token        string           // authentication token
	Capabilities []string         // negotiated capabilities (e.g. gzip, hmac-sha256)
	PickStrategy string           // stream selection strategy: "single" or "hash"
	StreamCount  int              // hash 模式下打开的数据流数量（<=0 用 defaultStreamCount）
}

// Client is an MBTA agent that connects to a server and sends event batches.
//
// 可靠投递语义：Client 仅在内存追踪已发送未 ACK 的 batch（pendingAcks/inflight）。
// 进程崩溃/重连后未 ACK 的 batch 会丢失——持久化与重发由调用方负责。这与
// 协议库的分层一致（协议只保证 ACK 语义，agent 自管持久化）。
type Client struct {
	config     ClientConfig
	conn       *Conn
	sm         *core.StateMachine
	negotiated *core.NegotiateResult
	keys       *core.SessionKeys
	seq        *core.SeqGenerator
	inflight   *core.Inflight
	window     *core.Window
	throttle   *core.ThrottleState
	picker     StreamPicker
	controlStr *quic.Stream
	controlMu  sync.Mutex // protects concurrent writes to controlStr
	sessionID  []byte
	challengeNonce []byte    // server challenge from HELLO_ACK
	expiresAt      time.Time // 会话过期时间，从 AUTH_OK 的 expires_at_unix 获取

	// sendMu serializes SendBatch calls so that the throttle/window check
	// and the actual write happen atomically. Without this lock, concurrent
	// callers can both pass the window check and exceed inflight limits.
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
	// heartbeatLoop). It is derived from the Connect caller's context so
	// goroutines exit on caller cancellation OR explicit Close().
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	// ackDone/reaperDone/heartbeatDone are closed when the corresponding
	// goroutine exits. Close() waits on them so no goroutine outlives Close.
	ackDone       chan struct{}
	reaperDone    chan struct{}
	heartbeatDone chan struct{}

	// ackQueue serializes user ACK/NACK callbacks onto a single worker so a
	// slow handler cannot head-of-line block readControlLoop. dispatchACK is
	// non-blocking; on a full queue the callback is dropped (the ackReaper
	// still reclaims inflight for unacked batches).
	ackQueue      chan ackTask
	ackWorkerDone chan struct{}

	drainCh   chan struct{} // signaled when pendingAcks reaches 0 during drain
	closeOnce sync.Once     // makes Close idempotent
	connErr   error         // captured inside closeOnce.Do for return
}

type pendingBatch struct {
	Seq      uint64
	Events   int
	Bytes    int64
	SentAt   time.Time
	Deadline time.Time // when this batch expires if no ACK received
}

// ackTask is a queued user ACK/NACK callback invocation.
type ackTask struct {
	chunkID string
	mode    string
}

// ackQueueSize bounds the ACK callback backlog. When full, dispatchACK drops
// the callback (logged) rather than blocking the control loop.
const ackQueueSize = 1024

// defaultStreamCount 是 hash 模式下默认打开的数据流数量。
// 取值小于服务端 MaxIncomingStreams(256)，开启多流以绕过单流的队头阻塞、
// 并行利用多核做加密/压缩，提升吞吐。
const defaultStreamCount = 4

// quicStreamWrapper adapts *quic.Stream to the DataStream interface.
//
// mu 串行化 SetWriteDeadline/Write/恢复 三步，使调用方 ctx 能安全绑定到写。
// SetWriteDeadline 是 per-quic.Stream 的，若无 mu，同一 stream 上多个并发发送者
// 会互相覆盖对方的 deadline。quic.Stream.Write 内部已按流串行（单流一发送缓冲 + 流控），
// 故本 mu 不引入 QUIC 之外的串行点，几乎零损耗。
type quicStreamWrapper struct {
	stream *quic.Stream
	idx    int
	mu     sync.Mutex
}

func (w *quicStreamWrapper) Index() int                  { return w.idx }
func (w *quicStreamWrapper) Write(p []byte) (int, error) { return w.stream.Write(p) }

// writeFrameCtx 写一帧并受调用方 ctx 约束（与 ntls.writeFrameCtx 同构）。
// 锁内按 ctx.Deadline 设 SetWriteDeadline，写完恢复（time.Time{}）。
// 语义：ctx 已取消进入即返回；带 Deadline 超时让 Write 失败；仅 WithCancel 无 deadline 不中断阻塞写。
// 超时写失败可能留下半帧，调用方收到错误后应视为连接损坏（Close 重连）。
func (w *quicStreamWrapper) writeFrameCtx(ctx context.Context, typ uint8, flags byte, channel uint8, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if dl, ok := ctx.Deadline(); ok {
		if err := w.stream.SetWriteDeadline(dl); err != nil {
			return core.WrapError(core.NumStream, core.CodeStream, "set write deadline", err)
		}
		defer func() { _ = w.stream.SetWriteDeadline(time.Time{}) }() // 恢复，避免影响后续无 ctx 的写
	}
	return core.Write(w, core.Version, typ, flags, channel, payload)
}

// NewClient creates a new MBTA client.
func NewClient(cfg ClientConfig) (*Client, error) {
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

// Connect dials the server and completes the HELLO/AUTH handshake.
//
// ctx 仅用于控制握手阶段（Dial、开 stream、HELLO/AUTH）的超时与取消——可用
// context.WithTimeout 限定握手时长。握手成功后，client 的后台 goroutine 运行在
// 独立的 lifecycle ctx 上，不随 ctx 取消而退出；client 生命周期由 Close() 终结。
// 因此用 WithTimeout + defer cancel 调用本方法是安全的，不会误停后台。
func (c *Client) Connect(ctx context.Context) error {
	// Dial QUIC
	if err := c.sm.Transition(core.StateConnecting); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to CONNECTING", err)
	}

	conn, err := Dial(ctx, c.config.Transport)
	if err != nil {
		return core.WrapError(core.NumTransport, core.CodeTransport, "dial", err)
	}
	c.conn = conn

	// Open control stream
	ctrlStr, err := conn.OpenControlStream(ctx)
	if err != nil {
		return core.WrapError(core.NumStream, core.CodeStream, "open control stream", err)
	}
	c.controlStr = ctrlStr
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

	c.sessionID = helloAck.GetSessionId()
	if err := c.sm.Transition(core.StateHelloAcked); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to HELLO_ACKED", err)
	}

	// Update window from HELLO_ACK
	if w := helloAck.GetInitialWindow(); w != nil {
		c.window.Update(int(w.GetMaxInflightBatches()), int(w.GetMaxInflightEvents()), w.GetMaxInflightBytes())
	}

	// Store heartbeat interval from server
	if helloAck.GetHeartbeatIntervalSec() > 0 {
		c.heartbeatInterval = time.Duration(helloAck.GetHeartbeatIntervalSec()) * time.Second
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

	// lifecycleCtx 驱动后台 goroutine（readControlLoop/ackReaper/heartbeat/ackWorker），
	// 独立于 caller ctx。caller 传入的 ctx 仅用于握手超时控制（Dial/OpenStream/HELLO/AUTH）；
	// 握手成功后 client 生命周期完全由 Close() 控制。
	//
	// 不派生自 ctx 是为了避免陷阱：若 caller 用 WithTimeout + defer cancel 调 Connect，
	// ctx 在 Connect 返回后立即取消，会级联停掉后台 goroutine，导致 ACK 无人读取。
	// 若需要「ctx 取消即停止 client」，调用方应自行监听 ctx 并调 Close()。
	c.lifecycleCtx, c.lifecycleCancel = context.WithCancel(context.Background())
	c.ackDone = make(chan struct{})
	c.reaperDone = make(chan struct{})
	c.heartbeatDone = make(chan struct{})
	c.ackQueue = make(chan ackTask, ackQueueSize)
	c.ackWorkerDone = make(chan struct{})

	// readControlLoop processes ACK/NACK/window/throttle frames. Each goroutine
	// closes its done channel on exit so Close() can wait.
	go func() { defer close(c.ackDone); c.readControlLoop(c.lifecycleCtx) }()
	go func() { defer close(c.reaperDone); c.ackReaper(c.lifecycleCtx) }()
	go func() { defer close(c.heartbeatDone); c.heartbeatLoop(c.lifecycleCtx) }()
	// runACKWorker drains ackQueue so user ACK callbacks run off the control
	// loop (M-3: a slow handler no longer blocks NACK/WINDOW/THROTTLE reads).
	go func() { defer close(c.ackWorkerDone); c.runACKWorker(c.lifecycleCtx) }()

	// Open data stream(s) per PickStrategy.
	if c.picker == nil {
		p, err := c.openDataStreams(ctx)
		if err != nil {
			return err
		}
		c.picker = p
	}

	slog.Info("MBTA client connected", "agent", c.config.AgentID, "session", c.sessionID)
	return nil
}

// openDataStreams 按 PickStrategy 打开数据流并构造 StreamPicker。
// "hash" 模式开启多条流并按 tag+source 一致哈希分发，绕过单流队头阻塞、并行利用
// 多核做加密/压缩；其余（含 "single" 与未设置）走单流。
func (c *Client) openDataStreams(ctx context.Context) (StreamPicker, error) {
	if c.config.PickStrategy == "hash" {
		picker := NewHashStreamPicker()
		n := c.config.StreamCount
		if n <= 0 {
			n = defaultStreamCount
		}
		opened := make([]*quic.Stream, 0, n)
		for i := 0; i < n; i++ {
			ds, err := c.conn.OpenDataStream(ctx)
			if err != nil {
				for _, s := range opened {
					_ = s.Close()
				}
				c.lifecycleCancel()
				c.waitGoroutines()
				return nil, core.WrapError(core.NumStream, core.CodeStream, "open data stream", err)
			}
			opened = append(opened, ds)
			picker.AddStream(&quicStreamWrapper{stream: ds, idx: i})
		}
		return picker, nil
	}

	ds, err := c.conn.OpenDataStream(ctx)
	if err != nil {
		// Cancel goroutines and wait for them to exit before returning,
		// otherwise they leak on a failed Connect.
		c.lifecycleCancel()
		c.waitGoroutines()
		return nil, core.WrapError(core.NumStream, core.CodeStream, "open data stream", err)
	}
	return NewSingleStream(&quicStreamWrapper{stream: ds, idx: 0}), nil
}

// SendBatch sends a SignalBatch through the MBTA protocol.
// Returns the chunkID assigned to this batch for ACK correlation, or an error.
//
// ctx 约束网络写：BATCH 写经 quicStreamWrapper 的 per-stream mu 安全绑定 SetWriteDeadline，
// 对端卡死时调用方超时能及时收到写错误。ctx 已取消则进入即返回。
// 注意：超时导致的写失败可能留下半帧、破坏对端帧同步，调用方收到错误后应 Close() 并重连。
// 仅 WithCancel（无 deadline）的 ctx 不会中断阻塞写。
//
// 锁粒度（P2）：sendMu 仅保护「window 检查 + 取 seq/chunkID + inflight/pending 登记」
// 这一小段，保证并发调用不会同时通过窗口后超限。重的 CPU 工作（marshal signalBatch、
// gzip+HMAC 的 Build、网络写）全部在锁外，使多调用方可跨 batch 并行利用多核。
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

	// --- 锁外：Build envelope（gzip+HMAC）+ marshal env + 选流 + 网络写 ---
	if writeErr := c.buildAndSend(ctx, seq, chunkID, tag, source, batchPayload); writeErr != nil {
		// 写失败：回滚 inflight/pending。未 ACK 的 batch 由调用方自行重发（agent 自管持久化）。
		c.inflight.Remove(batchEvents, batchBytes)
		if _, ok := c.pendingAcks.LoadAndDelete(chunkID.String()); ok {
			c.pendingCount.Add(-1)
		}
		return "", writeErr
	}

	slog.Debug("batch sent", "seq", seq, "chunk", chunkID.String(), "events", batchEvents)
	return chunkID.String(), nil
}

// reserveInflight 在 sendMu 保护下原子完成：取 seq/chunkID、构造 batch wrapper
// （手写，避免 json.Marshal 对 RawMessage 的 compact 扫描）、窗口检查、inflight 与 pending 登记。
// 返回 seq、chunkID 与构造好的 batchPayload（供 buildAndSend 直接 Build，避免重复 marshal）。
func (c *Client) reserveInflight(tag, source string, batchJSON []byte, batchEvents int) (uint64, core.ChunkID, []byte, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	seq := c.seq.Next()
	chunkID := core.NewChunkID()

	// r2：BatchMessage 用 corepb proto 编码（替代手写 JSON）。
	batchMsg := &corepb.BatchMessage{Seq: seq, ChunkId: chunkID.Bytes(), Tag: tag, Source: source}
	if batchEvents > 0 {
		batchMsg.EventsCount = int32(batchEvents)
	}
	batchMsg.Batch = batchJSON // SignalBatch proto 编码字节
	batchPayload, err := core.Encode(batchMsg)
	if err != nil {
		return 0, core.ChunkID{}, nil, core.WrapError(core.NumBatch, core.CodeBatch, "encode batch message", err)
	}
	batchBytes := int64(len(batchPayload))

	if !c.window.CanSend(c.inflight, batchEvents, batchBytes) {
		return 0, core.ChunkID{}, nil, ErrWindowFull
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

// buildAndSend 在锁外完成 envelope 构建（gzip+HMAC）、envelope marshal、流选择与网络写。
// batchPayload 由 reserveInflight 已构造（手写），此处直接 Build，不再重复 marshal。
func (c *Client) buildAndSend(ctx context.Context, seq uint64, chunkID core.ChunkID, tag, source string, batchPayload []byte) error {
	cs := corepb.CipherSuite_CIPHER_SUITE_INTL
	codec := corepb.Codec_CODEC_JSON
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
		return core.WrapError(core.NumEnvelope, core.CodeEnvelope, "build envelope", err)
	}
	envPayload, err := core.Encode(env)
	if err != nil {
		return core.WrapError(core.NumEnvelope, core.CodeEnvelope, "encode envelope", err)
	}

	ds, err := c.picker.Pick(tag, source)
	if err != nil {
		return core.WrapError(core.NumBatch, core.CodeBatch, "pick stream", err)
	}

	// ctx 约束网络写：quicStreamWrapper 经 per-stream mu 安全绑定 SetWriteDeadline。
	if w, ok := ds.(*quicStreamWrapper); ok {
		if err := w.writeFrameCtx(ctx, core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload); err != nil {
			return core.WrapError(core.NumBatch, core.CodeBatch, "write batch", err)
		}
		return nil
	}
	if err := core.Write(ds, core.Version, core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload); err != nil {
		return core.WrapError(core.NumBatch, core.CodeBatch, "write batch", err)
	}
	return nil
}

// SetACKHandler registers a callback invoked when the server acknowledges a batch.
// The handler receives (chunkID, ackMode) where ackMode is "durable", "accepted", etc.
func (c *Client) SetACKHandler(h func(chunkID, ackMode string)) {
	c.ackHandler.Store(&h)
}

func (c *Client) loadACKHandler() func(chunkID, ackMode string) {
	if p := c.ackHandler.Load(); p != nil {
		return *p
	}
	return nil
}

// dispatchACK enqueues a user ACK/NACK callback for asynchronous execution by
// runACKWorker. It never blocks: a full queue would stall the control loop, so
// the callback is dropped with a warning instead. Only the callback
// notification is lost — pendingAcks/inflight are still updated synchronously
// in handleAck/handleNack, and the ackReaper reclaims inflight for any batch
// that never gets acknowledged.
func (c *Client) dispatchACK(chunkID, mode string) {
	select {
	case c.ackQueue <- ackTask{chunkID: chunkID, mode: mode}:
	default:
		slog.Warn("ack callback queue full, dropping callback",
			"chunk", chunkID, "mode", mode)
	}
}

// runACKWorker consumes ackTask values and invokes the registered handler on a
// single goroutine, preserving ACK arrival order (important for reliable
// delivery). On shutdown it drains the queue first so already-enqueued
// callbacks are still delivered.
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

// invokeACKHandler runs the currently-registered handler for one task. The
// handler is loaded fresh each time so a SetACKHandler update takes effect
// immediately.
func (c *Client) invokeACKHandler(t ackTask) {
	if h := c.loadACKHandler(); h != nil {
		h(t.chunkID, t.mode)
	}
}

// Close sends a CLOSE frame, drains pending ACKs, and shuts down.
// It is idempotent: subsequent calls return the error from the first close.
//
// Lifecycle (the previous implementation cancelled all goroutines up front,
// which starved the drain loop — ACKs could no longer be processed so the
// 30s drain timeout always fired):
//  1. Send CLOSE frame while goroutines are still alive.
//  2. Transition to Draining and wait for pending ACKs to reach zero
//     (readControlLoop + ackReaper remain running to process final ACKs).
//  3. Cancel goroutines and wait for them to exit.
//  4. Clear state and close the connection.
func (c *Client) Close() error {
	c.closeOnce.Do(c.close)
	return c.connErr
}

// close performs the actual shutdown. Runs exactly once via closeOnce.
func (c *Client) close() {
	// 1. Send CLOSE frame before cancelling so the server learns we're done.
	if c.controlStr != nil {
		c.controlMu.Lock()
		closeMsg := &corepb.CloseMessage{Code: "shutdown", Reason: "client closing"}
		if payload, err := core.Encode(closeMsg); err == nil {
			if err := core.Write(c.controlStr, core.Version, core.TypeClose, core.FlagControl, core.ChannelControl, payload); err != nil {
				slog.Warn("write close frame", "error", err)
			}
		}
		c.controlMu.Unlock()
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
	// unblocks (the stream errors out) and can observe the cancellation.
	if c.conn != nil {
		c.connErr = c.conn.CloseWithError(0, "client shutdown")
	}
	// 5. Wait for goroutines to actually exit (bounded — see waitGoroutines).
	c.waitGoroutines()

	// 6. Clear pending ACKs to release references.
	c.pendingAcks.Range(func(key, _ any) bool {
		c.pendingAcks.Delete(key)
		return true
	})
	c.pendingCount.Store(0) // 此刻 readControlLoop/ackReaper 已退出，无并发

	// 6. Acquire sendMu so the field clearing below cannot race a concurrent
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
		for i := range c.keys.AEADKey {
			c.keys.AEADKey[i] = 0
		}
		c.keys = nil
	}
	c.sendMu.Unlock()
}

// waitGoroutines blocks until all background goroutines exit or the wait
// timeout elapses. The timeout bounds Close so a goroutine stuck in an
// uninterruptible read cannot hang shutdown indefinitely.
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

// countPendingAcks returns the number of batches awaiting ACK. Used only for
// diagnostics in drain timeout logging.
func (c *Client) countPendingAcks() int {
	n := 0
	c.pendingAcks.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// SessionID returns the current session ID.
func (c *Client) SessionID() string {
	return string(c.sessionID)
}

// State returns the current client state.
func (c *Client) State() core.State {
	return c.sm.State()
}

// ackReaper periodically scans pendingAcks and removes entries that have exceeded
// their deadline. Reclaimed inflight slots allow new batches to be sent.
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

// notifyDrainIfEmpty signals the drain channel when no pending ACKs remain.
// 读 pendingCount 原子值判断空，免去每次 ACK/NACK 的 sync.Map.Range 扫描。
func (c *Client) notifyDrainIfEmpty() {
	if c.pendingCount.Load() == 0 {
		select {
		case c.drainCh <- struct{}{}:
		default: // already signaled, no need to block
		}
	}
}

// heartbeatLoop periodically sends PING frames to keep the connection alive.
// The interval is negotiated with the server in HELLO_ACK (default 30s).
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
			ping := &corepb.PingMessage{
				TimeUnixMs: time.Now().UnixMilli(),
				Nonce:      core.NewChunkID().String(),
			}
			payload, err := core.Encode(ping)
			if err != nil {
				slog.Debug("marshal ping failed", "error", err)
				continue
			}
			c.controlMu.Lock()
			if err := core.Write(c.controlStr, core.Version, core.TypePing, core.FlagControl, core.ChannelControl, payload); err != nil {
				c.controlMu.Unlock()
				slog.Warn("write ping failed", "error", err)
				return
			}
			c.controlMu.Unlock()
		}
	}
}
