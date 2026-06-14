package v1

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/spool"
	"github.com/quic-go/quic-go"
)

// ClientConfig holds configuration for an MBTA client.
type ClientConfig struct {
	Transport    QUICClientConfig // QUIC connection settings
	AgentID      string           // unique agent identifier
	Hostname     string           // agent hostname (sent in HELLO)
	Token        string           // authentication token
	Capabilities []string         // negotiated capabilities (e.g. gzip, hmac-sha256)
	SpoolDir     string           // directory for durable event spooling (empty disables spool)
	PickStrategy string           // stream selection strategy: "single" or "hash"
	StreamCount  int              // hash 模式下打开的数据流数量（<=0 用 defaultStreamCount）
}

// Client is an MBTA agent that connects to a server and sends event batches.
type Client struct {
	config         ClientConfig
	conn           *Conn
	sm             *core.StateMachine
	negotiated     *core.NegotiateResult
	keys           *core.SessionKeys
	spool          *spool.Spool
	seq            *core.SeqGenerator
	inflight       *core.Inflight
	window         *core.Window
	throttle       *core.ThrottleState
	picker         StreamPicker
	controlStr     *quic.Stream
	controlMu      sync.Mutex // protects concurrent writes to controlStr
	sessionID      string
	challengeNonce string    // server challenge from HELLO_ACK
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
	RecordIDs    []string // spool 删除用；无 spool 时为空
	SpoolChunkID string   // spool key；全新发送==wire chunkID，重发==原 spool key
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
type quicStreamWrapper struct {
	stream *quic.Stream
	idx    int
}

func (w *quicStreamWrapper) Index() int                  { return w.idx }
func (w *quicStreamWrapper) Write(p []byte) (int, error) { return w.stream.Write(p) }

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

	if cfg.SpoolDir != "" {
		s, err := spool.New(cfg.SpoolDir)
		if err != nil {
			return nil, core.WrapError(core.NumSpool, core.CodeSpool, "open spool", err)
		}
		c.spool = s
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

	// 重连/崩溃恢复：重发 spool 中所有未 ACK 的 batch。置于 background goroutine
	// 启动之后，使重发产生的 ACK 能被 readControlLoop 处理。
	c.drainSpoolAfterConnect(ctx)

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
// ctx 当前为保留参数（尚未约束网络写）。QUIC 的网络写在 quic.Stream 上阻塞，
// 若要按调用方 ctx 中断需用 SetWriteDeadline，但该 deadline 是 per-stream 的——
// PickStrategy="single" 下多个发送者写同一 stream 会互相覆盖 deadline，存在并发问题；
// "hash"/多流策略下写者分流到不同 stream，理论上可安全绑定（待实现）。
// 因此 v1 暂不绑定 ctx，调用方若需超时应自行管理连接级生命周期。
// （对比：ntls 单连接写由 writeMu 串行，已实现 ctx→deadline 绑定，见 ntls.writeFrameCtx。）
//
// 锁粒度（P2）：sendMu 仅保护「window 检查 + 取 seq/chunkID + inflight/pending 登记」
// 这一小段，保证并发调用不会同时通过窗口后超限。重的 CPU 工作（marshal signalBatch、
// gzip+HMAC 的 Build、网络写）全部在锁外，使多调用方可跨 batch 并行利用多核。
func (c *Client) SendBatch(ctx context.Context, signalBatch *core.SignalBatch, tag, source string) (string, error) {
	return c.sendTracked(ctx, signalBatch, tag, source, nil, nil)
}

// sendTracked 发送一个 batch 并按需持久化到 spool，是 SendBatch 与重连重发的共用底层路径。
//
// alreadySpooledChunkID == nil：全新发送——为每个 event 生成 Record，PutBatch 持久化（buffered
// 模式仅 map 写无 I/O），pendingBatch.SpoolChunkID == wire chunkID，ACK 时删除该条目。
// alreadySpooledChunkID != nil：重发——跳过 PutBatch（数据已在 spool，避免双重持久化），
// wire 用新 seq/chunkID（服务端 ReplayCache per-connection，跨重连不去重，必须用新 ID），
// pendingBatch.SpoolChunkID == 原 spool key、RecordIDs == retransmitRecordIDs（来自原 spool batch），
// ACK 时删原条目与 records。
//
// 持久化语义（at-least-once）：PutBatch 成功后即使 write 失败也保留 spool 条目，
// 由重连 drain 重发。PutBatch 失败（如 spool 满）则 abort，返回错误让调用方降速。
func (c *Client) sendTracked(ctx context.Context, signalBatch *core.SignalBatch, tag, source string, alreadySpooledChunkID *string, retransmitRecordIDs []string) (string, error) {
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

	// 全新发送：为每个 event 构造 spool Record（锁外，CPU 工作）。
	// 重发：recordIDs 来自原 spool batch（retransmitRecordIDs），用于 ACK 时删除 records。
	var records []spool.Record
	var recordIDs []string
	fresh := alreadySpooledChunkID == nil
	if c.spool != nil && fresh {
		records, recordIDs = buildRecords(c.config.AgentID, tag, source, signalBatch.Signals)
	} else if !fresh {
		recordIDs = retransmitRecordIDs
	}

	// --- 锁内：取 seq/chunkID、窗口检查、inflight/spool/pending 登记 ---
	seq, chunkID, batchPayload, err := c.reserveInflight(tag, source, batchJSON, batchEvents, records, recordIDs, alreadySpooledChunkID)
	if err != nil {
		return "", err
	}
	batchBytes := int64(len(batchPayload))

	// --- 锁外：Build envelope（gzip+HMAC）+ marshal env + 选流 + 网络写 ---
	if writeErr := c.buildAndSend(seq, chunkID, tag, source, batchPayload); writeErr != nil {
		// 写失败：回滚 inflight/pending，但保留 spool 条目（at-least-once，重连重发）。
		c.inflight.Remove(batchEvents, batchBytes)
		if _, ok := c.pendingAcks.LoadAndDelete(chunkID); ok {
			c.pendingCount.Add(-1)
		}
		return "", writeErr
	}

	slog.Debug("batch sent", "seq", seq, "chunk", chunkID, "events", batchEvents, "retransmit", !fresh)
	return chunkID, nil
}

// buildRecords 为一批 event 构造 spool Record 与对应 RecordID（每 event 一个 UUID v7）。
// Record.Event 指向原 SignalRecord（零拷贝）；重发时从 spool 取回 Event 重建 SignalBatch。
func buildRecords(agentID, tag, source string, signals []*core.SignalRecord) ([]spool.Record, []string) {
	records := make([]spool.Record, len(signals))
	ids := make([]string, len(signals))
	now := time.Now().UnixMilli()
	for i, sig := range signals {
		id := uuid.Must(uuid.NewV7()).String()
		ids[i] = id
		records[i] = spool.Record{
			RecordID:        id,
			AgentID:         agentID,
			Event:           sig,
			Tag:             tag,
			Source:          source,
			CreatedAtUnixMs: now,
		}
	}
	return records, ids
}

// deleteSpooled 删除已 ACK（或毒消息丢弃）的 batch 对应 spool 条目（batch + records）。
// 无 spool 或 SpoolChunkID 为空时无操作。删除失败仅 warn 不影响 ACK 流程——
// 残留条目下次重连 drain 时重发，服务端 ReplayCache 幂等吸收重复。
func (c *Client) deleteSpooled(pb *pendingBatch) {
	if c.spool == nil || pb.SpoolChunkID == "" {
		return
	}
	if err := c.spool.DeleteBatch(pb.SpoolChunkID); err != nil {
		slog.Warn("spool delete batch failed", "chunk", pb.SpoolChunkID, "error", err)
	}
	if err := c.spool.DeleteRecords(pb.RecordIDs); err != nil {
		slog.Warn("spool delete records failed", "error", err)
	}
}

// drainSpoolAfterConnect 在握手成功后重发所有未 ACK 的 spool batch（崩溃/重连恢复）。
// 按 Seq 升序重发以尽量保持原始发送顺序。重发走 sendTracked 的 alreadySpooledChunkID
// 分支：跳过 PutBatch（防双重持久化），wire 用新 seq/chunkID，pendingBatch.SpoolChunkID
// 指向原 spool key 以便 ACK 时删除原条目。单条失败不删 spool，下次重连再试。
func (c *Client) drainSpoolAfterConnect(ctx context.Context) {
	if c.spool == nil {
		return
	}
	batches := c.spool.PendingBatches()
	if len(batches) == 0 {
		return
	}
	sort.Slice(batches, func(i, j int) bool { return batches[i].Seq < batches[j].Seq })
	slog.Info("draining spooled batches after reconnect", "count", len(batches))
	for _, b := range batches {
		recs := c.spool.GetRecords(b.RecordIDs)
		if len(recs) == 0 {
			continue
		}
		sb := &core.SignalBatch{Signals: make([]*core.SignalRecord, len(recs))}
		var tag, source string
		for i, r := range recs {
			sb.Signals[i] = r.Event
			if i == 0 {
				tag, source = r.Tag, r.Source
			}
		}
		origChunkID := b.ChunkID
		if _, err := c.sendTracked(ctx, sb, tag, source, &origChunkID, b.RecordIDs); err != nil {
			slog.Warn("spool retransmit failed", "chunk", origChunkID, "error", err)
			continue
		}
		if err := c.spool.UpdateBatchAttempt(origChunkID); err != nil {
			slog.Warn("spool update attempt failed", "chunk", origChunkID, "error", err)
		}
	}
}

// reserveInflight 在 sendMu 保护下原子完成：取 seq/chunkID、构造 batch wrapper
// （手写，避免 json.Marshal 对 RawMessage 的 compact 扫描）、窗口检查、inflight 与 pending 登记。
// 返回 seq、chunkID 与构造好的 batchPayload（供 buildAndSend 直接 Build，避免重复 marshal）。
func (c *Client) reserveInflight(tag, source string, batchJSON []byte, batchEvents int, records []spool.Record, recordIDs []string, alreadySpooledChunkID *string) (uint64, string, []byte, error) {
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

	// spool 持久化（与 inflight/pending 同临界区，保证三者原子）。
	// buffered 模式 PutBatch 仅 map 写 + markDirty 无 I/O；同步模式有 I/O 但用户显式选强持久化。
	var spoolChunkID string
	if c.spool != nil {
		if alreadySpooledChunkID != nil {
			// 重发：跳过 PutBatch（已在 spool），ACK 时删原条目。
			spoolChunkID = *alreadySpooledChunkID
		} else {
			if err := c.spool.PutBatch(records, spool.Batch{
				Seq:             seq,
				ChunkID:         chunkID,
				RecordIDs:       recordIDs,
				CreatedAtUnixMs: time.Now().UnixMilli(),
			}); err != nil {
				// Put 失败（spool 满等）：回滚 inflight，无法承诺持久化 → abort。
				c.inflight.Remove(batchEvents, batchBytes)
				return 0, "", nil, core.WrapError(core.NumSpool, core.CodeSpool, "spool put batch", err)
			}
			spoolChunkID = chunkID
		}
	}

	c.pendingAcks.Store(chunkID, &pendingBatch{
		Seq:          seq,
		Events:       batchEvents,
		Bytes:        batchBytes,
		SentAt:       time.Now(),
		Deadline:     time.Now().Add(c.ackTimeout),
		RecordIDs:    recordIDs,
		SpoolChunkID: spoolChunkID,
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

// buildAndSend 在锁外完成 envelope 构建（gzip+HMAC）、envelope marshal、流选择与网络写。
// batchPayload 由 reserveInflight 已构造（手写），此处直接 Build，不再重复 marshal。
func (c *Client) buildAndSend(seq uint64, chunkID, tag, source string, batchPayload []byte) error {
	// batch 仅用于 picker.Pick 的 tag+source 哈希，不含 Batch RawMessage，不 marshal。
	batch := core.BatchMessage{
		Seq:     seq,
		ChunkID: chunkID,
		Tag:     tag,
		Source:  source,
	}

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

	ds, err := c.picker.Pick(batch)
	if err != nil {
		return core.WrapError(core.NumBatch, core.CodeBatch, "pick stream", err)
	}

	if err := core.Write(ds, core.TypeBatch, core.FlagEnvelope|core.FlagData, envPayload); err != nil {
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
		closeMsg := core.CloseMessage{Code: "shutdown", Reason: "client closing"}
		if payload, err := core.FastMarshal(closeMsg); err == nil {
			if err := core.Write(c.controlStr, core.TypeClose, core.FlagControl, payload); err != nil {
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
		for i := range c.keys.SM4Key {
			c.keys.SM4Key[i] = 0
		}
		c.keys = nil
	}
	c.sendMu.Unlock()

	// 7. 关闭 spool：置于 waitGoroutines 之后，drain/ackReaper 阶段触发的 spool
	// 删除已落定，避免对已关闭 spool 写。Close 做 final flush 后释放后台 goroutine。
	if c.spool != nil {
		if err := c.spool.Close(); err != nil {
			slog.Warn("spool close failed", "error", err)
		}
	}
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
	return c.sessionID
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
			ping := core.PingMessage{
				TimeUnixMs: time.Now().UnixMilli(),
				Nonce:      uuid.Must(uuid.NewV7()).String(),
			}
			payload, err := core.FastMarshal(ping)
			if err != nil {
				slog.Debug("marshal ping failed", "error", err)
				continue
			}
			c.controlMu.Lock()
			if err := core.Write(c.controlStr, core.TypePing, core.FlagControl, payload); err != nil {
				c.controlMu.Unlock()
				slog.Warn("write ping failed", "error", err)
				return
			}
			c.controlMu.Unlock()
		}
	}
}
