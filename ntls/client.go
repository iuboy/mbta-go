package ntls

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/spool"
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
	spool      *spool.Spool
	seq        *core.SeqGenerator
	inflight   *core.Inflight
	window     *core.Window
	throttle   *core.ThrottleState
	sessionID  []byte

	challengeNonce []byte    // server challenge from HELLO_ACK
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
	Seq          uint64
	Events       int
	Bytes        int64
	SentAt       time.Time
	Deadline     time.Time // 此 batch 若无 ACK 的超时时刻
	RecordIDs    []string  // spool 删除用；无 spool 时为空
	SpoolChunkID string    // spool key；全新发送==wire chunkID，重发==原 spool key
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
	if cfg.SpoolDir != "" {
		s, err := spool.New(cfg.SpoolDir)
		if err != nil {
			return nil, core.WrapError(core.NumSpool, core.CodeSpool, "open spool", err)
		}
		c.spool = s
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

	// 重连/崩溃恢复：重发 spool 中所有未 ACK 的 batch（background goroutine 已启动，ACK 可被处理）。
	c.drainSpoolAfterConnect(ctx)

	slog.Info("MBTA-NTLS client connected", "agent", c.config.AgentID, "session", c.sessionID)
	return nil
}

// writeFrame 在 writeMu 保护下向单 TCP 连接写一帧。
// ntls 中所有写（HELLO/AUTH/BATCH/PING/PONG/CLOSE）都走此函数，保证帧级原子性。
func (c *Client) writeFrame(typ uint8, flags byte, channel uint8, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return core.Write(c.conn, typ, flags, channel, payload)
}

// writeFrameCtx 写一帧，并受调用方 ctx 约束。仅 BATCH 写路径（buildAndSend）使用。
//
// 实现：在 writeMu 临界区内按 ctx 的 Deadline 设置 SetWriteDeadline，写完恢复（time.Time{}）。
// writeMu 保证同一时刻只有一个写者，故 deadline 不会被并发写者互相覆盖——这是 ntls 单连接
// 能安全做 ctx→deadline 绑定的前提（v1 的 single 策略下多发送者写同一 quic.Stream，无此保证）。
//
// 语义：
//   - ctx 已取消（cancel-only 或 deadline 已过）：进入即返回 ctx.Err()，不触碰连接。
//   - ctx 带 Deadline：写超时按该 deadline 计；超时 Write 返回 deadline 错误。
//   - ctx 仅可取消但无 Deadline（如 WithCancel(Background)）：无法在不拆连接前提下中断
//     阻塞写，按连接级生命周期处理（与历史行为一致）。
//
// 注意：deadline 触发导致的写失败可能留下半帧（帧头声明的 Length 与实际写入不符，破坏对端
// 帧同步）。此类失败应视为连接已损坏——调用方收到错误后应 Close() 并重连，不应复用本连接。
func (c *Client) writeFrameCtx(ctx context.Context, typ uint8, flags byte, channel uint8, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetWriteDeadline(dl)
		defer func() { _ = c.conn.SetWriteDeadline(time.Time{}) }() // 恢复，避免影响后续无 ctx 的写
	}
	return core.Write(c.conn, typ, flags, channel, payload)
}

// SendBatch 通过 MBTA-NTLS 协议发送一个 SignalBatch。
// 返回分配给该 batch 的 chunkID（用于 ACK 关联），或错误。
//
// ctx 约束网络写：BATCH 写在 writeMu 临界区内按 ctx.Deadline() 设置 SetWriteDeadline，
// 对端卡死时调用方超时能及时收到写错误（而非阻塞到 TCP 自身放弃）。ctx 已取消则进入即返回。
// 注意：超时导致的写失败可能留下半帧、破坏对端帧同步，调用方收到错误后应 Close() 并重连，
// 不应复用本连接。仅 WithCancel（无 deadline）的 ctx 不会中断阻塞写（连接级生命周期处理）。
//
// 锁粒度：sendMu 仅保护「window 检查 + 取 seq/chunkID + inflight/pending 登记」，
// 重的 CPU 工作（marshal、gzip+HMAC Build、网络写）全部在锁外，使多调用方可并行利用多核。
func (c *Client) SendBatch(ctx context.Context, signalBatch *core.SignalBatch, tag, source string) (string, error) {
	return c.sendTracked(ctx, signalBatch, tag, source, nil, nil)
}

// sendTracked 发送一个 batch 并按需持久化到 spool，是 SendBatch 与重连重发的共用底层路径。
// 语义与 v1 sendTracked 一致：
//   - alreadySpooledChunkID == nil：全新发送，PutBatch 持久化，pendingBatch.SpoolChunkID == wire chunkID。
//   - alreadySpooledChunkID != nil：重发，跳过 PutBatch（防双重持久化），wire 用新 seq/chunkID
//     （服务端 ReplayCache per-connection，跨重连不去重），pendingBatch.SpoolChunkID == 原 spool key、
//     RecordIDs == retransmitRecordIDs（来自原 spool batch）。
//
// PutBatch 成功后即使 write 失败也保留 spool 条目（at-least-once，重连重发）。
// ctx 约束网络写（见 writeFrameCtx）。
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

	// 全新发送：为每个 event 构造 spool Record；重发：recordIDs 来自原 spool batch。
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

	// --- 锁外：Build envelope（gzip+HMAC）+ marshal env + 网络写 ---
	if writeErr := c.buildAndSend(ctx, seq, chunkID, tag, source, batchPayload); writeErr != nil {
		// 写失败：回滚 inflight/pending，但保留 spool 条目（at-least-once，重连重发）。
		c.inflight.Remove(batchEvents, batchBytes)
		if _, ok := c.pendingAcks.LoadAndDelete(chunkID.String()); ok {
			c.pendingCount.Add(-1)
		}
		return "", writeErr
	}

	slog.Debug("batch sent", "seq", seq, "chunk", chunkID.String(), "events", batchEvents, "retransmit", !fresh)
	return chunkID.String(), nil
}

// buildRecords 为一批 event 构造 spool Record 与对应 RecordID（每 event 一个 UUID v7）。
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

// deleteSpooled 删除已 ACK（或毒消息丢弃）的 batch 对应 spool 条目。删除失败仅 warn。
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

// drainSpoolAfterConnect 握手成功后重发所有未 ACK 的 spool batch（崩溃/重连恢复）。
// 按 Seq 升序重发；重发跳过 PutBatch，wire 用新 seq/chunkID，pendingBatch.SpoolChunkID
// 指向原 key 以便 ACK 删除原条目。单条失败不删 spool，下次重连再试。
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

// reserveInflight 在 sendMu 保护下原子完成：取 seq/chunkID、构造 batch wrapper、窗口检查、
// inflight/spool/pending 登记。PutBatch 与 inflight/pending 同临界区保证原子。
func (c *Client) reserveInflight(tag, source string, batchJSON []byte, batchEvents int, records []spool.Record, recordIDs []string, alreadySpooledChunkID *string) (uint64, core.ChunkID, []byte, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	seq := c.seq.Next()
	chunkID := core.NewChunkID()

	// r2：BatchMessage 用 corepb proto 编码。
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
		return 0, core.ChunkID{}, nil, ErrWindowFull
	}
	c.inflight.Add(batchEvents, batchBytes)

	chunkIDText := chunkID.String()
	var spoolChunkID string
	if c.spool != nil {
		if alreadySpooledChunkID != nil {
			spoolChunkID = *alreadySpooledChunkID
		} else {
			if err := c.spool.PutBatch(records, spool.Batch{
				Seq:             seq,
				ChunkID:         chunkIDText,
				RecordIDs:       recordIDs,
				CreatedAtUnixMs: time.Now().UnixMilli(),
			}); err != nil {
				c.inflight.Remove(batchEvents, batchBytes)
				return 0, core.ChunkID{}, nil, core.WrapError(core.NumSpool, core.CodeSpool, "spool put batch", err)
			}
			spoolChunkID = chunkIDText
		}
	}

	c.pendingAcks.Store(chunkIDText, &pendingBatch{
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

// buildAndSend 在锁外完成 envelope 构建（gzip+HMAC）、envelope marshal 与网络写。
// batchPayload 由 reserveInflight 已构造（手写），此处直接 Build，不再重复 marshal。
//
// ntls 与 v1 区别：写 BATCH 帧走 c.writeFrameCtx（受 ctx 约束的单连接 + writeMu），
// 替代 v1 的 c.picker.Pick(batch) + core.Write(ds, ...)（多流分发）。
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

	// ntls：单 TCP 连接，直接写 BATCH 帧（ChannelData）。
	if err := c.writeFrameCtx(ctx, core.TypeBatch, core.FlagEnvelope|core.FlagData, core.ChannelData, envPayload); err != nil {
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
		closeMsg := &corepb.CloseMessage{Code: "shutdown", Reason: "client closing"}
		if payload, err := core.Encode(closeMsg); err == nil {
			if err := c.writeFrame(core.TypeClose, core.FlagControl, core.ChannelControl, payload); err != nil {
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
		for i := range c.keys.AEADKey {
			c.keys.AEADKey[i] = 0
		}
		c.keys = nil
	}
	c.sendMu.Unlock()

	// 关闭 spool：置于 waitGoroutines 之后，drain/ackReaper 阶段触发的 spool 删除已落定。
	if c.spool != nil {
		if err := c.spool.Close(); err != nil {
			slog.Warn("spool close failed", "error", err)
		}
	}
}

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
	return string(c.sessionID)
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
			ping := &corepb.PingMessage{
				TimeUnixMs: time.Now().UnixMilli(),
				Nonce:      uuid.Must(uuid.NewV7()).String(),
			}
			payload, err := core.Encode(ping)
			if err != nil {
				slog.Debug("marshal ping failed", "error", err)
				continue
			}
			if err := c.writeFrame(core.TypePing, core.FlagControl, core.ChannelControl, payload); err != nil {
				slog.Warn("write ping failed", "error", err)
				return
			}
		}
	}
}
