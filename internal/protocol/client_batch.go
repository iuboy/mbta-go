package protocol

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// --- 批次发送 ---

// SendBatch 发送一个 SignalBatch。返回分配的 chunkID 用于 ACK 关联。
//
// 锁粒度：sendMu 仅保护「window 检查 + 取 seq/chunkID + inflight/pending 登记」，
// 重的 CPU 工作（marshal/Build/网络写）全部在锁外，使多调用方可跨 batch 并行利用多核。
//
// opts 携带 per-call 发送选项（如 core.WithTraceContext）；不传则行为与旧版一致。
func (c *CoreClient) SendBatch(ctx context.Context, signalBatch *core.SignalBatch, tag, source string, opts ...core.SendOption) (string, error) {
	if signalBatch == nil {
		return "", core.NewError(core.NumBatch, core.CodeBatch, "batch must not be nil")
	}

	sc := core.ApplySendOptions(opts)

	// --- 锁外：trace 上下文门控与前置校验 ---
	// cap 门控：携带 TraceContext 必须已协商 w3c_trace_context，否则显式报错（不静默丢弃，
	// 与协议「未协商 stable capability 不允许静默吞掉」惯例一致）。negotiated==nil 时
	// IsCapabilitySelected 返回 false → 报错（保守正确：握手前不应发送）。
	if sc.TraceContext != nil {
		n := c.negotiated.Load()
		if n == nil || !n.IsCapabilitySelected(core.CapW3CTraceContext) {
			return "", core.NewError(core.NumBatch, core.CodeBatch,
				"trace_context requires negotiated w3c_trace_context capability")
		}
		if err := core.ValidateBatchTraceContext(sc.TraceContext); err != nil {
			return "", err
		}
	}

	// --- 锁外：无状态前置检查 + marshal SignalBatch ---
	if c.sm.State() != core.StateReady {
		return "", fmt.Errorf("not ready, state=%s", c.sm.State())
	}
	if c.throttle.Active() {
		return "", fmt.Errorf("throttled, retry after %v", c.throttle.WaitDuration())
	}

	batchJSON, err := core.MarshalSignalBatchCodec(c.codecForMarshal(), signalBatch)
	if err != nil {
		return "", core.WrapError(core.NumBatch, core.CodeBatch, "marshal signal batch", err)
	}
	batchEvents := len(signalBatch.Signals)

	// --- 锁内：取 seq/chunkID、窗口检查、inflight/pending 登记 ---
	seq, chunkID, batchPayload, err := c.reserveInflight(tag, source, batchJSON, batchEvents, sc.TraceContext)
	if err != nil {
		return "", err
	}
	batchBytes := int64(len(batchPayload))

	// --- 锁外：Build envelope（gzip+HMAC）+ marshal env + 网络写 ---
	if writeErr := c.buildAndSend(ctx, seq, chunkID, batchPayload); writeErr != nil {
		c.inflight.Remove(batchEvents, batchBytes)
		if _, ok := c.pendingAcks.LoadAndDelete(chunkID.String()); ok {
			c.pendingCount.Add(-1)
		}
		return "", writeErr
	}

	c.metrics.BatchesSent().Inc()
	slog.Debug("batch sent", "seq", seq, "chunk", chunkID.String(), "events", batchEvents)
	return chunkID.String(), nil
}

// reserveInflight 在 sendMu 保护下原子完成：取 seq/chunkID、构造 BatchMessage proto、
// 窗口检查、inflight/pending 登记。
//
// traceContext 为可选的 batch 级 W3C trace 上下文；非 nil 时设到 BatchMessage.TraceContext
// （field 7），nil 时不设（与旧版 wire 一致）。调用前已通过 cap 门控与合法性校验。
func (c *CoreClient) reserveInflight(tag, source string, batchJSON []byte, batchEvents int, traceContext *corepb.TraceContext) (uint64, core.ChunkID, []byte, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	// TOCTOU 防护：SendBatch 在锁外已检查 state/throttle，但 marshal 期间状态可能变化
	// （连接断开 → state 非 Ready，或服务端下发 THROTTLE）。加锁后必须重新检查，
	// 否则 batch 仍会被登记到 inflight/pending 并发送，违反状态机约束或逃过节流。
	if c.sm.State() != core.StateReady {
		return 0, core.ChunkID{}, nil, core.NewError(core.NumSession, core.CodeSession, "client not ready")
	}
	if c.throttle.Active() {
		return 0, core.ChunkID{}, nil, core.NewError(core.NumThrottle, core.CodeThrottle, "throttled")
	}

	seq := c.seq.Next()
	chunkID := core.NewChunkID()

	batchMsg := &corepb.BatchMessage{Seq: seq, ChunkId: chunkID.Bytes(), Tag: tag, Source: source}
	if batchEvents > 0 {
		batchMsg.EventsCount = int32(batchEvents)
	}
	batchMsg.Batch = batchJSON
	if traceContext != nil {
		batchMsg.TraceContext = traceContext
	}
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

// codecForMarshal 返回当前应使用的 SignalBatch 编码 codec：优先协商结果，
// 否则回退到 binding 注入的 cfg.DefaultCodec。
func (c *CoreClient) codecForMarshal() corepb.Codec {
	if n := c.negotiated.Load(); n != nil {
		return n.Codec
	}
	return c.cfg.DefaultCodec
}

// buildAndSend 在锁外完成 envelope 构建（gzip+HMAC）、envelope marshal 与网络写。
// BATCH 写经 c.tr.WriteFrame（v1 走 picker 多流，ntls 走单连接），由 binding 实现。
func (c *CoreClient) buildAndSend(ctx context.Context, seq uint64, chunkID core.ChunkID, batchPayload []byte) error {
	cs := c.cfg.DefaultCipherSuite
	codec := c.cfg.DefaultCodec
	comp := c.cfg.DefaultCompression
	if n := c.negotiated.Load(); n != nil {
		cs = n.CipherSuite
		codec = n.Codec
		comp = n.Compression
	}
	params := core.BuildParams{
		SessionID:    c.getSessionID(),
		Seq:          seq,
		ChunkID:      chunkID,
		Codec:        codec,
		Compression:  comp,
		CipherSuite:  cs,
		DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
		MsgType:      corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
	}
	if k := c.keys.Load(); k != nil {
		params.KeyID = k.KeyID
		params.HMACKey = k.HMACKey()
		params.AEADKey = k.AEADKey()
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
