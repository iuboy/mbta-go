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

	batchJSON, err := core.MarshalSignalBatchCodec(c.codecForMarshal(), signalBatch)
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
// codecForMarshal 返回当前应使用的 SignalBatch 编码 codec：优先协商结果，
// 否则回退到 binding 注入的 cfg.DefaultCodec。
func (c *CoreClient) codecForMarshal() corepb.Codec {
	if c.negotiated != nil {
		return c.negotiated.Codec
	}
	return c.cfg.DefaultCodec
}

// buildAndSend 在锁外完成 envelope 构建（gzip+HMAC）、envelope marshal 与网络写。
// BATCH 写经 c.tr.WriteFrame（v1 走 picker 多流，ntls 走单连接），由 binding 实现。
func (c *CoreClient) buildAndSend(ctx context.Context, seq uint64, chunkID core.ChunkID, tag, source string, batchPayload []byte) error {
	cs := c.cfg.DefaultCipherSuite
	codec := c.cfg.DefaultCodec
	comp := c.cfg.DefaultCompression
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
		params.HMACKey = c.keys.HMACKey()
		params.AEADKey = c.keys.AEADKey()
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
