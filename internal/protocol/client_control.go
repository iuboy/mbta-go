package protocol

import (
	"context"
	"log/slog"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

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
