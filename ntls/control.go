package ntls

import (
	"context"
	"log/slog"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// readControlLoop 在单 TCP 连接上循环读取帧并分发（control/data 复用同连接）。
func (c *Client) readControlLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		f, err := core.Read(c.conn, core.DefaultLimits())
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
// chunk_id（wire ULID 16B）转 ULID 文本匹配 pendingAcks key。
func (c *Client) handleAck(payload []byte) {
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
func (c *Client) handleNack(payload []byte) {
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

func (c *Client) handleWindow(payload []byte) {
	var win core.WindowMessage
	if err := core.Decode(payload, &win); err != nil {
		slog.Debug("invalid window payload", "error", err)
		return
	}
	c.window.Update(int(win.GetMaxInflightBatches()), int(win.GetMaxInflightEvents()), win.GetMaxInflightBytes())
	slog.Debug("window updated", "batches", win.GetMaxInflightBatches(), "events", win.GetMaxInflightEvents())
}

func (c *Client) handleThrottle(payload []byte) {
	var throt core.ThrottleMessage
	if err := core.Decode(payload, &throt); err != nil {
		slog.Debug("invalid throttle payload", "error", err)
		return
	}
	c.throttle.Apply(int(throt.GetRetryDelayMs()))
	slog.Info("throttled", "delay_ms", throt.GetRetryDelayMs(), "reason", core.SanitizeForLog(throt.GetReason()))
}

// handlePing 响应 PING，回写 PONG（ntls 走 writeMu 单连接）。
func (c *Client) handlePing(payload []byte) {
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
	if err := c.writeFrame(core.TypePong, core.FlagControl, core.ChannelControl, pongPayload); err != nil {
		slog.Warn("write pong failed", "error", err)
	}
}

// ackModeString 把 corepb.AckMode 转为回调期望字符串。
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
