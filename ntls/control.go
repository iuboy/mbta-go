package ntls

import (
	"context"
	"log/slog"

	"github.com/iuboy/mbta-go/core"
)

// readControlLoop 在单 TCP 连接上循环读取帧并分发到对应处理器。
// 退出条件：ctx 取消，或读取返回错误（连接关闭等）。
//
// ntls 与 v1 的区别：所有 control/data 帧复用同一 net.Conn，
// 核心读取调用为 core.Read(c.conn, ...)（替代 v1 的 core.Read(c.controlStr, ...)）。
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
			if err := core.FastUnmarshal(f.Payload, &errMsg); err != nil {
				slog.Debug("invalid error payload", "error", err)
			} else {
				slog.Warn("server error", "code", errMsg.Code, "reason", core.SanitizeForLog(errMsg.Reason), "fatal", errMsg.Fatal)
				if errMsg.Fatal {
					return
				}
			}
		}
	}
}

// handleAck 处理 ACK 帧：从 inflight 移除该 batch，并异步通知 ACK 回调。
func (c *Client) handleAck(payload []byte) {
	var ack core.AckMessage
	if err := core.FastUnmarshal(payload, &ack); err != nil {
		slog.Debug("invalid ack payload", "error", err)
		return
	}

	if val, ok := c.pendingAcks.LoadAndDelete(ack.ChunkID); ok {
		c.pendingCount.Add(-1)
		if pb, ok := val.(*pendingBatch); ok {
			c.inflight.Remove(pb.Events, pb.Bytes)
			// ACK 即持久化确认：删除 spool 中对应 batch + records。
			c.deleteSpooled(pb)
		}
	}

	// Notify ACK handler asynchronously (e.g., EnhancedSender for reliable
	// delivery). Dispatching off the control loop prevents a slow handler from
	// head-of-line blocking NACK/WINDOW/THROTTLE processing.
	c.dispatchACK(ack.ChunkID, ack.AckMode)

	c.notifyDrainIfEmpty()

	slog.Debug("ack received", "seq", ack.Seq, "chunk", ack.ChunkID, "count", ack.Count, "mode", ack.AckMode)
}

// handleNack 处理 NACK 帧：从 inflight 移除该 batch，并以 "nack" 模式异步通知回调。
func (c *Client) handleNack(payload []byte) {
	var nack core.NackMessage
	if err := core.FastUnmarshal(payload, &nack); err != nil {
		slog.Debug("invalid nack payload", "error", err)
		return
	}

	if val, ok := c.pendingAcks.LoadAndDelete(nack.ChunkID); ok {
		c.pendingCount.Add(-1)
		if pb, ok := val.(*pendingBatch); ok {
			c.inflight.Remove(pb.Events, pb.Bytes)
			// 毒消息（不可重试）：从 spool 丢弃；retryable 保留待重连重发。
			if !nack.Retryable {
				c.deleteSpooled(pb)
			}
		}
	}

	// Notify ACK handler asynchronously with "nack" mode so the sender can
	// handle retry logic (see dispatchACK — never blocks the control loop).
	c.dispatchACK(nack.ChunkID, "nack")

	c.notifyDrainIfEmpty()

	slog.Warn("nack received", "seq", nack.Seq, "code", nack.Code, "reason", core.SanitizeForLog(nack.Reason), "retryable", nack.Retryable)
}

// handleWindow 处理 WINDOW 帧：更新本地流控窗口。
func (c *Client) handleWindow(payload []byte) {
	var win core.WindowMessage
	if err := core.FastUnmarshal(payload, &win); err != nil {
		slog.Debug("invalid window payload", "error", err)
		return
	}
	c.window.Update(win.MaxInflightBatches, win.MaxInflightEvents, win.MaxInflightBytes)
	slog.Debug("window updated", "batches", win.MaxInflightBatches, "events", win.MaxInflightEvents)
}

// handleThrottle 处理 THROTTLE 帧：应用退避防止压垮服务端。
func (c *Client) handleThrottle(payload []byte) {
	var throt core.ThrottleMessage
	if err := core.FastUnmarshal(payload, &throt); err != nil {
		slog.Debug("invalid throttle payload", "error", err)
		return
	}
	c.throttle.Apply(throt.RetryDelayMs)
	slog.Info("throttled", "delay_ms", throt.RetryDelayMs, "reason", core.SanitizeForLog(throt.Reason))
}

// handlePing 响应服务端的 PING 帧，回写 PONG。
//
// ntls 写帧走 c.writeFrame（writeMu 串行化），替代 v1 的
// c.controlMu.Lock() + core.Write(c.controlStr, ...)。
func (c *Client) handlePing(payload []byte) {
	var ping core.PingMessage
	if err := core.FastUnmarshal(payload, &ping); err != nil {
		slog.Debug("invalid ping payload", "error", err)
		return
	}

	pong := core.PongMessage{
		TimeUnixMs: ping.TimeUnixMs,
		Nonce:      ping.Nonce,
		Status:     "ok",
	}
	pongPayload, err := core.FastMarshal(pong)
	if err != nil {
		slog.Warn("marshal pong failed", "error", err)
		return
	}
	if err := c.writeFrame(core.TypePong, core.FlagControl, pongPayload); err != nil {
		slog.Warn("write pong failed", "error", err)
	}
}
