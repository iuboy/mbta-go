package v1

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/iuboy/mbta-go/core"
)

func (c *Client) readControlLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		f, err := core.Read(c.controlStr, core.DefaultLimits())
		if err != nil {
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
		}
	}
}

func (c *Client) handleAck(payload []byte) {
	var ack core.AckMessage
	if err := json.Unmarshal(payload, &ack); err != nil {
		return
	}

	if val, ok := c.pendingAcks.LoadAndDelete(ack.ChunkID); ok {
		pb := val.(*pendingBatch)
		c.inflight.Remove(pb.Events, pb.Bytes)
	}

	// Notify ACK handler (e.g., EnhancedSender for reliable delivery)
	if c.ackHandler != nil {
		c.ackHandler(ack.ChunkID, ack.AckMode)
	}

	slog.Debug("ack received", "seq", ack.Seq, "chunk", ack.ChunkID, "count", ack.Count, "mode", ack.AckMode)
}

func (c *Client) handleNack(payload []byte) {
	var nack core.NackMessage
	if err := json.Unmarshal(payload, &nack); err != nil {
		return
	}

	if val, ok := c.pendingAcks.LoadAndDelete(nack.ChunkID); ok {
		pb := val.(*pendingBatch)
		c.inflight.Remove(pb.Events, pb.Bytes)
	}

	// Notify ACK handler with "nack" mode so the sender can handle retry logic
	if c.ackHandler != nil {
		c.ackHandler(nack.ChunkID, "nack")
	}

	slog.Warn("nack received", "seq", nack.Seq, "code", nack.Code, "reason", nack.Reason, "retryable", nack.Retryable)
}

func (c *Client) handleWindow(payload []byte) {
	var win core.WindowMessage
	if err := json.Unmarshal(payload, &win); err != nil {
		return
	}
	c.window.Update(win.MaxInflightBatches, win.MaxInflightEvents, win.MaxInflightBytes)
	slog.Debug("window updated", "batches", win.MaxInflightBatches, "events", win.MaxInflightEvents)
}

func (c *Client) handleThrottle(payload []byte) {
	var throt core.ThrottleMessage
	if err := json.Unmarshal(payload, &throt); err != nil {
		return
	}
	c.throttle.Apply(throt.RetryDelayMs)
	slog.Info("throttled", "delay_ms", throt.RetryDelayMs, "reason", throt.Reason)
}
