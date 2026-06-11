package v1

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/iuboy/mbta-go/core"
)

// readControlLoop reads frames from the control stream and dispatches them
// to the appropriate handler. Exits when the context is cancelled or the
// control stream returns an error.
func (c *Client) readControlLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		f, err := core.Read(c.controlStr, core.DefaultLimits())
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
		}
	}
}

// handleAck processes an ACK frame: removes the batch from inflight tracking
// and invokes the registered ACK handler callback.
func (c *Client) handleAck(payload []byte) {
	var ack core.AckMessage
	if err := json.Unmarshal(payload, &ack); err != nil {
		slog.Debug("invalid ack payload", "error", err)
		return
	}

	if val, ok := c.pendingAcks.LoadAndDelete(ack.ChunkID); ok {
		if pb, ok := val.(*pendingBatch); ok {
			c.inflight.Remove(pb.Events, pb.Bytes)
		}
	}

	// Notify ACK handler (e.g., EnhancedSender for reliable delivery)
	if handler := c.loadACKHandler(); handler != nil {
		handler(ack.ChunkID, ack.AckMode)
	}

	slog.Debug("ack received", "seq", ack.Seq, "chunk", ack.ChunkID, "count", ack.Count, "mode", ack.AckMode)
}

// handleNack processes a NACK frame: removes the batch from inflight tracking
// and invokes the ACK handler with "nack" mode for retry logic.
func (c *Client) handleNack(payload []byte) {
	var nack core.NackMessage
	if err := json.Unmarshal(payload, &nack); err != nil {
		slog.Debug("invalid nack payload", "error", err)
		return
	}

	if val, ok := c.pendingAcks.LoadAndDelete(nack.ChunkID); ok {
		if pb, ok := val.(*pendingBatch); ok {
			c.inflight.Remove(pb.Events, pb.Bytes)
		}
	}

	// Notify ACK handler with "nack" mode so the sender can handle retry logic
	if handler := c.loadACKHandler(); handler != nil {
		handler(nack.ChunkID, "nack")
	}

	slog.Warn("nack received", "seq", nack.Seq, "code", nack.Code, "reason", nack.Reason, "retryable", nack.Retryable)
}

// handleWindow processes a WINDOW frame: updates the local flow-control limits.
func (c *Client) handleWindow(payload []byte) {
	var win core.WindowMessage
	if err := json.Unmarshal(payload, &win); err != nil {
		slog.Debug("invalid window payload", "error", err)
		return
	}
	c.window.Update(win.MaxInflightBatches, win.MaxInflightEvents, win.MaxInflightBytes)
	slog.Debug("window updated", "batches", win.MaxInflightBatches, "events", win.MaxInflightEvents)
}

// handleThrottle processes a THROTTLE frame: applies backoff to prevent
// overwhelming the server.
func (c *Client) handleThrottle(payload []byte) {
	var throt core.ThrottleMessage
	if err := json.Unmarshal(payload, &throt); err != nil {
		slog.Debug("invalid throttle payload", "error", err)
		return
	}
	c.throttle.Apply(throt.RetryDelayMs)
	slog.Info("throttled", "delay_ms", throt.RetryDelayMs, "reason", throt.Reason)
}
