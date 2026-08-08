package protocol

import (
	"context"
	"errors"
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

		f, err := c.tr.ReadFrame(ctx)
		if err != nil {
			// 区分临时错误（EAGAIN/EINTR 等可恢复）与致命错误（连接关闭/EOF）。
			// 临时错误继续循环，仅致命错误退出，避免网络抖动不必要地终止控制帧处理。
			if isTemporaryError(err) && ctx.Err() == nil {
				slog.Debug("control loop temporary read error, continuing", "error", err)
				continue
			}
			if ctx.Err() == nil {
				slog.Warn("control loop read error, exiting", "error", err)
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
				// MatchWireCode 把对端 wire 码反查为 ErrorCode，日志携带大类 Num 便于过滤；
				// 未注册码回退 ErrCodeUnknown（不影响 fatal 判定）。
				ec := core.MatchWireCode(errMsg.GetCode())
				slog.Warn("server error", "code", ec.Code, "num", ec.Num, "reason", core.SanitizeForLog(errMsg.GetReason()), "fatal", errMsg.GetFatal())
				if errMsg.GetFatal() {
					return
				}
			}
		case core.TypeRedirect:
			c.dispatchRedirect(f.Payload)
		}
	}
}

// handleAck 处理 ACK：释放 tracker slot（seq+chunkID 校验），观测 latency，回调。
func (c *CoreClient) handleAck(payload []byte) {
	var ack core.AckMessage
	if err := core.Decode(payload, &ack); err != nil {
		slog.Debug("invalid ack payload", "error", err)
		return
	}

	chunkID, valid := chunkIDFromWire(ack.GetChunkId())
	if !valid {
		// chunk_id 非 16 字节 ULID：服务端返回了无法解析的 chunk_id，tracker 无法定位 slot，
		// 记录告警便于定位（不调用 Release，计数器不变）。
		slog.Warn("ack chunk_id not valid ULID, cannot match pending batch", "len", len(ack.GetChunkId()))
		return
	}
	// Release 用 ACK 帧自带的 seq 取模定位 slot，chunkID 二次校验。
	// 三路并发 claim（ack/nack/reaper）中首个成功者清空 slot.seq，后续见 seq==0 失败。
	if slot, ok := c.tracker.Release(ack.GetSeq(), chunkID); ok {
		c.metrics.BatchLatency().Observe(time.Since(slot.SentAt).Seconds())
	}

	chunkIDText := chunkID.String()
	c.dispatchACK(chunkIDText, ackModeString(ack.GetAckMode()))
	c.notifyDrainIfEmpty()

	slog.Debug("ack received", "seq", ack.GetSeq(), "chunk", chunkIDText, "count", ack.GetCount(), "mode", ackModeString(ack.GetAckMode()))
}

// handleNack 处理 NACK：释放 tracker slot（seq+chunkID 校验），回调。
func (c *CoreClient) handleNack(payload []byte) {
	var nack core.NackMessage
	if err := core.Decode(payload, &nack); err != nil {
		slog.Debug("invalid nack payload", "error", err)
		return
	}

	chunkID, valid := chunkIDFromWire(nack.GetChunkId())
	if !valid {
		slog.Warn("nack chunk_id not valid ULID, cannot match pending batch", "len", len(nack.GetChunkId()))
		return
	}
	// NACK 同样释放 slot（不计 latency：被拒 batch 的 latency 无意义）。
	c.tracker.Release(nack.GetSeq(), chunkID)

	chunkIDText := chunkID.String()
	c.dispatchACK(chunkIDText, "nack")
	c.notifyDrainIfEmpty()

	slog.Warn("nack received", "seq", nack.GetSeq(), "code", nack.GetCode(), "reason", core.SanitizeForLog(nack.GetReason()), "retryable", nack.GetRetryable())
}

func (c *CoreClient) handleWindow(payload []byte) {
	var win core.WindowMessage
	if err := core.Decode(payload, &win); err != nil {
		slog.Debug("invalid window payload", "error", err)
		return
	}
	c.tracker.UpdateLimits(int(win.GetMaxInflightBatches()), int(win.GetMaxInflightEvents()), win.GetMaxInflightBytes())
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

// chunkIDFromWire 把 wire chunk_id（ULID 16B）解析为 ChunkID。
// 第二个返回值 ok 表示 chunk_id 是否为合法 16 字节 ULID；ok=false 时调用方不应
// 调用 tracker.Release（seq 索引虽可定位 slot，但 chunkID 校验会失败，且计数器不应变动）。
func chunkIDFromWire(chunkID []byte) (core.ChunkID, bool) {
	if c, err := core.ChunkIDFromBytes(chunkID); err == nil {
		return c, true
	}
	return core.ChunkID{}, false
}

// isTemporaryError 报告错误是否为可恢复的临时 I/O 错误（如 EAGAIN/EINTR）。
// 对此类错误应继续循环而非终止控制帧读取。
func isTemporaryError(err error) bool {
	var ne interface{ Temporary() bool }
	if errors.As(err, &ne) {
		return ne.Temporary()
	}
	return false
}
