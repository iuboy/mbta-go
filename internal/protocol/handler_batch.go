package protocol

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// processBatch 处理 reliable BATCH：envelope → 校验 → 路由 → ACK。
func (h *CoreHandler) processBatch(ctx context.Context, payload []byte) {
	env, err := core.DecodeEnvelope(payload)
	if err != nil {
		slog.Debug("invalid envelope", "error", err)
		h.sendError(ctx, core.CodeDecodeFailed, "invalid_envelope", false)
		return
	}

	if h.expiresAt.Load() > 0 && time.Now().Unix() > h.expiresAt.Load() {
		h.sendNack(ctx, env.GetSeq(), env.GetChunkId(), "session_expired", "session TTL exceeded, please reconnect", false)
		return
	}

	// Verify HMAC（在解密/解码前）。keys 经 atomic 读取，避免与 handleAuth 颁发新 keys 竞态（0-RTT）。
	keys := h.keys.Load()
	if keys != nil {
		ok, verr := core.VerifyMAC(keys.HMACKey(), env)
		if verr != nil || !ok {
			h.sendNack(ctx, env.GetSeq(), env.GetChunkId(), "hmac_mismatch", "HMAC verification failed", false)
			h.config.Metrics.HMACFailures().Inc()
			return
		}
	}

	// 算法一致性复核（依据权威协商结果）。
	if h.verifyEnvelopeAlgo(env) {
		return
	}

	// Open envelope（解密+解压）。
	var aeadKey []byte
	if keys != nil {
		aeadKey = keys.AEADKey()
	}
	batchPayload, err := core.Open(env, aeadKey)
	if err != nil {
		slog.Debug("envelope open failed", "error", err)
		h.config.Metrics.DecryptFailures().Inc()
		h.sendNack(ctx, env.GetSeq(), env.GetChunkId(), "envelope_open_error", "envelope could not be opened", true)
		return
	}
	if len(batchPayload) > maxBatchBytes {
		h.sendNack(ctx, env.GetSeq(), env.GetChunkId(), "batch_too_large",
			fmt.Sprintf("batch payload %d bytes exceeds limit %d", len(batchPayload), maxBatchBytes), false)
		return
	}

	var batchMsg corepb.BatchMessage
	if err := core.Decode(batchPayload, &batchMsg); err != nil {
		slog.Debug("batch decode failed", "error", err)
		h.sendNack(ctx, env.GetSeq(), env.GetChunkId(), "invalid_batch", "batch message could not be decoded", false)
		return
	}
	if err := core.ValidateBatch(&batchMsg); err != nil {
		slog.Debug("batch validation failed", "error", err)
		h.sendNack(ctx, batchMsg.GetSeq(), batchMsg.GetChunkId(), "batch_validation", "batch failed validation", false)
		return
	}
	// batch 级 W3C trace 上下文校验（capability w3c_trace_context，spec §6.2.2）。
	// 客户端发送前已校验，此处 defense-in-depth：拒绝绕过 SDK 直接构造的非法 trace。
	if tc := batchMsg.GetTraceContext(); tc != nil {
		if err := core.ValidateBatchTraceContext(tc); err != nil {
			slog.Debug("batch trace_context invalid", "error", err)
			h.sendNack(ctx, batchMsg.GetSeq(), batchMsg.GetChunkId(), "batch_trace_context", "invalid batch trace context", false)
			return
		}
	}

	// chunk_id dedup key（ULID 文本）。
	chunkIDText := chunkIDText(batchMsg.GetChunkId())
	batchEvents, signalBatchPtr := h.resolveBatchEvents(&batchMsg)
	if batchEvents < 0 {
		return // 已发 NACK
	}
	batchBytes := int64(len(batchPayload))

	// 服务端流控强制。
	if !h.window.CanSend(h.inflight, batchEvents, batchBytes) {
		h.sendThrottle(ctx, throttleRetryMs, "window_exceeded", "server flow-control window exceeded")
		return
	}
	h.inflight.Add(batchEvents, batchBytes)

	// Replay 去重。
	if existing := h.replay.SeenOrAdd(h.agentID, chunkIDText); existing != nil {
		h.config.Metrics.ReplayCacheHits().Inc()
		h.inflight.Remove(batchEvents, batchBytes)
		ackMode := corepb.AckMode_ACK_MODE_ACCEPTED
		if existing.Status == core.ReplayDurable {
			ackMode = corepb.AckMode_ACK_MODE_DURABLE
		}
		h.sendAck(ctx, batchMsg.GetSeq(), batchMsg.GetChunkId(), batchEvents, ackMode)
		return
	}

	h.replay.Update(h.agentID, chunkIDText, core.ReplayAccepted)
	h.routeAndACK(ctx, h.agentID, chunkIDText, &batchMsg, signalBatchPtr, batchEvents, batchBytes)
}

// processDatagram 处理 unreliable DATAGRAM：at-most-once，无 ACK/spool（core spec §11.4）。
func (h *CoreHandler) processDatagram(ctx context.Context, payload []byte) {
	env, err := core.DecodeEnvelope(payload)
	if err != nil {
		slog.Debug("datagram decode envelope failed", "error", err)
		return // 静默丢弃
	}
	// session 过期检查：与 processBatch 一致，过期会话的 datagram 不应再被处理。
	if h.expiresAt.Load() > 0 && time.Now().Unix() > h.expiresAt.Load() {
		slog.Debug("datagram rejected: session expired", "session", string(h.sessionID))
		return
	}
	keys := h.keys.Load()
	if keys != nil {
		ok, _ := core.VerifyMAC(keys.HMACKey(), env)
		if !ok {
			slog.Debug("datagram hmac failed")
			return // HMAC 失败静默丢弃
		}
	}
	var aeadKey []byte
	if keys != nil {
		aeadKey = keys.AEADKey()
	}
	batchPayload, err := core.Open(env, aeadKey)
	if err != nil {
		slog.Debug("datagram open failed", "error", err)
		h.config.Metrics.DecryptFailures().Inc()
		return
	}
	var batchMsg corepb.DatagramMessage
	if err := core.Decode(batchPayload, &batchMsg); err != nil {
		slog.Debug("datagram decode message failed", "error", err)
		return
	}
	// 不可靠投递：尽力路由，无 ACK。
	if h.config.Sink != nil {
		if rawSink, ok := h.config.Sink.(core.RawEventSink); ok {
			slog.Debug("datagram delivering to raw sink", "events", batchMsg.GetEventsCount())
			_, _ = rawSink.OnRawBatch(ctx, h.agentID, int(batchMsg.GetEventsCount()), batchMsg.GetBatch())
		} else {
			slog.Debug("datagram sink is not RawEventSink")
		}
	}
}

// codecForUnmarshal 返回服务端解码 SignalBatch 应使用的 codec：优先协商结果，
// 否则回退到 HandlerConfig.Policy.DefaultCodec。
func (h *CoreHandler) codecForUnmarshal() corepb.Codec {
	if n := h.negotiated.Load(); n != nil {
		return n.Codec
	}
	return h.config.Policy.DefaultCodec
}

// resolveBatchEvents 解析事件数（RawEventSink 快速路径 vs 完整解码）。batchEvents<0 表示已发 NACK。
func (h *CoreHandler) resolveBatchEvents(batchMsg *corepb.BatchMessage) (int, *core.SignalBatch) {
	rawSink, _ := h.config.Sink.(core.RawEventSink)
	if rawSink != nil && batchMsg.GetEventsCount() > 0 {
		ec := int(batchMsg.GetEventsCount())
		if ec > maxBatchEvents {
			h.sendNack(context.Background(), batchMsg.GetSeq(), batchMsg.GetChunkId(), "too_many_events",
				fmt.Sprintf("event count %d exceeds limit %d", ec, maxBatchEvents), false)
			return -1, nil
		}
		return ec, nil
	}
	sb, ok := h.decodeSignalBatch(batchMsg)
	if !ok {
		return -1, nil
	}
	return len(sb.Signals), sb
}

func (h *CoreHandler) decodeSignalBatch(batchMsg *corepb.BatchMessage) (*core.SignalBatch, bool) {
	sb, err := core.UnmarshalSignalBatchCodec(h.codecForUnmarshal(), batchMsg.GetBatch())
	if err != nil {
		slog.Debug("signal batch decode failed", "error", err)
		h.sendNack(context.Background(), batchMsg.GetSeq(), batchMsg.GetChunkId(), "invalid_signal_batch", "signal batch could not be decoded", false)
		return nil, false
	}
	if err := sb.Validate(); err != nil {
		slog.Debug("signal validation failed", "error", err)
		h.sendNack(context.Background(), batchMsg.GetSeq(), batchMsg.GetChunkId(), "signal_validation", "signal batch failed validation", false)
		return nil, false
	}
	if len(sb.Signals) > maxBatchEvents {
		h.sendNack(context.Background(), batchMsg.GetSeq(), batchMsg.GetChunkId(), "too_many_events",
			fmt.Sprintf("event count %d exceeds limit %d", len(sb.Signals), maxBatchEvents), false)
		return nil, false
	}
	return sb, true
}

// verifyEnvelopeAlgo 强制 envelope 使用协商算法（Compression + Codec + CipherSuite）。
// 任一不一致即拒绝——防止客户端单方面降级或注入未协商算法（defense-in-depth，
// 即使 HMAC 通过也不允许 wire 字段与权威协商结果不符）。返回 true 表示已发 NACK，调用方中止。
func (h *CoreHandler) verifyEnvelopeAlgo(env *core.SecureEnvelope) bool {
	n := h.negotiated.Load()
	if n == nil {
		return false
	}
	if env.Compression != n.Compression {
		h.sendNack(context.Background(), env.GetSeq(), env.GetChunkId(), CodeEnvelopeAlgoMismatch,
			"compression not negotiated", false)
		return true
	}
	if env.Codec != n.Codec {
		h.sendNack(context.Background(), env.GetSeq(), env.GetChunkId(), CodeEnvelopeAlgoMismatch,
			"codec not negotiated", false)
		return true
	}
	if env.CipherSuite != n.CipherSuite {
		h.sendNack(context.Background(), env.GetSeq(), env.GetChunkId(), CodeEnvelopeAlgoMismatch,
			"cipher suite not negotiated", false)
		return true
	}
	return false
}

// routeAndACK 路由 batch 到 sink 并发送 ACK（core spec §11）。
func (h *CoreHandler) routeAndACK(ctx context.Context, agentID, chunkID string, batchMsg *corepb.BatchMessage, signalBatch *core.SignalBatch, batchEvents int, batchBytes int64) {
	defer h.inflight.Remove(batchEvents, batchBytes)

	// 旁路通知 batch 级 trace 上下文（不改变路由/ACK 逻辑）。仅当 sink 实现
	// BatchTraceSink 且该 batch 携带 TraceContext 时触发；现有 sink 实现零影响。
	if tc := batchMsg.GetTraceContext(); tc != nil {
		if ts, ok := h.config.Sink.(core.BatchTraceSink); ok {
			ts.OnBatchTraceContext(ctx, agentID, tc) // *corepb.TraceContext 即 *core.TraceContext（类型别名）
		}
	}

	ackMode := corepb.AckMode_ACK_MODE_ACCEPTED

	if h.config.Sink != nil {
		if rawSink, ok := h.config.Sink.(core.RawEventSink); ok && signalBatch == nil {
			result, err := rawSink.OnRawBatch(ctx, h.agentID, batchEvents, batchMsg.GetBatch())
			if err != nil {
				slog.Warn("raw routing failed", "error", err)
			} else if h.applyRouteResult(ctx, result, agentID, chunkID, &ackMode) {
				return
			}
		} else if durable, ok := h.config.Sink.(core.DurableEventSink); ok {
			result, err := durable.OnSignalBatchWithResult(ctx, h.agentID, signalBatch)
			if err != nil {
				slog.Warn("durable routing failed", "error", err)
			} else if h.applyRouteResult(ctx, result, agentID, chunkID, &ackMode) {
				return
			}
		} else {
			if err := h.config.Sink.OnSignalBatch(ctx, h.agentID, signalBatch); err != nil {
				slog.Warn("event routing failed", "error", err)
			}
			pressure := h.config.Sink.OnPressure(h.agentID)
			h.applyPressure(ctx, pressure)
		}
	}

	h.sendAck(ctx, batchMsg.GetSeq(), batchMsg.GetChunkId(), batchEvents, ackMode)
	h.config.Metrics.BatchesAcked().Inc()
}

func (h *CoreHandler) applyRouteResult(ctx context.Context, result *core.RouteResult, agentID, chunkID string, ackMode *corepb.AckMode) bool {
	if result == nil {
		return false
	}
	switch result.Status {
	case core.ACKStatusDurable:
		*ackMode = corepb.AckMode_ACK_MODE_DURABLE
		h.replay.Update(agentID, chunkID, core.ReplayDurable)
	case core.ACKStatusThrottle:
		// 重置 replay entry 为 Processing，允许客户端重试时重新投递（否则 replay 仍为 Accepted，
		// 客户端重试会收到 ACK_ACCEPTED 但 batch 从未真正处理，造成静默数据丢失）。
		h.replay.Update(agentID, chunkID, core.ReplayProcessing)
		h.sendThrottle(ctx, throttleRetryMs, "queue_pressure", "queue pressure critical, retry later")
		return true
	default:
		*ackMode = corepb.AckMode_ACK_MODE_ACCEPTED
	}
	if result.Pressure != "" {
		h.applyPressure(ctx, result.Pressure)
	}
	return false
}

// applyPressure 在 pressure 变化时更新窗口并下发 WINDOW（core spec §9.2：取值变化时才发送，
// 避免同值重复）。加锁保证并发 BATCH 的"比较-更新-下发"原子——否则两个 goroutine 可能
// 同时读到旧值并各发一份相同 WINDOW。
func (h *CoreHandler) applyPressure(ctx context.Context, pressure core.PressureState) {
	if pressure == "" {
		return
	}
	h.pressureMu.Lock()
	defer h.pressureMu.Unlock()
	if pressure == h.loadLastPressure() {
		return
	}
	h.lastPressure.Store(pressure)
	b, e, by := pressureToWindow(pressure)
	h.window.Update(b, e, by)
	h.sendWindowUpdate(ctx, b, e, by, string(pressure))
}

func (h *CoreHandler) loadLastPressure() core.PressureState {
	if v := h.lastPressure.Load(); v != nil {
		return v.(core.PressureState)
	}
	return core.PressureNormal
}
