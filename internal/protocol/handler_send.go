package protocol

import (
	"context"
	"crypto/rand"
	"log/slog"
	"reflect"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// ===== 帧发送（均走 control channel）=====

func (h *CoreHandler) sendAck(ctx context.Context, seq uint64, chunkID []byte, count int, ackMode corepb.AckMode) {
	ack := &corepb.AckMessage{Seq: seq, ChunkId: chunkID, Count: int32(count), AckMode: ackMode, ReceivedAtUnixMs: time.Now().UnixMilli()} //nolint:gosec // G115: count bounded by maxBatchEvents
	p, err := core.Encode(ack)
	if err != nil {
		slog.Warn("encode ack failed", "error", err)
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeAck, core.FlagControl, p); err != nil {
		slog.Warn("write ack failed", "error", err)
	}
	h.config.Metrics.BatchesAcked().Inc()
}

func (h *CoreHandler) sendNack(ctx context.Context, seq uint64, chunkID []byte, code, reason string, retryable bool) {
	nack := &corepb.NackMessage{Seq: seq, ChunkId: chunkID, Code: code, Reason: reason, Retryable: retryable}
	p, err := core.Encode(nack)
	if err != nil {
		slog.Warn("encode nack failed", "error", err)
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeNack, core.FlagControl, p); err != nil {
		slog.Warn("write nack failed", "error", err)
	}
	h.config.Metrics.BatchesNacked().Inc()
}

func (h *CoreHandler) sendThrottle(ctx context.Context, retryDelayMs int, code, reason string) {
	t := &corepb.ThrottleMessage{RetryDelayMs: int32(retryDelayMs), Code: code, Reason: reason}
	p, err := core.Encode(t)
	if err != nil {
		slog.Warn("encode throttle failed", "error", err)
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeThrottle, core.FlagControl, p); err != nil {
		slog.Warn("write throttle failed", "error", err)
	}
	h.config.Metrics.Throttled().Inc()
	h.config.Metrics.ThrottleSeconds().Add(float64(retryDelayMs) / 1000)
}

// failAuth 发 AUTH_FAIL 并轮换 challengeNonce（每次在线验证用新挑战）。
func (h *CoreHandler) failAuth(ctx context.Context, code, reason string) {
	// 轮换 nonce；失败时保留旧 nonce（此处已是错误处理路径，最坏情况是下一次
	// 挑战复用旧值，优于丢弃 AUTH_FAIL 不响应）。AUTH_FAIL 帧仍可发送。
	if nonce, err := randBytes(challengeNonceLen); err != nil {
		slog.Warn("rotate challenge nonce failed, keeping previous", "error", err)
	} else {
		h.setChallengeNonce(nonce)
	}
	fail := &corepb.AuthFailMessage{Code: code, Reason: reason, Retryable: true, ChallengeNonce: h.getChallengeNonce()}
	p, err := core.Encode(fail)
	if err != nil {
		slog.Warn("encode auth_fail failed", "error", err)
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeAuthFail, core.FlagControl, p); err != nil {
		slog.Warn("write auth_fail failed", "error", err)
	}
}

func (h *CoreHandler) sendAuthFail(ctx context.Context, code, reason string, retryable bool) {
	fail := &corepb.AuthFailMessage{Code: code, Reason: reason, Retryable: retryable}
	p, err := core.Encode(fail)
	if err != nil {
		slog.Warn("encode auth_fail failed", "error", err)
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeAuthFail, core.FlagControl, p); err != nil {
		slog.Warn("write auth_fail failed", "error", err)
	}
	h.config.Metrics.AuthFailure().Inc()
}

func (h *CoreHandler) sendError(ctx context.Context, code, reason string, fatal bool) {
	e := &corepb.ErrorMessage{Code: code, Reason: reason, Fatal: fatal, Retryable: !fatal}
	p, err := core.Encode(e)
	if err != nil {
		slog.Warn("encode error frame failed", "error", err)
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeError, core.FlagControl, p); err != nil {
		slog.Warn("write error frame failed", "error", err, "fatal", fatal)
	}
}

func (h *CoreHandler) sendWindowUpdate(ctx context.Context, batches, events int, maxBytes int64, reason string) {
	w := &corepb.WindowMessage{MaxInflightBatches: int32(batches), MaxInflightEvents: int32(events), MaxInflightBytes: maxBytes, Reason: reason}
	p, err := core.Encode(w)
	if err != nil {
		slog.Warn("encode window frame failed", "error", err)
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeWindow, core.FlagControl, p); err != nil {
		slog.Warn("write window frame failed", "error", err)
	}
}

func pressureToWindow(pressure core.PressureState) (batches, events int, maxBytes int64) {
	switch pressure {
	case core.PressureDegraded:
		return windowMaxBatches / 2, windowMaxEvents / 2, windowMaxBytes / 2
	case core.PressureCritical:
		return windowMaxBatches / 10, windowMaxEvents / 10, windowMaxBytes / 10
	default:
		return windowMaxBatches, windowMaxEvents, windowMaxBytes
	}
}

// ===== helpers =====

// randBytes 生成 n 字节密码学随机数。
//
// crypto/rand.Read 在现代系统上极少失败，但失败时绝不应回退到可预测的时间戳
// 派生值——那会产出可猜测的 challenge nonce / session key，破坏 challenge-response
// 与会话机密性。故失败时直接返回 error，让调用方中断该次握手而非使用弱随机。
func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// chunkIDText 把 wire chunk_id（ULID 16B）转为文本作 ReplayCache/spool key。
func chunkIDText(chunkID []byte) string {
	if c, err := core.ChunkIDFromBytes(chunkID); err == nil {
		return c.String()
	}
	return string(chunkID) // fallback（非 16B 时）
}

// isNilMetrics 报告 Metrics 接口是否为 nil 或底层值为 typed-nil 指针。
// 安全处理值类型实现（NoOpMetrics 是 struct，IsNil 不适用）。
func isNilMetrics(m core.Metrics) bool {
	if m == nil {
		return true
	}
	v := reflect.ValueOf(m)
	// 仅对指针/接口/chan/map/slice 类型检查 IsNil；值类型（如 NoOpMetrics）非 nil。
	if v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		return v.IsNil()
	}
	return false
}
