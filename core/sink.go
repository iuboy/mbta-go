package core

// sink.go：r3 数据投递 API（注册式单接口，替代 v1 的 6 接口矩阵）。
//
// 能力在注册时静态声明（SinkOptions），协议层据此选择供给路径——
// Raw+Async 组合静默丢数据这类接口矩阵缺陷在结构上不可表达。

import (
	"context"
	"time"
)

// SinkOptions 是 sink handler 注册时声明的供给偏好。
type SinkOptions struct {
	Raw     bool // 供给原始编码字节（跳过逐事件解码）；Raw=true 时 BatchEvent.Raw 非 nil
	Durable bool // handler 会调用 done 表达持久化结果（服务端 ack_mode=durable 的前置）
	Async   bool // done 允许在 handler 返回后异步调用（协议层保证幂等与超时合成）
}

// BatchMeta 是 batch 的投递元信息。
type BatchMeta struct {
	Seq         uint64
	Correlation string
	EventsCount int
	ReceivedAt  time.Time
	Trace       *TraceContext // 可选（trace_context 能力）
}

// BatchEvent 是投递给 handler 的一个 batch。
// Raw/Decoded 按 SinkOptions 恰一供给（另一个为 nil）。
type BatchEvent struct {
	Agent   string
	Meta    BatchMeta
	Decoded *SignalBatch
	Raw     []byte
}

// OutcomeLevel 是投递结果级别（wire 语义见 ResultLevel）。
type OutcomeLevel int8

const (
	OutcomeAccepted OutcomeLevel = iota
	OutcomeDurable
	OutcomeRejected
	OutcomeReleased
)

// Outcome 是 handler 通过 done 报告的投递结果。
type Outcome struct {
	Level      OutcomeLevel
	Code       uint32        // Rejected 时必填（错误码注册表）
	RetryAfter time.Duration // Released 时可选
}

// BatchHandler 是注册的数据投递回调。
//
// done 契约（规范性 MUST，docs/v2-design.md §11.1）：
//   - 幂等：首调生效，后续调用安全丢弃；
//   - 单调：accepted 已发出后合法收缩为 Durable|Released；
//   - 超时：SinkDeadline 内未调 → 协议层合成 Outcome{Released, internal}；
//   - panic：per-invocation recover → 合成 released + 计数；
//   - 迟调：连接已关闭后安全丢弃。
type BatchHandler func(ctx context.Context, ev BatchEvent, done func(Outcome))
