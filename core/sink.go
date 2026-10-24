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
	Seq         uint64        // batch 的 wire 序号（与 RESULT.ref_seq 对应）
	Correlation string        // 发送方对账句柄（Batch.correlation 原样透传）
	EventsCount int           // 事件数（Raw 供给路径不解码即知规模）
	ReceivedAt  time.Time     // 服务端收到该 batch 的时刻
	Trace       *TraceContext // 可选 batch 级 trace（trace_context 能力）
}

// BatchEvent 是投递给 handler 的一个 batch。
// Raw/Decoded 按 SinkOptions 恰一供给（另一个为 nil）。
type BatchEvent struct {
	Agent   string       // 发送方 agent 身份（HELLO.agent_id）
	Meta    BatchMeta    // 投递元信息
	Decoded *SignalBatch // 解码后的 SignalBatch（SinkOptions.Raw=false 时非 nil）
	Raw     []byte       // 解密后的 batch 消息编码字节（SinkOptions.Raw=true 时非 nil）
}

// OutcomeLevel 是投递结果级别（wire 语义见 ResultLevel）。
type OutcomeLevel int8

const (
	// OutcomeUnspecified 是零值：handler 漏设 Level 的诊断标记——协议层按
	// released(internal) 处置并告警（此前零值即 Accepted，漏设字段静默变成
	// 投递成功且 durable 模式合成 DURABLE 终态，review P3-9 裁决：错误显式化）。
	OutcomeUnspecified OutcomeLevel = iota
	// OutcomeAccepted 表示批次已接受：accepted_only 模式下即终态（done 无 wire
	// 效果），durable 模式下协议层将本级别与 Durable 同样处置（推进为 durable 终态）。
	OutcomeAccepted
	// OutcomeDurable 表示批次已持久化完成（终态，durable 模式）。
	OutcomeDurable
	// OutcomeRejected 表示批次被终态拒绝（内容非法/超限；Code 必填错误码注册表值）。
	OutcomeRejected
	// OutcomeReleased 表示本次投递放弃（终态；客户端可用新 seq 重投，RetryAfter 可选）。
	OutcomeReleased
)

// Outcome 是 handler 通过 done 报告的投递结果。Level 必填（零值
// OutcomeUnspecified 会被协议层当 handler 缺陷处置为 released）。
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
//   - Level 必填：OutcomeUnspecified（漏设）→ 协议层合成 released(internal) + 告警；
//   - 超时：SinkDeadline 内未调 → 协议层合成 Outcome{Released, internal}；
//   - panic：per-invocation recover → 合成 released + 计数；
//   - 迟调：连接已关闭后安全丢弃。
type BatchHandler func(ctx context.Context, ev BatchEvent, done func(Outcome))
