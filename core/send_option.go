package core

// SendConfig 承载 per-call 发送选项，是变参 SendOption 的聚合目标。
// 仅含可选字段，零值即「不启用任何选项」，与不传 opts 的旧行为完全一致。
type SendConfig struct {
	// TraceContext 是 batch 级 W3C trace 上下文（capability w3c_trace_context，
	// spec §6.2.2）。非 nil 时由 CoreClient 设到 BatchMessage.TraceContext（field 7），
	// 不进入 SignalBatch 的 marshal 字节。nil 表示该 batch 不携带 batch 级 trace
	// （混装多 trace 场景应保持 nil，改用 SignalRecord 的 per-signal trace 字段）。
	TraceContext *TraceContext
}

// SendOption 是发送类 API 的 per-call 选项，参照 ClientOption 的函数式选项范式。
// 变参形态保证旧调用（不传 opts）零改动兼容。
type SendOption func(*SendConfig)

// WithTraceContext 携带 batch 级 W3C trace 上下文（整批共享一个 trace 的优化承载）。
//
// 适用前提：整个 batch 属于同一 trace（如 trace 聚合器收集单 trace 的全部 span）。
// 若 batch 混装多个不同 trace_id 的 signal（FIFO 攒批的常见形态），不应使用本选项——
// 应改用每个 SignalRecord 的 per-signal trace 字段（TraceID/SpanID/ParentSpanID/
// TraceFlags/TraceState），下游按 trace_id 重组。batch 级 TraceContext 与 per-signal
// trace 是协同设计：前者是整批基线，后者是偏离覆盖。
//
// 需对端握手协商 w3c_trace_context，否则发送端在门控阶段显式报错（不静默丢弃）。
func WithTraceContext(tc *TraceContext) SendOption {
	return func(sc *SendConfig) { sc.TraceContext = tc }
}

// ApplySendOptions 聚合变参为 SendConfig，供各发送层统一解析。
// 显式导出以便 internal/protocol 层跨包调用。
func ApplySendOptions(opts []SendOption) SendConfig {
	var sc SendConfig
	for _, opt := range opts {
		opt(&sc)
	}
	return sc
}
