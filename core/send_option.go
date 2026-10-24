package core

import (
	"google.golang.org/protobuf/proto"
)

// SendConfig 承载 per-call 发送选项，是变参 SendOption 的聚合目标。
// 仅含可选字段，零值即「不启用任何选项」，与不传 opts 的旧行为完全一致。
type SendConfig struct {
	// TraceContext 是 batch 级 W3C trace 上下文（capability trace_context）。
	// 非 nil 时由发送路径设到 Batch.Trace（proto field 3，随 Batch 编码进入
	// Envelope 密文），不进入 SignalBatch payload 的 marshal 字节。nil 表示该
	// batch 不携带 batch 级 trace（混装多 trace 场景应保持 nil，改用 SignalRecord
	// 的 per-signal trace 字段）。
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
// 服务端对携带的 TraceContext 做 W3C 格式校验（ValidateBatchTraceContext），
// 非法判 batch_invalid。
func WithTraceContext(tc *TraceContext) SendOption {
	// 防御性拷贝：TraceContext 经 ApplySendOptions → SendBatch/SendDatagram 的
	// encodeAndSeal 设到 Batch.Trace（protobuf 字段）。若共享调用方的指针，
	// 调用方在发送并发期间修改字段会与编码构成 data race 与语义错误。
	return func(sc *SendConfig) {
		if tc == nil {
			sc.TraceContext = nil
			return
		}
		sc.TraceContext = proto.Clone(tc).(*TraceContext)
	}
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
