package core

import (
	"fmt"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// TraceStateEntry 是 W3C tracestate 的有序键值对成员（core spec §6.2.2 / W3C Trace Context）。
// 等价 corepb.TraceStateEntry。
type TraceStateEntry = corepb.TraceStateEntry

// TraceContext 是 batch/stream 级 W3C trace 上下文继承点（core spec §6.2.2，
// capability w3c_trace_context）。等价 corepb.TraceContext。
type TraceContext = corepb.TraceContext

// signal_type 取值（core spec §6.2）。
const (
	SignalTypeLog    = "log"
	SignalTypeMetric = "metric"
	SignalTypeSpan   = "span"
)

// SignalBatch 是 BATCH payload 的规范结构，对齐协议文档 §6。
type SignalBatch struct {
	SchemaURL string          `json:"schema_url"`
	Resource  Resource        `json:"resource"`
	Scope     Scope           `json:"scope"`
	Signals   []*SignalRecord `json:"signals"`
}

// Validate 校验 SignalBatch 必填字段。
func (b *SignalBatch) Validate() error {
	if len(b.Signals) == 0 {
		return NewError(NumValidation, CodeValidation, "signals must not be empty")
	}
	for i, s := range b.Signals {
		if s.SignalType == "" {
			return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: signal_type is required", i))
		}
		// 基于 signal_type 的类型特定校验
		switch s.SignalType {
		case SignalTypeMetric:
			if s.MetricName == "" {
				return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: metric_name is required for metric type", i))
			}
		case SignalTypeSpan:
			if s.Name == "" {
				return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: name is required for span type", i))
			}
			if s.TraceID == "" {
				return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: trace_id is required for span type", i))
			}
		case SignalTypeLog:
			if s.Body == nil {
				return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: body is required for log type", i))
			}
		}

		// 字段长度与控制字符约束 (L-2)：在协议入口拒绝异常长输入与日志注入面。
		// 仅校验非空字段；Body/Attributes 等结构化字段不在此处递归校验。
		for _, f := range []struct{ name, val string }{
			{"signal_type", s.SignalType},
			{"event_id", s.EventID},
			{"trace_id", s.TraceID},
			{"span_id", s.SpanID},
			{"parent_span_id", s.ParentSpanID},
			{"metric_name", s.MetricName},
			{"unit", s.Unit},
			{"name", s.Name},
			{"kind", s.Kind},
			{"status_code", s.StatusCode},
			{"status_message", s.StatusMessage},
			{"severity_text", s.SeverityText},
		} {
			if f.val == "" {
				continue
			}
			if err := validateTextField(f.name, f.val); err != nil {
				return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: %s", i, err.Error()))
			}
		}

		// trace 上下文 ID 格式约束（spec §6.2.1）：非空时必须是 W3C/OTel 格式
		// （小写 hex + 正确长度 + 非全零），支撑 signal_type="span" 无损映射 OTLP。
		// 空值合法（表示不参与 trace 关联）。
		if err := validateHexID("trace_id", s.TraceID, 16); err != nil {
			return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: %s", i, err.Error()))
		}
		if err := validateHexID("span_id", s.SpanID, 8); err != nil {
			return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: %s", i, err.Error()))
		}
		if err := validateHexID("parent_span_id", s.ParentSpanID, 8); err != nil {
			return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: %s", i, err.Error()))
		}

		// W3C Trace Context（capability w3c_trace_context，§6.2.2）：
		// trace-flags 是 W3C traceparent 的 1 字节字段（仅低 8 位有效）；
		// tracestate 为有序键值对（≤ 32 成员）。详见 validation.validateTraceState。
		if s.TraceFlags > 0xff {
			return NewError(NumValidation, CodeValidation,
				fmt.Sprintf("signal[%d]: trace_flags exceeds 8-bit W3C range (0x%x)", i, s.TraceFlags))
		}
		if err := validateTraceState(s.TraceState); err != nil {
			return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: %s", i, err.Error()))
		}
	}
	return nil
}

// Resource 产生信号的实体属性。
type Resource struct {
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Scope 采集器或插件信息。
type Scope struct {
	Name        string `json:"name,omitempty"`
	Version     string `json:"version,omitempty"`
	CollectorID string `json:"collector_id,omitempty"`
}

// SignalRecord 统一信号记录外壳。
type SignalRecord struct {
	SignalType     string         `json:"signal_type"` // 必填，禁止空字符串
	EventID        string         `json:"event_id,omitempty"`
	TimeUnixMs     int64          `json:"time_unix_ms"`
	ObservedTimeMs int64          `json:"observed_time_unix_ms,omitempty"`
	TraceID        string         `json:"trace_id,omitempty"`
	SpanID         string         `json:"span_id,omitempty"`
	ParentSpanID   string         `json:"parent_span_id,omitempty"`
	Attributes     map[string]any `json:"attributes,omitempty"`
	Body           any            `json:"body,omitempty"`
	SeverityNumber int            `json:"severity_number,omitempty"`
	SeverityText   string         `json:"severity_text,omitempty"`
	// 指标字段
	MetricName   string             `json:"metric_name,omitempty"`
	MetricFields map[string]float64 `json:"metric_fields,omitempty"`
	Unit         string             `json:"unit,omitempty"`
	Temporality  string             `json:"temporality,omitempty"`
	IsMonotonic  bool               `json:"is_monotonic,omitempty"`
	// Span 字段
	Name            string `json:"name,omitempty"`
	Kind            string `json:"kind,omitempty"`
	StartTimeUnixMs int64  `json:"start_time_unix_ms,omitempty"`
	EndTimeUnixMs   int64  `json:"end_time_unix_ms,omitempty"`
	StatusCode      string `json:"status_code,omitempty"`
	StatusMessage   string `json:"status_message,omitempty"`
	// W3C Trace Context 字段（capability w3c_trace_context，core spec §6.2.2）。
	// trace_flags 承载 traceparent 的采样位等（低 8 位有效）；
	// trace_state 承载 W3C tracestate（有序键值对）。
	// 这两个字段与 trace_id/span_id/parent_span_id 一起构成完整的 W3C traceparent 语义，
	// 使外部请求携带的 traceparent 能在协议层无损承载，而非退化塞入 attributes。
	TraceFlags uint32            `json:"trace_flags,omitempty"`
	TraceState []*TraceStateEntry `json:"trace_state,omitempty"`
}
