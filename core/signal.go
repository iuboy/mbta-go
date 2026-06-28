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

// ExponentialHistogram 是 histogram signal 的 exponential bucket 表达（core spec §6.2）。
// 等价 corepb.ExponentialHistogram。
type ExponentialHistogram = corepb.ExponentialHistogram

// ProfilePayload 是 profile signal 载荷 + 跨信号双向关联（core spec §6.2）。
// 等价 corepb.ProfilePayload。
type ProfilePayload = corepb.ProfilePayload

// signal_type 取值（core spec §6.2 闭合枚举）。值发布后不可改（§1.4）。
const (
	SignalTypeLog       = "log"
	SignalTypeGauge     = "gauge"
	SignalTypeCounter   = "counter"
	SignalTypeHistogram = "histogram"
	SignalTypeSummary   = "summary"
	SignalTypeSpan      = "span"
	SignalTypeProfile   = "profile"
)

// validSignalTypes 是 spec §6.2 允许的 signal_type 闭合集合。
// 非法值（含历史误用的 "metric"）在 Validate 被拒——协议入口拦截，防止发出后
// 被合规对端当未知 type 拒绝、且无法映射 OTLP（§15）。
var validSignalTypes = map[string]bool{
	SignalTypeLog: true, SignalTypeGauge: true, SignalTypeCounter: true,
	SignalTypeHistogram: true, SignalTypeSummary: true,
	SignalTypeSpan: true, SignalTypeProfile: true,
}

// Deprecated: "metric" 不在 spec §6.2 的闭合枚举内（{log,gauge,counter,histogram,
// summary,span,profile}），使用 SignalTypeGauge/SignalTypeCounter 等具体类型。
// 保留仅为过渡；Validate 会拒绝该值。
const SignalTypeMetric = "metric"

// SignalBatch 是 BATCH payload 的规范结构，对齐协议文档 §6。
type SignalBatch struct {
	SchemaURL string          `json:"schema_url"`
	Resource  Resource        `json:"resource"`
	Scope     Scope           `json:"scope"`
	Signals   []*SignalRecord `json:"signals"`
}

// signal wire 字段名常量：用于校验报错与 trace ID 格式校验，避免重复 magic string
// （goconst）。这些是协议线路字段名，与 JSON tag 取值一致，发布后不可改（§1.4）。
const (
	fieldTraceID      = "trace_id"
	fieldSpanID       = "span_id"
	fieldParentSpanID = "parent_span_id"
)

// Validate 校验 SignalBatch 必填字段。
func (b *SignalBatch) Validate() error {
	if len(b.Signals) == 0 {
		return NewError(NumValidation, CodeValidation, "signals must not be empty")
	}
	for i, s := range b.Signals {
		if err := validateSignal(i, s); err != nil {
			return err
		}
	}
	return nil
}

// validateSignal 校验单个 SignalRecord：signal_type 合法性、类型特定必填、字段长度与
// trace 上下文约束。拆分自 Validate 以控制认知复杂度。
func validateSignal(i int, s *SignalRecord) error {
	if err := validateSignalType(i, s); err != nil {
		return err
	}
	if err := validateSignalFieldLengths(i, s); err != nil {
		return err
	}
	return validateSignalTraceContext(i, s)
}

// validateSignalType 校验 signal_type 必填、闭合枚举（§6.2，拦截 "metric" 等历史/非法值）
// 以及各 signal_type 的类型特定必填字段。
func validateSignalType(i int, s *SignalRecord) error {
	if s.SignalType == "" {
		return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: signal_type is required", i))
	}
	if !validSignalTypes[s.SignalType] {
		return NewError(NumValidation, CodeValidation,
			fmt.Sprintf("signal[%d]: invalid signal_type %q", i, s.SignalType))
	}
	switch s.SignalType {
	case SignalTypeGauge, SignalTypeCounter, SignalTypeHistogram, SignalTypeSummary:
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
	return nil
}

// signalTextFields 返回参与长度/控制字符校验（L-2）的字段名与值。Body/Attributes 等
// 结构化字段不在此处递归校验。
func signalTextFields(s *SignalRecord) []struct{ name, val string } {
	return []struct{ name, val string }{
		{"signal_type", s.SignalType},
		{"event_id", s.EventID},
		{fieldTraceID, s.TraceID},
		{fieldSpanID, s.SpanID},
		{fieldParentSpanID, s.ParentSpanID},
		{"metric_name", s.MetricName},
		{"unit", s.Unit},
		{"name", s.Name},
		{"kind", s.Kind},
		{"status_code", s.StatusCode},
		{"status_message", s.StatusMessage},
		{"severity_text", s.SeverityText},
	}
}

// validateSignalFieldLengths 校验非空字符串字段的长度与控制字符约束（L-2）：
// 在协议入口拒绝异常长输入与日志注入面。
func validateSignalFieldLengths(i int, s *SignalRecord) error {
	for _, f := range signalTextFields(s) {
		if f.val == "" {
			continue
		}
		if err := validateTextField(f.name, f.val); err != nil {
			return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: %s", i, err.Error()))
		}
	}
	return nil
}

// validateSignalTraceContext 校验 W3C trace 上下文（spec §6.2.1/§6.2.2）：
// trace_id/span_id/parent_span_id 的 hex 格式、trace-flags 的 8 位范围、
// tracestate 成员约束。空 trace ID 合法（表示该 signal 不参与 trace 关联）。
func validateSignalTraceContext(i int, s *SignalRecord) error {
	hexIDs := []struct {
		name      string
		val       string
		wantBytes int
	}{
		{fieldTraceID, s.TraceID, 16},
		{fieldSpanID, s.SpanID, 8},
		{fieldParentSpanID, s.ParentSpanID, 8},
	}
	for _, id := range hexIDs {
		if err := validateHexID(id.name, id.val, id.wantBytes); err != nil {
			return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: %s", i, err.Error()))
		}
	}
	// trace-flags 是 W3C traceparent 的 1 字节字段（仅低 8 位有效）。
	if s.TraceFlags > 0xff {
		return NewError(NumValidation, CodeValidation,
			fmt.Sprintf("signal[%d]: trace_flags exceeds 8-bit W3C range (0x%x)", i, s.TraceFlags))
	}
	// tracestate 为有序键值对（≤ 32 成员）。详见 validation.validateTraceState。
	if err := validateTraceState(s.TraceState); err != nil {
		return NewError(NumValidation, CodeValidation, fmt.Sprintf("signal[%d]: %s", i, err.Error()))
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
	TraceFlags uint32             `json:"trace_flags,omitempty"`
	TraceState []*TraceStateEntry `json:"trace_state,omitempty"`
	// Histogram / Profile 载荷（core spec §6.2）。
	// exp_histogram 用于 signal_type=histogram 且 aggregation=exponential；
	// profile 用于 signal_type=profile（OTLP Profiles 映射，附录 B）。
	ExpHistogram *ExponentialHistogram `json:"exp_histogram,omitempty"`
	Profile      *ProfilePayload       `json:"profile,omitempty"`
}
