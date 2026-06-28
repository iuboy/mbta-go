package core

import "testing"

func TestApplySendOptions(t *testing.T) {
	// 无 opts → 零值 SendConfig（TraceContext == nil），与旧调用行为一致。
	sc := ApplySendOptions(nil)
	if sc.TraceContext != nil {
		t.Errorf("nil opts yielded non-nil TraceContext: %v", sc.TraceContext)
	}

	// WithTraceContext 设置字段。
	tc := &TraceContext{TraceId: "0123456789abcdef0123456789abcdef", SpanId: "0123456789abcdef"}
	sc = ApplySendOptions([]SendOption{WithTraceContext(tc)})
	if sc.TraceContext != tc {
		t.Errorf("TraceContext not set: got %v, want %v", sc.TraceContext, tc)
	}

	// 多次 opts：后者覆盖前者（函数式选项语义）。
	tc2 := &TraceContext{TraceId: "fedcba9876543210fedcba9876543210", SpanId: "fedcba9876543210"}
	sc = ApplySendOptions([]SendOption{WithTraceContext(tc), WithTraceContext(tc2)})
	if sc.TraceContext != tc2 {
		t.Error("last WithTraceContext should win")
	}
}
