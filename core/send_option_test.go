package core

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/iuboy/mbta-go/internal/testutil"
)

func TestApplySendOptions(t *testing.T) {
	// 无 opts → 零值 SendConfig（TraceContext == nil），与旧调用行为一致。
	sc := ApplySendOptions(nil)
	if sc.TraceContext != nil {
		t.Errorf("nil opts yielded non-nil TraceContext: %v", sc.TraceContext)
	}

	// WithTraceContext 设置字段（内部 proto.Clone 防御性拷贝，故用 proto.Equal 比较值）。
	traceID, spanID := testutil.RandTraceID(), testutil.RandSpanID()
	tc := &TraceContext{TraceId: traceID, SpanId: spanID}
	sc = ApplySendOptions([]SendOption{WithTraceContext(tc)})
	if !proto.Equal(sc.TraceContext, tc) {
		t.Errorf("TraceContext not set: got %v, want %v", sc.TraceContext, tc)
	}
	// 防御性拷贝：修改原始 tc 不应影响已设置的 SendConfig。
	tc.TraceId = "modified"
	if sc2 := ApplySendOptions([]SendOption{WithTraceContext(&TraceContext{TraceId: testutil.RandTraceID(), SpanId: testutil.RandSpanID()})}); proto.Equal(sc2.TraceContext, tc) {
		t.Error("WithTraceContext should clone, not share pointer")
	}

	// 多次 opts：后者覆盖前者（函数式选项语义）。
	tc2 := &TraceContext{TraceId: testutil.RandTraceID(), SpanId: testutil.RandSpanID()}
	sc = ApplySendOptions([]SendOption{WithTraceContext(tc), WithTraceContext(tc2)})
	if !proto.Equal(sc.TraceContext, tc2) {
		t.Error("last WithTraceContext should win")
	}

	// nil TraceContext 应保持 nil（不 panic）。
	sc = ApplySendOptions([]SendOption{WithTraceContext(nil)})
	if sc.TraceContext != nil {
		t.Errorf("nil TraceContext should yield nil, got %v", sc.TraceContext)
	}
}
