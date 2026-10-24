package protocol

import (
	"testing"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// Outcome 零值语义回归（review P3-9 裁决）：done 漏设 Level 此前零值=Accepted，
// durable 模式会静默合成 DURABLE 终态（数据未落盘却回执已持久化）。现在
// Unspecified 合成 released(internal)——客户端按可重试路径收敛。
func TestMakeDone_UnspecifiedLevelSynthesizesReleased(t *testing.T) {
	ft := &fakeCommandTransport{written: make(chan core.Frame, 8)}
	m := core.NewCreditManager(10, 1<<20, 256)
	h := &CoreHandler{tr: ft, credit: m} // makeDone→Settle 触发 lazy flush，credit 必须就位
	ar := m.Admit(1)
	if err := ar.Grant.Consume(128); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	done := h.makeDone(ar.Grant, true)
	done(core.Outcome{}) // 漏设 Level（零值 Unspecified）

	// 终态环经 ForceSettle 幂等重放读取：必须是 released/internal。
	var got *corepb.Result
	m.ForceSettle(func(r *corepb.Result) { got = r }, 1,
		corepb.ResultLevel_RESULT_LEVEL_RELEASED, core.CodeInternal, 1000, 128)
	if got == nil {
		t.Fatal("batch not settled by unspecified-outcome done")
	}
	if got.Level != corepb.ResultLevel_RESULT_LEVEL_RELEASED || got.Code != core.CodeInternal {
		t.Fatalf("settled as %v/code=%d; want released/internal (zero value must NOT synthesize durable)",
			got.Level, got.Code)
	}
}

// 正常显式 Level 对照：DURABLE 语义不变。
func TestMakeDone_ExplicitDurableSettlesDurable(t *testing.T) {
	ft := &fakeCommandTransport{written: make(chan core.Frame, 8)}
	m := core.NewCreditManager(10, 1<<20, 256)
	h := &CoreHandler{tr: ft, credit: m}
	ar := m.Admit(2)
	if err := ar.Grant.Consume(128); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	h.makeDone(ar.Grant, true)(core.Outcome{Level: core.OutcomeDurable})

	var got *corepb.Result
	m.ForceSettle(func(r *corepb.Result) { got = r }, 2,
		corepb.ResultLevel_RESULT_LEVEL_RELEASED, core.CodeInternal, 1000, 128)
	if got == nil {
		t.Fatal("batch not settled")
	}
	if got.Level != corepb.ResultLevel_RESULT_LEVEL_DURABLE {
		t.Fatalf("settled as %v; want durable", got.Level)
	}
}

// accepted_only 模式：done 无 wire 效果（含 Unspecified 分支不 panic、不触发终态）。
func TestMakeDone_AcceptedOnlyIgnoresDone(t *testing.T) {
	ft := &fakeCommandTransport{written: make(chan core.Frame, 8)}
	m := core.NewCreditManager(10, 1<<20, 256)
	h := &CoreHandler{tr: ft, credit: m}
	ar := m.Admit(3)
	if err := ar.Grant.Consume(128); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	h.makeDone(ar.Grant, false)(core.Outcome{}) // 零值 + accepted_only：仅告警

	if got := m.Pending(); got != 1 {
		t.Fatalf("pending = %d, want 1 (accepted_only done must not settle)", got)
	}
}
