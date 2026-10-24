package core

import (
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// 敌意序列回归（审查 F1）：对端持有有效 token 却永不发送 low 指向的 seq，
// 持续发送更高 seq——accepted 曾无界增长（认证后内存 DoS）。trimAcceptedLocked
// 必须沿最小 seq 跳过空洞，使 len(accepted) 恒 ≤ cap+1。
func TestCreditManager_AcceptedBoundedUnderGapAttack(t *testing.T) {
	// 初始 credit 放大：攻击可持续（额度经 Settle→TakeRecovered 返还）。
	m := NewCreditManager(1<<30, 1<<50, 256)
	settle := func(seq uint64) {
		t.Helper()
		ar := m.Admit(seq)
		if ar.Decision != AdmitAccept {
			t.Fatalf("seq %d: decision = %v, want AdmitAccept", seq, ar.Decision)
		}
		if err := ar.Grant.Consume(128); err != nil {
			t.Fatalf("seq %d: Consume: %v", seq, err)
		}
		ar.Grant.Settle(func(*corepb.Result) {}, corepb.ResultLevel_RESULT_LEVEL_RELEASED, 0, 0, 128)
	}
	// 攻击者永不发送 seq=1（low 恒为 1），发送 2..N。
	const n = defaultAcceptedCap + 512
	for seq := uint64(2); seq <= n; seq++ {
		settle(seq)
		m.TakeRecovered() // 模拟 CREDIT 攒批发放，维持攻击可持续
	}
	if len(m.accepted) > defaultAcceptedCap+1 {
		t.Fatalf("len(accepted) = %d, want <= %d (unbounded growth)", len(m.accepted), defaultAcceptedCap+1)
	}
	if m.low == 1 {
		t.Fatalf("low stuck at 1: trim never advanced the watermark")
	}
	// 被跳过空洞（seq < low）重放 → BelowUnknown released（宁重发不吞数据），不重复投递。
	if ar := m.Admit(1); ar.Decision != AdmitBelowUnknown {
		t.Fatalf("replay of skipped seq 1: decision = %v, want AdmitBelowUnknown", ar.Decision)
	}
}

// 顺序流量回归：正常客户端（seq 连续）下 trim 不改变语义——low 推进、accepted 清空。
func TestCreditManager_SequentialTrafficUnaffected(t *testing.T) {
	m := NewCreditManager(1<<20, 1<<40, 256)
	for seq := uint64(1); seq <= 100; seq++ {
		ar := m.Admit(seq)
		if ar.Decision != AdmitAccept {
			t.Fatalf("seq %d: decision = %v", seq, ar.Decision)
		}
		if err := ar.Grant.Consume(64); err != nil {
			t.Fatalf("seq %d: Consume: %v", seq, err)
		}
		ar.Grant.Settle(func(*corepb.Result) {}, corepb.ResultLevel_RESULT_LEVEL_DURABLE, 0, 0, 64)
	}
	if len(m.accepted) != 0 {
		t.Fatalf("len(accepted) = %d, want 0 after contiguous drain", len(m.accepted))
	}
	if m.low != 101 {
		t.Fatalf("low = %d, want 101", m.low)
	}
}

// 负 frameBytes 是守恒核心的反向记账缺口（审查 P2）：必须拒绝、释放占位，
// 绝不允许 outstandingY 反向增加（凭空造出额度）。
func TestSettleGrant_ConsumeRejectsNegativeBytes(t *testing.T) {
	m := NewCreditManager(10, 1<<20, 256)
	beforeY := m.outstandingY
	ar := m.Admit(1)
	if ar.Decision != AdmitAccept {
		t.Fatalf("decision = %v", ar.Decision)
	}
	err := ar.Grant.Consume(-5)
	if err == nil {
		t.Fatal("Consume(-5) must fail")
	}
	if CodeNumOf(err) != CodeInternal {
		t.Fatalf("code = %d, want %d (internal)", CodeNumOf(err), CodeInternal)
	}
	if m.outstandingY != beforeY {
		t.Fatalf("outstandingY = %d, want unchanged %d (credit minted from thin air)", m.outstandingY, beforeY)
	}
	// 占位已释放：同 seq 可重新准入（连接内合法重试路径不残留幽灵占位）。
	if ar2 := m.Admit(1); ar2.Decision != AdmitAccept {
		t.Fatalf("re-admit after negative reject: decision = %v, want AdmitAccept", ar2.Decision)
	}
}
