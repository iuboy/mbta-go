package conformance

// credit_test.go：流控与去重数据结构（v2-design §6 模型 B / §7.2 集合制窗口、
// §16-1/2/3）。
//
// CreditLedger（客户端账本）：
//   - RESULT 不隐含返还（返还一律经 CREDIT → OnCredit）；
//   - 零 delta 忽略、超钳制、负值违规丢弃；
//   - reaper 只标记失败不回补（防与服务端视图发散）。
//
// AdmissionWindow（服务端准入）：
//   - 乱序窗内接受、duplicate 幂等、窗外 violation；
//   - 终态环回执（RESULT 丢失后同 seq 重发可答）；
//   - BelowUnknown（环未命中 → 宁重发不吞数据）；
//   - low 水位永不越过在途 seq。

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// === CreditLedger ===

// TestCreditLedger_ConsumeAvailable 验证 consume/available 基本语义与两维额度。
func TestCreditLedger_ConsumeAvailable(t *testing.T) {
	l := core.NewCreditLedger(3, 1000, 0, 0)
	if b, y := l.Available(); b != 3 || y != 1000 {
		t.Fatalf("initial available = (%d,%d), want (3,1000)", b, y)
	}
	if err := l.Consume(1, 300, "c1", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("consume 1: %v", err)
	}
	if b, y := l.Available(); b != 2 || y != 700 {
		t.Errorf("after consume available = (%d,%d), want (2,700)", b, y)
	}
	// 批数维耗尽：3 批额度第 4 次消费必须失败。
	_ = l.Consume(2, 10, "", time.Now().Add(time.Minute))
	_ = l.Consume(3, 10, "", time.Now().Add(time.Minute))
	if err := l.Consume(4, 10, "", time.Now().Add(time.Minute)); err == nil {
		t.Error("4th consume accepted with 3-batch grant")
	} else if core.CodeNumOf(err) != core.CodeWindowExceeded {
		t.Errorf("exhausted code = %d, want %d", core.CodeNumOf(err), core.CodeWindowExceeded)
	}
	// 字节维耗尽。
	l2 := core.NewCreditLedger(10, 100, 0, 0)
	if err := l2.Consume(1, 150, "", time.Now().Add(time.Minute)); err == nil {
		t.Error("consume 150B accepted with 100B grant")
	}
}

// TestCreditLedger_ResultNotImplicitReturn 验证模型 B 核心：RESULT（Terminal）
// 只移除 slot、不返还额度；额度返还只能经 OnCredit（CREDIT 帧）。
func TestCreditLedger_ResultNotImplicitReturn(t *testing.T) {
	l := core.NewCreditLedger(2, 1000, 0, 0)
	if err := l.Consume(1, 400, "c1", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	slot := l.Terminal(1)
	if slot == nil || slot.Seq != 1 || slot.Correlation != "c1" {
		t.Fatalf("terminal slot = %+v, want seq=1 corr=c1", slot)
	}
	if b, y := l.Available(); b != 1 || y != 600 {
		t.Errorf("after RESULT available = (%d,%d), want (1,600)（RESULT 不返还）", b, y)
	}
	if l.Pending() != 0 || !l.Drained() {
		t.Error("ledger not drained after terminal")
	}
	// 未知 seq 的 RESULT：nil slot，无副作用。
	if s := l.Terminal(99); s != nil {
		t.Errorf("terminal for unknown seq returned %+v, want nil", s)
	}
	// CREDIT 返还后才恢复。
	l.OnCredit(1, 400)
	if b, y := l.Available(); b != 2 || y != 1000 {
		t.Errorf("after CREDIT available = (%d,%d), want (2,1000)", b, y)
	}
}

// TestCreditLedger_OnCredit_ValidationRules 验证 CREDIT 校验规则（§6.3）：
// 零 delta 忽略；负值违规丢弃；超 consumed 的返还被钳制。
func TestCreditLedger_OnCredit_ValidationRules(t *testing.T) {
	l := core.NewCreditLedger(5, 5000, 0, 0)
	_ = l.Consume(1, 100, "", time.Now().Add(time.Minute))

	l.OnCredit(0, 0) // 零 delta：忽略
	if b, y := l.Available(); b != 4 || y != 4900 {
		t.Errorf("after zero-delta available = (%d,%d), want (4,4900)", b, y)
	}

	l.OnCredit(-1, 0) // 负 delta：违规丢弃
	l.OnCredit(0, -50)
	if b, y := l.Available(); b != 4 || y != 4900 {
		t.Errorf("after negative delta available = (%d,%d), want (4,4900)", b, y)
	}

	// 超钳制：未消耗却返还（服务端不应返还未消耗额度）→ 钳制到已消耗量。
	l.OnCredit(3, 300)
	if b, y := l.Available(); b != 5 || y != 5000 {
		t.Errorf("after over-return available = (%d,%d), want clamped (5,5000)", b, y)
	}
}

// TestCreditLedger_InitialClamp 验证初始 credit 超本地钳制上限时建账即钳制。
func TestCreditLedger_InitialClamp(t *testing.T) {
	l := core.NewCreditLedger(1<<20, 1<<40, 64, 1<<10)
	if b, y := l.Available(); b != 64 || y != 1<<10 {
		t.Errorf("initial available = (%d,%d), want clamp (64,1024)", b, y)
	}
}

// TestCreditLedger_ReapNoCreditReturn 验证客户端 reaper 职责收缩：
// 超时 slot 标记失败并移出 pending，但严禁回补 credit。
func TestCreditLedger_ReapNoCreditReturn(t *testing.T) {
	l := core.NewCreditLedger(4, 4000, 0, 0)
	past := time.Now().Add(-time.Second)
	_ = l.Consume(1, 100, "", past)                        // 已过期
	_ = l.Consume(2, 100, "", time.Now().Add(time.Minute)) // 未过期

	reaped := l.ReapExpired(time.Now())
	if len(reaped) != 1 || reaped[0].Seq != 1 || !reaped[0].Failed {
		t.Fatalf("reaped = %+v, want only seq=1 marked failed", reaped)
	}
	if b, y := l.Available(); b != 2 || y != 3800 {
		t.Errorf("after reap available = (%d,%d), want (2,3800)（reaper 不回补）", b, y)
	}
	if l.Pending() != 1 {
		t.Errorf("pending = %d, want 1", l.Pending())
	}
	// Reset 清空 pending（close 路径）。
	l.Reset()
	if l.Pending() != 0 || !l.Drained() {
		t.Error("Reset did not clear pending slots")
	}
}

// === CreditManager（服务端准入/去重/守恒，根治版）===

// grantSettle 是测试便利：Admit→Accept 路径的 grant 直接 Settle(durable)。
func grantSettle(m *core.CreditManager, seq uint64, bytes int64) *core.SettleGrant {
	ar := m.Admit(seq)
	if ar.Decision != core.AdmitAccept {
		return nil
	}
	if err := ar.Grant.Consume(bytes); err != nil {
		return nil
	}
	return ar.Grant
}

// TestCreditManager_OutOfOrderAccept 验证集合制去重：乱序接受、duplicate 幂等、
// seq=0 violation（无 cap 判定——超发防线是 Consume 的额度检查）。
func TestCreditManager_OutOfOrderAccept(t *testing.T) {
	m := core.NewCreditManager(8, 1<<20, 8)
	// 乱序：3、1、2 均可接受。
	for _, seq := range []uint64{3, 1, 2} {
		if d := m.Admit(seq).Decision; d != core.AdmitAccept {
			t.Fatalf("Admit(%d) = %v, want Accept（乱序窗内合法）", seq, d)
		}
	}
	// 占位式：Admit(3) 的占位仍在途——同 seq 再 Admit = Duplicate。
	if d := m.Admit(3).Decision; d != core.AdmitDuplicate {
		t.Errorf("Admit(3) while in-flight = %v, want Duplicate（占位防并发双接受）", d)
	}
	if d := m.Admit(0).Decision; d != core.AdmitViolation {
		t.Errorf("Admit(0) = %v, want Violation", d)
	}
}

// TestCreditManager_TerminalRingReplay 乱序终态后的幂等重放（根治缺陷 3）：
// seq=3 先到并终态（1、2 未到，low 停在 1）——重放 seq=3 必须命中终态环
// （不再依赖 low 前缀推进），不得重新接受（否则重复投递）。
func TestCreditManager_TerminalRingReplay(t *testing.T) {
	m := core.NewCreditManager(8, 1<<20, 8)
	g := grantSettle(m, 3, 10)
	if g == nil {
		t.Fatal("grant(3) failed")
	}
	g.Settle(nil, corepb.ResultLevel_RESULT_LEVEL_ACCEPTED, 0, 0, 10)

	// 关键断言：乱序终态（1、2 未到）后重放 3。
	if d := m.Admit(3).Decision; d != core.AdmitTerminalHit {
		t.Errorf("Admit(3) after out-of-order terminal = %v, want TerminalHit（不依赖 low 推进）", d)
	}
	// 顺连补 1、2 后（low 推进过 3），重放仍 TerminalHit。
	g1 := grantSettle(m, 1, 10)
	g2 := grantSettle(m, 2, 10)
	if g1 == nil || g2 == nil {
		t.Fatal("grant(1/2) failed")
	}
	g1.Settle(nil, corepb.ResultLevel_RESULT_LEVEL_ACCEPTED, 0, 0, 10)
	g2.Settle(nil, corepb.ResultLevel_RESULT_LEVEL_ACCEPTED, 0, 0, 10)
	if d := m.Admit(3).Decision; d != core.AdmitTerminalHit {
		t.Errorf("Admit(3) after prefix advance = %v, want TerminalHit", d)
	}
}

// TestCreditManager_BelowUnknownAndEviction 终态环 LRU 淘汰 → BelowUnknown。
func TestCreditManager_BelowUnknownAndEviction(t *testing.T) {
	m := core.NewCreditManager(16, 1<<20, 4) // ring cap 4
	for seq := uint64(1); seq <= 6; seq++ {
		g := grantSettle(m, seq, 1)
		if g == nil {
			t.Fatalf("grant(%d) failed", seq)
		}
		g.Settle(nil, corepb.ResultLevel_RESULT_LEVEL_DURABLE, 0, 0, 1)
	}
	// ring 容量 4：保留 3..6；1、2 淘汰。
	if d := m.Admit(1).Decision; d != core.AdmitBelowUnknown {
		t.Errorf("Admit(1-evicted) = %v, want BelowUnknown", d)
	}
	if d := m.Admit(3).Decision; d != core.AdmitTerminalHit {
		t.Errorf("Admit(3-in-ring) = %v, want TerminalHit", d)
	}
}

// TestCreditManager_CreditExhaustion 无额度发送 → Consume 失败 + 占位自动释放。
func TestCreditManager_CreditExhaustion(t *testing.T) {
	m := core.NewCreditManager(2, 100, 8)
	g1 := grantSettle(m, 1, 10)
	g2 := grantSettle(m, 2, 10)
	if g1 == nil || g2 == nil {
		t.Fatal("grants failed")
	}
	g1.Settle(nil, corepb.ResultLevel_RESULT_LEVEL_DURABLE, 0, 0, 10) // 回收 1 批（未 TakeRecovered：outstanding=0）
	// 剩 0 批：Consume 失败。
	ar := m.Admit(3)
	if ar.Decision != core.AdmitAccept {
		t.Fatalf("Admit(3) = %v", ar.Decision)
	}
	if err := ar.Grant.Consume(20); err == nil {
		t.Fatal("Consume with insufficient credit succeeded")
	}
	// 失败后占位已释放：同 seq 可重新准入。
	if d := m.Admit(3).Decision; d != core.AdmitAccept {
		t.Errorf("Admit(3) after failed Consume = %v, want Accept（占位已释放）", d)
	}
}

// TestCreditManager_Conservation grant 生命周期完整闭环的守恒断言：
// 初始 N → N 次「Consume+Settle」→ TakeRecovered 返还 N → outstanding 复原。
func TestCreditManager_Conservation(t *testing.T) {
	m := core.NewCreditManager(4, 1<<20, 8)
	for seq := uint64(1); seq <= 4; seq++ {
		g := grantSettle(m, seq, 100)
		if g == nil {
			t.Fatalf("grant(%d) failed", seq)
		}
		g.Settle(nil, corepb.ResultLevel_RESULT_LEVEL_DURABLE, 0, 0, 100)
	}
	b, y := m.TakeRecovered()
	if b != 4 || y != 400 {
		t.Errorf("TakeRecovered = %d/%d, want 4/400（守恒：每 grant 恰一次回收）", b, y)
	}
	// 二次 Take 无残留。
	if b2, y2 := m.TakeRecovered(); b2 != 0 || y2 != 0 {
		t.Errorf("second TakeRecovered = %d/%d, want 0/0", b2, y2)
	}
}

// TestCreditManager_DoubleSettleGuard 双 Settle 防双回收（构造性守恒）：
// grant.Settle 两次 + ForceSettle 抢先——额度只回收一次。
func TestCreditManager_DoubleSettleGuard(t *testing.T) {
	m := core.NewCreditManager(2, 1<<20, 8)
	g := grantSettle(m, 1, 50)
	if g == nil {
		t.Fatal("grant failed")
	}
	g.Settle(nil, corepb.ResultLevel_RESULT_LEVEL_DURABLE, 0, 0, 50)
	g.Settle(nil, corepb.ResultLevel_RESULT_LEVEL_DURABLE, 0, 0, 50) // 幂等 no-op
	// reaper 对同一 seq ForceSettle：终态环已命中 → 仅重发 RESULT，不再回收。
	var sent []*corepb.Result
	m.ForceSettle(func(r *corepb.Result) { sent = append(sent, r) }, 1,
		corepb.ResultLevel_RESULT_LEVEL_RELEASED, core.CodeInternal, 0, 50)
	if b, y := m.TakeRecovered(); b != 1 || y != 50 {
		t.Errorf("TakeRecovered = %d/%d, want 1/50（防双回收）", b, y)
	}
	if len(sent) != 1 || sent[0].GetLevel() != corepb.ResultLevel_RESULT_LEVEL_DURABLE {
		t.Errorf("ForceSettle replay = %+v, want 1 durable RESULT（幂等回执=回存储 outcome，非传入 level）", sent)
	}
}

// TestCreditManager_ConcurrentSameSeq 占位防并发双接受（根治缺陷 4：
// Admit→Register 解密间隙的同 seq 双帧）。
func TestCreditManager_ConcurrentSameSeq(t *testing.T) {
	m := core.NewCreditManager(100, 1<<20, 64)
	const workers = 16
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if m.Admit(1).Decision == core.AdmitAccept {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != 1 {
		t.Errorf("concurrent Admit(1): %d Accepts, want 1（占位独占）", got)
	}
}

// TestCreditManager_SemFullPath 直拒路径守恒（根治缺陷 1）：
// 未走完整流水的 Consume+Settle（batchSem 满等）同样恰一次回收。
func TestCreditManager_SemFullPath(t *testing.T) {
	m := core.NewCreditManager(4, 1<<20, 8)
	ar := m.Admit(1)
	if ar.Decision != core.AdmitAccept {
		t.Fatal("admit failed")
	}
	if err := ar.Grant.Consume(77); err != nil {
		t.Fatal(err)
	}
	ar.Grant.Settle(nil, corepb.ResultLevel_RESULT_LEVEL_RELEASED, core.CodeServerDraining, 1000, 77)
	if b, y := m.TakeRecovered(); b != 1 || y != 77 {
		t.Errorf("TakeRecovered = %d/%d, want 1/77（直拒守恒）", b, y)
	}
}
