package protocol

import (
	"strconv"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

func farFuture() time.Time { return time.Now().Add(time.Hour) }

// newTestCoreClient 构造仅账本/回调面可用的 CoreClient（handleCredit/handleResult
// 不触碰 transport；ackQueue 直接注入以捕获 dispatchResult）。
func newTestCoreClient(t *testing.T) *CoreClient {
	t.Helper()
	c := NewCoreClient(nil, CoreClientConfig{AgentID: "agent-1"})
	l := core.NewCreditLedger(10, 1<<20, 0, 0)
	c.ledger.Store(l)
	c.ackQueue = make(chan resultNotify, 8)
	return c
}

// CREDIT 单零维度回归（审查 F2/F3）：服务端合法路径（占位未 Consume 的
// reaper ForceSettle）可产生 CREDIT{b>0, y=0}——此前 fatalTeardown 误拆连接；
// 双零此前同样被误杀（与 CreditLedger.OnCredit 的「双零忽略」实现矛盾）。
func TestHandleCredit_ZeroDimensionsDoNotTeardown(t *testing.T) {
	for name, cr := range map[string]*core.Credit{
		"single-zero batches": {Batches: 1, Bytes: 0},
		"single-zero bytes":   {Batches: 0, Bytes: 128},
		"double-zero":         {Batches: 0, Bytes: 0},
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestCoreClient(t)
			p, err := core.Encode(cr)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			c.handleCredit(p)
			if c.IsClosed() {
				t.Fatalf("handleCredit(%v) torn down the session; want tolerated", cr)
			}
		})
	}
}

// 单零维度经账本钳制后额度正确返还：CREDIT{1,0} 只返还批数维（字节维被
// maxRet 钳制吸收为 0，守恒不破）。
func TestHandleCredit_SingleZeroAppliesLedger(t *testing.T) {
	c := newTestCoreClient(t)
	l := c.ledger.Load()
	if err := l.Consume(1, 512, "", farFuture()); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	p, err := core.Encode(&core.Credit{Batches: 1, Bytes: 0})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	c.handleCredit(p)
	b, y := l.Available()
	if b != 10 || y != 1<<20-512 {
		t.Fatalf("available = (%d, %d), want (10, %d): batches refunded, bytes clamped", b, y, 1<<20-512)
	}
}

// 迟到 RESULT 回归（审查 F5）：slot 已被 AckReaper 超时处置且 timeout 回调已
// 派发后，迟到的真实 RESULT 不再二次回调。
func TestHandleResult_SuppressesDuplicateAfterReap(t *testing.T) {
	c := newTestCoreClient(t)
	l := c.ledger.Load()
	if err := l.Consume(7, 128, "", farFuture()); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	// 模拟 reaper 超时处置：slot 移除 + 登记并派发 timeout 回调。
	reaped := l.ReapExpired(farFuture())
	if len(reaped) != 1 {
		t.Fatalf("reaped = %d, want 1", len(reaped))
	}
	c.markTimedOut(7)
	c.dispatchResult(resultNotify{seq: 7, level: "timeout", code: core.CodeInternal})

	p, err := core.Encode(&core.Result{RefSeq: 7, Level: corepb.ResultLevel_RESULT_LEVEL_RELEASED})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	c.handleResult(p)

	close(c.ackQueue)
	for n := range c.ackQueue {
		if n.level != "timeout" {
			t.Fatalf("late RESULT dispatched level=%q; want suppressed after timeout", n.level)
		}
	}
}

// durable 模式回归：ACCEPTED（中间态）与 DURABLE（终态）都必须到达应用——
// 迟到抑制不得误伤同 seq 的多次合法派发（集成面由 TestIntegration_V1_DurableResult
// 兜底，此处验证队列语义）。
func TestHandleResult_DurableIntermediateAndTerminalBothDispatch(t *testing.T) {
	c := newTestCoreClient(t)
	l := c.ledger.Load()
	if err := l.Consume(9, 128, "", farFuture()); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	for _, lvl := range []corepb.ResultLevel{
		corepb.ResultLevel_RESULT_LEVEL_ACCEPTED,
		corepb.ResultLevel_RESULT_LEVEL_DURABLE,
	} {
		p, err := core.Encode(&core.Result{RefSeq: 9, Level: lvl})
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		c.handleResult(p)
	}
	if got := len(c.ackQueue); got != 2 {
		t.Fatalf("dispatched = %d, want 2 (accepted + durable)", got)
	}
}

// 正常路径回归：slot 在途时 RESULT 正常派发（抑制逻辑不误伤主路径）。
func TestHandleResult_DispatchesInflightResult(t *testing.T) {
	c := newTestCoreClient(t)
	l := c.ledger.Load()
	if err := l.Consume(3, 128, "corr-1", farFuture()); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	p, err := core.Encode(&core.Result{RefSeq: 3, Level: corepb.ResultLevel_RESULT_LEVEL_ACCEPTED, Correlation: "corr-1"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	c.handleResult(p)
	select {
	case n := <-c.ackQueue:
		if n.seq != 3 || n.correlation != "corr-1" {
			t.Fatalf("notify = %+v", n)
		}
	default:
		t.Fatal("inflight RESULT not dispatched")
	}
}

// seenCommands 环形淘汰回归（审查 F4）：满容量后新命令不得因整体清空而
// 立即遗忘——最旧条目按到达序淘汰，刚插入的 ID 仍可去重。
func TestMarkSeenCommand_RingEvictsOldestNotNewest(t *testing.T) {
	c := newTestCoreClient(t)
	for i := 0; i <= maxSeenCommands; i++ { // 填满 + 溢出 1 条：触发淘汰
		if c.markSeenCommand(cmdID(i)) {
			t.Fatalf("command %d reported duplicate on first sight", i)
		}
	}
	c.seenCmdMu.Lock()
	_, newestSeen := c.seenCommands[cmdID(maxSeenCommands)]
	_, oldestStillThere := c.seenCommands[cmdID(0)]
	c.seenCmdMu.Unlock()
	// 最新插入的第 257 条必须仍在窗口内（此前整体清空会把它一并遗忘 → 重复执行）。
	if !newestSeen {
		t.Fatal("newest command id evicted immediately (clear-on-full regression)")
	}
	// 溢出 1 条仅淘汰最旧 1 条：ID 0 已淘汰。
	if oldestStillThere {
		t.Fatal("oldest command id not evicted; ring eviction not working")
	}
	// 窗口内的重复 ID 命中去重（锁已释放，可安全调用簿记方法）。
	if !c.markSeenCommand(cmdID(maxSeenCommands)) {
		t.Fatal("in-window duplicate not detected")
	}
}

func cmdID(i int) string { return "cmd-" + strconv.Itoa(i) }
