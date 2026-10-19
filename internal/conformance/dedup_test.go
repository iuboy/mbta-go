package conformance

// dedup_test.go：集合制窗口去重（v2-design §7.2 / §16-3）。
//
//   - 窗内同 seq 重发 → 幂等回 accepted，handler 只投递一次；
//   - 终态后重发 → 终态环回执存储 outcome（不重复投递）；
//   - 窗外 seq → ABORT(window_exceeded) 拆连接。

import (
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// TestDedup_InWindowDuplicate_Idempotent 验证在途（已接受未终态）同 seq 重发：
// durable 模式下 handler 持有 done 不放，seq 稳定停留在 seen 集合——重发帧全部
// 判定 Duplicate，幂等回 accepted，handler 只投递一次。
func TestDedup_InWindowDuplicate_Idempotent(t *testing.T) {
	sink := newSinkCapture()
	env := startEnv(t, envConfig{
		ackMode:              corepb.AckMode_ACK_MODE_DURABLE,
		initialCreditBatches: 8,
		sinkOpts:             core.SinkOptions{Durable: true},
		sink:                 sink.handler,
	})

	p := env.sendBatch(t, 1, "dup-batch", "corr-dup")
	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED {
		t.Fatalf("first result level = %v, want ACCEPTED", r.GetLevel())
	}
	sink.waitEvent(t, 1, 5*time.Second)
	// done 未调用：seq=1 仍在 seen（在途）。

	// 原样重发两次（模拟客户端未收到 RESULT 的重试）。
	env.tr.DataIn <- MakeFrame(core.TypeBatch, p)
	env.tr.DataIn <- MakeFrame(core.TypeBatch, p)
	for n := range 2 {
		r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
		if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED {
			t.Errorf("duplicate reply #%d level = %v, want ACCEPTED（幂等回执）", n, r.GetLevel())
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := sink.countSeq(1); n != 1 {
		t.Errorf("seq=1 delivered %d times, want exactly 1（去重失效）", n)
	}
	// duplicate 回执的 correlation echo 由 TestResult_CorrelationEcho 断言（已知缺陷 bug-C）。
}

// TestDedup_AfterTerminal_ReplaysStoredOutcome 验证终态环回执：
// seq=1 达成终态（accepted_only 下 accepted 即终态）且窗口滑过后，同 seq 重发
// 回存储的 outcome（accepted），不再投递 handler。
//
// 时序控制：sink handler 收到 seq=1 即代表 window.Terminal(1) 已完成
// （deliver 在 enqueue 前先 sendResult + terminal），此后才发送 seq=2——
// 保证 low 推进到 2，seq=1 的重发落入选中终态环的分支（确定路径）。
func TestDedup_AfterTerminal_ReplaysStoredOutcome(t *testing.T) {
	sink := newSinkCapture()
	env := startEnv(t, envConfig{
		ackMode:              corepb.AckMode_ACK_MODE_ACCEPTED_ONLY,
		initialCreditBatches: 8,
		sink:                 sink.handler,
	})

	p1 := env.sendBatch(t, 1, "first", "")
	AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	sink.waitEvent(t, 1, 5*time.Second) // terminal(1) 已记录

	env.sendBatch(t, 2, "second", "")
	AwaitResult(t, env.tr.Sent, 2, 5*time.Second)
	sink.waitEvent(t, 2, 5*time.Second) // terminal(2) 已记录，low=2

	// 重发 seq=1（窗口下界以下）→ 终态环命中 → 回存储 outcome。
	env.tr.DataIn <- MakeFrame(core.TypeBatch, p1)
	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED {
		t.Errorf("replay result level = %v, want ACCEPTED（回存储 outcome）", r.GetLevel())
	}
	if r.GetCode() != 0 {
		t.Errorf("replay result code = %d, want 0", r.GetCode())
	}
	time.Sleep(200 * time.Millisecond)
	if n := sink.countSeq(1); n != 1 {
		t.Errorf("seq=1 delivered %d times after replay, want 1（终态重发不得重复投递）", n)
	}
	if n := sink.count(); n != 2 {
		t.Errorf("total deliveries = %d, want 2 (seq1+seq2)", n)
	}
}

// TestDedup_BeyondWindow_Aborts 验证超发（客户端额度耗尽仍发送）→
// 协议违规：ABORT(window_exceeded) + 立即拆连接。
// r3 根治版语义：无 cap 数值判定（seq 空间含 DGRAM，按 batches 计的 cap 会
// 误杀混发连接）——超发的唯一防线是额度检查（grant.Consume 失败即 ABORT）。
func TestDedup_BeyondWindow_Aborts(t *testing.T) {
	sink := newSinkCapture()
	env := startEnv(t, envConfig{
		initialCreditBatches: 2,
		sink:                 sink.handler,
	})
	// 耗尽 2 批额度（均被接受），第 3 批超发。
	env.sendBatch(t, 1, "fill-1", "")
	env.sendBatch(t, 2, "fill-2", "")
	env.sendBatch(t, 3, "beyond", "")

	f := AwaitFrame(t, env.tr.Sent, core.TypeAbort, 5*time.Second)
	var a core.AbortMsg
	if err := core.Decode(f.Payload, &a); err != nil {
		t.Fatalf("decode abort: %v", err)
	}
	if a.GetCode() != core.CodeWindowExceeded {
		t.Errorf("abort code = %d (%s), want %d (window_exceeded)",
			a.GetCode(), core.CodeName(a.GetCode()), core.CodeWindowExceeded)
	}
	// 连接必须被拆除：Handle 返回。
	select {
	case <-env.handleErr:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return after window violation")
	}
}
