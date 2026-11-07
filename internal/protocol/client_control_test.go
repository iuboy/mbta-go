package protocol

import (
	"context"
	"strconv"
	"strings"
	"sync/atomic"
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
	// 模拟 reaper 超时处置：slot 移除 + timedOut 登记（账本锁内，ReapExpired
	// 一并完成）+ 派发 timeout 回调。
	reaped := l.ReapExpired(farFuture())
	if len(reaped) != 1 {
		t.Fatalf("reaped = %d, want 1", len(reaped))
	}
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

// --- 审查修复回归（2026-11 对抗性检查批次）：RESULT 防线与命令限流 ---

// stubClientTransport 是客户端命令/RESULT 路径测试的最小传输桩（记录写出帧）。
type stubClientTransport struct {
	written chan core.Frame
}

func (s *stubClientTransport) ReadFrame(ctx context.Context) (core.Frame, error) {
	<-ctx.Done()
	return core.Frame{}, ctx.Err()
}

func (s *stubClientTransport) WriteFrame(_ context.Context, typ uint8, payload []byte) error {
	s.written <- core.Frame{Header: core.Header{Type: typ, Length: uint64(len(payload))}, Payload: payload}
	return nil
}

func (s *stubClientTransport) CloseConn() error { return nil }

// TestHandleResult_InvalidLevelDropped 验证非法 level（含零值 UNSPECIFIED）的
// RESULT 被丢弃（spec §7.1 MUST）：不触达回调、不触碰账本。
func TestHandleResult_InvalidLevelDropped(t *testing.T) {
	c := newTestCoreClient(t)
	if err := c.ledger.Load().Consume(3, 64, "", farFuture()); err != nil {
		t.Fatal(err)
	}
	for _, lvl := range []corepb.ResultLevel{
		corepb.ResultLevel_RESULT_LEVEL_UNSPECIFIED,
		corepb.ResultLevel(99),
	} {
		p, err := core.Encode(&core.Result{RefSeq: 3, Level: lvl})
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		c.handleResult(p)
	}
	if n := len(c.ackQueue); n != 0 {
		t.Fatalf("invalid-level results dispatched %d callbacks, want 0", n)
	}
	if c.ledger.Load().Pending() != 1 {
		t.Fatal("invalid-level result must not terminal the slot")
	}
}

// TestHandleResult_OversizedCorrelationSanitized 验证恶意服务端超大
// correlation 被清洗为空串（终态记账继续——slot 正常移出，仅回显字段不可信）。
func TestHandleResult_OversizedCorrelationSanitized(t *testing.T) {
	c := newTestCoreClient(t)
	if err := c.ledger.Load().Consume(5, 64, "", farFuture()); err != nil {
		t.Fatal(err)
	}
	p, err := core.Encode(&core.Result{
		RefSeq:      5,
		Level:       corepb.ResultLevel_RESULT_LEVEL_DURABLE,
		Correlation: strings.Repeat("x", core.MaxBatchCorrelationLen+1),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	c.handleResult(p)

	if n := len(c.ackQueue); n != 1 {
		t.Fatalf("dispatched %d callbacks, want 1（清洗不清除派发）", n)
	}
	n := <-c.ackQueue
	if n.correlation != "" {
		t.Errorf("correlation = %q..., want sanitized empty", n.correlation[:min(16, len(n.correlation))])
	}
	if c.ledger.Load().Pending() != 0 {
		t.Error("slot not terminal after oversized-correlation result")
	}
}

// TestDispatchCommand_LongIDRejected 验证超限 command_id 被拒绝（不登记幂等
// 窗口、不执行、不回 ACK——恶意帧静默丢弃）。
func TestDispatchCommand_LongIDRejected(t *testing.T) {
	c := newTestCoreClient(t)
	st := &stubClientTransport{written: make(chan core.Frame, 4)}
	c.SetTransport(st)
	c.negCaps.Store([]string{core.CapControlCommands})
	var called atomic.Bool
	c.SetCommandHandler(func(context.Context, *corepb.ControlCommand) (corepb.CommandAckCode, string) {
		called.Store(true)
		return corepb.CommandAckCode_COMMAND_ACK_CODE_APPLIED, ""
	})

	p, err := core.Encode(&corepb.ControlCommand{CommandId: strings.Repeat("i", maxCommandIDLen+1)})
	if err != nil {
		t.Fatal(err)
	}
	c.dispatchCommand(context.Background(), p)

	if called.Load() {
		t.Error("handler invoked for oversized command_id")
	}
	select {
	case f := <-st.written:
		t.Fatalf("frame 0x%02x written for oversized command_id, want silent drop", f.Header.Type)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestDispatchCommand_SlotsFullFastReject 验证命令槽满时快失败：立即回
// COMMAND_ACK(failed)（服务端 SendCommand 立刻拿到失败而非等满 ACK 超时）。
func TestDispatchCommand_SlotsFullFastReject(t *testing.T) {
	c := newTestCoreClient(t)
	st := &stubClientTransport{written: make(chan core.Frame, 16)}
	c.SetTransport(st)
	c.negCaps.Store([]string{core.CapControlCommands})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c.SetCommandHandler(func(context.Context, *corepb.ControlCommand) (corepb.CommandAckCode, string) {
		<-release // 钉满全部命令槽
		return corepb.CommandAckCode_COMMAND_ACK_CODE_APPLIED, ""
	})

	// 先发 maxCommandHandlers 条（各自钉一个槽），再发一条触发满槽路径。
	for i := range maxCommandHandlers + 1 {
		p, err := core.Encode(&corepb.ControlCommand{CommandId: "cmd-" + strconv.Itoa(i)})
		if err != nil {
			t.Fatal(err)
		}
		c.dispatchCommand(context.Background(), p)
	}

	// 满槽的一条立即回 failed ACK。
	deadline := time.After(2 * time.Second)
	for {
		select {
		case f := <-st.written:
			if f.Header.Type != core.TypeCommandAck {
				t.Fatalf("unexpected frame 0x%02x", f.Header.Type)
			}
			var ack corepb.ControlCommandAck
			if err := core.Decode(f.Payload, &ack); err != nil {
				t.Fatal(err)
			}
			if ack.GetCode() == corepb.CommandAckCode_COMMAND_ACK_CODE_FAILED {
				if ack.GetMessage() != "command concurrency limit" {
					t.Errorf("reject message = %q, want concurrency limit", ack.GetMessage())
				}
				return // 满槽快失败已证实
			}
		case <-deadline:
			t.Fatal("no fast-fail COMMAND_ACK when handler slots full")
		}
	}
}

// TestDrain_CountPredicateWaitsForAllSeqs 验证 drain 判定是计数谓词
// （spec §3.7/§12.6-4）：乱序 durable（seq2 先终态、seq1 未终态）下 drain 不得
// 提前返回——max 谓词回归会在乱序场景提前关连接丢数据。同时钉住 durable 模式
// accepted 中间态不参与 drain 收敛（slot 保留至终态）。
func TestDrain_CountPredicateWaitsForAllSeqs(t *testing.T) {
	c := newTestCoreClient(t)
	c.ackMode.Store(corepb.AckMode_ACK_MODE_DURABLE)
	l := c.ledger.Load()
	for _, seq := range []uint64{1, 2} {
		if err := l.Consume(seq, 128, "", farFuture()); err != nil {
			t.Fatal(err)
		}
	}

	// 先到 accepted（中间态）：slot 必须保留（drain 不因中间态收敛）。
	pa, err := core.Encode(&core.Result{RefSeq: 1, Level: corepb.ResultLevel_RESULT_LEVEL_ACCEPTED})
	if err != nil {
		t.Fatal(err)
	}
	c.handleResult(pa)
	if l.Pending() != 2 {
		t.Fatalf("pending after intermediate accepted = %d, want 2（中间态不移出 slot）", l.Pending())
	}

	done := make(chan struct{})
	go func() { c.drain(); close(done) }()

	// 乱序终态：seq=2 先 durable，seq=1 未终态——计数谓词下 drain 继续等待。
	p2, err := core.Encode(&core.Result{RefSeq: 2, Level: corepb.ResultLevel_RESULT_LEVEL_DURABLE})
	if err != nil {
		t.Fatal(err)
	}
	c.handleResult(p2)
	select {
	case <-done:
		t.Fatal("drain completed with seq=1 still pending——判定疑似 max 谓词或中间态误收敛")
	case <-time.After(300 * time.Millisecond):
	}

	// 补齐 seq=1 终态：计数归零，drain 立即收敛。
	p1, err := core.Encode(&core.Result{RefSeq: 1, Level: corepb.ResultLevel_RESULT_LEVEL_DURABLE})
	if err != nil {
		t.Fatal(err)
	}
	c.handleResult(p1)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not complete after all seqs terminal")
	}
}
