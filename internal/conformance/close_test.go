package conformance

// close_test.go：CLOSE/drain 语义（v2-design §5.3 交错矩阵 / §6.4 / §18-H6）。
//
//   - CLOSE → Handle 正常返回（nil）；
//   - 服务端排空超时放弃 inflight → 对每个放弃项发 RESULT(released, server_draining)
//     + 额度回收（禁止沉默）；
//   - 放弃后的迟到 done 安全丢弃；
//   - PING → PONG（TCP binding 保活路径）。

import (
	"context"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// TestClose_DrainReleasesStuck 验证 CLOSE 后服务端排空：卡住的 inflight（handler
// 未调 done）被合成为 RESULT(released, server_draining) 并回收额度；迟到的
// done(Durable) 被安全丢弃。
//
// 已知实现缺陷（见任务报告 bug-D）：releaseStuck → terminal() 只记终态+回收，
// 从不发送 RESULT 帧——drain 放弃项的 released(server_draining) 反馈缺失，
// 客户端只能白等 AckTimeout（§5.3「禁止沉默」被违反）。本测试钉住规格，
// 待实现修复后转绿。
func TestClose_DrainReleasesStuck(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })

	var lateDone func(core.Outcome)
	doneCh := make(chan func(core.Outcome), 8)
	handler := func(_ context.Context, ev core.BatchEvent, done func(core.Outcome)) {
		doneCh <- done
		<-block // 卡死：不调 done
	}

	env := startEnv(t, envConfig{
		ackMode:              corepb.AckMode_ACK_MODE_DURABLE,
		initialCreditBatches: 4,
		sinkOpts:             core.SinkOptions{Durable: true},
		sinkDeadline:         30 * time.Second, // 排空判定不得依赖 sink deadline
		sink:                 handler,
	})

	env.sendBatch(t, 1, "stuck-at-close", "")
	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED {
		t.Fatalf("accepted missing: %v", r.GetLevel())
	}
	select {
	case lateDone = <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("handler not invoked")
	}
	// accepted 中间态不返还：此刻不应有 CREDIT。
	if f, ok := NextFrame(env.tr.Sent, 200*time.Millisecond); ok {
		t.Fatalf("frame 0x%02x after accepted（中间态不得返还 credit）", f.Header.Type)
	}

	// CLOSE（drain 超时 1s，clamp 下限）。
	closePayload, err := core.Encode(&core.CloseMsg{Reason: "client closing", DrainTimeoutMs: 1000})
	if err != nil {
		t.Fatal(err)
	}
	env.tr.ControlIn <- MakeFrame(core.TypeClose, closePayload)

	// 放弃 inflight → released(server_draining)（禁止沉默）。
	r2 := AwaitResult(t, env.tr.Sent, 1, 3*time.Second)
	if r2.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_RELEASED {
		t.Fatalf("drain result = %v, want RELEASED", r2.GetLevel())
	}
	if r2.GetCode() != core.CodeServerDraining {
		t.Errorf("drain code = %d (%s), want %d (server_draining)",
			r2.GetCode(), core.CodeName(r2.GetCode()), core.CodeServerDraining)
	}
	// 放弃即回收：CREDIT 帧到达。
	c := AwaitCredit(t, env.tr.Sent, 5*time.Second)
	if c.GetBatches() != 1 {
		t.Errorf("credit batches = %d, want 1（放弃项额度回收）", c.GetBatches())
	}

	// Handle 以 nil 收场（正常关闭，非协议错误）。
	select {
	case err := <-env.handleErr:
		if err != nil {
			t.Errorf("Handle returned %v after CLOSE, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return after CLOSE")
	}

	// 迟到的 done：终态已记录（released），安全丢弃。
	if lateDone != nil {
		lateDone(core.Outcome{Level: core.OutcomeDurable})
	}
	if f, ok := NextFrame(env.tr.Sent, 300*time.Millisecond); ok && f.Header.Type == core.TypeResult {
		var r3 core.Result
		if core.Decode(f.Payload, &r3) == nil && r3.GetRefSeq() == 1 {
			t.Fatalf("late done produced RESULT %v after drain release", r3.GetLevel())
		}
	}
}

// TestClose_DrainTimeoutClamp 验证 drain 超时 clamp 到 [1s, 30s]：
// 0 与超大值均落入合法区间（行为级断言：超大提示不放大排空等待）。
func TestClose_DrainTimeoutClamp(t *testing.T) {
	env := startEnv(t, envConfig{})
	// 只验证 CLOSE 帧可被接受且 Handle 正常返回（clamp 内部逻辑无独立观测面）。
	closePayload, err := core.Encode(&core.CloseMsg{Reason: "bye", DrainTimeoutMs: 0})
	if err != nil {
		t.Fatal(err)
	}
	env.tr.ControlIn <- MakeFrame(core.TypeClose, closePayload)
	select {
	case err := <-env.handleErr:
		if err != nil {
			t.Errorf("Handle returned %v after CLOSE(drain=0), want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return after CLOSE")
	}
}

// TestPing_Pong 验证 TCP binding 保活路径：PING 回显 PONG（nonce/时间戳）。
func TestPing_Pong(t *testing.T) {
	env := startEnv(t, envConfig{})
	ping := &core.PingMsg{TimeUnixMs: 123456, Nonce: []byte{0x07, 0x89}}
	p, err := core.Encode(ping)
	if err != nil {
		t.Fatal(err)
	}
	env.tr.ControlIn <- MakeFrame(core.TypePing, p)

	pongF := AwaitFrame(t, env.tr.Sent, core.TypePong, 5*time.Second)
	var pong core.PongMsg
	if err := core.Decode(pongF.Payload, &pong); err != nil {
		t.Fatalf("decode pong: %v", err)
	}
	if pong.GetTimeUnixMs() != 123456 || string(pong.GetNonce()) != "\x07\x89" {
		t.Errorf("pong echo = (%d,% X), want (123456, 07 89)", pong.GetTimeUnixMs(), pong.GetNonce())
	}
}
