package conformance

// sink_test.go：Sink 契约 §11.1 全部条目的 wire 断言（durable 模式）。
//
//	1. done 幂等（双调一次生效）；
//	3. deadline 未调 → 服务端合成 released(internal)；
//	4. panic → 合成 released + 计数；
//	5. ctx 取消/终态后迟到的 done 安全丢弃；
//	6. 队列满/字节超限 → released(server_draining) + 额度回收；
//	+ Async 语义：handler 返回后异步调用 done 仍然生效。

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// TestSink_DoneIdempotent 验证 done 双调只生效一次：seq=1 只产生一个
// RESULT(durable)。
func TestSink_DoneIdempotent(t *testing.T) {
	sink := newSinkCapture()
	env := startEnv(t, envConfig{
		ackMode:              corepb.AckMode_ACK_MODE_DURABLE,
		initialCreditBatches: 4,
		sinkOpts:             core.SinkOptions{Durable: true},
		sink:                 sink.handler,
	})

	env.sendBatch(t, 1, "idem", "")
	AwaitResult(t, env.tr.Sent, 1, 5*time.Second) // accepted
	sink.waitEvent(t, 1, 5*time.Second)

	done := sink.doneOf(1)
	if done == nil {
		t.Fatal("no done captured")
	}
	done(core.Outcome{Level: core.OutcomeDurable})
	done(core.Outcome{Level: core.OutcomeDurable}) // 双调：安全丢弃
	done(core.Outcome{Level: core.OutcomeReleased, Code: core.CodeInternal})

	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_DURABLE {
		t.Fatalf("level = %v, want DURABLE（首次调用生效）", r.GetLevel())
	}
	// 第 2/3 次调用不得对同 seq 再产生 RESULT（CREDIT 帧不是 RESULT，需按类型区分）。
	if f, ok := NextFrame(env.tr.Sent, 300*time.Millisecond); ok && f.Header.Type == core.TypeResult {
		var r2 core.Result
		if core.Decode(f.Payload, &r2) == nil && r2.GetRefSeq() == 1 {
			t.Fatalf("duplicate RESULT for seq=1 after repeated done calls: level %v", r2.GetLevel())
		}
	}
}

// TestSink_DeadlineSynthesizesReleased 验证 handler 在 SinkDeadline 内未调 done →
// 服务端合成 Outcome{Released, internal}；随后迟到的真实调用（durable）被安全丢弃。
func TestSink_DeadlineSynthesizesReleased(t *testing.T) {
	block := make(chan struct{})
	var lateDone func(core.Outcome)
	var mu sync.Mutex
	handler := func(_ context.Context, ev core.BatchEvent, done func(core.Outcome)) {
		mu.Lock()
		lateDone = done
		mu.Unlock()
		<-block // 阻塞超过 deadline；测试结束时放行
	}
	t.Cleanup(func() { close(block) })

	env := startEnv(t, envConfig{
		ackMode:              corepb.AckMode_ACK_MODE_DURABLE,
		initialCreditBatches: 4,
		sinkOpts:             core.SinkOptions{Durable: true, Async: true},
		sinkDeadline:         300 * time.Millisecond,
		sink:                 handler,
	})

	env.sendBatch(t, 1, "stuck", "")
	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED {
		t.Fatalf("first result = %v, want ACCEPTED", r.GetLevel())
	}
	r2 := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r2.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_RELEASED {
		t.Fatalf("second result = %v, want RELEASED（deadline 合成）", r2.GetLevel())
	}
	if r2.GetCode() != core.CodeInternal {
		t.Errorf("released code = %d (%s), want %d (internal)",
			r2.GetCode(), core.CodeName(r2.GetCode()), core.CodeInternal)
	}
	// 合成终态后额度回收（threshold=1 → CREDIT）。
	AwaitCredit(t, env.tr.Sent, 5*time.Second)

	// 迟到的真实调用：安全丢弃，不得再产生 RESULT(durable)。
	deadline := time.Now().Add(300 * time.Millisecond)
	for deadline.After(time.Now()) {
		mu.Lock()
		fn := lateDone
		mu.Unlock()
		if fn != nil {
			fn(core.Outcome{Level: core.OutcomeDurable})
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if lateDone == nil {
		t.Fatal("handler never invoked; late done unavailable")
	}
	if f, ok := NextFrame(env.tr.Sent, 300*time.Millisecond); ok && f.Header.Type == core.TypeResult {
		var r3 core.Result
		_ = core.Decode(f.Payload, &r3)
		if r3.GetRefSeq() == 1 {
			t.Fatalf("late done produced RESULT %v after synthesized terminal", r3.GetLevel())
		}
	}
}

// TestSink_PanicSynthesizesReleased 验证 handler panic → 合成 released(internal)，
// 连接与后续投递不受影响（worker 存活）。
func TestSink_PanicSynthesizesReleased(t *testing.T) {
	sink := newSinkCapture()
	var panicOn atomic.Uint64
	handler := func(_ context.Context, ev core.BatchEvent, done func(core.Outcome)) {
		if ev.Meta.Seq == panicOn.Load() {
			panic("sink boom")
		}
		sink.handler(context.TODO(), ev, done)
	}
	panicOn.Store(1)

	env := startEnv(t, envConfig{
		ackMode:              corepb.AckMode_ACK_MODE_DURABLE,
		initialCreditBatches: 4,
		sinkOpts:             core.SinkOptions{Durable: true},
		sink:                 handler,
	})

	env.sendBatch(t, 1, "panic", "")
	AwaitResult(t, env.tr.Sent, 1, 5*time.Second) // accepted
	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_RELEASED {
		t.Fatalf("panic result = %v, want RELEASED", r.GetLevel())
	}
	if r.GetCode() != core.CodeInternal {
		t.Errorf("panic code = %d, want %d (internal)", r.GetCode(), core.CodeInternal)
	}

	// 后续 batch 正常投递（panic 不摧毁 worker/连接）。
	env.sendBatch(t, 2, "after-panic", "")
	AwaitResult(t, env.tr.Sent, 2, 5*time.Second) // accepted
	sink.waitEvent(t, 1, 5*time.Second)           // seq=2 的投递（panic 的 seq=1 不投递计数）
	sink.callDone(2, core.Outcome{Level: core.OutcomeDurable})
	r2 := AwaitResult(t, env.tr.Sent, 2, 5*time.Second)
	if r2.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_DURABLE {
		t.Errorf("post-panic result = %v, want DURABLE", r2.GetLevel())
	}
	if n := sink.countSeq(2); n != 1 {
		t.Errorf("seq=2 delivered %d times, want 1", n)
	}
}

// TestSink_AsyncDoneAfterReturn 验证 Async 语义：handler 返回（不调 done），
// done 由应用层稍后异步调用 → RESULT(durable) 正常产生。
func TestSink_AsyncDoneAfterReturn(t *testing.T) {
	var mu sync.Mutex
	dones := map[uint64]func(core.Outcome){}
	handler := func(_ context.Context, ev core.BatchEvent, done func(core.Outcome)) {
		mu.Lock()
		dones[ev.Meta.Seq] = done
		mu.Unlock()
		// 立即返回：done 稍后异步调用。
	}
	env := startEnv(t, envConfig{
		ackMode:              corepb.AckMode_ACK_MODE_DURABLE,
		initialCreditBatches: 4,
		sinkOpts:             core.SinkOptions{Durable: true, Async: true},
		sinkDeadline:         10 * time.Second,
		sink:                 handler,
	})

	env.sendBatch(t, 1, "async", "")
	AwaitResult(t, env.tr.Sent, 1, 5*time.Second) // accepted

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		fn := dones[1]
		mu.Unlock()
		if fn != nil {
			fn(core.Outcome{Level: core.OutcomeDurable})
			break
		}
		if !deadline.After(time.Now()) {
			t.Fatal("handler never invoked")
		}
		time.Sleep(20 * time.Millisecond)
	}
	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_DURABLE {
		t.Errorf("async done result = %v, want DURABLE", r.GetLevel())
	}
}

// TestSink_QueueFull_Released 验证投递队列满 → RESULT(released, server_draining,
// retry_hint) + 额度回收；释放后其余批次正常 durable（enqueue 失败必须映射 wire 语义）。
//
// 容量与饱和判定：稳态容量 = worker 数 + 队列缓冲——每个已入队任务占住一个
// worker（runSinkTask 等待 handler 完成）或缓冲槽，handler 阻塞期间槽位不可能
// 释放。worker 懒启动存在调度竞态：首批任务可能在 worker 就位前撞满缓冲出现
// 瞬时 released——released ≠ 稳态饱和，唯一确定性饱和条件是 accepted 达到
// 理论容量（workers + queueCap）。
func TestSink_QueueFull_Released(t *testing.T) {
	var releaseOnce sync.Once
	block := make(chan struct{})
	t.Cleanup(func() { releaseOnce.Do(func() { close(block) }) })

	var durable atomic.Int64
	handler := func(_ context.Context, ev core.BatchEvent, done func(core.Outcome)) {
		<-block
		done(core.Outcome{Level: core.OutcomeDurable})
	}

	workers := runtime.NumCPU()
	const queueCap = 1
	capacity := workers + queueCap

	env := startEnv(t, envConfig{
		ackMode:              corepb.AckMode_ACK_MODE_DURABLE,
		initialCreditBatches: 1000, // 大初始额度：攒批阈值 250，测试期内不触发 CREDIT
		initialCreditBytes:   1 << 20,
		sinkOpts:             core.SinkOptions{Durable: true},
		sinkDeadline:         30 * time.Second, // 阻塞期不得被 deadline 抢跑
		sinkQueueSize:        queueCap,
		sink:                 handler,
	})

	// 填充至真饱和（accepted == workers + queueCap）。途中出现的 released 是
	// 懒启动竞态的瞬时拒绝，不占容量；其 wire 语义（server_draining +
	// retry_hint）与饱和路径一致，一并断言。
	var accepted int
	var seq uint64
	fillBound := capacity + 16 // 瞬时 released 不占容量：留裕量
	for i := 0; i < fillBound && accepted < capacity; i++ {
		seq = uint64(i + 1)
		env.sendBatch(t, seq, "flood", "")
		r := AwaitResult(t, env.tr.Sent, seq, 10*time.Second)
		switch r.GetLevel() {
		case corepb.ResultLevel_RESULT_LEVEL_ACCEPTED:
			accepted++
		case corepb.ResultLevel_RESULT_LEVEL_RELEASED:
			if r.GetCode() != core.CodeServerDraining {
				t.Errorf("released code = %d (%s), want %d (server_draining)",
					r.GetCode(), core.CodeName(r.GetCode()), core.CodeServerDraining)
			}
			if r.GetRetryHintMs() == 0 {
				t.Error("released retry_hint_ms = 0, want non-zero")
			}
		default:
			t.Fatalf("seq %d: unexpected level %v", seq, r.GetLevel())
		}
	}
	if accepted < capacity {
		t.Fatalf("queue never saturated: accepted %d < capacity %d (workers=%d + queue=%d)",
			accepted, capacity, workers, queueCap)
	}

	// 真饱和：handler 全阻塞、槽位无以为继 → 后续批次 enqueue 必失败，
	// 全部 released(server_draining)。
	for extra := 1; extra <= 2; extra++ {
		s := seq + uint64(extra)
		env.sendBatch(t, s, "flood", "")
		r := AwaitResult(t, env.tr.Sent, s, 10*time.Second)
		if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_RELEASED {
			t.Errorf("seq %d: level = %v, want RELEASED（队列已满）", s, r.GetLevel())
		}
		if r.GetCode() != core.CodeServerDraining {
			t.Errorf("seq %d: released code = %d, want %d", s, r.GetCode(), core.CodeServerDraining)
		}
	}

	// 放行 handler：容量内的批次全部 durable（accepted 与 durable 一一对应）。
	releaseOnce.Do(func() { close(block) })
	durDeadline := time.Now().Add(15 * time.Second)
	for durable.Load() < int64(accepted) && time.Now().Before(durDeadline) {
		f, ok := NextFrame(env.tr.Sent, 500*time.Millisecond)
		if !ok {
			continue
		}
		if f.Header.Type == core.TypeResult {
			var r core.Result
			if core.Decode(f.Payload, &r) == nil && r.GetLevel() == corepb.ResultLevel_RESULT_LEVEL_DURABLE {
				durable.Add(1)
			}
		}
	}
	if got := durable.Load(); got != int64(accepted) {
		t.Errorf("durable = %d, want %d（accepted 批次在释放后全部 durable）", got, accepted)
	}
}

// TestSink_QueueByteLimit_Released 验证队列字节上限：单任务字节数超限 →
// 立即 released（不入队）。
func TestSink_QueueByteLimit_Released(t *testing.T) {
	sink := newSinkCapture()
	env := startEnv(t, envConfig{
		ackMode:         corepb.AckMode_ACK_MODE_DURABLE,
		sinkOpts:        core.SinkOptions{Durable: true},
		sinkDeadline:    30 * time.Second,
		sinkQueueSize:   8,
		sinkQueueMaxByt: 8, // 任何真实 batch 都超限
		sink:            sink.handler,
	})

	env.sendBatch(t, 1, "too-heavy", "")
	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_RELEASED {
		t.Fatalf("level = %v, want RELEASED（字节超限不入队）", r.GetLevel())
	}
	if r.GetCode() != core.CodeServerDraining {
		t.Errorf("code = %d, want %d", r.GetCode(), core.CodeServerDraining)
	}
	if n := sink.count(); n != 0 {
		t.Errorf("sink delivered %d batches despite byte limit", n)
	}
}
