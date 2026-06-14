package v1

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestDispatchACK_AsyncExecutes: dispatchACK 投递后回调由 runACKWorker 异步执行，
// 不在调用方栈上同步运行（M-3：解除控制流对用户回调的阻塞）。
func TestDispatchACK_AsyncExecutes(t *testing.T) {
	c := &Client{ackQueue: make(chan ackTask, 4)}
	got := make(chan ackTask, 4)
	h := func(cid, mode string) { got <- ackTask{chunkID: cid, mode: mode} }
	c.ackHandler.Store(&h)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.runACKWorker(ctx)

	c.dispatchACK("chunk-1", "durable")
	select {
	case task := <-got:
		if task.chunkID != "chunk-1" || task.mode != "durable" {
			t.Errorf("callback got %+v, want chunk-1/durable", task)
		}
	case <-time.After(time.Second):
		t.Fatal("callback not executed asynchronously within timeout")
	}
}

// TestDispatchACK_QueueFullDrops: 队列满时 dispatchACK 走 default 分支丢弃，
// 绝不阻塞调用方（控制流不能因回调积压而 stall）。
func TestDispatchACK_QueueFullDrops(t *testing.T) {
	c := &Client{ackQueue: make(chan ackTask, 2)}
	c.dispatchACK("a", "durable")
	c.dispatchACK("b", "durable")

	// 队列已满：第 3 次必须立即返回（drop），不得阻塞。
	done := make(chan struct{})
	go func() { c.dispatchACK("c", "durable"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatchACK blocked on full queue; must drop instead")
	}
	if len(c.ackQueue) != 2 {
		t.Errorf("queue len = %d, want 2 (3rd callback should have been dropped)", len(c.ackQueue))
	}
}

// TestRunACKWorker_DrainsOnClose: ctx 取消后 worker 排空已入队回调再退出，
// 保证关闭时不丢失已投递的可靠投递通知。
func TestRunACKWorker_DrainsOnClose(t *testing.T) {
	c := &Client{ackQueue: make(chan ackTask, 8)}
	var (
		mu  sync.Mutex
		got []ackTask
		wg  sync.WaitGroup
	)
	h := func(cid, mode string) {
		mu.Lock()
		got = append(got, ackTask{chunkID: cid, mode: mode})
		mu.Unlock()
		wg.Done()
	}
	c.ackHandler.Store(&h)

	// 预填充 3 个任务（worker 尚未启动）。
	for i := 0; i < 3; i++ {
		c.ackQueue <- ackTask{chunkID: fmt.Sprintf("c%d", i), mode: "durable"}
		wg.Add(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 启动前即取消，强制走 ctx.Done 排空路径

	exited := make(chan struct{})
	go func() { c.runACKWorker(ctx); close(exited) }()

	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit after ctx cancellation")
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 {
		t.Errorf("drain executed %d callbacks, want 3 (all pre-enqueued must drain)", len(got))
	}
}
