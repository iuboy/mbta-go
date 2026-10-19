package protocol

// handler_sink.go：异步投递队列（grant 流 + 继承全部加固：条数+字节双限界、
// 排空超时、panic 契约、字节记账配平、入队二次检查、懒启动 worker）。
// done 闭包驱动 grant.Settle；SinkDeadline 内未调 → 经同一 done 合成 released。

import (
	"context"
	"log/slog"
	"math"
	"runtime"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// sinkTask 是投递单元。
type sinkTask struct {
	ev       core.BatchEvent
	handler  core.BatchHandler
	done     func(core.Outcome)
	bytes    int64
	deadline time.Time
}

// initSinkQueue 构造期只创建通道与限额；worker 懒启动（首个成功入队触发）。
func (h *CoreHandler) initSinkQueue() {
	if h.config.SinkHandler == nil {
		return
	}
	size := h.config.SinkQueueSize
	if size == 0 {
		size = defaultSinkQueueSize
	}
	if size < 0 {
		return // 同步模式（测试）
	}
	h.sinkQueue = make(chan sinkTask, size)
	h.sinkDone = make(chan struct{})
	maxBytes := h.config.SinkQueueMaxBytes
	if maxBytes == 0 {
		maxBytes = defaultSinkQueueMaxBytes
	} else if maxBytes < 0 {
		maxBytes = math.MaxInt64
	}
	h.sinkMaxBytes = maxBytes
}

// enqueueSink 投递 task。返回 false = 队列满/收尾/字节超限（调用方 grant.Settle(released)）。
func (h *CoreHandler) enqueueSink(ctx context.Context, grant *core.SettleGrant, batch *core.Batch, batchWire []byte, frameBytes int64, durable bool) bool {
	if h.sinkQueue == nil {
		// 同步模式（测试）：直接调用。
		ev := h.makeEvent(batch, batchWire)
		h.callHandler(ctx, ev, h.makeDone(grant, durable))
		return true
	}
	select {
	case <-h.sinkDone:
		return false
	default:
	}
	task := sinkTask{
		ev:       h.makeEvent(batch, batchWire),
		handler:  h.config.SinkHandler,
		done:     h.makeDone(grant, durable),
		bytes:    frameBytes,
		deadline: time.Now().Add(h.sinkDeadline),
	}
	for {
		cur := h.sinkQueuedBytes.Load()
		if cur+task.bytes > h.sinkMaxBytes {
			slog.Warn("sink queue byte limit reached", "queued", cur, "task", task.bytes, "limit", h.sinkMaxBytes)
			return false
		}
		if h.sinkQueuedBytes.CompareAndSwap(cur, cur+task.bytes) {
			break
		}
	}
	h.startSinkWorkersOnce()
	select {
	case h.sinkQueue <- task:
		select {
		case <-h.sinkDone: // 二次检查（TOCTOU 收口：跳过 accepted 谎报）
			return false
		default:
		}
		return true
	default:
		h.sinkQueuedBytes.Add(-task.bytes)
		slog.Warn("sink queue full", "cap", cap(h.sinkQueue))
		return false
	}
}

// startSinkWorkersOnce 懒启动 worker pool（首个成功入队触发）——
// 握手前不占 goroutine（万连接下防 pre-auth DoS 放大）。
func (h *CoreHandler) startSinkWorkersOnce() {
	h.sinkStart.Do(func() {
		workers := runtime.NumCPU()
		if workers < 1 {
			workers = 1
		}
		for range workers {
			h.sinkWG.Add(1)
			go h.sinkWorker()
		}
	})
}

// sinkWorker 消费队列；sinkDone 关闭后排空现存 task 退出。
func (h *CoreHandler) sinkWorker() {
	defer h.sinkWG.Done()
	for {
		select {
		case t := <-h.sinkQueue:
			h.runSinkTask(t)
		case <-h.sinkDone:
			for {
				select {
				case t := <-h.sinkQueue:
					h.runSinkTask(t)
				default:
					return
				}
			}
		}
	}
}

// runSinkTask 执行单个 task：SinkDeadline 内 handler 未调 done 则经 done 合成
// released（done 幂等，迟到的真实调用安全丢弃）。
func (h *CoreHandler) runSinkTask(t sinkTask) {
	defer h.sinkQueuedBytes.Add(-t.bytes)
	completed := make(chan struct{})
	go func() {
		defer close(completed)
		h.callHandler(h.sinkCtx, t.ev, t.done) // panic 契约由 callHandler 统一实现
	}()
	timeout := time.Until(t.deadline)
	if timeout < 0 {
		timeout = 0
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-completed:
	case <-timer.C:
		t.done(core.Outcome{Level: core.OutcomeReleased, Code: core.CodeInternal})
		<-completed
	}
}
