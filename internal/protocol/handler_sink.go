package protocol

import (
	"log/slog"
	"runtime"
	"sync"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// sinkTask 是 sinkQueue 的投递单元，统一承载普通 EventSink 与 AsyncDurableSink 两路径。
// routeAndACK 投递、worker 消费；asyncDurable=false 走普通 EventSink（fire-and-forget），
// true 走 AsyncDurableSink（持久化后回调 notifier 发 durable 升级）。
type sinkTask struct {
	agentID      string
	batch        *core.SignalBatch // 普通 EventSink + AsyncDurableSink 共用
	asyncDurable bool              // true = AsyncDurableSink 路径
	// AsyncDurableSink 路径专用：发 durable 升级帧所需的元信息。
	seq         uint64
	chunkID     []byte
	eventsCount int
	notifier    core.DurableNotifier // 协议层注入，sink 持久化后回调
}

// initSinkQueue 根据 sink 类型决定是否启用异步投递队列。
// 启用条件：sink 是普通 EventSink（fire-and-forget）或 AsyncDurableSink（持久化后回调升级）。
// 仅实现 DurableEventSink/RawEventSink 但未实现 AsyncDurableSink 的 sink 走同步路径（需 RouteResult）。
// SinkQueueSize < 0 显式禁用异步（测试用）。
func (h *CoreHandler) initSinkQueue() {
	if h.config.Sink == nil {
		return
	}
	// 判断是否可异步：普通 EventSink（非 Durable）或 AsyncDurableSink（Durable 的可选扩展）。
	_, isAsyncDurable := h.config.Sink.(core.AsyncDurableSink)
	_, isDurable := h.config.Sink.(core.DurableEventSink)
	if isDurable && !isAsyncDurable {
		return // 同步 Durable/Raw sink：需 RouteResult，不能异步
	}
	size := h.config.SinkQueueSize
	if size == 0 {
		size = defaultSinkQueueSize
	}
	if size < 0 {
		return // 显式禁用异步
	}
	h.sinkQueue = make(chan sinkTask, size)
	// AsyncDurableSink 路径需要 notifier 发 durable 升级帧（复用上方 isAsyncDurable 判定）。
	if isAsyncDurable {
		h.durableNotifier = &durableNotifier{handler: h}
	}
	workers := defaultSinkWorkers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	for range workers {
		h.sinkWG.Add(1)
		go h.sinkWorker()
	}
}

// sinkWorker 消费 sinkQueue，按 task 类型分发：普通 EventSink 调 OnSignalBatch，
// AsyncDurableSink 调 OnSignalBatchAsync（持久化后回调 notifier 发 durable 升级）。
// 用 h.sinkCtx（派生自连接 ctx）使连接关闭后 sink 调用可被取消；普通 EventSink 的
// 错误递增 SinkFailures 并告警（ACK 已发但 sink 持久化失败=数据丢失风险）。
func (h *CoreHandler) sinkWorker() {
	defer h.sinkWG.Done()
	for task := range h.sinkQueue {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// sink 是用户实现，panic 不可控。recover 让单个 task 的 panic 不杀 worker 进程。
					h.config.Metrics.SinkFailures().Inc()
					slog.Warn("sink panicked, batch dropped",
						"agent", task.agentID, "chunk_id", string(task.chunkID), "panic", r)
				}
			}()
			if task.asyncDurable {
				if asyncSink, ok := h.config.Sink.(core.AsyncDurableSink); ok {
					asyncSink.OnSignalBatchAsync(h.sinkCtx, task.agentID, task.batch,
						task.notifier, task.seq, task.chunkID, task.eventsCount)
				}
			} else {
				if err := h.config.Sink.OnSignalBatch(h.sinkCtx, task.agentID, task.batch); err != nil {
					// ACK_MODE_ACCEPTED 已先发，sink 失败=潜在数据丢失。metrics + 告警让运维感知。
					h.config.Metrics.SinkFailures().Inc()
					slog.Warn("sink OnSignalBatch failed after ACK accepted (potential data loss)",
						"agent", task.agentID, "chunk_id", string(task.chunkID), "error", err)
				}
			}
		}()
	}
}

// durableNotifier 是协议层提供给 AsyncDurableSink 的回调接口实现。
// sink 持久化完成后调 NotifyDurable，本实现发 ACK_MODE_DURABLE 升级帧。
// 幂等保护：已发 durable 的 seq 不重复发（防 sink 误多次回调）。
type durableNotifier struct {
	handler *CoreHandler
	seen    sync.Map // seq → struct{}{}，已发 durable 的去重
}

func (n *durableNotifier) NotifyDurable(seq uint64, chunkID []byte, eventsCount int) {
	if _, loaded := n.seen.LoadOrStore(seq, struct{}{}); loaded {
		return // 已发过 durable，幂等跳过
	}
	// durable 升级帧用 sinkCtx 发送——派生自 Handle 的 ctx，连接关闭时自动取消。
	n.handler.sendAck(n.handler.sinkCtx, seq, chunkID, eventsCount, corepb.AckMode_ACK_MODE_DURABLE)
}
