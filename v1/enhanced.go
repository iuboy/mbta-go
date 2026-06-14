package v1

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// agentQueueTTL 是 agent 队列条目的默认过期时间。
// 超过此时间未收到该 agent 的 batch，条目将被惰性清理。
const agentQueueTTL = 30 * time.Minute

// evictInterval 控制过期清理的节流频率：每这么多次统计更新才全表扫描一次，
// 避免每次 batch 投递都遍历整个 agentQueues。
const evictInterval = 128

// EnhancedRouter 路由事件到上层 EventSink，提供背压反馈。
// 实现 core.DurableEventSink 接口。
//
// agentQueues 使用惰性过期策略防止无界增长：updateAgentStats 每 evictInterval 次
// 顺便清理超过 agentQueueTTL 未活跃的条目。高频的 EventsIn 累加走 atomic，避免写锁。
type EnhancedRouter struct {
	sink         core.EventSink
	mu           sync.RWMutex
	agentQueues  map[string]*agentQueueEntry
	evictCounter atomic.Int64
}

// agentQueueEntry wraps AgentQueue with last-access time for lazy eviction.
// eventsIn / lastAccess 用 atomic 维护，使已存在条目的统计更新无需写锁。
type agentQueueEntry struct {
	*core.AgentQueue
	eventsIn   atomic.Int64
	lastAccess atomic.Int64 // unix nano
}

// NewEnhancedRouter 创建增强路由器。
func NewEnhancedRouter(sink core.EventSink) *EnhancedRouter {
	return &EnhancedRouter{
		sink:        sink,
		agentQueues: make(map[string]*agentQueueEntry),
	}
}

// OnSignalBatch 实现 core.EventSink。
func (r *EnhancedRouter) OnSignalBatch(ctx context.Context, agentID string, batch *core.SignalBatch) error {
	result, err := r.OnSignalBatchWithResult(ctx, agentID, batch)
	if err != nil {
		return err
	}
	return result.Error
}

// OnPressure 实现 core.EventSink。
func (r *EnhancedRouter) OnPressure(agentID string) core.PressureState {
	return r.sink.OnPressure(agentID)
}

// OnSignalBatchWithResult 实现 core.DurableEventSink。
func (r *EnhancedRouter) OnSignalBatchWithResult(ctx context.Context, agentID string, batch *core.SignalBatch) (*core.RouteResult, error) {
	if len(batch.Signals) == 0 {
		return &core.RouteResult{
			Status:      core.ACKStatusAccepted,
			EventsCount: 0,
		}, nil
	}

	// 检查上层背压
	pressure := r.sink.OnPressure(agentID)
	if pressure == core.PressureCritical {
		return &core.RouteResult{
			Status:      core.ACKStatusThrottle,
			EventsCount: len(batch.Signals),
			Pressure:    pressure,
			Error:       core.NewError(core.NumThrottle, core.CodeThrottle, "queue pressure critical, throttling"),
		}, nil
	}

	// 委托投递到上层 sink
	if err := r.sink.OnSignalBatch(ctx, agentID, batch); err != nil {
		return &core.RouteResult{
			Status:      core.ACKStatusAccepted,
			EventsCount: len(batch.Signals),
			Pressure:    pressure,
			Error:       err,
		}, err
	}

	// 更新 agent 统计
	r.updateAgentStats(agentID, len(batch.Signals))

	slog.Info("batch enqueued",
		"agent", agentID,
		"status", core.ACKStatusDurable,
		"pressure", pressure,
		"events", len(batch.Signals))

	return &core.RouteResult{
		Status:      core.ACKStatusDurable,
		EventsCount: len(batch.Signals),
		Pressure:    pressure,
	}, nil
}

// GetAgentQueue 返回指定 agent 的队列信息。
func (r *EnhancedRouter) GetAgentQueue(agentID string) (*core.AgentQueue, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.agentQueues[agentID]
	if !ok {
		return nil, false
	}
	// 将 atomic 计数快照到公开字段，保持 AgentQueue.EventsIn 语义兼容。
	entry.EventsIn = entry.eventsIn.Load()
	return entry.AgentQueue, true
}

// GetEnqueueResult 返回指定 agent 的路由结果快照。
func (r *EnhancedRouter) GetEnqueueResult(agentID string) *core.RouteResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, exists := r.agentQueues[agentID]
	if !exists {
		return &core.RouteResult{
			Status:    core.ACKStatusAccepted,
			QueueType: "none",
		}
	}

	return &core.RouteResult{
		Status:    core.ACKStatusDurable,
		QueueType: entry.QueueType,
		Pressure:  r.sink.OnPressure(agentID),
	}
}

// RemoveAgent 移除指定 agent 的队列条目。
// 在连接断开或 agent 会话结束时调用，防止无界增长。
func (r *EnhancedRouter) RemoveAgent(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.agentQueues, agentID)
}

func (r *EnhancedRouter) updateAgentStats(agentID string, count int) {
	nowNano := time.Now().UnixNano()

	// 快路径：entry 已存在，用 RLock 取指针后走 atomic 更新，避免写锁竞争。
	r.mu.RLock()
	entry, exists := r.agentQueues[agentID]
	r.mu.RUnlock()
	if exists {
		entry.eventsIn.Add(int64(count))
		entry.lastAccess.Store(nowNano)
		r.maybeEvict()
		return
	}

	// 慢路径：首次创建 entry，需写锁。double-check 防并发重复创建。
	r.mu.Lock()
	entry, exists = r.agentQueues[agentID]
	if !exists {
		entry = &agentQueueEntry{
			AgentQueue: &core.AgentQueue{
				AgentID:   agentID,
				QueueType: "durable",
				CreatedAt: time.Now(),
			},
		}
		entry.lastAccess.Store(nowNano)
		r.agentQueues[agentID] = entry
	}
	r.mu.Unlock()
	entry.eventsIn.Add(int64(count))
	entry.lastAccess.Store(nowNano)
	r.maybeEvict()
}

// maybeEvict 节流触发过期清理，避免每次统计更新都全表扫描。
func (r *EnhancedRouter) maybeEvict() {
	if r.evictCounter.Add(1)%evictInterval != 0 {
		return
	}
	r.evictExpired()
}

// evictExpired 清理超过 agentQueueTTL 未活跃的条目。
// 持写锁删除 map 条目，lastAccess 通过 atomic 读取（无需额外同步）。
func (r *EnhancedRouter) evictExpired() {
	deadline := time.Now().Add(-agentQueueTTL).UnixNano()
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, entry := range r.agentQueues {
		if entry.lastAccess.Load() < deadline {
			delete(r.agentQueues, id)
		}
	}
}
