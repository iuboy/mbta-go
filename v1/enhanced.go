package v1

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// agentQueueTTL 是 agent 队列条目的默认过期时间。
// 超过此时间未收到该 agent 的 batch，条目将被惰性清理。
const agentQueueTTL = 30 * time.Minute

// EnhancedRouter 路由事件到上层 EventSink，提供背压反馈。
// 实现 core.DurableEventSink 接口。
//
// agentQueues 使用惰性过期策略防止无界增长：每次 updateAgentStats 时
// 顺便清理超过 agentQueueTTL 未活跃的条目。
type EnhancedRouter struct {
	sink        core.EventSink
	mu          sync.RWMutex
	agentQueues map[string]*agentQueueEntry
}

// agentQueueEntry wraps AgentQueue with last-access time for lazy eviction.
type agentQueueEntry struct {
	*core.AgentQueue
	lastAccess time.Time
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
			Error:       core.NewError(core.NumThrottle, core.ErrThrottle, "queue pressure critical, throttling"),
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
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	entry, exists := r.agentQueues[agentID]
	if !exists {
		entry = &agentQueueEntry{
			AgentQueue: &core.AgentQueue{
				AgentID:   agentID,
				QueueType: "durable",
				CreatedAt: now,
			},
			lastAccess: now,
		}
		r.agentQueues[agentID] = entry
	}
	entry.EventsIn += int64(count)
	entry.lastAccess = now

	// 惰性清理：每次更新时顺带清除过期条目
	r.evictExpiredLocked(now)
}

// evictExpiredLocked 清理超过 agentQueueTTL 未活跃的条目。
// 必须在 r.mu 持锁状态下调用。
func (r *EnhancedRouter) evictExpiredLocked(now time.Time) {
	// 性能优化：仅在条目数较多时才执行清理，避免每次更新都遍历
	if len(r.agentQueues) < 64 {
		return
	}

	deadline := now.Add(-agentQueueTTL)
	for id, entry := range r.agentQueues {
		if entry.lastAccess.Before(deadline) {
			delete(r.agentQueues, id)
		}
	}
}
