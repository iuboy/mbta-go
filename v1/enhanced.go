package v1

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// EnhancedRouter 路由事件到上层 EventSink，提供背压反馈。
// 实现 core.DurableEventSink 接口。
type EnhancedRouter struct {
	sink        core.EventSink
	mu          sync.RWMutex
	agentQueues map[string]*core.AgentQueue
}

// NewEnhancedRouter 创建增强路由器。
func NewEnhancedRouter(sink core.EventSink) *EnhancedRouter {
	return &EnhancedRouter{
		sink:        sink,
		agentQueues: make(map[string]*core.AgentQueue),
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
	aq, ok := r.agentQueues[agentID]
	return aq, ok
}

// GetEnqueueResult 返回指定 agent 的路由结果快照。
func (r *EnhancedRouter) GetEnqueueResult(agentID string) *core.RouteResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	aq, exists := r.agentQueues[agentID]
	if !exists {
		return &core.RouteResult{
			Status:    core.ACKStatusAccepted,
			QueueType: "none",
		}
	}

	return &core.RouteResult{
		Status:    core.ACKStatusDurable,
		QueueType: aq.QueueType,
		Pressure:  r.sink.OnPressure(agentID),
	}
}

func (r *EnhancedRouter) updateAgentStats(agentID string, count int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	aq, exists := r.agentQueues[agentID]
	if !exists {
		aq = &core.AgentQueue{
			AgentID:   agentID,
			QueueType: "durable",
			CreatedAt: time.Now(),
		}
		r.agentQueues[agentID] = aq
	}
	aq.EventsIn += int64(count)
}
