package v1

import (
	"context"

	"github.com/iuboy/mbta-go/core"
)

// PipelineEventRouter 将 SignalBatch 委托到上层 EventSink。
type PipelineEventRouter struct {
	Sink core.EventSink // 上层注入
}

// RouteEvents 将 SignalBatch 委托到上层 sink。
func (r *PipelineEventRouter) RouteEvents(ctx context.Context, agentID string, batch *core.SignalBatch) error {
	return r.Sink.OnSignalBatch(ctx, agentID, batch)
}
