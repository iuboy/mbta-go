package v1

import (
	"context"

	"github.com/iuboy/mbta-go/core"
)

// mockEventSink 测试用 EventSink，可注入 OnSignalBatch/OnPressure 行为。
// （从已删除的 router_test.go 迁移，enhanced_test.go 等仍依赖。）
type mockEventSink struct {
	onSignalBatchFunc func(ctx context.Context, agentID string, batch *core.SignalBatch) error
	onPressureFunc    func(agentID string) core.PressureState
}

func (m *mockEventSink) OnSignalBatch(ctx context.Context, agentID string, batch *core.SignalBatch) error {
	if m.onSignalBatchFunc != nil {
		return m.onSignalBatchFunc(ctx, agentID, batch)
	}
	return nil
}

func (m *mockEventSink) OnPressure(agentID string) core.PressureState {
	if m.onPressureFunc != nil {
		return m.onPressureFunc(agentID)
	}
	return core.PressureNormal
}
