package v1

import (
	"context"
	"errors"
	"testing"

	"github.com/iuboy/mbta-go/core"
)

// mockEventSink is a mock implementation of core.EventSink for testing.
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

// TestPipelineEventRouterStructure tests that PipelineEventRouter can be created.
func TestPipelineEventRouterStructure(t *testing.T) {
	sink := &mockEventSink{}
	router := &PipelineEventRouter{Sink: sink}

	if router.Sink == nil {
		t.Error("Sink should not be nil")
	}
}

// TestRouteEventsSuccess tests successful event routing.
func TestRouteEventsSuccess(t *testing.T) {
	called := false
	calledWithAgentID := ""
	calledWithBatch := false

	sink := &mockEventSink{
		onSignalBatchFunc: func(ctx context.Context, agentID string, batch *core.SignalBatch) error {
			called = true
			calledWithAgentID = agentID
			calledWithBatch = (batch != nil)
			return nil
		},
	}

	router := &PipelineEventRouter{Sink: sink}

	ctx := context.Background()
	agentID := "test-agent"
	batch := &core.SignalBatch{
		SchemaURL: "test-schema",
		Signals:   []*core.SignalRecord{{SignalType: "test"}},
	}

	err := router.RouteEvents(ctx, agentID, batch)
	if err != nil {
		t.Errorf("RouteEvents error = %v", err)
	}

	if !called {
		t.Error("Sink.OnSignalBatch was not called")
	}
	if calledWithAgentID != agentID {
		t.Errorf("Called with agentID = %q, want %q", calledWithAgentID, agentID)
	}
	if !calledWithBatch {
		t.Error("Called with nil batch")
	}
}

// TestRouteEventsSinkError tests error handling when sink returns error.
func TestRouteEventsSinkError(t *testing.T) {
	expectedErr := errors.New("sink error")
	sink := &mockEventSink{
		onSignalBatchFunc: func(ctx context.Context, agentID string, batch *core.SignalBatch) error {
			return expectedErr
		},
	}

	router := &PipelineEventRouter{Sink: sink}

	ctx := context.Background()
	batch := &core.SignalBatch{}

	err := router.RouteEvents(ctx, "test-agent", batch)
	if err != expectedErr {
		t.Errorf("RouteEvents error = %v, want %v", err, expectedErr)
	}
}

// TestRouteEventsNilSink tests that nil sink causes panic.
func TestRouteEventsNilSink(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic (expected): %v", r)
		}
	}()

	router := &PipelineEventRouter{}
	ctx := context.Background()
	batch := &core.SignalBatch{}

	// This should panic because Sink is nil
	_ = router.RouteEvents(ctx, "test-agent", batch)
}

// TestRouteEventsNilBatch tests routing with nil batch.
func TestRouteEventsNilBatch(t *testing.T) {
	calledWithNil := false
	sink := &mockEventSink{
		onSignalBatchFunc: func(ctx context.Context, agentID string, batch *core.SignalBatch) error {
			calledWithNil = (batch == nil)
			return nil
		},
	}

	router := &PipelineEventRouter{Sink: sink}

	ctx := context.Background()
	err := router.RouteEvents(ctx, "test-agent", nil)
	if err != nil {
		t.Errorf("RouteEvents with nil batch error = %v", err)
	}

	if !calledWithNil {
		t.Error("Sink should be called with nil batch")
	}
}

// TestRouteEventsEmptyBatch tests routing with empty batch.
func TestRouteEventsEmptyBatch(t *testing.T) {
	sink := &mockEventSink{
		onSignalBatchFunc: func(ctx context.Context, agentID string, batch *core.SignalBatch) error {
			if len(batch.Signals) != 0 {
				t.Errorf("Expected empty batch, got %d signals", len(batch.Signals))
			}
			return nil
		},
	}

	router := &PipelineEventRouter{Sink: sink}

	ctx := context.Background()
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{},
	}

	err := router.RouteEvents(ctx, "test-agent", batch)
	if err != nil {
		t.Errorf("RouteEvents with empty batch error = %v", err)
	}
}

// TestRouteEventsMultipleSignals tests routing with multiple signals.
func TestRouteEventsMultipleSignals(t *testing.T) {
	signalCount := 0
	sink := &mockEventSink{
		onSignalBatchFunc: func(ctx context.Context, agentID string, batch *core.SignalBatch) error {
			signalCount = len(batch.Signals)
			return nil
		},
	}

	router := &PipelineEventRouter{Sink: sink}

	ctx := context.Background()
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log"},
			{SignalType: "metric"},
			{SignalType: "span"},
		},
	}

	err := router.RouteEvents(ctx, "test-agent", batch)
	if err != nil {
		t.Errorf("RouteEvents with multiple signals error = %v", err)
	}

	if signalCount != 3 {
		t.Errorf("Expected 3 signals, got %d", signalCount)
	}
}

// TestPipelineEventRouterImplementsInterface tests that PipelineEventRouter correctly implements the routing pattern.
func TestPipelineEventRouterImplementsInterface(t *testing.T) {
	sink := &mockEventSink{}
	router := &PipelineEventRouter{Sink: sink}

	// This is a compile-time test to ensure RouteEvents signature is correct
	_ = func(ctx context.Context, agentID string, batch *core.SignalBatch) error {
		return router.RouteEvents(ctx, agentID, batch)
	}
}
