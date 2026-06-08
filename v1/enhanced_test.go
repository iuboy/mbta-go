package v1

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// TestNewEnhancedRouter tests creating a new EnhancedRouter.
func TestNewEnhancedRouter(t *testing.T) {
	sink := &mockEventSink{}
	router := NewEnhancedRouter(sink)

	if router == nil {
		t.Fatal("NewEnhancedRouter should not return nil")
	}
	if router.sink == nil {
		t.Error("sink should not be nil")
	}
	if router.agentQueues == nil {
		t.Error("agentQueues should be initialized")
	}
}

// TestEnhancedRouterOnSignalBatchEmptyBatch tests routing with empty batch.
func TestEnhancedRouterOnSignalBatchEmptyBatch(t *testing.T) {
	sink := &mockEventSink{}
	router := NewEnhancedRouter(sink)

	ctx := context.Background()
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{},
	}

	err := router.OnSignalBatch(ctx, "test-agent", batch)
	if err != nil {
		t.Errorf("OnSignalBatch with empty batch error = %v", err)
	}

	// Check that no agent queue was created for empty batch
	_, exists := router.GetAgentQueue("test-agent")
	if exists {
		t.Error("Agent queue should not be created for empty batch")
	}
}

// TestEnhancedRouterOnSignalBatchSuccess tests successful event routing.
func TestEnhancedRouterOnSignalBatchSuccess(t *testing.T) {
	sink := &mockEventSink{
		onSignalBatchFunc: func(ctx context.Context, agentID string, batch *core.SignalBatch) error {
			return nil
		},
		onPressureFunc: func(agentID string) core.PressureState {
			return core.PressureNormal
		},
	}
	router := NewEnhancedRouter(sink)

	ctx := context.Background()
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log"},
		},
	}

	err := router.OnSignalBatch(ctx, "test-agent", batch)
	if err != nil {
		t.Errorf("OnSignalBatch error = %v", err)
	}

	// Check that agent queue was created
	aq, exists := router.GetAgentQueue("test-agent")
	if !exists {
		t.Fatal("Agent queue should be created after successful routing")
	}
	if aq.EventsIn != 1 {
		t.Errorf("EventsIn = %d, want 1", aq.EventsIn)
	}
}

// TestEnhancedRouterOnSignalBatchCriticalPressure tests throttling on critical pressure.
func TestEnhancedRouterOnSignalBatchCriticalPressure(t *testing.T) {
	sink := &mockEventSink{
		onPressureFunc: func(agentID string) core.PressureState {
			return core.PressureCritical
		},
	}
	router := NewEnhancedRouter(sink)

	ctx := context.Background()
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log"},
		},
	}

	err := router.OnSignalBatch(ctx, "test-agent", batch)
	// Should return error indicating throttling
	if err == nil {
		t.Error("OnSignalBatch with critical pressure should return error")
	}

	// Check that agent queue was not created due to throttling
	_, exists := router.GetAgentQueue("test-agent")
	if exists {
		t.Error("Agent queue should not be created when throttling")
	}
}

// TestEnhancedRouterOnSignalBatchSinkError tests error handling when sink fails.
func TestEnhancedRouterOnSignalBatchSinkError(t *testing.T) {
	expectedErr := errors.New("sink error")
	sink := &mockEventSink{
		onSignalBatchFunc: func(ctx context.Context, agentID string, batch *core.SignalBatch) error {
			return expectedErr
		},
		onPressureFunc: func(agentID string) core.PressureState {
			return core.PressureNormal
		},
	}
	router := NewEnhancedRouter(sink)

	ctx := context.Background()
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log"},
		},
	}

	err := router.OnSignalBatch(ctx, "test-agent", batch)
	if err != expectedErr {
		t.Errorf("OnSignalBatch error = %v, want %v", err, expectedErr)
	}

	// Check that agent queue was not created when sink failed
	_, exists := router.GetAgentQueue("test-agent")
	if exists {
		t.Error("Agent queue should not be created when sink fails")
	}
}

// TestEnhancedRouterOnSignalBatchWithResult tests the WithResult method.
func TestEnhancedRouterOnSignalBatchWithResult(t *testing.T) {
	sink := &mockEventSink{
		onSignalBatchFunc: func(ctx context.Context, agentID string, batch *core.SignalBatch) error {
			return nil
		},
		onPressureFunc: func(agentID string) core.PressureState {
			return core.PressureNormal
		},
	}
	router := NewEnhancedRouter(sink)

	ctx := context.Background()
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log"},
		},
	}

	result, err := router.OnSignalBatchWithResult(ctx, "test-agent", batch)
	if err != nil {
		t.Errorf("OnSignalBatchWithResult error = %v", err)
	}

	if result.Status != core.ACKStatusDurable {
		t.Errorf("Status = %s, want %s", result.Status, core.ACKStatusDurable)
	}
	if result.EventsCount != 1 {
		t.Errorf("EventsCount = %d, want 1", result.EventsCount)
	}
	if result.Error != nil {
		t.Errorf("Error should be nil, got %v", result.Error)
	}
}

// TestEnhancedRouterOnSignalBatchWithResultCriticalPressure tests WithResult with critical pressure.
func TestEnhancedRouterOnSignalBatchWithResultCriticalPressure(t *testing.T) {
	sink := &mockEventSink{
		onPressureFunc: func(agentID string) core.PressureState {
			return core.PressureCritical
		},
	}
	router := NewEnhancedRouter(sink)

	ctx := context.Background()
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log"},
		},
	}

	result, err := router.OnSignalBatchWithResult(ctx, "test-agent", batch)
	if err != nil {
		t.Errorf("OnSignalBatchWithResult with critical pressure should not error, got %v", err)
	}

	if result.Status != core.ACKStatusThrottle {
		t.Errorf("Status = %s, want %s", result.Status, core.ACKStatusThrottle)
	}
	if result.Pressure != core.PressureCritical {
		t.Errorf("Pressure = %s, want %s", result.Pressure, core.PressureCritical)
	}
	if result.Error == nil {
		t.Error("Error should not be nil when throttling")
	}
}

// TestEnhancedRouterOnPressure tests OnPressure delegation.
func TestEnhancedRouterOnPressure(t *testing.T) {
	sink := &mockEventSink{
		onPressureFunc: func(agentID string) core.PressureState {
			return core.PressureDegraded
		},
	}
	router := NewEnhancedRouter(sink)

	pressure := router.OnPressure("test-agent")
	if pressure != core.PressureDegraded {
		t.Errorf("OnPressure = %s, want %s", pressure, core.PressureDegraded)
	}
}

// TestEnhancedRouterGetAgentQueue tests GetAgentQueue method.
func TestEnhancedRouterGetAgentQueue(t *testing.T) {
	sink := &mockEventSink{
		onSignalBatchFunc: func(ctx context.Context, agentID string, batch *core.SignalBatch) error {
			return nil
		},
		onPressureFunc: func(agentID string) core.PressureState {
			return core.PressureNormal
		},
	}
	router := NewEnhancedRouter(sink)

	// Initially, no queue exists
	_, exists := router.GetAgentQueue("test-agent")
	if exists {
		t.Error("Agent queue should not exist initially")
	}

	// Create queue by routing a batch
	ctx := context.Background()
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log"},
		},
	}
	_ = router.OnSignalBatch(ctx, "test-agent", batch)

	// Now queue should exist
	aq, exists := router.GetAgentQueue("test-agent")
	if !exists {
		t.Fatal("Agent queue should exist after routing")
	}
	if aq.AgentID != "test-agent" {
		t.Errorf("AgentID = %s, want 'test-agent'", aq.AgentID)
	}
}

// TestEnhancedRouterGetEnqueueResult tests GetEnqueueResult method.
func TestEnhancedRouterGetEnqueueResult(t *testing.T) {
	sink := &mockEventSink{
		onSignalBatchFunc: func(ctx context.Context, agentID string, batch *core.SignalBatch) error {
			return nil
		},
		onPressureFunc: func(agentID string) core.PressureState {
			return core.PressureNormal
		},
	}
	router := NewEnhancedRouter(sink)

	// Before any routing
	result := router.GetEnqueueResult("test-agent")
	if result.Status != core.ACKStatusAccepted {
		t.Errorf("Initial Status = %s, want %s", result.Status, core.ACKStatusAccepted)
	}

	// After routing
	ctx := context.Background()
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log"},
		},
	}
	_ = router.OnSignalBatch(ctx, "test-agent", batch)

	result = router.GetEnqueueResult("test-agent")
	if result.Status != core.ACKStatusDurable {
		t.Errorf("After routing Status = %s, want %s", result.Status, core.ACKStatusDurable)
	}
	if result.QueueType != "durable" {
		t.Errorf("QueueType = %s, want 'durable'", result.QueueType)
	}
}

// TestEnhancedRouterMultipleAgents tests routing from multiple agents.
func TestEnhancedRouterMultipleAgents(t *testing.T) {
	sink := &mockEventSink{
		onSignalBatchFunc: func(ctx context.Context, agentID string, batch *core.SignalBatch) error {
			return nil
		},
		onPressureFunc: func(agentID string) core.PressureState {
			return core.PressureNormal
		},
	}
	router := NewEnhancedRouter(sink)

	ctx := context.Background()
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log"},
		},
	}

	// Route from multiple agents
	agents := []string{"agent-1", "agent-2", "agent-3"}
	for _, agentID := range agents {
		_ = router.OnSignalBatch(ctx, agentID, batch)
	}

	// Check all queues exist
	for _, agentID := range agents {
		aq, exists := router.GetAgentQueue(agentID)
		if !exists {
			t.Errorf("Agent queue for %s should exist", agentID)
		}
		if aq.AgentID != agentID {
			t.Errorf("AgentID = %s, want %s", aq.AgentID, agentID)
		}
	}
}

// TestEnhancedRouterConcurrentRouting tests concurrent routing safety.
func TestEnhancedRouterConcurrentRouting(t *testing.T) {
	sink := &mockEventSink{
		onSignalBatchFunc: func(ctx context.Context, agentID string, batch *core.SignalBatch) error {
			time.Sleep(1 * time.Millisecond) // Simulate work
			return nil
		},
		onPressureFunc: func(agentID string) core.PressureState {
			return core.PressureNormal
		},
	}
	router := NewEnhancedRouter(sink)

	ctx := context.Background()
	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log"},
		},
	}

	// Launch concurrent routings
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			agentID := "test-agent"
			_ = router.OnSignalBatch(ctx, agentID, batch)
			done <- true
		}(i)
	}

	// Wait for all to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify queue exists and has correct count
	aq, exists := router.GetAgentQueue("test-agent")
	if !exists {
		t.Fatal("Agent queue should exist after concurrent routing")
	}
	if aq.EventsIn != 10 {
		t.Errorf("EventsIn = %d, want 10", aq.EventsIn)
	}
}
