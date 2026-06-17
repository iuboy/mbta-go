package core

import (
	"context"
	"errors"
	"sync"
	"testing"

	mbtatest "github.com/iuboy/mbta-go/testing"
)

// TestPressureStateString tests PressureState enum values.
func TestPressureStateString(t *testing.T) {
	tests := []struct {
		state    PressureState
		expected string
	}{
		{PressureNormal, "normal"},
		{PressureDegraded, "degraded"},
		{PressureCritical, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.state) != tt.expected {
				t.Errorf("PressureState = %q, want %q", tt.state, tt.expected)
			}
		})
	}
}

// TestACKStatusString tests ACKStatus enum values.
func TestACKStatusString(t *testing.T) {
	tests := []struct {
		status   ACKStatus
		expected string
	}{
		{ACKStatusDurable, "durable"},
		{ACKStatusAccepted, "accepted"},
		{ACKStatusThrottle, "throttle"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.status) != tt.expected {
				t.Errorf("ACKStatus = %q, want %q", tt.status, tt.expected)
			}
		})
	}
}

// TestRouteResult tests RouteResult structure.
func TestRouteResult(t *testing.T) {
	t.Run("successful routing result", func(t *testing.T) {
		result := &RouteResult{
			Status:      ACKStatusDurable,
			EventsCount: 100,
			QueueType:   "memory",
			Pressure:    PressureNormal,
			Error:       nil,
		}

		if result.Status != ACKStatusDurable {
			t.Errorf("Status = %q, want 'durable'", result.Status)
		}
		if result.EventsCount != 100 {
			t.Errorf("EventsCount = %d, want 100", result.EventsCount)
		}
		if result.Pressure != PressureNormal {
			t.Errorf("Pressure = %q, want 'normal'", result.Pressure)
		}
		if result.Error != nil {
			t.Errorf("Error should be nil, got %v", result.Error)
		}
	})

	t.Run("throttled routing result", func(t *testing.T) {
		err := errors.New("queue pressure critical")
		result := &RouteResult{
			Status:      ACKStatusThrottle,
			EventsCount: 50,
			QueueType:   "memory",
			Pressure:    PressureCritical,
			Error:       err,
		}

		if result.Status != ACKStatusThrottle {
			t.Errorf("Status = %q, want 'throttle'", result.Status)
		}
		if result.Error == nil {
			t.Error("Error should not be nil")
		}
	})
}

// TestEventSinkInterface tests that types implement EventSink correctly.
func TestEventSinkInterface(t *testing.T) {
	// Create a mock implementation
	mock := &mockEventSink{
		batches: make(map[string][]*SignalBatch),
	}

	ctx := context.Background()
	agentID := testAgentID
	batch := &SignalBatch{
		Signals: []*SignalRecord{{SignalType: "log"}},
	}

	// Test OnSignalBatch
	err := mock.OnSignalBatch(ctx, agentID, batch)
	mbtatest.AssertNoError(t, err, "OnSignalBatch")

	// Test OnPressure
	pressure := mock.OnPressure(agentID)
	if pressure != PressureNormal {
		t.Errorf("OnPressure() = %q, want 'normal'", pressure)
	}
}

// TestDurableEventSinkInterface tests that types implement DurableEventSink correctly.
func TestDurableEventSinkInterface(t *testing.T) {
	mock := &mockDurableEventSink{
		mockEventSink: mockEventSink{
			batches: make(map[string][]*SignalBatch),
		},
	}

	ctx := context.Background()
	agentID := testAgentID
	batch := &SignalBatch{
		Signals: []*SignalRecord{{SignalType: "log"}},
	}

	// Test OnSignalBatchWithResult
	result, err := mock.OnSignalBatchWithResult(ctx, agentID, batch)
	if err != nil {
		t.Errorf("OnSignalBatchWithResult() error: %v", err)
	}
	if result == nil {
		t.Error("Result should not be nil")
	}

	// Test OnPressure (inherited from EventSink)
	pressure := mock.OnPressure(agentID)
	if pressure != PressureNormal {
		t.Errorf("OnPressure() = %q, want 'normal'", pressure)
	}
}
func TestInflight(t *testing.T) {
	t.Run("Add inflight counters", func(t *testing.T) {
		inf := &Inflight{}

		inf.Add(10, 1024)

		if inf.batches.Load() != 1 {
			t.Errorf("batches = %d, want 1", inf.batches.Load())
		}
		if inf.events.Load() != 10 {
			t.Errorf("events = %d, want 10", inf.events.Load())
		}
		if inf.bytes.Load() != 1024 {
			t.Errorf("bytes = %d, want 1024", inf.bytes.Load())
		}
	})

	t.Run("Add multiple times", func(t *testing.T) {
		inf := &Inflight{}

		inf.Add(10, 1024)
		inf.Add(20, 2048)
		inf.Add(30, 4096)

		if inf.batches.Load() != 3 {
			t.Errorf("batches = %d, want 3", inf.batches.Load())
		}
		if inf.events.Load() != 60 {
			t.Errorf("events = %d, want 60", inf.events.Load())
		}
		if inf.bytes.Load() != 7168 {
			t.Errorf("bytes = %d, want 7168", inf.bytes.Load())
		}
	})

	t.Run("Add is thread-safe", func(t *testing.T) {
		inf := &Inflight{}
		done := make(chan bool)
		concurrency := 10

		for i := 0; i < concurrency; i++ {
			go func() {
				inf.Add(10, 1024)
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < concurrency; i++ {
			<-done
		}

		if inf.batches.Load() != int64(concurrency) {
			t.Errorf("batches = %d, want %d", inf.batches.Load(), concurrency)
		}
		if inf.events.Load() != int64(concurrency)*10 {
			t.Errorf("events = %d, want %d", inf.events.Load(), concurrency*10)
		}
	})
}

// TestInflightRemove tests the Remove method.
func TestInflightRemove(t *testing.T) {
	inf := &Inflight{}

	// Add some inflight
	inf.Add(100, 10240)
	inf.Add(50, 5120)

	// Mark one batch as done (remove)
	inf.Remove(50, 5120)

	if inf.batches.Load() != 1 {
		t.Errorf("batches = %d, want 1", inf.batches.Load())
	}
	if inf.events.Load() != 100 {
		t.Errorf("events = %d, want 100", inf.events.Load())
	}
	if inf.bytes.Load() != 10240 {
		t.Errorf("bytes = %d, want 10240", inf.bytes.Load())
	}
}

// TestInflightSnapshot tests the Snapshot method.
func TestInflightSnapshot(t *testing.T) {
	inf := &Inflight{}

	// Add inflight
	inf.Add(100, 10240)

	// Get current values via Snapshot
	batches, events, bytes := inf.Snapshot()

	if batches != 1 {
		t.Errorf("Snapshot().batches = %d, want 1", batches)
	}
	if events != 100 {
		t.Errorf("Snapshot().events = %d, want 100", events)
	}
	if bytes != 10240 {
		t.Errorf("Snapshot().bytes = %d, want 10240", bytes)
	}
}

// ===== Mock Implementations =====

// mockEventSink is a test implementation of EventSink.
type mockEventSink struct {
	mu      sync.Mutex
	batches map[string][]*SignalBatch
}

func (m *mockEventSink) OnSignalBatch(ctx context.Context, agentID string, batch *SignalBatch) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.batches[agentID] = append(m.batches[agentID], batch)
	return nil
}

func (m *mockEventSink) OnPressure(agentID string) PressureState {
	return PressureNormal
}

// mockDurableEventSink is a test implementation of DurableEventSink.
type mockDurableEventSink struct {
	mockEventSink
}

func (m *mockDurableEventSink) OnSignalBatchWithResult(ctx context.Context, agentID string, batch *SignalBatch) (*RouteResult, error) {
	err := m.OnSignalBatch(ctx, agentID, batch)
	return &RouteResult{
		Status:      ACKStatusDurable,
		EventsCount: len(batch.Signals),
		Pressure:    PressureNormal,
	}, err
}
