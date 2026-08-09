package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/internal/testutil"
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
			Status:   ACKStatusDurable,
			Pressure: PressureNormal,
		}

		if result.Status != ACKStatusDurable {
			t.Errorf("Status = %q, want 'durable'", result.Status)
		}
		if result.Pressure != PressureNormal {
			t.Errorf("Pressure = %q, want 'normal'", result.Pressure)
		}
	})

	t.Run("throttled routing result", func(t *testing.T) {
		result := &RouteResult{
			Status:   ACKStatusThrottle,
			Pressure: PressureCritical,
		}

		if result.Status != ACKStatusThrottle {
			t.Errorf("Status = %q, want 'throttle'", result.Status)
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
	agentID := testutil.RandAgentID()
	batch := &SignalBatch{
		Signals: []*SignalRecord{{SignalType: "log"}},
	}

	// Test OnSignalBatch
	err := mock.OnSignalBatch(ctx, agentID, batch)
	if err != nil {
		t.Errorf("%s: %v", "OnSignalBatch", err)
	}

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
	agentID := testutil.RandAgentID()
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
		events := testutil.RandInt(1, 100)
		nbytes := int64(testutil.RandInt(1, 10000))

		inf.Add(events, nbytes)

		if inf.batches.Load() != 1 {
			t.Errorf("batches = %d, want 1", inf.batches.Load())
		}
		if inf.events.Load() != int64(events) {
			t.Errorf("events = %d, want %d", inf.events.Load(), events)
		}
		if inf.bytes.Load() != nbytes {
			t.Errorf("bytes = %d, want %d", inf.bytes.Load(), nbytes)
		}
	})

	t.Run("Add multiple times", func(t *testing.T) {
		inf := &Inflight{}
		e1, b1 := testutil.RandInt(1, 100), int64(testutil.RandInt(1, 10000))
		e2, b2 := testutil.RandInt(1, 100), int64(testutil.RandInt(1, 10000))
		e3, b3 := testutil.RandInt(1, 100), int64(testutil.RandInt(1, 10000))

		inf.Add(e1, b1)
		inf.Add(e2, b2)
		inf.Add(e3, b3)

		if inf.batches.Load() != 3 {
			t.Errorf("batches = %d, want 3", inf.batches.Load())
		}
		if inf.events.Load() != int64(e1+e2+e3) {
			t.Errorf("events = %d, want %d", inf.events.Load(), e1+e2+e3)
		}
		if inf.bytes.Load() != b1+b2+b3 {
			t.Errorf("bytes = %d, want %d", inf.bytes.Load(), b1+b2+b3)
		}
	})

	t.Run("Add is thread-safe", func(t *testing.T) {
		inf := &Inflight{}
		done := make(chan bool)
		concurrency := 10
		events, nbytes := testutil.RandInt(1, 100), int64(testutil.RandInt(1, 10000))

		for range concurrency {
			go func() {
				inf.Add(events, nbytes)
				done <- true
			}()
		}

		// Wait for all goroutines
		for range concurrency {
			<-done
		}

		if inf.batches.Load() != int64(concurrency) {
			t.Errorf("batches = %d, want %d", inf.batches.Load(), concurrency)
		}
		if inf.events.Load() != int64(concurrency)*int64(events) {
			t.Errorf("events = %d, want %d", inf.events.Load(), concurrency*events)
		}
	})
}

// TestInflightRemove tests the Remove method.
func TestInflightRemove(t *testing.T) {
	inf := &Inflight{}

	// Add some inflight
	e1, b1 := testutil.RandInt(10, 1000), int64(testutil.RandInt(100, 100000))
	e2, b2 := testutil.RandInt(10, 1000), int64(testutil.RandInt(100, 100000))
	inf.Add(e1, b1)
	inf.Add(e2, b2)

	// Mark one batch as done (remove)
	inf.Remove(e2, b2)

	if inf.batches.Load() != 1 {
		t.Errorf("batches = %d, want 1", inf.batches.Load())
	}
	if inf.events.Load() != int64(e1) {
		t.Errorf("events = %d, want %d", inf.events.Load(), e1)
	}
	if inf.bytes.Load() != b1 {
		t.Errorf("bytes = %d, want %d", inf.bytes.Load(), b1)
	}
}

// TestInflightSnapshot tests the Snapshot method.
func TestInflightSnapshot(t *testing.T) {
	inf := &Inflight{}

	// Add inflight
	events, nbytes := testutil.RandInt(10, 1000), int64(testutil.RandInt(100, 100000))
	inf.Add(events, nbytes)

	// Get current values via Snapshot
	batches, gotEvents, gotBytes := inf.Snapshot()

	if batches != 1 {
		t.Errorf("Snapshot().batches = %d, want 1", batches)
	}
	if gotEvents != events {
		t.Errorf("Snapshot().events = %d, want %d", gotEvents, events)
	}
	if gotBytes != nbytes {
		t.Errorf("Snapshot().bytes = %d, want %d", gotBytes, nbytes)
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
		Status:   ACKStatusDurable,
		Pressure: PressureNormal,
	}, err
}

// --- Window 单元测试 ---

func TestWindow_CanSend_Boundary(t *testing.T) {
	w := NewWindow(10, 100, 1000)
	inf := &Inflight{}

	// 空闲时正好等于上限应通过（batches: 0+1 <= 10）。
	if !w.CanSend(inf, 100, 1000) {
		t.Error("CanSend should allow batch exactly at limit")
	}

	// 超过任一维度应拒绝。
	if w.CanSend(inf, 101, 1000) {
		t.Error("CanSend should reject events exceeding limit")
	}
	if w.CanSend(inf, 100, 1001) {
		t.Error("CanSend should reject bytes exceeding limit")
	}
}

func TestWindow_CanSend_PausedDimension(t *testing.T) {
	// max=0 表示该维度暂停。
	w := NewWindow(0, 100, 1000)
	inf := &Inflight{}
	if w.CanSend(inf, 1, 1) {
		t.Error("CanSend should reject when maxBatches=0 (paused)")
	}
}

func TestWindow_CanSend_NilReceiver(t *testing.T) {
	var w *Window
	inf := &Inflight{}
	if w.CanSend(inf, 1, 1) {
		t.Error("nil Window CanSend should return false")
	}
}

// --- ThrottleState 单元测试 ---

func TestThrottleState_Apply_NegativeDelay(t *testing.T) {
	var ts ThrottleState
	ts.Apply(-100) // 负值应被 clamp 到 0
	if ts.Active() {
		t.Error("negative delay should not activate throttle (clamped to 0)")
	}
}

func TestThrottleState_Active_And_WaitDuration(t *testing.T) {
	var ts ThrottleState
	if ts.Active() {
		t.Error("zero-value ThrottleState should not be active")
	}
	if d := ts.WaitDuration(); d != 0 {
		t.Errorf("zero-value WaitDuration = %v, want 0", d)
	}

	ts.Apply(100) // 100ms
	if !ts.Active() {
		t.Error("ThrottleState should be active after Apply(100ms)")
	}
	d := ts.WaitDuration()
	if d <= 0 || d > 100*time.Millisecond {
		t.Errorf("WaitDuration = %v, want (0, 100ms]", d)
	}
}

func TestThrottleState_Expired(t *testing.T) {
	var ts ThrottleState
	ts.Apply(1) // 1ms
	time.Sleep(10 * time.Millisecond)
	if ts.Active() {
		t.Error("ThrottleState should be inactive after expiry")
	}
	if d := ts.WaitDuration(); d != 0 {
		t.Errorf("expired WaitDuration = %v, want 0", d)
	}
}

func TestThrottleState_MaxThrottleDelayClamp(t *testing.T) {
	var ts ThrottleState
	// 超大值应被 clamp 到 MaxThrottleDelay。
	ts.Apply(int(MaxThrottleDelay/time.Millisecond) + 10000)
	if !ts.Active() {
		t.Error("should still be active after huge delay (clamped)")
	}
	// WaitDuration 不应超过 MaxThrottleDelay。
	if d := ts.WaitDuration(); d > MaxThrottleDelay {
		t.Errorf("WaitDuration = %v, exceeds MaxThrottleDelay %v", d, MaxThrottleDelay)
	}
}
