package core

import (
	"testing"
)

func BenchmarkStateMachine_Transition(b *testing.B) {
	sm := NewStateMachine()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		// Reset to initial state for each iteration
		sm.mu.Lock()
		sm.state = StateConnecting
		sm.mu.Unlock()

		_ = sm.Transition(StateControlStreamOpen)
		_ = sm.Transition(StateDisconnected)
	}
}

func BenchmarkStateMachine_State(b *testing.B) {
	sm := NewStateMachine()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = sm.State()
	}
}

func BenchmarkStateMachine_ConcurrentState(b *testing.B) {
	sm := NewStateMachine()
	sm.mu.Lock()
	sm.state = StateReady
	sm.mu.Unlock()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = sm.State()
		}
	})
}

func BenchmarkServerMachine_Transition(b *testing.B) {
	sm := NewServerMachine()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		sm.mu.Lock()
		sm.state = ServerStateAccepted
		sm.mu.Unlock()

		_ = sm.Transition(ServerStateControlWait)
		_ = sm.Transition(ServerStateClosed)
	}
}
