package core

import (
	"strings"
	"testing"
)

func TestStateMachineTransition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		from    State
		to      State
		wantErr bool
	}{
		{StateDisconnected, StateConnecting, false},
		{StateConnecting, StateControlStreamOpen, false},
		{StateConnecting, StateDisconnected, false},
		{StateControlStreamOpen, StateHelloSent, false},
		{StateControlStreamOpen, StateDisconnected, false},
		{StateHelloSent, StateHelloAcked, false},
		{StateHelloSent, StateDisconnected, false},
		{StateHelloAcked, StateAuthSent, false},
		{StateHelloAcked, StateDisconnected, false},
		{StateAuthSent, StateReady, false},
		{StateAuthSent, StateDisconnected, false},
		{StateReady, StateDraining, false},
		{StateReady, StateClosed, false},
		{StateReady, StateDisconnected, false},
		{StateDraining, StateClosed, false},
		// Invalid transitions
		{StateDisconnected, StateReady, true},
		{StateDisconnected, StateClosed, true},
		{StateReady, StateConnecting, true},
		{StateClosed, StateDisconnected, true},
		{StateClosed, StateReady, true},
	}

	for _, tt := range tests {
		t.Run(tt.from.String()+"->"+tt.to.String(), func(t *testing.T) {
			t.Parallel()
			sm := NewStateMachine()
			// Force into the "from" state
			sm.mu.Lock()
			sm.state = tt.from
			sm.mu.Unlock()

			err := sm.Transition(tt.to)
			if tt.wantErr {
				if err == nil {
					t.Errorf("%s: expected error, got nil", "transition should fail")
				}
			} else {
				if err != nil {
					t.Errorf("%s: %v", "transition should succeed", err)
				}
				if sm.State() != tt.to {
					t.Errorf("State() = %v, want %v", sm.State(), tt.to)
				}
			}
		})
	}
}

func TestStateMachineInitialState(t *testing.T) {
	t.Parallel()
	sm := NewStateMachine()
	if sm.State() != StateDisconnected {
		t.Errorf("Initial state = %v, want Disconnected", sm.State())
	}
}

func TestStateMachineFullHandshake(t *testing.T) {
	t.Parallel()
	sm := NewStateMachine()

	steps := []State{
		StateConnecting,
		StateControlStreamOpen,
		StateHelloSent,
		StateHelloAcked,
		StateAuthSent,
		StateReady,
	}
	for _, next := range steps {
		err := sm.Transition(next)
		if err != nil {
			t.Errorf("%s: %v", "transition to "+next.String(), err)
		}
		if sm.State() != next {
			t.Errorf("State() = %v, want %v", sm.State(), next)
		}
	}
}

// --- ServerMachine tests ---

func TestServerMachineInitialState(t *testing.T) {
	t.Parallel()
	sm := NewServerMachine()
	if sm.State() != ServerStateAccepted {
		t.Errorf("Initial state = %v, want Accepted", sm.State())
	}
}

func TestServerMachineValidTransitions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		from    ServerState
		to      ServerState
		wantErr bool
	}{
		{ServerStateAccepted, ServerStateControlWait, false},
		{ServerStateControlWait, ServerStateHelloReceived, false},
		{ServerStateControlWait, ServerStateClosed, false},
		{ServerStateHelloReceived, ServerStateAuthWait, false},
		{ServerStateHelloReceived, ServerStateClosed, false},
		{ServerStateAuthWait, ServerStateReady, false},
		{ServerStateAuthWait, ServerStateClosed, false},
		{ServerStateReady, ServerStateDraining, false},
		{ServerStateReady, ServerStateClosed, false},
		{ServerStateDraining, ServerStateClosed, false},
		// Invalid
		{ServerStateAccepted, ServerStateReady, true},
		{ServerStateAccepted, ServerStateClosed, true},
		{ServerStateReady, ServerStateAccepted, true},
		{ServerStateClosed, ServerStateAccepted, true},
		{ServerStateClosed, ServerStateReady, true},
	}

	for _, tt := range tests {
		t.Run(tt.from.String()+"->"+tt.to.String(), func(t *testing.T) {
			t.Parallel()
			sm := NewServerMachine()
			sm.mu.Lock()
			sm.state = tt.from
			sm.mu.Unlock()

			err := sm.Transition(tt.to)
			if tt.wantErr {
				if err == nil {
					t.Errorf("%s: expected error, got nil", "transition should fail")
				}
				if err != nil && !strings.Contains(err.Error(), "invalid server transition") {
					t.Errorf("Error = %v, want error containing 'invalid server transition'", err)
				}
			} else {
				if err != nil {
					t.Errorf("%s: %v", "transition should succeed", err)
				}
				if sm.State() != tt.to {
					t.Errorf("State() = %v, want %v", sm.State(), tt.to)
				}
			}
		})
	}
}

func TestServerMachineFullHandshake(t *testing.T) {
	t.Parallel()
	sm := NewServerMachine()

	steps := []ServerState{
		ServerStateControlWait,
		ServerStateHelloReceived,
		ServerStateAuthWait,
		ServerStateReady,
		ServerStateDraining,
		ServerStateClosed,
	}
	for _, next := range steps {
		err := sm.Transition(next)
		if err != nil {
			t.Errorf("%s: %v", "transition to "+next.String(), err)
		}
		if sm.State() != next {
			t.Errorf("State() = %v, want %v", sm.State(), next)
		}
	}
}

func TestServerMachineErrorPath(t *testing.T) {
	t.Parallel()
	sm := NewServerMachine()

	// Accepted -> ControlWait -> Closed (client disconnects during hello)
	if err := sm.Transition(ServerStateControlWait); err != nil {
		t.Errorf("%s: %v", "control wait", err)
	}
	if err := sm.Transition(ServerStateClosed); err != nil {
		t.Errorf("%s: %v", "close from control wait", err)
	}
}

func TestStateMachineErrorIs(t *testing.T) {
	t.Parallel()
	sm := NewStateMachine()
	err := sm.Transition(StateReady) // Invalid: Disconnected -> Ready
	if err == nil {
		t.Fatal("Expected error for invalid transition")
	}
	if !IsMBTAError(err) {
		t.Error("Expected MBTA error type")
	}
}

// IsMBTAError checks if an error is an MBTA *Error type.
func IsMBTAError(err error) bool {
	_, ok := err.(*Error)
	return ok
}
