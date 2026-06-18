package core

import (
	"fmt"
	"slices"
	"sync"
	"time"
)

// State represents the session state machine state.
type State int

const (
	// StateDisconnected 表示会话已断开连接。
	StateDisconnected State = iota
	// StateConnecting 表示正在建立连接。
	StateConnecting
	// StateControlStreamOpen 表示控制流已打开。
	StateControlStreamOpen
	// StateHelloSent 表示已发送HELLO消息。
	StateHelloSent
	// StateHelloAcked 表示HELLO消息已确认。
	StateHelloAcked
	// StateAuthSent 表示已发送认证消息。
	StateAuthSent
	// StateReady 表示会话就绪，可以处理数据。
	StateReady
	// StateDraining 表示正在排空缓冲区。
	StateDraining
	// StateClosed 表示会话已关闭。
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateDisconnected:
		return "DISCONNECTED"
	case StateConnecting:
		return "CONNECTING"
	case StateControlStreamOpen:
		return "CONTROL_STREAM_OPEN"
	case StateHelloSent:
		return "HELLO_SENT"
	case StateHelloAcked:
		return "HELLO_ACKED"
	case StateAuthSent:
		return "AUTH_SENT"
	case StateReady:
		return "READY"
	case StateDraining:
		return "DRAINING"
	case StateClosed:
		return "CLOSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// validTransitions defines which state can transition to which.
var validTransitions = map[State][]State{
	StateDisconnected:      {StateConnecting},
	StateConnecting:        {StateControlStreamOpen, StateDisconnected},
	StateControlStreamOpen: {StateHelloSent, StateDisconnected},
	StateHelloSent:         {StateHelloAcked, StateDisconnected},
	StateHelloAcked:        {StateAuthSent, StateDisconnected},
	StateAuthSent:          {StateReady, StateDisconnected},
	StateReady:             {StateDraining, StateClosed, StateDisconnected},
	StateDraining:          {StateClosed},
	StateClosed:            {},
}

// ServerState represents the server-side session state.
type ServerState int

const (
	// ServerStateAccepted 表示服务器已接受连接。
	ServerStateAccepted ServerState = iota
	// ServerStateControlWait 表示等待控制流建立。
	ServerStateControlWait
	// ServerStateHelloReceived 表示已收到HELLO消息。
	ServerStateHelloReceived
	// ServerStateAuthWait 表示等待认证完成。
	ServerStateAuthWait
	// ServerStateReady 表示服务器会话就绪。
	ServerStateReady
	// ServerStateDraining 表示服务器正在排空缓冲区。
	ServerStateDraining
	// ServerStateClosed 表示服务器会话已关闭。
	ServerStateClosed
)

func (s ServerState) String() string {
	switch s {
	case ServerStateAccepted:
		return "ACCEPTED"
	case ServerStateControlWait:
		return "CONTROL_WAIT"
	case ServerStateHelloReceived:
		return "HELLO_RECEIVED"
	case ServerStateAuthWait:
		return "AUTH_WAIT"
	case ServerStateReady:
		return "READY"
	case ServerStateDraining:
		return "DRAINING"
	case ServerStateClosed:
		return "CLOSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// DefaultDrainTimeout is the maximum time to wait in StateDraining before
// the caller should force-close the connection.
const DefaultDrainTimeout = 30 * time.Second

// StateMachine is a thread-safe client-side state machine for MBTA sessions.
type StateMachine struct {
	mu           sync.Mutex
	state        State
	drainTimer   *time.Timer
	drainTimeout time.Duration
}

// NewStateMachine creates a client state machine starting at Disconnected.
func NewStateMachine() *StateMachine {
	return &StateMachine{state: StateDisconnected, drainTimeout: DefaultDrainTimeout}
}

// State returns the current state.
func (sm *StateMachine) State() State {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.state
}

// Transition attempts to move from current state to next.
func (sm *StateMachine) Transition(next State) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if slices.Contains(validTransitions[sm.state], next) {
		sm.state = next
		// Start drain timer when entering Draining state.
		if next == StateDraining && sm.drainTimeout > 0 {
			if sm.drainTimer != nil {
				sm.drainTimer.Stop()
			}
			sm.drainTimer = time.NewTimer(sm.drainTimeout)
		}
		return nil
	}
	return NewError(NumSession, CodeSession, fmt.Sprintf("invalid transition %s -> %s", sm.state, next))
}

// DrainExpired returns true if the drain timer has fired.
// Returns false if not in draining state, or if the timer hasn't expired yet.
func (sm *StateMachine) DrainExpired() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.state != StateDraining || sm.drainTimer == nil {
		return false
	}
	select {
	case <-sm.drainTimer.C:
		return true
	default:
		return false
	}
}

// ServerMachine is a thread-safe server-side state machine.
type ServerMachine struct {
	mu    sync.Mutex
	state ServerState
}

// NewServerMachine creates a server state machine starting at Accepted.
func NewServerMachine() *ServerMachine {
	return &ServerMachine{state: ServerStateAccepted}
}

// State returns the current state.
func (sm *ServerMachine) State() ServerState {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.state
}

// Transition moves to next state.
func (sm *ServerMachine) Transition(next ServerState) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	switch sm.state {
	case ServerStateAccepted:
		if next != ServerStateControlWait {
			goto invalid
		}
	case ServerStateControlWait:
		if next != ServerStateHelloReceived && next != ServerStateClosed {
			goto invalid
		}
	case ServerStateHelloReceived:
		if next != ServerStateAuthWait && next != ServerStateClosed {
			goto invalid
		}
	case ServerStateAuthWait:
		if next != ServerStateReady && next != ServerStateClosed {
			goto invalid
		}
	case ServerStateReady:
		if next != ServerStateDraining && next != ServerStateClosed {
			goto invalid
		}
	case ServerStateDraining:
		if next != ServerStateClosed {
			goto invalid
		}
	case ServerStateClosed:
		goto invalid
	default:
		goto invalid
	}

	sm.state = next
	return nil

invalid:
	return NewError(NumSession, CodeSession, fmt.Sprintf("invalid server transition %s -> %s", sm.state, next))
}
