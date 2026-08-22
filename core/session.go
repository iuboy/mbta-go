package core

import (
	"fmt"
	"slices"
	"sync"
	"time"
)

// --- 客户端状态机（4 态；Closed 是任意状态的一等出边）---

type State int

const (
	// StateIdle 初始态（含握手进行中——握手子步骤不再是 wire 可见状态）。
	StateIdle State = iota
	// StateReady 就绪，可发送。
	StateReady
	// StateDraining 排空中（等待全部已发 seq 终态）。
	StateDraining
	// StateClosed 终态。任意状态可达（close 收敛保证）。
	StateClosed
)

const (
	stateStrIdle     = "IDLE"
	stateStrReady    = "READY"
	stateStrDraining = "DRAINING"
	stateStrClosed   = "CLOSED"
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return stateStrIdle
	case StateReady:
		return stateStrReady
	case StateDraining:
		return stateStrDraining
	case StateClosed:
		return stateStrClosed
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// clientTransitions：Idle→Ready（握手完成）/ Ready→Draining→Closed；
// 任意状态 → Closed（close 必须总能收敛）；Idle→Closed（从未连接即 Close）。
var clientTransitions = map[State][]State{
	StateIdle:     {StateReady, StateClosed},
	StateReady:    {StateDraining, StateClosed},
	StateDraining: {StateClosed},
	StateClosed:   {},
}

// StateMachine 是线程安全的客户端状态机。
type StateMachine struct {
	mu    sync.Mutex
	state State
}

func NewStateMachine() *StateMachine { return &StateMachine{state: StateIdle} }

func (sm *StateMachine) State() State {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.state
}

func (sm *StateMachine) Transition(next State) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if slices.Contains(clientTransitions[sm.state], next) {
		sm.state = next
		return nil
	}
	return NewError(ErrCodeProtocol, fmt.Sprintf("invalid transition %s -> %s", sm.state, next))
}

// ForceClosed 从任意状态收敛到 Closed（close 专用；幂等）。
func (sm *StateMachine) ForceClosed() {
	sm.mu.Lock()
	sm.state = StateClosed
	sm.mu.Unlock()
}

// --- 服务端状态机（3 态）---

type ServerState int

const (
	// ServerStateHandshaking 等待/处理 HELLO。
	ServerStateHandshaking ServerState = iota
	// ServerStateReady 已完成握手。
	ServerStateReady
	// ServerStateDraining 排空中。
	ServerStateDraining
)

func (s ServerState) String() string {
	switch s {
	case ServerStateHandshaking:
		return "HANDSHAKING"
	case ServerStateReady:
		return stateStrReady
	case ServerStateDraining:
		return stateStrDraining
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// ServerMachine 是线程安全的服务端状态机。
type ServerMachine struct {
	mu    sync.Mutex
	state ServerState
}

func NewServerMachine() *ServerMachine { return &ServerMachine{state: ServerStateHandshaking} }

func (sm *ServerMachine) State() ServerState {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.state
}

func (sm *ServerMachine) Transition(next ServerState) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	valid := (sm.state == ServerStateHandshaking && next == ServerStateReady) ||
		(sm.state == ServerStateReady && next == ServerStateDraining)
	if !valid {
		return NewError(ErrCodeProtocol, fmt.Sprintf("invalid server transition %s -> %s", sm.state, next))
	}
	sm.state = next
	return nil
}

// --- 超时常量（继承 v1 防御值）---

// DefaultDrainTimeout 是 Close 排空的默认上限。
const DefaultDrainTimeout = 30 * time.Second

// DefaultReadTimeout 是无 ctx deadline 时 transport 读操作的默认上限。
const DefaultReadTimeout = 5 * time.Minute

// DefaultWriteTimeout 是无 ctx deadline 时 transport 写操作的默认上限。
const DefaultWriteTimeout = 30 * time.Second

// DefaultSessionTTL 是会话默认有效期。
const DefaultSessionTTL = 24 * time.Hour
