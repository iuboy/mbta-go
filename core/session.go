package core

import (
	"fmt"
	"sync"
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

// StateMachine is a thread-safe client-side state machine for MBTA sessions.
type StateMachine struct {
	mu    sync.Mutex
	state State
}

// NewStateMachine creates a client state machine starting at Disconnected.
func NewStateMachine() *StateMachine {
	return &StateMachine{state: StateDisconnected}
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

	for _, valid := range validTransitions[sm.state] {
		if valid == next {
			sm.state = next
			return nil
		}
	}
	return fmt.Errorf("invalid transition %s -> %s", sm.state, next)
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
	return fmt.Errorf("invalid server transition %s -> %s", sm.state, next)
}

// Policy controls which capabilities the server accepts and which algorithms it prefers.
type Policy struct {
	RequireToken      bool
	EnableGzip        bool
	EnableHMACSHA256  bool
	EnableHMACSM3     bool
	EnableSM4GCM      bool
	EnableSM2CertAuth bool
	EnablePartialAck  bool
	EnableWindow      bool
	EnableThrottle    bool
	EnableDurableAck  bool
	EnableMultiStream bool
}

// NegotiateResult contains the selected capabilities and algorithms.
type NegotiateResult struct {
	SelectedCapabilities []string
	Codec                string
	Compression          string
	HMACAlgo             string
	Encryption           string
}

// Negotiate computes the server-selected capabilities based on client offers and server policy.
func Negotiate(clientCaps []string, policy Policy) NegotiateResult {
	offered := toSet(clientCaps)
	res := NegotiateResult{
		Codec:       CodecJSON,
		Compression: CompressionNone,
		HMACAlgo:    HMACAlgoNone,
		Encryption:  EncryptionNone,
	}

	// Codec: json is required
	res.SelectedCapabilities = append(res.SelectedCapabilities, CapCodecJSON)

	// Compression
	if policy.EnableGzip && offered[CapCompressGzip] {
		res.Compression = CompressionGzip
		res.SelectedCapabilities = append(res.SelectedCapabilities, CapCompressGzip)
	}

	// HMAC: prefer sm3 over sha256 when both available
	if policy.EnableHMACSM3 && offered[CapHMACSM3] {
		res.HMACAlgo = HMACAlgoSM3
		res.SelectedCapabilities = append(res.SelectedCapabilities, CapHMACSM3)
	} else if policy.EnableHMACSHA256 && offered[CapHMACSHA256] {
		res.HMACAlgo = HMACAlgoSHA256
		res.SelectedCapabilities = append(res.SelectedCapabilities, CapHMACSHA256)
	}

	// Encryption
	if policy.EnableSM4GCM && offered[CapSM4GCM] {
		res.Encryption = EncryptionSM4
		res.SelectedCapabilities = append(res.SelectedCapabilities, CapSM4GCM)
	}

	// SM2 cert auth
	if policy.EnableSM2CertAuth && offered[CapSM2CertAuth] {
		res.SelectedCapabilities = append(res.SelectedCapabilities, CapSM2CertAuth)
	}

	// Other capabilities
	for _, cap := range []struct {
		enable  bool
		offered string
	}{
		{policy.EnablePartialAck, CapPartialAck},
		{policy.EnableWindow, CapWindowFlowCtrl},
		{policy.EnableThrottle, CapThrottle},
		{policy.EnableDurableAck, CapDurableAck},
		{policy.EnableMultiStream, CapMultiStream},
	} {
		if cap.enable && offered[cap.offered] {
			res.SelectedCapabilities = append(res.SelectedCapabilities, cap.offered)
		}
	}

	return res
}

// ValidateHello checks the HELLO message is valid for v1.
func ValidateHello(agentID string, version int) error {
	if agentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	if version != 1 {
		return fmt.Errorf("unsupported version %d", version)
	}
	return nil
}

func toSet(caps []string) map[string]bool {
	s := make(map[string]bool, len(caps))
	for _, c := range caps {
		s[c] = true
	}
	return s
}
