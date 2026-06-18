package core

import (
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"
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

// Policy 控制 server 接受的 capability 与默认算法（r2 capability-driven）。
// 默认 CipherSuite 跟随传输 binding 合规语境（core spec §8.3）。
type Policy struct {
	// SupportedCapabilities 是服务端支持的 stable capability 集合。
	// Negotiate 与客户端宣告取交集（自动降级，core spec §12.1）。
	SupportedCapabilities []string
	// 默认算法（客户端未 offer 对应 capability 时使用）。
	DefaultCodec       corepb.Codec       // 通常 CODEC_PROTO
	DefaultCompression corepb.Compression // 通常 COMPRESSION_ZSTD
	CipherSuite        corepb.CipherSuite // intl / gm，跟随 binding
}

// NegotiateResult 包含选定 capability 与算法（r2：corepb enum）。
type NegotiateResult struct {
	SelectedCapabilities []string
	Codec                corepb.Codec
	Compression          corepb.Compression
	CipherSuite          corepb.CipherSuite
}

// Negotiate 计算 server 选定的 capability（r2 capability-driven）。
//
// 协商失败语义（core spec §1.3）：
//   - 客户端宣告的未识别 stable capability → 返回协议错误（不允许静默吞掉）；
//   - experimental（x-）→ 静默忽略。
//
// 算法选择：从客户端与服务端的公共 stable capability 集合推导 codec/compression/cipher，
// 否则用 Policy 默认。selected 排序以保证 HELLO_ACK 确定性。
//
// 设计说明：HELLO 和 AUTH 分为两步，便于 token 轮换、AUTH payload 加密保护、
// 以及 HELLO_ACK 下发 challenge nonce 用于挑战-响应。
func Negotiate(clientCaps []string, policy Policy) (NegotiateResult, error) {
	if unknown := FilterUnknownStable(clientCaps); len(unknown) > 0 {
		return NegotiateResult{}, NewError(NumProtocol, CodeProtocol,
			fmt.Sprintf("unknown stable capabilities from client: %v", unknown))
	}

	serverSupported := toSet(policy.SupportedCapabilities)
	clientSet := toSet(clientCaps)

	var selected []string
	for capName := range stableCapabilities {
		if clientSet[capName] && serverSupported[capName] {
			selected = append(selected, capName)
		}
	}
	sort.Strings(selected)

	return NegotiateResult{
		SelectedCapabilities: selected,
		Codec:                pickCodec(selected, policy.DefaultCodec),
		Compression:          pickCompression(selected, policy.DefaultCompression),
		CipherSuite:          pickCipherSuite(selected, policy.CipherSuite),
	}, nil
}

// pickCodec 从选定 capability 推导 codec。
//
// 当前仅支持 proto（唯一实现的 codec，见 signal_codec.go）。即便 def 传入
// CODEC_JSON/CODEC_JSON 也忽略——协商层面已从 capability 移除 codec_cbor/codec_json，
// 此函数只可能命中 codec_proto 或返回 def。def 通常为 CODEC_PROTO。
func pickCodec(selected []string, def corepb.Codec) corepb.Codec {
	set := toSet(selected)
	if set["codec_proto"] {
		return corepb.Codec_CODEC_PROTO
	}
	return def
}

func pickCompression(selected []string, def corepb.Compression) corepb.Compression {
	set := toSet(selected)
	switch {
	case set["comp_zstd"]:
		return corepb.Compression_COMPRESSION_ZSTD
	case set["comp_lz4"]:
		return corepb.Compression_COMPRESSION_LZ4
	case set["comp_gzip"]:
		return corepb.Compression_COMPRESSION_GZIP
	case set["comp_none"]:
		return corepb.Compression_COMPRESSION_NONE
	}
	return def
}

func pickCipherSuite(selected []string, def corepb.CipherSuite) corepb.CipherSuite {
	set := toSet(selected)
	if set["cs_gm"] {
		return corepb.CipherSuite_CIPHER_SUITE_GM
	}
	if set["cs_intl"] {
		return corepb.CipherSuite_CIPHER_SUITE_INTL
	}
	return def
}

// IsCapabilitySelected reports whether capability was among the server-selected
// capabilities. Safe to call on a nil *NegotiateResult (returns false), so
// callers need not nil-check before querying.
func (r *NegotiateResult) IsCapabilitySelected(capability string) bool {
	if r == nil {
		return false
	}
	return slices.Contains(r.SelectedCapabilities, capability)
}

func toSet(caps []string) map[string]bool {
	s := make(map[string]bool, len(caps))
	for _, c := range caps {
		s[c] = true
	}
	return s
}
