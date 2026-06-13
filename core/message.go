package core

import (
	"encoding/json"
	"fmt"
)

// HelloMessage is sent by the agent on connect (C→S).
type HelloMessage struct {
	AgentID       string   `json:"agent_id"`
	Hostname      string   `json:"hostname"`
	Version       int      `json:"version"`
	AgentVersion  string   `json:"agent_version"`
	Capabilities  []string `json:"capabilities"`
	InstanceID    string   `json:"instance_id"`
	ConnID        string   `json:"conn_id,omitempty"`
	StartedAtUnix int64    `json:"started_at_unix,omitempty"`
}

// Validate 检查HelloMessage的有效性。
func (m *HelloMessage) Validate() error {
	if m.AgentID == "" {
		return NewError(NumValidation, CodeValidation, "agent_id is required")
	}
	if m.Version != 1 {
		return NewError(NumValidation, CodeValidation, fmt.Sprintf("version must be 1, got %d", m.Version))
	}
	return nil
}

// HelloAckMessage is the server's response to HELLO (S→C).
type HelloAckMessage struct {
	ServerVersion        int           `json:"server_version"`
	ServerID             string        `json:"server_id"`
	SessionID            string        `json:"session_id"`
	SelectedCapabilities []string      `json:"selected_capabilities"`
	Codec                string        `json:"codec"`
	Compression          string        `json:"compression"`
	HMACAlgo             string        `json:"hmac_algo"`
	Encryption           string        `json:"encryption"`
	HeartbeatIntervalSec int           `json:"heartbeat_interval_sec"`
	MaxFramePayloadBytes int           `json:"max_frame_payload_bytes"`
	MaxBatchBytes        int           `json:"max_batch_bytes"`
	MaxEventBytes        int           `json:"max_event_bytes"`
	MaxBatchEvents       int           `json:"max_batch_events"`
	InitialWindow        WindowMessage `json:"initial_window"`
	ChallengeNonce       string        `json:"challenge_nonce,omitempty"` // 服务端生成的挑战，客户端需回传
}

// Validate 检查HelloAckMessage的有效性。
func (m *HelloAckMessage) Validate() error {
	if m.SessionID == "" {
		return NewError(NumValidation, CodeValidation, "session_id is required")
	}
	if m.ServerVersion != 1 {
		return NewError(NumValidation, CodeValidation, "server_version must be 1")
	}
	return nil
}

// AuthMessage carries authentication credentials (C→S).
type AuthMessage struct {
	Token      string `json:"token,omitempty"`
	AgentID    string `json:"agent_id"`
	SessionID  string `json:"session_id"`
	HMACAlgo   string `json:"hmac_algo,omitempty"`
	SM2CertPEM string `json:"sm2_cert_pem,omitempty"`
	AuthNonce  string `json:"auth_nonce"`
}

// Validate 检查AuthMessage的有效性。
func (m *AuthMessage) Validate() error {
	if m.AgentID == "" {
		return NewError(NumValidation, CodeValidation, "agent_id is required")
	}
	if m.SessionID == "" {
		return NewError(NumValidation, CodeValidation, "session_id is required")
	}
	if m.AuthNonce == "" {
		return NewError(NumValidation, CodeValidation, "auth_nonce is required")
	}
	return nil
}

// AuthOKMessage is sent on successful authentication (S→C).
type AuthOKMessage struct {
	SessionID        string `json:"session_id"`
	KeyID            string `json:"key_id"`
	HMACKey          string `json:"hmac_key,omitempty"`  // Base64(32 bytes)
	HMACAlgo         string `json:"hmac_algo,omitempty"` // "sha256" or "sm3"
	SM4Key           string `json:"sm4_key,omitempty"`   // Base64(16 bytes)
	ServerSM2CertPEM string `json:"server_sm2_cert_pem,omitempty"`
	ExpiresAtUnix    int64  `json:"expires_at_unix,omitempty"`
}

// AuthFailMessage is sent on authentication failure (S→C).
type AuthFailMessage struct {
	Code      string `json:"code"`
	Reason    string `json:"reason"`
	Retryable bool   `json:"retryable"`
	// ChallengeNonce carries a freshly rotated server challenge on retryable
	// failures. Each challenge is valid for exactly one AUTH attempt, so a
	// client implementing retry MUST recompute AuthNonce against this new nonce
	// before resending. Older clients that do not recognize this field simply
	// surface the failure (backwards compatible). Optional: omitted on
	// non-retryable failures (e.g. too_many_attempts).
	ChallengeNonce string `json:"challenge_nonce,omitempty"`
}

// BatchMessage carries a batch of events inside the SecureEnvelope payload.
type BatchMessage struct {
	Seq     uint64          `json:"seq"`
	ChunkID string          `json:"chunk_id"`
	Tag     string          `json:"tag,omitempty"`
	Source  string          `json:"source,omitempty"`
	Batch   json.RawMessage `json:"batch"` // 原始 SignalBatch JSON（延迟解码）
}

// Validate 检查BatchMessage的有效性。
func (m *BatchMessage) Validate() error {
	if m.Seq == 0 {
		return NewError(NumValidation, CodeValidation, "seq must be >= 1")
	}
	if m.ChunkID == "" {
		return NewError(NumValidation, CodeValidation, "chunk_id is required")
	}
	if len(m.ChunkID) > 256 {
		return NewError(NumValidation, CodeValidation, "chunk_id exceeds maximum length of 256")
	}
	if len(m.Batch) == 0 {
		return NewError(NumValidation, CodeValidation, "batch must not be empty")
	}
	if !json.Valid(m.Batch) {
		return NewError(NumValidation, CodeValidation, "batch must be valid JSON")
	}
	return nil
}

// AckMessage confirms a batch was accepted (S→C).
type AckMessage struct {
	Seq        uint64 `json:"seq"`
	ChunkID    string `json:"chunk_id"`
	Count      int    `json:"count"`
	AckMode    string `json:"ack_mode"`
	ReceivedAt int64  `json:"received_at_unix_ms"`
}

// NackMessage rejects an entire batch (S→C).
type NackMessage struct {
	Seq          uint64 `json:"seq"`
	ChunkID      string `json:"chunk_id"`
	Code         string `json:"code"`
	Reason       string `json:"reason"`
	Retryable    bool   `json:"retryable"`
	RetryAfterMs int    `json:"retry_after_ms,omitempty"`
}

// PartialAckMessage acknowledges some events and rejects others (S→C).
type PartialAckMessage struct {
	Seq      uint64          `json:"seq"`
	ChunkID  string          `json:"chunk_id"`
	Accepted []uint32        `json:"accepted,omitempty"`
	Rejected []RejectedEvent `json:"rejected,omitempty"`
	AckMode  string          `json:"ack_mode"`
}

// RejectedEvent describes a single rejected event within a batch.
type RejectedEvent struct {
	Index     uint32 `json:"index"`
	EventID   string `json:"event_id,omitempty"`
	Code      string `json:"code"`
	Reason    string `json:"reason"`
	Retryable bool   `json:"retryable"`
}

// WindowMessage carries flow-control limits (S→C).
type WindowMessage struct {
	MaxInflightBatches int    `json:"max_inflight_batches"`
	MaxInflightEvents  int    `json:"max_inflight_events"`
	MaxInflightBytes   int64  `json:"max_inflight_bytes"`
	Reason             string `json:"reason,omitempty"`
}

// ThrottleMessage tells the client to pause sending (S→C).
type ThrottleMessage struct {
	RetryDelayMs int    `json:"retry_delay_ms"`
	Code         string `json:"code"`
	Reason       string `json:"reason"`
}

// PingMessage is a health-check probe (bidirectional).
type PingMessage struct {
	TimeUnixMs int64  `json:"time_unix_ms"`
	Nonce      string `json:"nonce"`
}

// PongMessage is a health-check response (bidirectional).
type PongMessage struct {
	TimeUnixMs int64  `json:"time_unix_ms"`
	Nonce      string `json:"nonce"`
	Status     string `json:"status"` // ok / degraded
}

// CloseMessage initiates graceful connection close (bidirectional).
type CloseMessage struct {
	Code   string `json:"code"`
	Reason string `json:"reason,omitempty"`
}

// ErrorMessage reports a protocol error (bidirectional).
type ErrorMessage struct {
	Code      string `json:"code"`
	Reason    string `json:"reason"`
	Fatal     bool   `json:"fatal"`
	Retryable bool   `json:"retryable"`
}

// AuthResult is returned for both AUTH_OK and AUTH_FAIL.
type AuthResult struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// Encode marshals a message to JSON bytes.
func Encode(v any) ([]byte, error) {
	return json.Marshal(v)
}

// Decode unmarshals JSON bytes into v.
func Decode(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
