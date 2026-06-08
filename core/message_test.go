package core

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	mbtatest "github.com/iuboy/mbta-go/testing"
)

// TestHelloMessageValidate tests the HelloMessage Validate method.
func TestHelloMessageValidate(t *testing.T) {
	tests := []struct {
		name    string
		msg     HelloMessage
		wantErr bool
		errSub  string
	}{
		{
			name: "valid HelloMessage",
			msg: HelloMessage{
				AgentID:      "agent-123",
				Hostname:     "localhost",
				Version:      1,
				AgentVersion: "1.0.0",
				Capabilities: []string{"codec_json", "compress_gzip"},
				InstanceID:   "inst-456",
			},
			wantErr: false,
		},
		{
			name:    "empty agent_id",
			msg:     HelloMessage{AgentID: "", Version: 1},
			wantErr: true,
			errSub:  "agent_id is required",
		},
		{
			name:    "invalid version",
			msg:     HelloMessage{AgentID: "test", Version: 2},
			wantErr: true,
			errSub:  "version must be 1",
		},
		{
			name:    "zero version",
			msg:     HelloMessage{AgentID: "test", Version: 0},
			wantErr: true,
			errSub:  "version must be 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.errSub)
				} else if !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errSub)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestHelloAckMessageValidate tests the HelloAckMessage Validate method.
func TestHelloAckMessageValidate(t *testing.T) {
	tests := []struct {
		name    string
		msg     HelloAckMessage
		wantErr bool
		errSub  string
	}{
		{
			name: "valid HelloAckMessage",
			msg: HelloAckMessage{
				ServerVersion:        1,
				ServerID:             "srv-123",
				SessionID:            "sess-456",
				SelectedCapabilities: []string{"codec_json"},
				Codec:                "json",
				Compression:          "gzip",
				HMACAlgo:             "sha256",
				Encryption:           "aes-256-gcm",
				HeartbeatIntervalSec: 30,
			},
			wantErr: false,
		},
		{
			name:    "empty session_id",
			msg:     HelloAckMessage{ServerVersion: 1, ServerID: "srv"},
			wantErr: true,
			errSub:  "session_id is required",
		},
		{
			name:    "invalid server version",
			msg:     HelloAckMessage{ServerVersion: 2, SessionID: "sess"},
			wantErr: true,
			errSub:  "server_version must be 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.errSub)
				} else if !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errSub)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestAuthMessageValidate tests the AuthMessage Validate method.
func TestAuthMessageValidate(t *testing.T) {
	tests := []struct {
		name    string
		msg     AuthMessage
		wantErr bool
		errSub  string
	}{
		{
			name: "valid AuthMessage with token",
			msg: AuthMessage{
				Token:     "test-token",
				AgentID:   "agent-123",
				SessionID: "sess-456",
				AuthNonce: "nonce-789",
			},
			wantErr: false,
		},
		{
			name: "valid AuthMessage with SM2 cert",
			msg: AuthMessage{
				AgentID:    "agent-123",
				SessionID:  "sess-456",
				AuthNonce:  "nonce-789",
				SM2CertPEM: "-----BEGIN CERT-----...",
			},
			wantErr: false,
		},
		{
			name:    "empty agent_id",
			msg:     AuthMessage{SessionID: "sess", AuthNonce: "nonce"},
			wantErr: true,
			errSub:  "agent_id is required",
		},
		{
			name:    "empty session_id",
			msg:     AuthMessage{AgentID: "agent", AuthNonce: "nonce"},
			wantErr: true,
			errSub:  "session_id is required",
		},
		{
			name:    "empty auth_nonce",
			msg:     AuthMessage{AgentID: "agent", SessionID: "sess"},
			wantErr: true,
			errSub:  "auth_nonce is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.errSub)
				} else if !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errSub)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestBatchMessageValidate tests the BatchMessage Validate method.
func TestBatchMessageValidate(t *testing.T) {
	tests := []struct {
		name    string
		msg     BatchMessage
		wantErr bool
		errSub  string
	}{
		{
			name: "valid BatchMessage",
			msg: BatchMessage{
				Seq:     1,
				ChunkID: "chunk-123",
				Tag:     "tag-1",
				Source:  "source-1",
				Batch:   []byte(`{"signals":[]}`),
			},
			wantErr: false,
		},
		{
			name:    "zero seq",
			msg:     BatchMessage{Seq: 0, ChunkID: "chunk", Batch: []byte("{}")},
			wantErr: true,
			errSub:  "seq must be >= 1",
		},
		{
			name:    "empty chunk_id",
			msg:     BatchMessage{Seq: 1, ChunkID: "", Batch: []byte("{}")},
			wantErr: true,
			errSub:  "chunk_id is required",
		},
		{
			name:    "empty batch",
			msg:     BatchMessage{Seq: 1, ChunkID: "chunk", Batch: []byte{}},
			wantErr: true,
			errSub:  "batch must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.errSub)
				} else if !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errSub)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestEncodeDecodeRoundTrip tests that Encode and Decode are inverses.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		obj  any
	}{
		{
			name: "HelloMessage",
			obj: HelloMessage{
				AgentID:      "agent-123",
				Hostname:     "localhost",
				Version:      1,
				AgentVersion: "1.0.0",
				Capabilities: []string{"codec_json", "compress_gzip"},
				InstanceID:   "inst-456",
			},
		},
		{
			name: "HelloAckMessage",
			obj: HelloAckMessage{
				ServerVersion:        1,
				ServerID:             "srv-123",
				SessionID:            "sess-456",
				SelectedCapabilities: []string{"codec_json"},
				Codec:                "json",
				Compression:          "gzip",
			},
		},
		{
			name: "AuthMessage",
			obj: AuthMessage{
				Token:     "test-token",
				AgentID:   "agent-123",
				SessionID: "sess-456",
				AuthNonce: "nonce-789",
			},
		},
		{
			name: "AuthOKMessage",
			obj: AuthOKMessage{
				SessionID: "sess-456",
				KeyID:     "key-789",
			},
		},
		{
			name: "AuthFailMessage",
			obj: AuthFailMessage{
				Code:      "INVALID_TOKEN",
				Reason:    "Token expired",
				Retryable: true,
			},
		},
		{
			name: "BatchMessage",
			obj: BatchMessage{
				Seq:     1,
				ChunkID: "chunk-123",
				Tag:     "tag-1",
				Batch:   []byte(`{"signals":[{"type":"log"}]}`),
			},
		},
		{
			name: "AckMessage",
			obj: AckMessage{
				Seq:        1,
				ChunkID:    "chunk-123",
				Count:      10,
				AckMode:    "durable",
				ReceivedAt: 1234567890,
			},
		},
		{
			name: "NackMessage",
			obj: NackMessage{
				Seq:       1,
				ChunkID:   "chunk-123",
				Code:      "INVALID_BATCH",
				Reason:    "Validation failed",
				Retryable: false,
			},
		},
		{
			name: "WindowMessage",
			obj: WindowMessage{
				MaxInflightBatches: 100,
				MaxInflightEvents:  10000,
				MaxInflightBytes:   10 * 1024 * 1024,
			},
		},
		{
			name: "ThrottleMessage",
			obj: ThrottleMessage{
				RetryDelayMs: 5000,
				Code:         "RATE_LIMIT",
				Reason:       "Too many requests",
			},
		},
		{
			name: "PingMessage",
			obj: PingMessage{
				TimeUnixMs: 1234567890,
				Nonce:      "ping-nonce",
			},
		},
		{
			name: "PongMessage",
			obj: PongMessage{
				TimeUnixMs: 1234567890,
				Nonce:      "ping-nonce",
				Status:     "ok",
			},
		},
		{
			name: "CloseMessage",
			obj: CloseMessage{
				Code:   "GRACEFUL",
				Reason: "Shutdown",
			},
		},
		{
			name: "ErrorMessage",
			obj: ErrorMessage{
				Code:      "PROTOCOL_ERROR",
				Reason:    "Invalid frame",
				Fatal:     true,
				Retryable: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			data, err := Encode(tt.obj)
			mbtatest.AssertNoError(t, err, "Encode()")

			// Decode
			decoded := newInstanceOf(tt.obj)
			err = Decode(data, decoded)
			mbtatest.AssertNoError(t, err, "Decode()")

			// Verify round-trip
			if !isEqual(t, tt.obj, decoded) {
				t.Errorf("Round-trip failed: original != decoded")
			}
		})
	}
}

// TestEncode tests the Encode function with various inputs.
func TestEncode(t *testing.T) {
	tests := []struct {
		name    string
		obj     any
		wantErr bool
	}{
		{
			name:    "valid HelloMessage",
			obj:     HelloMessage{AgentID: "test", Version: 1},
			wantErr: false,
		},
		{
			name:    "struct with all fields",
			obj:     BatchMessage{Seq: 1, ChunkID: "chunk", Batch: []byte("{}")},
			wantErr: false,
		},
		{
			name:    "nested struct",
			obj:     PartialAckMessage{Seq: 1, ChunkID: "chunk", AckMode: "durable"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := Encode(tt.obj)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Encode() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Encode() unexpected error: %v", err)
				}
				if len(data) == 0 {
					t.Errorf("Encode() returned empty data")
				}
			}
		})
	}
}

// TestDecode tests the Decode function with various inputs.
func TestDecode(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		target  any
		wantErr bool
		errSub  string
	}{
		{
			name:    "valid HelloMessage JSON",
			data:    []byte(`{"agent_id":"test","version":1,"hostname":"localhost"}`),
			target:  &HelloMessage{},
			wantErr: false,
		},
		{
			name:    "valid BatchMessage JSON",
			data:    []byte(`{"seq":1,"chunk_id":"chunk","batch":"e30="}`), // base64 of "{}"
			target:  &BatchMessage{},
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			data:    []byte(`{invalid json}`),
			target:  &HelloMessage{},
			wantErr: true,
			errSub:  "invalid character",
		},
		{
			name:    "empty JSON",
			data:    []byte(`{}`),
			target:  &HelloMessage{},
			wantErr: false, // empty JSON is valid, just zero values
		},
		{
			name:    "wrong type in JSON",
			data:    []byte(`{"agent_id":123}`), // should be string
			target:  &HelloMessage{},
			wantErr: true,
			errSub:  "cannot unmarshal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Decode(tt.data, tt.target)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Decode() expected error containing %q, got nil", tt.errSub)
				} else if !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("Decode() error = %v, want error containing %q", err, tt.errSub)
				}
			} else {
				if err != nil {
					t.Errorf("Decode() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestAckMessage tests AckMessage structure.
func TestAckMessage(t *testing.T) {
	tests := []struct {
		name      string
		msg       AckMessage
		wantValid bool
	}{
		{
			name: "valid durable ACK",
			msg: AckMessage{
				Seq:        1,
				ChunkID:    "chunk-123",
				Count:      10,
				AckMode:    "durable",
				ReceivedAt: 1234567890,
			},
			wantValid: true,
		},
		{
			name: "valid accepted ACK",
			msg: AckMessage{
				Seq:     2,
				ChunkID: "chunk-456",
				Count:   5,
				AckMode: "accepted",
			},
			wantValid: true,
		},
		{
			name: "zero count (allowed)",
			msg: AckMessage{
				Seq:     3,
				ChunkID: "chunk-789",
				Count:   0,
				AckMode: "accepted",
			},
			wantValid: true,
		},
		{
			name: "empty ack_mode (invalid in practice but struct allows)",
			msg: AckMessage{
				Seq:     1,
				ChunkID: "chunk",
				AckMode: "",
			},
			wantValid: true, // struct has no validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// AckMessage has no Validate method, just test JSON handling
			data, err := Encode(tt.msg)
			mbtatest.AssertNoError(t, err, "Encode()")

			var decoded AckMessage
			err = Decode(data, &decoded)
			mbtatest.AssertNoError(t, err, "Decode()")

			if decoded.Seq != tt.msg.Seq {
				t.Errorf("Seq = %d, want %d", decoded.Seq, tt.msg.Seq)
			}
			if decoded.ChunkID != tt.msg.ChunkID {
				t.Errorf("ChunkID = %q, want %q", decoded.ChunkID, tt.msg.ChunkID)
			}
		})
	}
}

// TestWindowMessage tests WindowMessage structure.
func TestWindowMessage(t *testing.T) {
	msg := WindowMessage{
		MaxInflightBatches: 100,
		MaxInflightEvents:  10000,
		MaxInflightBytes:   10 * 1024 * 1024,
		Reason:             "Initial window",
	}

	data, err := Encode(msg)
	mbtatest.AssertNoError(t, err, "Encode()")

	var decoded WindowMessage
	err = Decode(data, &decoded)
	mbtatest.AssertNoError(t, err, "Decode()")

	if decoded.MaxInflightBatches != msg.MaxInflightBatches {
		t.Errorf("MaxInflightBatches = %d, want %d", decoded.MaxInflightBatches, msg.MaxInflightBatches)
	}
	if decoded.MaxInflightEvents != msg.MaxInflightEvents {
		t.Errorf("MaxInflightEvents = %d, want %d", decoded.MaxInflightEvents, msg.MaxInflightEvents)
	}
	if decoded.MaxInflightBytes != msg.MaxInflightBytes {
		t.Errorf("MaxInflightBytes = %d, want %d", decoded.MaxInflightBytes, msg.MaxInflightBytes)
	}
}

// TestPartialAckMessage tests PartialAckMessage with RejectedEvent.
func TestPartialAckMessage(t *testing.T) {
	msg := PartialAckMessage{
		Seq:      1,
		ChunkID:  "chunk-123",
		Accepted: []uint32{0, 2, 4},
		Rejected: []RejectedEvent{
			{Index: 1, EventID: "evt-1", Code: "INVALID", Reason: "Bad format"},
			{Index: 3, EventID: "evt-3", Code: "TOO_LARGE", Reason: "Exceeds limit"},
		},
		AckMode: "partial",
	}

	data, err := Encode(msg)
	mbtatest.AssertNoError(t, err, "Encode()")

	var decoded PartialAckMessage
	err = Decode(data, &decoded)
	mbtatest.AssertNoError(t, err, "Decode()")

	if len(decoded.Accepted) != 3 {
		t.Errorf("Accepted count = %d, want 3", len(decoded.Accepted))
	}
	if len(decoded.Rejected) != 2 {
		t.Errorf("Rejected count = %d, want 2", len(decoded.Rejected))
	}

	// Verify rejected event details
	if decoded.Rejected[0].Index != 1 {
		t.Errorf("First rejected index = %d, want 1", decoded.Rejected[0].Index)
	}
	if decoded.Rejected[0].EventID != "evt-1" {
		t.Errorf("First rejected EventID = %q, want %q", decoded.Rejected[0].EventID, "evt-1")
	}
}

// TestPingPongMessage tests Ping and Pong messages.
func TestPingPongMessage(t *testing.T) {
	ping := PingMessage{
		TimeUnixMs: 1234567890,
		Nonce:      "ping-nonce-123",
	}

	data, err := Encode(ping)
	mbtatest.AssertNoError(t, err, "Encode()")

	var decodedPing PingMessage
	err = Decode(data, &decodedPing)
	mbtatest.AssertNoError(t, err, "Decode()")

	if decodedPing.TimeUnixMs != ping.TimeUnixMs {
		t.Errorf("TimeUnixMs = %d, want %d", decodedPing.TimeUnixMs, ping.TimeUnixMs)
	}
	if decodedPing.Nonce != ping.Nonce {
		t.Errorf("Nonce = %q, want %q", decodedPing.Nonce, ping.Nonce)
	}

	// Test Pong
	pong := PongMessage{
		TimeUnixMs: 1234567891,
		Nonce:      "ping-nonce-123",
		Status:     "ok",
	}

	data, err = Encode(pong)
	mbtatest.AssertNoError(t, err, "Encode() Pong")

	var decodedPong PongMessage
	err = Decode(data, &decodedPong)
	mbtatest.AssertNoError(t, err, "Decode() Pong")

	if decodedPong.Status != "ok" {
		t.Errorf("Status = %q, want %q", decodedPong.Status, "ok")
	}
}

// TestCloseAndErrorMessage tests Close and ErrorMessage structures.
func TestCloseAndErrorMessage(t *testing.T) {
	// Test CloseMessage
	closeMsg := CloseMessage{
		Code:   "GRACEFUL",
		Reason: "Shutdown",
	}

	data, err := Encode(closeMsg)
	mbtatest.AssertNoError(t, err, "Encode() CloseMessage")

	var decodedClose CloseMessage
	err = Decode(data, &decodedClose)
	mbtatest.AssertNoError(t, err, "Decode() CloseMessage")

	if decodedClose.Code != "GRACEFUL" {
		t.Errorf("Code = %q, want %q", decodedClose.Code, "GRACEFUL")
	}

	// Test ErrorMessage
	errMsg := ErrorMessage{
		Code:      "PROTOCOL_ERROR",
		Reason:    "Invalid frame header",
		Fatal:     true,
		Retryable: false,
	}

	data, err = Encode(errMsg)
	mbtatest.AssertNoError(t, err, "Encode() ErrorMessage")

	var decodedErr ErrorMessage
	err = Decode(data, &decodedErr)
	mbtatest.AssertNoError(t, err, "Decode() ErrorMessage")

	if !decodedErr.Fatal {
		t.Errorf("Fatal = false, want true")
	}
	if decodedErr.Retryable {
		t.Errorf("Retryable = true, want false")
	}
}

// TestAuthResult tests AuthResult structure.
func TestAuthResult(t *testing.T) {
	tests := []struct {
		name   string
		result AuthResult
	}{
		{
			name:   "successful auth",
			result: AuthResult{OK: true},
		},
		{
			name:   "failed auth with reason",
			result: AuthResult{OK: false, Reason: "Invalid token"},
		},
		{
			name:   "failed auth without reason",
			result: AuthResult{OK: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := Encode(tt.result)
			mbtatest.AssertNoError(t, err, "Encode()")

			var decoded AuthResult
			err = Decode(data, &decoded)
			mbtatest.AssertNoError(t, err, "Decode()")

			if decoded.OK != tt.result.OK {
				t.Errorf("OK = %v, want %v", decoded.OK, tt.result.OK)
			}
		})
	}
}

// TestMessageJSONFields tests that all message types produce valid JSON.
func TestMessageJSONFields(t *testing.T) {
	messages := []any{
		HelloMessage{AgentID: "test", Version: 1},
		HelloAckMessage{ServerVersion: 1, SessionID: "sess"},
		AuthMessage{AgentID: "test", SessionID: "sess", AuthNonce: "nonce"},
		AuthOKMessage{SessionID: "sess"},
		AuthFailMessage{Code: "ERROR", Reason: "Test"},
		BatchMessage{Seq: 1, ChunkID: "chunk", Batch: []byte("{}")},
		AckMessage{Seq: 1, ChunkID: "chunk", Count: 10},
		NackMessage{Seq: 1, Code: "ERROR", Reason: "Test"},
		PartialAckMessage{Seq: 1, Accepted: []uint32{0, 1}},
		WindowMessage{MaxInflightBatches: 100},
		ThrottleMessage{RetryDelayMs: 5000, Code: "SLOW"},
		PingMessage{TimeUnixMs: 12345, Nonce: "test"},
		PongMessage{TimeUnixMs: 12346, Nonce: "test", Status: "ok"},
		CloseMessage{Code: "DONE"},
		ErrorMessage{Code: "ERROR", Reason: "Test", Fatal: false, Retryable: true},
	}

	for _, msg := range messages {
		t.Run(getTypeName(msg), func(t *testing.T) {
			data, err := Encode(msg)
			mbtatest.AssertNoError(t, err, "Encode()")

			// Verify it's valid JSON
			if !json.Valid(data) {
				t.Errorf("Encoded data is not valid JSON: %q", string(data))
			}
		})
	}
}

// TestEmptyMessageFields tests messages with optional fields omitted.
func TestEmptyMessageFields(t *testing.T) {
	tests := []struct {
		name  string
		obj   any
		field string
	}{
		{
			name:  "HelloMessage with optional fields",
			obj:   HelloMessage{AgentID: "test", Version: 1},
			field: "agent_id",
		},
		{
			name:  "BatchMessage with only required fields",
			obj:   BatchMessage{Seq: 1, ChunkID: "chunk", Batch: []byte("{}")},
			field: "seq",
		},
		{
			name:  "WindowMessage with no reason",
			obj:   WindowMessage{MaxInflightBatches: 100},
			field: "max_inflight_batches",
		},
		{
			name:  "ThrottleMessage with code only",
			obj:   ThrottleMessage{Code: "SLOW"},
			field: "code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := Encode(tt.obj)
			mbtatest.AssertNoError(t, err, "Encode()")

			// Verify JSON contains required field
			if !strings.Contains(string(data), tt.field) {
				t.Errorf("JSON missing field %q", tt.field)
			}
		})
	}
}

// ===== Helper Functions =====

// newInstanceOf creates a new instance of the same type as obj.
func newInstanceOf(obj any) any {
	switch obj.(type) {
	case HelloMessage:
		return &HelloMessage{}
	case HelloAckMessage:
		return &HelloAckMessage{}
	case AuthMessage:
		return &AuthMessage{}
	case AuthOKMessage:
		return &AuthOKMessage{}
	case AuthFailMessage:
		return &AuthFailMessage{}
	case BatchMessage:
		return &BatchMessage{}
	case AckMessage:
		return &AckMessage{}
	case NackMessage:
		return &NackMessage{}
	case PartialAckMessage:
		return &PartialAckMessage{}
	case WindowMessage:
		return &WindowMessage{}
	case ThrottleMessage:
		return &ThrottleMessage{}
	case PingMessage:
		return &PingMessage{}
	case PongMessage:
		return &PongMessage{}
	case CloseMessage:
		return &CloseMessage{}
	case ErrorMessage:
		return &ErrorMessage{}
	case AuthResult:
		return &AuthResult{}
	default:
		panic("unknown type in newInstanceOf")
	}
}

// isEqual compares two objects for equality.

func isEqual(t *testing.T, a, b any) bool {
	t.Helper()

	switch va := a.(type) {
	case HelloMessage:
		vb, ok := b.(*HelloMessage)
		if !ok {
			return false
		}
		return va.AgentID == vb.AgentID &&
			va.Hostname == vb.Hostname &&
			va.Version == vb.Version &&
			equalStringSlices(va.Capabilities, vb.Capabilities)
	case HelloAckMessage:
		vb, ok := b.(*HelloAckMessage)
		if !ok {
			return false
		}
		return va.ServerVersion == vb.ServerVersion &&
			va.SessionID == vb.SessionID
	case AuthMessage:
		vb, ok := b.(*AuthMessage)
		if !ok {
			return false
		}
		return va.AgentID == vb.AgentID &&
			va.SessionID == vb.SessionID &&
			va.AuthNonce == vb.AuthNonce
	case AuthOKMessage:
		vb, ok := b.(*AuthOKMessage)
		if !ok {
			return false
		}
		return va.SessionID == vb.SessionID &&
			va.KeyID == vb.KeyID
	case AuthFailMessage:
		vb, ok := b.(*AuthFailMessage)
		if !ok {
			return false
		}
		return va.Code == vb.Code &&
			va.Reason == vb.Reason &&
			va.Retryable == vb.Retryable
	case BatchMessage:
		vb, ok := b.(*BatchMessage)
		if !ok {
			return false
		}
		return va.Seq == vb.Seq &&
			va.ChunkID == vb.ChunkID &&
			bytes.Equal(va.Batch, vb.Batch)
	case AckMessage:
		vb, ok := b.(*AckMessage)
		if !ok {
			return false
		}
		return va.Seq == vb.Seq &&
			va.ChunkID == vb.ChunkID &&
			va.Count == vb.Count
	case NackMessage:
		vb, ok := b.(*NackMessage)
		if !ok {
			return false
		}
		return va.Seq == vb.Seq &&
			va.ChunkID == vb.ChunkID &&
			va.Code == vb.Code &&
			va.Retryable == vb.Retryable
	case PartialAckMessage:
		vb, ok := b.(*PartialAckMessage)
		if !ok {
			return false
		}
		if va.Seq != vb.Seq || va.ChunkID != vb.ChunkID {
			return false
		}
		if !equalUint32Slices(va.Accepted, vb.Accepted) {
			return false
		}
		if len(va.Rejected) != len(vb.Rejected) {
			return false
		}
		for i := range va.Rejected {
			if va.Rejected[i].Index != vb.Rejected[i].Index ||
				va.Rejected[i].EventID != vb.Rejected[i].EventID {
				return false
			}
		}
		return true
	case WindowMessage:
		vb, ok := b.(*WindowMessage)
		if !ok {
			return false
		}
		return va.MaxInflightBatches == vb.MaxInflightBatches &&
			va.MaxInflightEvents == vb.MaxInflightEvents &&
			va.MaxInflightBytes == vb.MaxInflightBytes
	case ThrottleMessage:
		vb, ok := b.(*ThrottleMessage)
		if !ok {
			return false
		}
		return va.RetryDelayMs == vb.RetryDelayMs &&
			va.Code == vb.Code
	case PingMessage:
		vb, ok := b.(*PingMessage)
		if !ok {
			return false
		}
		return va.TimeUnixMs == vb.TimeUnixMs &&
			va.Nonce == vb.Nonce
	case PongMessage:
		vb, ok := b.(*PongMessage)
		if !ok {
			return false
		}
		return va.TimeUnixMs == vb.TimeUnixMs &&
			va.Nonce == vb.Nonce &&
			va.Status == vb.Status
	case CloseMessage:
		vb, ok := b.(*CloseMessage)
		if !ok {
			return false
		}
		return va.Code == vb.Code &&
			va.Reason == vb.Reason
	case ErrorMessage:
		vb, ok := b.(*ErrorMessage)
		if !ok {
			return false
		}
		return va.Code == vb.Code &&
			va.Reason == vb.Reason &&
			va.Fatal == vb.Fatal &&
			va.Retryable == vb.Retryable
	case AuthResult:
		vb, ok := b.(*AuthResult)
		if !ok {
			return false
		}
		return va.OK == vb.OK &&
			va.Reason == vb.Reason
	default:
		// For other types, do basic comparison
		return false
	}
}

// equalStringSlices compares two string slices for equality.
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// equalUint32Slices compares two uint32 slices for equality.
func equalUint32Slices(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// getTypeName returns the type name of an object.
func getTypeName(obj any) string {
	switch obj.(type) {
	case HelloMessage:
		return "HelloMessage"
	case HelloAckMessage:
		return "HelloAckMessage"
	case AuthMessage:
		return "AuthMessage"
	case AuthOKMessage:
		return "AuthOKMessage"
	case AuthFailMessage:
		return "AuthFailMessage"
	case BatchMessage:
		return "BatchMessage"
	case AckMessage:
		return "AckMessage"
	case NackMessage:
		return "NackMessage"
	case PartialAckMessage:
		return "PartialAckMessage"
	case WindowMessage:
		return "WindowMessage"
	case ThrottleMessage:
		return "ThrottleMessage"
	case PingMessage:
		return "PingMessage"
	case PongMessage:
		return "PongMessage"
	case CloseMessage:
		return "CloseMessage"
	case ErrorMessage:
		return "ErrorMessage"
	case AuthResult:
		return "AuthResult"
	default:
		return "unknown"
	}
}
