package v1

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// TestAckMessageStructure tests AckMessage structure.
func TestAckMessageStructure(t *testing.T) {
	ack := core.AckMessage{
		Seq:     1,
		ChunkID: "test-chunk",
		Count:   10,
		AckMode: "durable",
	}

	data, err := json.Marshal(ack)
	if err != nil {
		t.Fatalf("Marshal AckMessage failed: %v", err)
	}

	var decoded core.AckMessage
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal AckMessage failed: %v", err)
	}

	if decoded.Seq != 1 {
		t.Errorf("Seq = %d, want 1", decoded.Seq)
	}
	if decoded.ChunkID != "test-chunk" {
		t.Errorf("ChunkID = %s, want 'test-chunk'", decoded.ChunkID)
	}
	if decoded.Count != 10 {
		t.Errorf("Count = %d, want 10", decoded.Count)
	}
	if decoded.AckMode != "durable" {
		t.Errorf("AckMode = %s, want 'durable'", decoded.AckMode)
	}
}

// TestNackMessageStructure tests NackMessage structure.
func TestNackMessageStructure(t *testing.T) {
	nack := core.NackMessage{
		Seq:       1,
		ChunkID:   "test-chunk",
		Code:      "ERR_INVALID_FRAME",
		Reason:    "Frame validation failed",
		Retryable: true,
	}

	data, err := json.Marshal(nack)
	if err != nil {
		t.Fatalf("Marshal NackMessage failed: %v", err)
	}

	var decoded core.NackMessage
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal NackMessage failed: %v", err)
	}

	if decoded.Seq != 1 {
		t.Errorf("Seq = %d, want 1", decoded.Seq)
	}
	if decoded.ChunkID != "test-chunk" {
		t.Errorf("ChunkID = %s, want 'test-chunk'", decoded.ChunkID)
	}
	if decoded.Code != "ERR_INVALID_FRAME" {
		t.Errorf("Code = %s, want 'ERR_INVALID_FRAME'", decoded.Code)
	}
	if !decoded.Retryable {
		t.Error("Retryable should be true")
	}
}

// TestWindowMessageStructure tests WindowMessage structure.
func TestWindowMessageStructure(t *testing.T) {
	win := core.WindowMessage{
		MaxInflightBatches: 100,
		MaxInflightEvents:  10000,
		MaxInflightBytes:   16 * 1024 * 1024,
	}

	data, err := json.Marshal(win)
	if err != nil {
		t.Fatalf("Marshal WindowMessage failed: %v", err)
	}

	var decoded core.WindowMessage
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal WindowMessage failed: %v", err)
	}

	if decoded.MaxInflightBatches != 100 {
		t.Errorf("MaxInflightBatches = %d, want 100", decoded.MaxInflightBatches)
	}
	if decoded.MaxInflightEvents != 10000 {
		t.Errorf("MaxInflightEvents = %d, want 10000", decoded.MaxInflightEvents)
	}
	if decoded.MaxInflightBytes != 16*1024*1024 {
		t.Errorf("MaxInflightBytes = %d, want %d", decoded.MaxInflightBytes, 16*1024*1024)
	}
}

// TestThrottleMessageStructure tests ThrottleMessage structure.
func TestThrottleMessageStructure(t *testing.T) {
	throt := core.ThrottleMessage{
		RetryDelayMs: 5000,
		Reason:       "Server overloaded",
	}

	data, err := json.Marshal(throt)
	if err != nil {
		t.Fatalf("Marshal ThrottleMessage failed: %v", err)
	}

	var decoded core.ThrottleMessage
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal ThrottleMessage failed: %v", err)
	}

	if decoded.RetryDelayMs != 5000 {
		t.Errorf("RetryDelayMs = %d, want 5000", decoded.RetryDelayMs)
	}
	if decoded.Reason != "Server overloaded" {
		t.Errorf("Reason = %s, want 'Server overloaded'", decoded.Reason)
	}
}

// TestCloseMessageStructure tests CloseMessage structure.
func TestCloseMessageStructure(t *testing.T) {
	close := core.CloseMessage{
		Code:   "shutdown",
		Reason: "Client closing",
	}

	data, err := json.Marshal(close)
	if err != nil {
		t.Fatalf("Marshal CloseMessage failed: %v", err)
	}

	var decoded core.CloseMessage
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal CloseMessage failed: %v", err)
	}

	if decoded.Code != "shutdown" {
		t.Errorf("Code = %s, want 'shutdown'", decoded.Code)
	}
	if decoded.Reason != "Client closing" {
		t.Errorf("Reason = %s, want 'Client closing'", decoded.Reason)
	}
}

// TestErrorMessageStructure tests ErrorMessage structure.
func TestErrorMessageStructure(t *testing.T) {
	errMsg := core.ErrorMessage{
		Code:   "ERR_AUTH_FAILED",
		Reason: "Invalid token",
	}

	data, err := json.Marshal(errMsg)
	if err != nil {
		t.Fatalf("Marshal ErrorMessage failed: %v", err)
	}

	var decoded core.ErrorMessage
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal ErrorMessage failed: %v", err)
	}

	if decoded.Code != "ERR_AUTH_FAILED" {
		t.Errorf("Code = %s, want 'ERR_AUTH_FAILED'", decoded.Code)
	}
	if decoded.Reason != "Invalid token" {
		t.Errorf("Reason = %s, want 'Invalid token'", decoded.Reason)
	}
}

// TestPendingBatchStructure tests pendingBatch structure.
func TestPendingBatchStructure(t *testing.T) {
	pb := &pendingBatch{
		Seq:    1,
		Events: 10,
		Bytes:  1024,
		SentAt: testTimeNow(),
	}

	if pb.Seq == 0 {
		t.Error("Seq should be set")
	}
	if pb.Events == 0 {
		t.Error("Events should be set")
	}
	if pb.Bytes == 0 {
		t.Error("Bytes should be set")
	}
	if pb.SentAt.IsZero() {
		t.Error("SentAt should be set")
	}
}

// testTimeNow returns a fixed time for testing.
func testTimeNow() time.Time {
	return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
}

// TestControlMessageTypes tests various control message types.
func TestControlMessageTypes(t *testing.T) {
	tests := []struct {
		name    string
		marshal func() ([]byte, error)
	}{
		{
			name: "AckMessage",
			marshal: func() ([]byte, error) {
				return json.Marshal(core.AckMessage{Seq: 1, ChunkID: "chunk-1", AckMode: "durable"})
			},
		},
		{
			name: "NackMessage",
			marshal: func() ([]byte, error) {
				return json.Marshal(core.NackMessage{Seq: 1, ChunkID: "chunk-1", Code: "ERR_INVALID"})
			},
		},
		{
			name: "WindowMessage",
			marshal: func() ([]byte, error) {
				return json.Marshal(core.WindowMessage{MaxInflightBatches: 100})
			},
		},
		{
			name: "ThrottleMessage",
			marshal: func() ([]byte, error) {
				return json.Marshal(core.ThrottleMessage{RetryDelayMs: 5000})
			},
		},
		{
			name: "CloseMessage",
			marshal: func() ([]byte, error) {
				return json.Marshal(core.CloseMessage{Code: "shutdown"})
			},
		},
		{
			name: "ErrorMessage",
			marshal: func() ([]byte, error) {
				return json.Marshal(core.ErrorMessage{Code: "ERR_AUTH", Reason: "Failed"})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.marshal()
			if err != nil {
				t.Errorf("Marshal %s failed: %v", tt.name, err)
			}

			// Verify JSON is valid (not empty)
			if len(data) == 0 {
				t.Errorf("Marshal %s produced empty JSON", tt.name)
			}
		})
	}
}

// TestAckModeValues tests common ACK mode values.
func TestAckModeValues(t *testing.T) {
	modes := []string{"durable", "accepted", "nack", "throttle"}

	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			ack := core.AckMessage{
				Seq:     1,
				ChunkID: "chunk-1",
				AckMode: mode,
			}

			data, err := json.Marshal(ack)
			if err != nil {
				t.Errorf("Marshal ACK with mode %s failed: %v", mode, err)
			}

			var decoded core.AckMessage
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Errorf("Unmarshal ACK with mode %s failed: %v", mode, err)
			}

			if decoded.AckMode != mode {
				t.Errorf("AckMode = %s, want %s", decoded.AckMode, mode)
			}
		})
	}
}
