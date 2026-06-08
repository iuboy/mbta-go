package v1

import (
	"encoding/base64"
	"testing"

	"github.com/iuboy/mbta-go/core"
)

func TestNewClient(t *testing.T) {
	cfg := ClientConfig{
		AgentID:      "test-agent",
		Token:        "test-token",
		Capabilities: []string{core.CapCodecJSON, core.CapCompressGzip},
		PickStrategy: "single",
	}

	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if c.State() != core.StateDisconnected {
		t.Errorf("initial state = %s, want DISCONNECTED", c.State())
	}
	if c.SessionID() != "" {
		t.Error("session_id should be empty before connect")
	}
}

func TestDecodeBase64Key(t *testing.T) {
	// Valid 32-byte key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(key)

	got, err := decodeBase64Key(b64, 32)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 32 {
		t.Errorf("length = %d, want 32", len(got))
	}

	// Wrong length
	_, err = decodeBase64Key(b64, 16)
	if err == nil {
		t.Error("should fail on wrong length")
	}

	// Invalid base64
	_, err = decodeBase64Key("not-valid-base64!!!", 32)
	if err == nil {
		t.Error("should fail on invalid base64")
	}
}

func TestPendingBatchTracking(t *testing.T) {
	c, _ := NewClient(ClientConfig{AgentID: "test"})

	// Simulate storing a pending batch
	c.pendingAcks.Store("chunk-1", &pendingBatch{
		Seq:    1,
		Events: 10,
		Bytes:  1024,
	})

	// Retrieve it
	val, ok := c.pendingAcks.Load("chunk-1")
	if !ok {
		t.Fatal("pending batch not found")
	}
	pb := val.(*pendingBatch)
	if pb.Seq != 1 || pb.Events != 10 || pb.Bytes != 1024 {
		t.Errorf("pending batch mismatch: %+v", pb)
	}

	// Delete it
	c.pendingAcks.Delete("chunk-1")
	_, ok = c.pendingAcks.Load("chunk-1")
	if ok {
		t.Error("pending batch should be deleted")
	}
}

func TestStreamPickerIntegration(t *testing.T) {
	cfg := ClientConfig{
		AgentID:      "test-agent",
		PickStrategy: "hash",
	}
	c, _ := NewClient(cfg)

	// Default picker should be nil before connect
	if c.picker != nil {
		t.Error("picker should be nil before connect")
	}
}
