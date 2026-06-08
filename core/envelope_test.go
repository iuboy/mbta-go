package core

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	mbtatest "github.com/iuboy/mbta-go/testing"
)

// TestBuildEnvelope tests the Build function with various parameters.
func TestBuildEnvelope(t *testing.T) {
	batchPayload := []byte(`{"signals":[{"type":"log","message":"test"}]}`)

	tests := []struct {
		name    string
		params  Params
		wantErr bool
		check   func(*testing.T, *SecureEnvelope)
	}{
		{
			name: "minimal envelope",
			params: Params{
				SessionID:   "sess-123",
				Seq:         1,
				ChunkID:     "chunk-1",
				Codec:       "json",
				Compression: "none",
				HMACAlgo:    "none",
			},
			wantErr: false,
			check: func(t *testing.T, env *SecureEnvelope) {
				if env.EnvelopeVersion != EnvelopeVersion {
					t.Errorf("EnvelopeVersion = %d, want %d", env.EnvelopeVersion, EnvelopeVersion)
				}
				if env.MessageType != "batch" {
					t.Errorf("MessageType = %q, want 'batch'", env.MessageType)
				}
				if env.SessionID != "sess-123" {
					t.Errorf("SessionID = %q, want 'sess-123'", env.SessionID)
				}
				if env.Seq != 1 {
					t.Errorf("Seq = %d, want 1", env.Seq)
				}
				if env.ChunkID != "chunk-1" {
					t.Errorf("ChunkID = %q, want 'chunk-1'", env.ChunkID)
				}
			},
		},
		{
			name: "with gzip compression",
			params: Params{
				SessionID:   "sess-123",
				Seq:         1,
				ChunkID:     "chunk-1",
				Codec:       "json",
				Compression: "gzip",
				HMACAlgo:    "none",
			},
			wantErr: false,
			check: func(t *testing.T, env *SecureEnvelope) {
				if env.Compression != "gzip" {
					t.Errorf("Compression = %q, want 'gzip'", env.Compression)
				}
				// Verify payload is base64 encoded
				_, err := base64.StdEncoding.DecodeString(env.Payload)
				if err != nil {
					t.Errorf("Payload should be valid base64, got error: %v", err)
				}
			},
		},
		{
			name: "with HMAC-SHA256",
			params: Params{
				SessionID:   "sess-123",
				Seq:         1,
				ChunkID:     "chunk-1",
				Codec:       "json",
				Compression: "none",
				HMACAlgo:    "sha256",
				HMACKey:     make([]byte, 32), // Use zero key for testing
			},
			wantErr: false,
			check: func(t *testing.T, env *SecureEnvelope) {
				if env.HMACAlgo != "sha256" {
					t.Errorf("HMACAlgo = %q, want 'sha256'", env.HMACAlgo)
				}
				if env.MAC == "" {
					t.Error("MAC should not be empty for sha256")
				}
				// Verify MAC is base64 encoded
				_, err := base64.StdEncoding.DecodeString(env.MAC)
				if err != nil {
					t.Errorf("MAC should be valid base64, got error: %v", err)
				}
			},
		},
		{
			name: "with KeyID",
			params: Params{
				SessionID:   "sess-123",
				KeyID:       "key-456",
				Seq:         1,
				ChunkID:     "chunk-1",
				Codec:       "json",
				Compression: "none",
				HMACAlgo:    "none",
			},
			wantErr: false,
			check: func(t *testing.T, env *SecureEnvelope) {
				if env.KeyID != "key-456" {
					t.Errorf("KeyID = %q, want 'key-456'", env.KeyID)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, err := Build(tt.params, batchPayload)
			if tt.wantErr {
				mbtatest.AssertError(t, err, tt.name)
			} else {
				mbtatest.AssertNoError(t, err, tt.name)
				if tt.check != nil {
					tt.check(t, env)
				}
			}
		})
	}
}

// TestCanonicalSigningString tests the CanonicalSigningString function.
func TestCanonicalSigningString(t *testing.T) {
	env := &SecureEnvelope{
		MessageType:     "batch",
		SessionID:       "sess-123",
		KeyID:           "key-456",
		Seq:             1,
		ChunkID:         "chunk-1",
		CreatedAtUnixMs: 1234567890,
		Codec:           "json",
		Compression:     "gzip",
		Encryption:      "none",
		HMACAlgo:        "sha256",
		Nonce:           "nonce-789",
		Payload:         "base64payload",
	}

	signingBytes := CanonicalSigningString(env)
	signingStr := string(signingBytes)

	// Verify format
	expectedParts := []string{
		"mbta-v1",
		"message_type=batch",
		"session_id=sess-123",
		"key_id=key-456",
		"seq=1",
		"chunk_id=chunk-1",
		"created_at_unix_ms=1234567890",
		"codec=json",
		"compression=gzip",
		"encryption=none",
		"hmac_algo=sha256",
		"nonce=nonce-789",
		"payload=base64payload",
	}

	for _, part := range expectedParts {
		if !strings.Contains(signingStr, part) {
			t.Errorf("Signing string missing %q", part)
		}
	}

	// Verify each field is on its own line (except payload which is last without trailing newline)
	lines := strings.Split(signingStr, "\n")
	if len(lines) != 13 { // 12 fields + header line
		t.Errorf("Expected 13 lines, got %d", len(lines))
	}
}

// TestGzipCompression tests that gzip compression works correctly.
func TestGzipCompression(t *testing.T) {
	batchPayload := []byte(`{"signals":[{"type":"log","message":"test"}]}`)

	params := Params{
		SessionID:   "sess-123",
		Seq:         1,
		ChunkID:     "chunk-1",
		Codec:       "json",
		Compression: "gzip",
		HMACAlgo:    "none",
	}

	env, err := Build(params, batchPayload)
	mbtatest.AssertNoError(t, err, "Build()")

	// Decode base64 payload
	decodedPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	mbtatest.AssertNoError(t, err, "base64 decode")

	// Decompress gzip
	reader, err := gzip.NewReader(bytes.NewReader(decodedPayload))
	mbtatest.AssertNoError(t, err, "gzip reader")
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	mbtatest.AssertNoError(t, err, "gzip decompress")

	// Verify original data
	if !bytes.Equal(decompressed, batchPayload) {
		t.Errorf("Decompressed payload = %q, want %q", decompressed, batchPayload)
	}
}

// TestSecureEnvelopeJSON tests JSON encoding/decoding of SecureEnvelope.
func TestSecureEnvelopeJSON(t *testing.T) {
	env := &SecureEnvelope{
		EnvelopeVersion: EnvelopeVersion,
		MessageType:     "batch",
		SessionID:       "sess-123",
		KeyID:           "key-456",
		Seq:             1,
		ChunkID:         "chunk-1",
		CreatedAtUnixMs: 1234567890,
		Codec:           "json",
		Compression:     "none",
		HMACAlgo:        "sha256",
		Payload:         "base64payload",
		MAC:             "base64mac",
	}

	// Encode
	data, err := json.Marshal(env)
	mbtatest.AssertNoError(t, err, "JSON marshal")

	// Verify it's valid JSON
	if !json.Valid(data) {
		t.Error("Encoded data is not valid JSON")
	}

	// Decode
	var decoded SecureEnvelope
	err = json.Unmarshal(data, &decoded)
	mbtatest.AssertNoError(t, err, "JSON unmarshal")

	// Verify fields
	if decoded.EnvelopeVersion != env.EnvelopeVersion {
		t.Errorf("EnvelopeVersion = %d, want %d", decoded.EnvelopeVersion, env.EnvelopeVersion)
	}
	if decoded.SessionID != env.SessionID {
		t.Errorf("SessionID = %q, want %q", decoded.SessionID, env.SessionID)
	}
}

// TestEnvelopeConstants tests envelope-related constants.
func TestEnvelopeConstants(t *testing.T) {
	if EnvelopeVersion != 1 {
		t.Errorf("EnvelopeVersion = %d, want 1", EnvelopeVersion)
	}
}

// TestBuildWithLargePayload tests building envelope with large payload.
func TestBuildWithLargePayload(t *testing.T) {
	// Create a 1MB payload
	largePayload := make([]byte, 1024*1024)
	for i := range largePayload {
		largePayload[i] = byte('a' + (i % 26))
	}

	params := Params{
		SessionID:   "sess-123",
		Seq:         1,
		ChunkID:     "chunk-1",
		Codec:       "json",
		Compression: "gzip",
		HMACAlgo:    "none",
	}

	env, err := Build(params, largePayload)
	mbtatest.AssertNoError(t, err, "Build() with large payload")

	if env == nil {
		t.Fatal("Envelope should not be nil")
	}
	if env.Payload == "" {
		t.Error("Payload should not be empty")
	}
}

// TestBuildWithEmptyPayload tests building envelope with empty payload.
func TestBuildWithEmptyPayload(t *testing.T) {
	emptyPayload := []byte{}

	params := Params{
		SessionID:   "sess-123",
		Seq:         1,
		ChunkID:     "chunk-1",
		Codec:       "json",
		Compression: "none",
		HMACAlgo:    "none",
	}

	env, err := Build(params, emptyPayload)
	mbtatest.AssertNoError(t, err, "Build() with empty payload")

	if env == nil {
		t.Fatal("Envelope should not be nil")
	}
	// Empty bytes encode to empty base64 string
	if env.Payload != "" {
		t.Errorf("Payload should be empty for empty input, got %q", env.Payload)
	}
}
