package core

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// EnvelopeVersion is the current wire-format version for secure envelopes.
const EnvelopeVersion = 1

// SecureEnvelope is the wire-level wrapper for BATCH payloads.
type SecureEnvelope struct {
	EnvelopeVersion int    `json:"envelope_version"`
	MessageType     string `json:"message_type"`
	SessionID       string `json:"session_id"`
	KeyID           string `json:"key_id,omitempty"`
	Seq             uint64 `json:"seq"`
	ChunkID         string `json:"chunk_id"`
	CreatedAtUnixMs int64  `json:"created_at_unix_ms"`
	Codec           string `json:"codec"`
	Compression     string `json:"compression"`
	Encryption      string `json:"encryption"`
	HMACAlgo        string `json:"hmac_algo"`
	Nonce           string `json:"nonce,omitempty"`
	Payload         string `json:"payload"`
	MAC             string `json:"mac,omitempty"`
}

// Params controls how a SecureEnvelope is built.
type Params struct {
	SessionID   string
	KeyID       string
	Seq         uint64
	ChunkID     string
	Codec       string // json
	Compression string // none, gzip
	Encryption  string // none, sm4_gcm
	HMACAlgo    string // none, sha256, sm3
	HMACKey     []byte // 32 bytes when hmac enabled
}

// Build creates a SecureEnvelope from a batch payload.
func Build(params Params, batchPayload []byte) (*SecureEnvelope, error) {
	env := &SecureEnvelope{
		EnvelopeVersion: EnvelopeVersion,
		MessageType:     "batch",
		SessionID:       params.SessionID,
		KeyID:           params.KeyID,
		Seq:             params.Seq,
		ChunkID:         params.ChunkID,
		CreatedAtUnixMs: nowUnixMs(),
		Codec:           params.Codec,
		Compression:     params.Compression,
		Encryption:      params.Encryption,
		HMACAlgo:        params.HMACAlgo,
	}

	// Step 1: Compress
	processed := batchPayload
	if params.Compression == CompressionGzip {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(batchPayload); err != nil {
			return nil, WrapError(NumEnvelope, ErrEnvelope, "gzip compress", err)
		}
		if err := w.Close(); err != nil {
			return nil, WrapError(NumEnvelope, ErrEnvelope, "gzip close", err)
		}
		processed = buf.Bytes()
	}

	// Step 2: Encrypt (v1 phase 5: encryption=none, but field is ready)
	// When sm4_gcm is enabled, encrypt processed here.

	// Step 3: Base64 payload
	env.Payload = base64.StdEncoding.EncodeToString(processed)

	// Step 4: HMAC
	if params.HMACAlgo == HMACAlgoSHA256 {
		signingBytes := CanonicalSigningString(env)
		mac := computeHMACSHA256(params.HMACKey, signingBytes)
		env.MAC = base64.StdEncoding.EncodeToString(mac)
	}

	return env, nil
}

func nowUnixMs() int64 {
	return time.Now().UnixMilli()
}

// CanonicalSigningString builds the deterministic HMAC input.
func CanonicalSigningString(env *SecureEnvelope) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "mbta-v1\n")
	fmt.Fprintf(&buf, "message_type=%s\n", env.MessageType)
	fmt.Fprintf(&buf, "session_id=%s\n", env.SessionID)
	fmt.Fprintf(&buf, "key_id=%s\n", env.KeyID)
	fmt.Fprintf(&buf, "seq=%d\n", env.Seq)
	fmt.Fprintf(&buf, "chunk_id=%s\n", env.ChunkID)
	fmt.Fprintf(&buf, "created_at_unix_ms=%d\n", env.CreatedAtUnixMs)
	fmt.Fprintf(&buf, "codec=%s\n", env.Codec)
	fmt.Fprintf(&buf, "compression=%s\n", env.Compression)
	fmt.Fprintf(&buf, "encryption=%s\n", env.Encryption)
	fmt.Fprintf(&buf, "hmac_algo=%s\n", env.HMACAlgo)
	fmt.Fprintf(&buf, "nonce=%s\n", env.Nonce)
	fmt.Fprintf(&buf, "payload=%s", env.Payload) // no trailing newline
	return buf.Bytes()
}

func computeHMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMACSHA256 checks the MAC against the envelope.
func VerifyHMACSHA256(key []byte, env *SecureEnvelope) bool {
	signingBytes := CanonicalSigningString(env)
	expected := computeHMACSHA256(key, signingBytes)

	got, err := base64.StdEncoding.DecodeString(env.MAC)
	if err != nil {
		return false
	}
	return hmac.Equal(got, expected)
}

// Open decodes and decompresses an envelope's payload.
func Open(env *SecureEnvelope) ([]byte, error) {
	// Base64 decode
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, WrapError(NumEnvelope, ErrEnvelope, "base64 decode payload", err)
	}

	// Decrypt (when encryption enabled)
	// ...

	// Decompress
	if env.Compression == CompressionGzip {
		r, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, WrapError(NumEnvelope, ErrEnvelope, "gzip reader", err)
		}
		defer r.Close()
		decompressed, err := io.ReadAll(r)
		if err != nil {
			return nil, WrapError(NumEnvelope, ErrEnvelope, "gzip decompress", err)
		}
		return decompressed, nil
	}

	return raw, nil
}

// EncodeEnvelope JSON-encodes the envelope.
func EncodeEnvelope(env *SecureEnvelope) ([]byte, error) {
	return json.Marshal(env)
}

// DecodeEnvelope JSON-decodes into a SecureEnvelope.
func DecodeEnvelope(data []byte) (*SecureEnvelope, error) {
	var env SecureEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, WrapError(NumEnvelope, ErrEnvelope, "decode envelope", err)
	}
	return &env, nil
}
