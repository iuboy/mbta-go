package core

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/iuboy/pollux-go/sm3"
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

	// Step 0: 当 HMAC 启用时，生成随机 nonce 增强防重放保护。
	if params.HMACAlgo == HMACAlgoSHA256 || params.HMACAlgo == HMACAlgoSM3 {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "generate nonce", err)
		}
		env.Nonce = base64.StdEncoding.EncodeToString(nonceBytes)
	}

	// Step 1: Compress
	processed := batchPayload
	if params.Compression == CompressionGzip {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(batchPayload); err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "gzip compress", err)
		}
		if err := w.Close(); err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "gzip close", err)
		}
		processed = buf.Bytes()
	}

	// Step 2: Encrypt (v1 phase 5: encryption=none, but field is ready)
	// When sm4_gcm is enabled, encrypt processed here.

	// Step 3: Base64 payload
	env.Payload = base64.StdEncoding.EncodeToString(processed)

	// Step 4: HMAC
	switch params.HMACAlgo {
	case HMACAlgoSHA256:
		signingBytes := CanonicalSigningString(env)
		mac := computeHMACSHA256(params.HMACKey, signingBytes)
		env.MAC = base64.StdEncoding.EncodeToString(mac)
	case HMACAlgoSM3:
		signingBytes := CanonicalSigningString(env)
		mac := computeHMACSM3(params.HMACKey, signingBytes)
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
	fmt.Fprintf(&buf, "envelope_version=%d\n", env.EnvelopeVersion)
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

func computeHMACSM3(key, data []byte) []byte {
	h := hmac.New(sm3.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMACSHA256 checks the MAC against the envelope using HMAC-SHA256.
func VerifyHMACSHA256(key []byte, env *SecureEnvelope) bool {
	signingBytes := CanonicalSigningString(env)
	expected := computeHMACSHA256(key, signingBytes)

	got, err := base64.StdEncoding.DecodeString(env.MAC)
	if err != nil {
		return false
	}
	return hmac.Equal(got, expected)
}

// VerifyHMACSM3 checks the MAC against the envelope using HMAC-SM3.
func VerifyHMACSM3(key []byte, env *SecureEnvelope) bool {
	signingBytes := CanonicalSigningString(env)
	expected := computeHMACSM3(key, signingBytes)

	got, err := base64.StdEncoding.DecodeString(env.MAC)
	if err != nil {
		return false
	}
	return hmac.Equal(got, expected)
}

// VerifyHMAC checks the MAC using the algorithm specified in the envelope.
// Returns false if the algorithm is unknown or verification fails.
func VerifyHMAC(key []byte, env *SecureEnvelope) bool {
	switch env.HMACAlgo {
	case HMACAlgoSHA256:
		return VerifyHMACSHA256(key, env)
	case HMACAlgoSM3:
		return VerifyHMACSM3(key, env)
	default:
		return false
	}
}

// MaxDecompressedSize limits a decompressed envelope payload to 8 MiB.
//
// This is aligned with the protocol's maxBatchBytes cap: a decompressed batch
// can never legitimately exceed the batch-size limit, so anything larger is an
// attack (zip-bomb) or a malformed payload. The check runs in Open() — which
// handler.go calls *before* its own maxBatchBytes check — so this is the bound
// that actually limits peak allocation during decompression. Setting it to the
// same value as maxBatchBytes removes the previous 100 MiB window in which a
// high-ratio gzip payload could force the server to allocate far beyond the
// batch limit before being rejected.
const MaxDecompressedSize = 8 * 1024 * 1024

// Open decodes and decompresses an envelope's payload.
func Open(env *SecureEnvelope) ([]byte, error) {
	// Base64 decode
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, WrapError(NumEnvelope, CodeEnvelope, "base64 decode payload", err)
	}

	// Decrypt (when encryption enabled)
	// ...

	// Decompress
	if env.Compression == CompressionGzip {
		r, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "gzip reader", err)
		}
		defer r.Close()

		// Limit decompressed size to prevent zip-bomb OOM
		lr := &io.LimitedReader{R: r, N: MaxDecompressedSize + 1}
		decompressed, err := io.ReadAll(lr)
		if err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "gzip decompress", err)
		}
		if lr.N == 0 {
			return nil, NewError(NumEnvelope, CodeEnvelope, fmt.Sprintf("decompressed payload exceeds %d bytes limit", MaxDecompressedSize))
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
		return nil, WrapError(NumEnvelope, CodeEnvelope, "decode envelope", err)
	}
	return &env, nil
}
