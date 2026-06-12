package core

import (
	"testing"

	mbtatest "github.com/iuboy/mbta-go/testing"
)

func TestEncodeDecodeEnvelope(t *testing.T) {
	t.Parallel()
	env := &SecureEnvelope{
		EnvelopeVersion: EnvelopeVersion,
		MessageType:     "batch",
		SessionID:       "sess-encode-decode",
		KeyID:           "key-789",
		Seq:             42,
		ChunkID:         "chunk-abc",
		CreatedAtUnixMs: 1700000000000,
		Codec:           CodecJSON,
		Compression:     CompressionGzip,
		Encryption:      EncryptionNone,
		HMACAlgo:        HMACAlgoSHA256,
		Nonce:           "nonce-xyz",
		Payload:         "cGF5bG9hZA==",
		MAC:             "bWFj",
	}

	// Encode
	data, err := EncodeEnvelope(env)
	mbtatest.AssertNoError(t, err, "EncodeEnvelope")
	if len(data) == 0 {
		t.Fatal("Encoded data should not be empty")
	}

	// Decode
	decoded, err := DecodeEnvelope(data)
	mbtatest.AssertNoError(t, err, "DecodeEnvelope")

	// Verify round-trip
	if decoded.EnvelopeVersion != env.EnvelopeVersion {
		t.Errorf("EnvelopeVersion = %d, want %d", decoded.EnvelopeVersion, env.EnvelopeVersion)
	}
	if decoded.SessionID != env.SessionID {
		t.Errorf("SessionID = %q, want %q", decoded.SessionID, env.SessionID)
	}
	if decoded.Seq != env.Seq {
		t.Errorf("Seq = %d, want %d", decoded.Seq, env.Seq)
	}
	if decoded.ChunkID != env.ChunkID {
		t.Errorf("ChunkID = %q, want %q", decoded.ChunkID, env.ChunkID)
	}
	if decoded.Codec != env.Codec {
		t.Errorf("Codec = %q, want %q", decoded.Codec, env.Codec)
	}
	if decoded.Compression != env.Compression {
		t.Errorf("Compression = %q, want %q", decoded.Compression, env.Compression)
	}
	if decoded.HMACAlgo != env.HMACAlgo {
		t.Errorf("HMACAlgo = %q, want %q", decoded.HMACAlgo, env.HMACAlgo)
	}
	if decoded.Payload != env.Payload {
		t.Errorf("Payload = %q, want %q", decoded.Payload, env.Payload)
	}
	if decoded.MAC != env.MAC {
		t.Errorf("MAC = %q, want %q", decoded.MAC, env.MAC)
	}
}

func TestDecodeEnvelopeInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := DecodeEnvelope([]byte("not valid json{{{"))
	mbtatest.AssertError(t, err, "invalid JSON should error")
}

func TestDecodeEnvelopeEmpty(t *testing.T) {
	t.Parallel()
	_, err := DecodeEnvelope([]byte{})
	mbtatest.AssertError(t, err, "empty data should error")
}

func TestVerifyHMACSHA256RoundTrip(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	batchPayload := []byte(`{"signals":[{"type":"log","message":"hmac test"}]}`)

	params := Params{
		SessionID:   "sess-hmac-test",
		KeyID:       "key-hmac",
		Seq:         1,
		ChunkID:     "chunk-hmac",
		Codec:       CodecJSON,
		Compression: CompressionNone,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoSHA256,
		HMACKey:     key,
	}

	env, err := Build(params, batchPayload)
	mbtatest.AssertNoError(t, err, "Build with HMAC")

	// Verify HMAC
	if !VerifyHMACSHA256(key, env) {
		t.Error("VerifyHMACSHA256 should return true for valid MAC")
	}
}

func TestVerifyHMACSHA256WrongKey(t *testing.T) {
	t.Parallel()
	correctKey := make([]byte, 32)
	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = 0xFF
	}

	batchPayload := []byte(`{"signals":[{"type":"log"}]}`)

	params := Params{
		SessionID:   "sess-wrong-key",
		Seq:         1,
		ChunkID:     "chunk-wrong",
		Codec:       CodecJSON,
		Compression: CompressionNone,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoSHA256,
		HMACKey:     correctKey,
	}

	env, err := Build(params, batchPayload)
	mbtatest.AssertNoError(t, err, "Build with HMAC")

	// Verify with wrong key should fail
	if VerifyHMACSHA256(wrongKey, env) {
		t.Error("VerifyHMACSHA256 should return false for wrong key")
	}
}

func TestVerifyHMACSHA256TamperedPayload(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)

	batchPayload := []byte(`{"signals":[{"type":"log"}]}`)

	params := Params{
		SessionID:   "sess-tampered",
		Seq:         1,
		ChunkID:     "chunk-tampered",
		Codec:       CodecJSON,
		Compression: CompressionNone,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoSHA256,
		HMACKey:     key,
	}

	env, err := Build(params, batchPayload)
	mbtatest.AssertNoError(t, err, "Build with HMAC")

	// Tamper with payload
	env.Payload = "dGFtcGVyZWQ="

	if VerifyHMACSHA256(key, env) {
		t.Error("VerifyHMACSHA256 should return false for tampered payload")
	}
}

func TestVerifyHMACSHA256InvalidMAC(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)

	env := &SecureEnvelope{
		MessageType:     "batch",
		SessionID:       "sess",
		Seq:             1,
		ChunkID:         "chunk",
		CreatedAtUnixMs: 123,
		Codec:           CodecJSON,
		Compression:     CompressionNone,
		Encryption:      EncryptionNone,
		HMACAlgo:        HMACAlgoSHA256,
		Payload:         "cGF5bG9hZA==",
		MAC:             "not-valid-base64!!!",
	}

	if VerifyHMACSHA256(key, env) {
		t.Error("VerifyHMACSHA256 should return false for invalid MAC encoding")
	}
}

func TestOpenEnvelopeRoundTrip(t *testing.T) {
	t.Parallel()
	original := []byte(`{"signals":[{"type":"log","message":"round trip"}]}`)

	// Without compression
	params := Params{
		SessionID:   "sess-open-rt",
		Seq:         1,
		ChunkID:     "chunk-rt",
		Codec:       CodecJSON,
		Compression: CompressionNone,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoNone,
	}

	env, err := Build(params, original)
	mbtatest.AssertNoError(t, err, "Build")

	recovered, err := Open(env)
	mbtatest.AssertNoError(t, err, "Open")

	if string(recovered) != string(original) {
		t.Errorf("Recovered = %q, want %q", recovered, original)
	}
}

func TestOpenEnvelopeGzipRoundTrip(t *testing.T) {
	t.Parallel()
	original := []byte(`{"signals":[{"type":"log","message":"gzip round trip"}]}`)

	params := Params{
		SessionID:   "sess-gzip-rt",
		Seq:         1,
		ChunkID:     "chunk-gzip-rt",
		Codec:       CodecJSON,
		Compression: CompressionGzip,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoNone,
	}

	env, err := Build(params, original)
	mbtatest.AssertNoError(t, err, "Build with gzip")

	recovered, err := Open(env)
	mbtatest.AssertNoError(t, err, "Open with gzip")

	if string(recovered) != string(original) {
		t.Errorf("Recovered = %q, want %q", recovered, original)
	}
}

func TestOpenInvalidBase64(t *testing.T) {
	t.Parallel()
	env := &SecureEnvelope{
		Compression: CompressionNone,
		Payload:     "not-valid-base64!!!",
	}

	_, err := Open(env)
	mbtatest.AssertError(t, err, "invalid base64 should error")
}

func TestEncodeEnvelopeNilEnvelope(t *testing.T) {
	t.Parallel()
	// nil envelope should still marshal (to JSON null)
	data, err := EncodeEnvelope(nil)
	mbtatest.AssertNoError(t, err, "EncodeEnvelope nil")
	if string(data) != "null" {
		t.Errorf("Expected null JSON, got %q", data)
	}
}

func TestCanonicalSigningStringDeterministic(t *testing.T) {
	t.Parallel()
	env := &SecureEnvelope{
		MessageType:     "batch",
		SessionID:       "sess-deterministic",
		KeyID:           "key-det",
		Seq:             99,
		ChunkID:         "chunk-det",
		CreatedAtUnixMs: 1700000000000,
		Codec:           CodecJSON,
		Compression:     CompressionNone,
		Encryption:      EncryptionNone,
		HMACAlgo:        HMACAlgoSHA256,
		Nonce:           "nonce-det",
		Payload:         "cGF5bG9hZA==",
	}

	first := CanonicalSigningString(env)
	second := CanonicalSigningString(env)

	if string(first) != string(second) {
		t.Error("CanonicalSigningString should be deterministic")
	}
}
