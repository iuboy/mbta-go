package core

import (
	"bytes"
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// r2 envelope 测试基线：corepb.SecureEnvelope + 原生 bytes + canonical HMAC +
// 双轨 CipherSuite（intl/gm）+ 四压缩（none/gzip/zstd/lz4）。

func makeBuildParams(cs corepb.CipherSuite, comp corepb.Compression, hmacKey, aeadKey []byte, payload []byte) BuildParams {
	return BuildParams{
		SessionID:    []byte("sess-1"),
		KeyID:        "key-1",
		Seq:          1,
		ChunkID:      NewChunkID(),
		Codec:        corepb.Codec_CODEC_PROTO,
		Compression:  comp,
		CipherSuite:  cs,
		DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
		MsgType:      corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
		HMACKey:      hmacKey,
		AEADKey:      aeadKey,
		BatchPayload: payload,
	}
}

func TestBuildOpenRoundTrip_Intl_AESGCM(t *testing.T) {
	hmacKey := make([]byte, HMACKeyLenIntl)
	aeadKey := make([]byte, AEADKeyLenIntl)
	payload := []byte("hello intl envelope")

	env, err := Build(makeBuildParams(corepb.CipherSuite_CIPHER_SUITE_INTL, corepb.Compression_COMPRESSION_NONE, hmacKey, aeadKey, payload))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if env.CipherSuite != corepb.CipherSuite_CIPHER_SUITE_INTL {
		t.Errorf("cipher suite = %v, want INTL", env.CipherSuite)
	}
	if len(env.Nonce) != AEADNonceSize {
		t.Errorf("nonce len = %d, want %d", len(env.Nonce), AEADNonceSize)
	}
	if len(env.Mac) == 0 {
		t.Error("mac empty")
	}

	ok, err := VerifyMAC(hmacKey, env)
	if err != nil || !ok {
		t.Fatalf("VerifyMAC: ok=%v err=%v", ok, err)
	}

	got, err := Open(env, hmacKey, aeadKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

func TestBuildOpenRoundTrip_GM_SM4GCM(t *testing.T) {
	hmacKey := make([]byte, HMACKeyLenGM)
	aeadKey := make([]byte, AEADKeyLenGM)
	payload := []byte("hello gm envelope 国密")

	env, err := Build(makeBuildParams(corepb.CipherSuite_CIPHER_SUITE_GM, corepb.Compression_COMPRESSION_NONE, hmacKey, aeadKey, payload))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if env.CipherSuite != corepb.CipherSuite_CIPHER_SUITE_GM {
		t.Errorf("cipher suite = %v, want GM", env.CipherSuite)
	}

	ok, err := VerifyMAC(hmacKey, env)
	if err != nil || !ok {
		t.Fatalf("VerifyMAC: ok=%v err=%v", ok, err)
	}

	got, err := Open(env, hmacKey, aeadKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

func TestBuildOpen_Compressions(t *testing.T) {
	hmacKey := make([]byte, HMACKeyLenIntl)
	aeadKey := make([]byte, AEADKeyLenIntl)
	payload := bytes.Repeat([]byte("ABCDEFGH"), 256) // 2KB

	comps := []corepb.Compression{
		corepb.Compression_COMPRESSION_NONE,
		corepb.Compression_COMPRESSION_GZIP,
		corepb.Compression_COMPRESSION_ZSTD,
		corepb.Compression_COMPRESSION_LZ4,
	}
	for _, c := range comps {
		t.Run(c.String(), func(t *testing.T) {
			env, err := Build(makeBuildParams(corepb.CipherSuite_CIPHER_SUITE_INTL, c, hmacKey, aeadKey, payload))
			if err != nil {
				t.Fatalf("Build(%v): %v", c, err)
			}
			if env.Compression != c {
				t.Errorf("compression field = %v, want %v", env.Compression, c)
			}
			got, err := Open(env, hmacKey, aeadKey)
			if err != nil {
				t.Fatalf("Open(%v): %v", c, err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("%v: payload mismatch (got %d bytes, want %d)", c, len(got), len(payload))
			}
		})
	}
}

func TestVerifyMAC_WrongKey(t *testing.T) {
	hmacKey := make([]byte, HMACKeyLenIntl)
	aeadKey := make([]byte, AEADKeyLenIntl)
	env, _ := Build(makeBuildParams(corepb.CipherSuite_CIPHER_SUITE_INTL, corepb.Compression_COMPRESSION_NONE, hmacKey, aeadKey, []byte("x")))

	wrong := make([]byte, HMACKeyLenIntl)
	wrong[0] = 1
	ok, err := VerifyMAC(wrong, env)
	if err != nil {
		t.Fatalf("VerifyMAC err: %v", err)
	}
	if ok {
		t.Error("VerifyMAC should fail with wrong key")
	}
}

func TestVerifyMAC_TamperedPayload(t *testing.T) {
	hmacKey := make([]byte, HMACKeyLenIntl)
	aeadKey := make([]byte, AEADKeyLenIntl)
	env, _ := Build(makeBuildParams(corepb.CipherSuite_CIPHER_SUITE_INTL, corepb.Compression_COMPRESSION_NONE, hmacKey, aeadKey, []byte("plaintext")))

	if len(env.Payload) > 0 {
		env.Payload[0] ^= 0xFF
	}
	ok, err := VerifyMAC(hmacKey, env)
	if err != nil {
		t.Fatalf("VerifyMAC err: %v", err)
	}
	if ok {
		t.Error("VerifyMAC should fail after payload tamper")
	}
}

func TestBuild_RejectsUnspecifiedCipherSuite(t *testing.T) {
	p := makeBuildParams(corepb.CipherSuite_CIPHER_SUITE_UNSPECIFIED, corepb.Compression_COMPRESSION_NONE, make([]byte, 32), make([]byte, 32), []byte("x"))
	if _, err := Build(p); err == nil {
		t.Error("Build should reject unspecified cipher suite")
	}
}

func TestBuild_OpenDecryptionFailure(t *testing.T) {
	hmacKey := make([]byte, HMACKeyLenIntl)
	aeadKey := make([]byte, AEADKeyLenIntl)
	env, _ := Build(makeBuildParams(corepb.CipherSuite_CIPHER_SUITE_INTL, corepb.Compression_COMPRESSION_NONE, hmacKey, aeadKey, []byte("secret")))

	wrong := make([]byte, AEADKeyLenIntl)
	wrong[0] = 1
	if _, err := Open(env, hmacKey, wrong); err == nil {
		t.Error("Open should fail with wrong AEAD key")
	}
}

func TestBuild_LargeAndEmptyPayload(t *testing.T) {
	hmacKey := make([]byte, HMACKeyLenIntl)
	aeadKey := make([]byte, AEADKeyLenIntl)

	env, err := Build(makeBuildParams(corepb.CipherSuite_CIPHER_SUITE_INTL, corepb.Compression_COMPRESSION_ZSTD, hmacKey, aeadKey, []byte{}))
	if err != nil {
		t.Fatalf("Build empty: %v", err)
	}
	got, err := Open(env, hmacKey, aeadKey)
	if err != nil || len(got) != 0 {
		t.Errorf("empty payload round trip: got=%v err=%v", got, err)
	}

	large := bytes.Repeat([]byte{0xAB}, 1<<16)
	env2, err := Build(makeBuildParams(corepb.CipherSuite_CIPHER_SUITE_INTL, corepb.Compression_COMPRESSION_ZSTD, hmacKey, aeadKey, large))
	if err != nil {
		t.Fatalf("Build large: %v", err)
	}
	got2, err := Open(env2, hmacKey, aeadKey)
	if err != nil {
		t.Fatalf("Open large: %v", err)
	}
	if !bytes.Equal(got2, large) {
		t.Error("large payload mismatch")
	}
}

func TestCanonicalMAC_Deterministic(t *testing.T) {
	hmacKey := make([]byte, HMACKeyLenIntl)
	aeadKey := make([]byte, AEADKeyLenIntl)
	env, _ := Build(makeBuildParams(corepb.CipherSuite_CIPHER_SUITE_INTL, corepb.Compression_COMPRESSION_NONE, hmacKey, aeadKey, []byte("deterministic")))

	m1, _ := canonicalMAC(env.CipherSuite, hmacKey, env)
	m2, _ := canonicalMAC(env.CipherSuite, hmacKey, env)
	if !bytes.Equal(m1, m2) {
		t.Error("canonicalMAC must be deterministic for same envelope")
	}
	if !bytes.Equal(m1, env.Mac) {
		t.Error("canonicalMAC must equal env.Mac")
	}
}

func TestEncodeDecodeEnvelopeRoundTrip(t *testing.T) {
	hmacKey := make([]byte, HMACKeyLenIntl)
	aeadKey := make([]byte, AEADKeyLenIntl)
	env, _ := Build(makeBuildParams(corepb.CipherSuite_CIPHER_SUITE_INTL, corepb.Compression_COMPRESSION_GZIP, hmacKey, aeadKey, []byte("wire trip")))

	wire, err := EncodeEnvelope(env)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodeEnvelope(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(got.Payload, env.Payload) || !bytes.Equal(got.Mac, env.Mac) {
		t.Error("encode/decode payload/mac mismatch")
	}
}
