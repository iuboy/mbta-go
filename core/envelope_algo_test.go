package core

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestOpen_UnsupportedCompressionRejected: Open 拒绝非 v1 支持的 compression
// （zstd 为保留值未实现，bogus 显式非法），不再当未压缩 raw 返回 (L-1)。
func TestOpen_UnsupportedCompressionRejected(t *testing.T) {
	for _, comp := range []string{CompressionZstd, "bogus", ""} {
		env := &SecureEnvelope{
			Compression: comp,
			Encryption:  EncryptionNone,
			Payload:     base64.StdEncoding.EncodeToString([]byte("x")),
		}
		if _, err := Open(env, nil); err == nil {
			t.Errorf("compression %q: expected error, got nil", comp)
		}
	}
}

// TestOpen_UnsupportedEncryptionRejected: Open 拒绝非 none 的 encryption
// （sm4_gcm 为保留值未实现），杜绝把未实现加密的 envelope 当明文处理 (L-1)。
func TestOpen_UnsupportedEncryptionRejected(t *testing.T) {
	env := &SecureEnvelope{
		Compression: CompressionNone,
		Encryption:  EncryptionSM4,
		Payload:     base64.StdEncoding.EncodeToString([]byte("x")),
	}
	if _, err := Open(env, nil); err == nil {
		t.Fatal("expected error for unsupported encryption, got nil")
	}
}

// TestOpen_NoneCompressionReturnsRaw: none 压缩 + none 加密下 Open 返回原始字节
// （回归：白名单不得破坏合法的未压缩路径）。
func TestOpen_NoneCompressionReturnsRaw(t *testing.T) {
	raw := []byte("hello-world")
	env := &SecureEnvelope{
		Compression: CompressionNone,
		Encryption:  EncryptionNone,
		Payload:     base64.StdEncoding.EncodeToString(raw),
	}
	got, err := Open(env, nil)
	if err != nil {
		t.Fatalf("open none: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("open none = %q, want %q", got, raw)
	}
}

// TestBuild_NormalizesEmptyAlgorithms: Build 把空 compression/encryption 归一化为
// none，保证上线 envelope 永远是 Open 允许的规范值。
func TestBuild_NormalizesEmptyAlgorithms(t *testing.T) {
	env, err := Build(Params{
		SessionID: "s", Seq: 1, ChunkID: "c", Codec: CodecJSON,
		HMACAlgo: HMACAlgoNone,
		// Compression / Encryption 留空
	}, []byte(`{}`))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if env.Compression != CompressionNone {
		t.Errorf("Compression = %q, want none (normalized)", env.Compression)
	}
	if env.Encryption != EncryptionNone {
		t.Errorf("Encryption = %q, want none (normalized)", env.Encryption)
	}
	// 归一化后必须能被 Open 接受。
	if _, err := Open(env, nil); err != nil {
		t.Fatalf("open normalized envelope: %v", err)
	}
}

// TestOpen_ErrorDoesNotLeakPayload: 拒绝错误信息不回显 payload 内容。
func TestOpen_ErrorDoesNotLeakPayload(t *testing.T) {
	secret := "super-secret-content"
	env := &SecureEnvelope{
		Compression: "bogus",
		Payload:     base64.StdEncoding.EncodeToString([]byte(secret)),
	}
	_, err := Open(env, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error message leaks payload: %q", err.Error())
	}
}
