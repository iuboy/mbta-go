package core

import (
	"crypto/rand"
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// envelopeBenchParams 构造一个合法的 BuildParams（已 codec 编码的 batch payload），
// 用于 Build/Open 基准。payloadSize 控制 batch 字节数（测试不同 size 的加解密开销）。
func envelopeBenchParams(b *testing.B, cs corepb.CipherSuite, payloadSize int) BuildParams {
	b.Helper()
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		b.Fatalf("rand: %v", err)
	}
	hmacKey := make([]byte, HMACKeyLen(cs))
	aeadKey := make([]byte, AEADKeyLen(cs))
	_, _ = rand.Read(hmacKey)
	_, _ = rand.Read(aeadKey)
	p := BuildParams{
		SessionID:    []byte("bench-session-01"),
		KeyID:        "bench-key",
		Seq:          1,
		Codec:        corepb.Codec_CODEC_PROTO,
		Compression:  corepb.Compression_COMPRESSION_NONE,
		CipherSuite:  cs,
		DeliveryMode: corepb.DeliveryMode_DELIVERY_MODE_RELIABLE,
		MsgType:      corepb.EnvelopeMsgType_ENVELOPE_MSG_TYPE_BATCH,
		HMACKey:      hmacKey,
		AEADKey:      aeadKey,
		BatchPayload: payload,
	}
	chunkID := NewChunkID()
	p.ChunkID = chunkID
	return p
}

// BenchmarkEnvelopeBuild 测量 SecureEnvelope 构建（压缩 + AEAD 加密 + HMAC 签名）延迟。
// 覆盖 INTL/GM 两个 cipher suite × 3 个 payload size，报 ns/op + bytes/sec（加密吞吐）。
func BenchmarkEnvelopeBuild(b *testing.B) {
	for _, tc := range []struct {
		name    string
		cs      corepb.CipherSuite
		payload int
	}{
		{"INTL_256B", corepb.CipherSuite_CIPHER_SUITE_INTL, 256},
		{"INTL_4KB", corepb.CipherSuite_CIPHER_SUITE_INTL, 4096},
		{"INTL_64KB", corepb.CipherSuite_CIPHER_SUITE_INTL, 65536},
		{"GM_256B", corepb.CipherSuite_CIPHER_SUITE_GM, 256},
		{"GM_4KB", corepb.CipherSuite_CIPHER_SUITE_GM, 4096},
		{"GM_64KB", corepb.CipherSuite_CIPHER_SUITE_GM, 65536},
	} {
		b.Run(tc.name, func(b *testing.B) {
			p := envelopeBenchParams(b, tc.cs, tc.payload)
			b.ResetTimer()
			b.SetBytes(int64(tc.payload))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Build(p); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEnvelopeOpen 测量 SecureEnvelope 打开（HMAC 校验 + AEAD 解密）延迟。
// 报 ns/op + bytes/sec（解密吞吐）。
func BenchmarkEnvelopeOpen(b *testing.B) {
	for _, tc := range []struct {
		name    string
		cs      corepb.CipherSuite
		payload int
	}{
		{"INTL_256B", corepb.CipherSuite_CIPHER_SUITE_INTL, 256},
		{"INTL_4KB", corepb.CipherSuite_CIPHER_SUITE_INTL, 4096},
		{"INTL_64KB", corepb.CipherSuite_CIPHER_SUITE_INTL, 65536},
		{"GM_256B", corepb.CipherSuite_CIPHER_SUITE_GM, 256},
		{"GM_4KB", corepb.CipherSuite_CIPHER_SUITE_GM, 4096},
		{"GM_64KB", corepb.CipherSuite_CIPHER_SUITE_GM, 65536},
	} {
		b.Run(tc.name, func(b *testing.B) {
			p := envelopeBenchParams(b, tc.cs, tc.payload)
			env, err := Build(p)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			b.SetBytes(int64(tc.payload))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Open(env, p.HMACKey, p.AEADKey); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEnvelopeBuild_Open_RoundTrip 测量 Build + Open 完整往返（客户端加密 + 服务端解密
// 的聚合延迟），用于评估 envelope 环节对端到端延迟的贡献。
func BenchmarkEnvelopeBuild_Open_RoundTrip(b *testing.B) {
	p := envelopeBenchParams(b, corepb.CipherSuite_CIPHER_SUITE_INTL, 4096)
	b.ResetTimer()
	b.SetBytes(4096)
	b.ReportAllocs()
	for b.Loop() {
		env, err := Build(p)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := Open(env, p.HMACKey, p.AEADKey); err != nil {
			b.Fatal(err)
		}
	}
}
