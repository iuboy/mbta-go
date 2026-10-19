package core

// cipher_bench_test.go：双 profile 密码原语直压（intl vs gm，4KB 载荷）。
//
//   - HMAC：SHA-256 vs SM3（token_proof / finished MAC 的底层原语）；
//   - AEAD：AES-256-GCM vs SM4-GCM Seal/Open（envelope 的加解密原语）。
//
// 数量级预期（arm64 硬件加速）：HMAC-SHA256 4KB ~1-2µs（GB/s 级）；
// AES-256-GCM 4KB Seal ~1-3µs；SM3/SM4 为纯软件实现（pollux/gmsm），
// 预期比国际套件慢一个数量级左右——偏离超过两个数量级才视为异常。

import (
	"crypto/rand"
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// benchProfiles 是双 profile 基准矩阵。
var benchProfiles = []struct {
	name    string
	profile corepb.Profile
}{
	{"INTL", corepb.Profile_PROFILE_INTL},
	{"GM", corepb.Profile_PROFILE_GM},
}

// benchHMACKey 生成 profile 对应长度的随机 HMAC 密钥。
func benchHMACKey(b *testing.B, p corepb.Profile) []byte {
	b.Helper()
	key := make([]byte, HMACKeyLen(p))
	if _, err := rand.Read(key); err != nil {
		b.Fatalf("read rand: %v", err)
	}
	return key
}

// benchAEADKey 生成 profile 对应长度的随机 AEAD 密钥。
func benchAEADKey(b *testing.B, p corepb.Profile) []byte {
	b.Helper()
	key := make([]byte, AEADKeyLen(p))
	if _, err := rand.Read(key); err != nil {
		b.Fatalf("read rand: %v", err)
	}
	return key
}

// BenchmarkHMAC HMAC 吞吐（INTL=HMAC-SHA-256 / GM=HMAC-SM3，4KB）。
// TokenProof / FinishedMAC 每 batch/每连接调用，是握手的底层原语。
func BenchmarkHMAC(b *testing.B) {
	for _, tc := range benchProfiles {
		b.Run(tc.name, func(b *testing.B) {
			h, err := NewHMAC(tc.profile, benchHMACKey(b, tc.profile))
			if err != nil {
				b.Fatal(err)
			}
			payload := make([]byte, 4096)
			if _, err := rand.Read(payload); err != nil {
				b.Fatalf("read rand: %v", err)
			}
			b.SetBytes(4096)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				h.Reset()
				h.Write(payload)
				_ = h.Sum(nil)
			}
		})
	}
}

// BenchmarkNewHMAC 构造开销（每 envelope seal/open 当前都重新构造 hasher，
// 该数字是 envelope 路径的固定开销成分）。
func BenchmarkNewHMAC(b *testing.B) {
	for _, tc := range benchProfiles {
		b.Run(tc.name, func(b *testing.B) {
			key := benchHMACKey(b, tc.profile)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := NewHMAC(tc.profile, key); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkAEAD_Seal 加密吞吐（INTL=AES-256-GCM / GM=SM4-GCM，4KB）。
// SealEnvelope 的加密子环节（Seal 到复用 dst，贴近热路径用法）。
func BenchmarkAEAD_Seal(b *testing.B) {
	for _, tc := range benchProfiles {
		b.Run(tc.name, func(b *testing.B) {
			a, err := NewAEAD(tc.profile, benchAEADKey(b, tc.profile))
			if err != nil {
				b.Fatal(err)
			}
			plaintext := make([]byte, 4096)
			if _, err := rand.Read(plaintext); err != nil {
				b.Fatalf("read rand: %v", err)
			}
			nonce := make([]byte, a.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				b.Fatalf("read rand: %v", err)
			}
			b.SetBytes(4096)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = a.Seal(plaintext[:0], nonce, plaintext, nil)
			}
		})
	}
}

// BenchmarkAEAD_Open 解密吞吐（INTL vs GM，4KB）。
// OpenEnvelope 的解密子环节。
func BenchmarkAEAD_Open(b *testing.B) {
	for _, tc := range benchProfiles {
		b.Run(tc.name, func(b *testing.B) {
			a, err := NewAEAD(tc.profile, benchAEADKey(b, tc.profile))
			if err != nil {
				b.Fatal(err)
			}
			plaintext := make([]byte, 4096)
			if _, err := rand.Read(plaintext); err != nil {
				b.Fatalf("read rand: %v", err)
			}
			nonce := make([]byte, a.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				b.Fatalf("read rand: %v", err)
			}
			ciphertext := a.Seal(nil, nonce, plaintext, nil)
			b.SetBytes(4096)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := a.Open(nil, nonce, ciphertext, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkNewAEAD 构造开销（SealEnvelope/OpenEnvelope 每次调用的固定成本：
// AES key schedule / SM4 密钥扩展）。
func BenchmarkNewAEAD(b *testing.B) {
	for _, tc := range benchProfiles {
		b.Run(tc.name, func(b *testing.B) {
			key := benchAEADKey(b, tc.profile)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := NewAEAD(tc.profile, key); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
