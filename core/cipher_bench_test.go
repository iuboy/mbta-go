package core

import (
	"crypto/rand"
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// BenchmarkHMAC 测量 HMAC 算法本身的吞吐（INTL=HMAC-SHA-256 vs GM=HMAC-SM3）。
// envelope 的 canonicalMAC 每 batch 调一次，是 envelope Build/Open 的核心子环节。
func BenchmarkHMAC(b *testing.B) {
	for _, tc := range []struct {
		name string
		cs   corepb.CipherSuite
	}{
		{"INTL_SHA256", corepb.CipherSuite_CIPHER_SUITE_INTL},
		{"GM_SM3", corepb.CipherSuite_CIPHER_SUITE_GM},
	} {
		b.Run(tc.name, func(b *testing.B) {
			key := make([]byte, HMACKeyLen(tc.cs))
			_, _ = rand.Read(key)
			h, err := NewHMAC(tc.cs, key)
			if err != nil {
				b.Fatal(err)
			}
			payload := make([]byte, 4096)
			_, _ = rand.Read(payload)
			b.ResetTimer()
			b.SetBytes(4096)
			b.ReportAllocs()
			for b.Loop() {
				h.Reset()
				h.Write(payload)
				_ = h.Sum(nil)
			}
		})
	}
}

// BenchmarkAEAD_Seal 测量 AEAD 加密吞吐（INTL=AES-256-GCM vs GM=SM4-GCM）。
// envelope Build 的加密子环节。
func BenchmarkAEAD_Seal(b *testing.B) {
	for _, tc := range []struct {
		name string
		cs   corepb.CipherSuite
	}{
		{"INTL_AES256GCM", corepb.CipherSuite_CIPHER_SUITE_INTL},
		{"GM_SM4GCM", corepb.CipherSuite_CIPHER_SUITE_GM},
	} {
		b.Run(tc.name, func(b *testing.B) {
			key := make([]byte, AEADKeyLen(tc.cs))
			_, _ = rand.Read(key)
			a, err := NewAEAD(tc.cs, key)
			if err != nil {
				b.Fatal(err)
			}
			plaintext := make([]byte, 4096)
			_, _ = rand.Read(plaintext)
			nonce := make([]byte, a.NonceSize())
			_, _ = rand.Read(nonce)
			b.ResetTimer()
			b.SetBytes(4096)
			b.ReportAllocs()
			for b.Loop() {
				_ = a.Seal(plaintext[:0], nonce, plaintext, nil)
			}
		})
	}
}

// BenchmarkAEAD_Open 测量 AEAD 解密吞吐（INTL vs GM）。
// envelope Open 的解密子环节。
func BenchmarkAEAD_Open(b *testing.B) {
	for _, tc := range []struct {
		name string
		cs   corepb.CipherSuite
	}{
		{"INTL_AES256GCM", corepb.CipherSuite_CIPHER_SUITE_INTL},
		{"GM_SM4GCM", corepb.CipherSuite_CIPHER_SUITE_GM},
	} {
		b.Run(tc.name, func(b *testing.B) {
			key := make([]byte, AEADKeyLen(tc.cs))
			_, _ = rand.Read(key)
			a, err := NewAEAD(tc.cs, key)
			if err != nil {
				b.Fatal(err)
			}
			plaintext := make([]byte, 4096)
			_, _ = rand.Read(plaintext)
			nonce := make([]byte, a.NonceSize())
			_, _ = rand.Read(nonce)
			ciphertext := a.Seal(nil, nonce, plaintext, nil)
			b.ResetTimer()
			b.SetBytes(4096)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := a.Open(nil, nonce, ciphertext, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
