package core

import (
	"bytes"
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
)

func TestHMACKeyLen(t *testing.T) {
	tests := []struct {
		name string
		cs   corepb.CipherSuite
		want int
	}{
		{"intl", corepb.CipherSuite_CIPHER_SUITE_INTL, HMACKeyLenIntl},
		{"gm", corepb.CipherSuite_CIPHER_SUITE_GM, HMACKeyLenGM},
		{"unspecified", corepb.CipherSuite_CIPHER_SUITE_UNSPECIFIED, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HMACKeyLen(tt.cs); got != tt.want {
				t.Errorf("HMACKeyLen(%v) = %d, want %d", tt.cs, got, tt.want)
			}
		})
	}
}

func TestAEADKeyLen(t *testing.T) {
	tests := []struct {
		name string
		cs   corepb.CipherSuite
		want int
	}{
		{"intl", corepb.CipherSuite_CIPHER_SUITE_INTL, AEADKeyLenIntl},
		{"gm", corepb.CipherSuite_CIPHER_SUITE_GM, AEADKeyLenGM},
		{"unspecified", corepb.CipherSuite_CIPHER_SUITE_UNSPECIFIED, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AEADKeyLen(tt.cs); got != tt.want {
				t.Errorf("AEADKeyLen(%v) = %d, want %d", tt.cs, got, tt.want)
			}
		})
	}
}

func TestNewHMAC_InvalidKeyLength(t *testing.T) {
	// 错误长度的密钥应返回 error，而非静默成功。
	if _, err := NewHMAC(corepb.CipherSuite_CIPHER_SUITE_INTL, make([]byte, 10)); err == nil {
		t.Error("NewHMAC with wrong key length should fail")
	}
	if _, err := NewHMAC(corepb.CipherSuite_CIPHER_SUITE_GM, make([]byte, 10)); err == nil {
		t.Error("NewHMAC GM with wrong key length should fail")
	}
}

func TestNewHMAC_UnsupportedSuite(t *testing.T) {
	if _, err := NewHMAC(corepb.CipherSuite_CIPHER_SUITE_UNSPECIFIED, make([]byte, 32)); err == nil {
		t.Error("NewHMAC with UNSPECIFIED suite should fail")
	}
}

func TestNewAEAD_InvalidKeyLength(t *testing.T) {
	if _, err := NewAEAD(corepb.CipherSuite_CIPHER_SUITE_INTL, make([]byte, 10)); err == nil {
		t.Error("NewAEAD with wrong key length should fail")
	}
}

func TestNewAEAD_UnsupportedSuite(t *testing.T) {
	if _, err := NewAEAD(corepb.CipherSuite_CIPHER_SUITE_UNSPECIFIED, make([]byte, 32)); err == nil {
		t.Error("NewAEAD with UNSPECIFIED suite should fail")
	}
}

func TestNewHMAC_RoundTrip(t *testing.T) {
	for _, cs := range []corepb.CipherSuite{
		corepb.CipherSuite_CIPHER_SUITE_INTL,
		corepb.CipherSuite_CIPHER_SUITE_GM,
	} {
		t.Run(cs.String(), func(t *testing.T) {
			key := make([]byte, HMACKeyLen(cs))
			h, err := NewHMAC(cs, key)
			if err != nil {
				t.Fatalf("NewHMAC(%v): %v", cs, err)
			}
			h.Write([]byte("payload"))
			mac1 := h.Sum(nil)

			h2, _ := NewHMAC(cs, key)
			h2.Write([]byte("payload"))
			mac2 := h2.Sum(nil)
			if !bytes.Equal(mac1, mac2) {
				t.Error("HMAC not deterministic for same key+payload")
			}
		})
	}
}

func TestNewAEAD_SealOpenRoundTrip(t *testing.T) {
	for _, cs := range []corepb.CipherSuite{
		corepb.CipherSuite_CIPHER_SUITE_INTL,
		corepb.CipherSuite_CIPHER_SUITE_GM,
	} {
		t.Run(cs.String(), func(t *testing.T) {
			key := make([]byte, AEADKeyLen(cs))
			aead, err := NewAEAD(cs, key)
			if err != nil {
				t.Fatalf("NewAEAD(%v): %v", cs, err)
			}
			nonce := make([]byte, aead.NonceSize())
			plaintext := []byte("secret payload")
			ct := aead.Seal(nil, nonce, plaintext, nil)
			pt, err := aead.Open(nil, nonce, ct, nil)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Error("round-trip mismatch")
			}
		})
	}
}

func TestGenerateSessionKeys_UnsupportedSuite(t *testing.T) {
	// UNSPECIFIED 不应生成空密钥——应 fail-fast。
	if _, err := GenerateSessionKeys(corepb.CipherSuite_CIPHER_SUITE_UNSPECIFIED); err == nil {
		t.Error("GenerateSessionKeys with UNSPECIFIED should fail")
	}
}

func TestGenerateSessionKeys_ValidSuites(t *testing.T) {
	for _, cs := range []corepb.CipherSuite{
		corepb.CipherSuite_CIPHER_SUITE_INTL,
		corepb.CipherSuite_CIPHER_SUITE_GM,
	} {
		t.Run(cs.String(), func(t *testing.T) {
			keys, err := GenerateSessionKeys(cs)
			if err != nil {
				t.Fatalf("GenerateSessionKeys(%v): %v", cs, err)
			}
			if keys.HMACKey() == nil || len(keys.HMACKey()) != HMACKeyLen(cs) {
				t.Errorf("HMACKey length = %d, want %d", len(keys.HMACKey()), HMACKeyLen(cs))
			}
			if keys.AEADKey() == nil || len(keys.AEADKey()) != AEADKeyLen(cs) {
				t.Errorf("AEADKey length = %d, want %d", len(keys.AEADKey()), AEADKeyLen(cs))
			}
		})
	}
}
