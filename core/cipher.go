package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"

	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/pollux-go/sm3"
	"github.com/iuboy/pollux-go/sm4"
)

// 密码套件密钥长度（core spec §8）。
const (
	HMACKeyLenIntl = 32 // HMAC-SHA-256
	HMACKeyLenGM   = 32 // HMAC-SM3
	AEADKeyLenIntl = 32 // AES-256-GCM
	AEADKeyLenGM   = 16 // SM4-GCM
)

// HMACKeyLen 返回指定套件的 HMAC 密钥长度。
func HMACKeyLen(cs corepb.CipherSuite) int {
	if cs == corepb.CipherSuite_CIPHER_SUITE_GM {
		return HMACKeyLenGM
	}
	return HMACKeyLenIntl
}

// AEADKeyLen 返回指定套件的 AEAD 密钥长度。
func AEADKeyLen(cs corepb.CipherSuite) int {
	if cs == corepb.CipherSuite_CIPHER_SUITE_GM {
		return AEADKeyLenGM
	}
	return AEADKeyLenIntl
}

// NewHMAC 按密码套件创建 HMAC hasher。
//
//	intl → HMAC-SHA-256
//	gm   → HMAC-SM3
func NewHMAC(cs corepb.CipherSuite, key []byte) (hash.Hash, error) {
	switch cs {
	case corepb.CipherSuite_CIPHER_SUITE_INTL:
		if len(key) != HMACKeyLenIntl {
			return nil, fmt.Errorf("intl hmac key must be %d bytes, got %d", HMACKeyLenIntl, len(key))
		}
		return hmac.New(sha256.New, key), nil
	case corepb.CipherSuite_CIPHER_SUITE_GM:
		if len(key) != HMACKeyLenGM {
			return nil, fmt.Errorf("gm hmac key must be %d bytes, got %d", HMACKeyLenGM, len(key))
		}
		return hmac.New(sm3.New, key), nil
	default:
		return nil, fmt.Errorf("unsupported cipher suite: %v", cs)
	}
}

// NewAEAD 按密码套件创建 AEAD。
//
//	intl → AES-256-GCM（crypto/aes + crypto/cipher）
//	gm   → SM4-GCM（pollux-go/sm4）
//
// 密文格式：nonce(12) || ciphertext || tag(16)（core spec §8.4）。
func NewAEAD(cs corepb.CipherSuite, key []byte) (cipher.AEAD, error) {
	switch cs {
	case corepb.CipherSuite_CIPHER_SUITE_INTL:
		if len(key) != AEADKeyLenIntl {
			return nil, fmt.Errorf("intl aead key must be %d bytes, got %d", AEADKeyLenIntl, len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aes init: %w", err)
		}
		return cipher.NewGCM(block)
	case corepb.CipherSuite_CIPHER_SUITE_GM:
		if len(key) != AEADKeyLenGM {
			return nil, fmt.Errorf("gm aead key must be %d bytes, got %d", AEADKeyLenGM, len(key))
		}
		return sm4.NewGCM(key)
	default:
		return nil, fmt.Errorf("unsupported cipher suite: %v", cs)
	}
}
