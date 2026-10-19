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

// 各 profile 密钥长度（r3：profile 一次选定 ECDH+KDF+AEAD 组合）。
const (
	HMACKeyLenIntl = 32 // HMAC-SHA-256
	HMACKeyLenGM   = 32 // HMAC-SM3
	AEADKeyLenIntl = 32 // AES-256-GCM
	AEADKeyLenGM   = 16 // SM4-GCM
)

// HMACKeyLen 返回 profile 的 HMAC 密钥长度。未知 profile 返回 -1 哨兵
// （负长度强制调用方显式处理，避免静默空密钥）。
func HMACKeyLen(p corepb.Profile) int {
	switch p {
	case corepb.Profile_PROFILE_INTL:
		return HMACKeyLenIntl
	case corepb.Profile_PROFILE_GM:
		return HMACKeyLenGM
	default:
		return -1
	}
}

// AEADKeyLen 返回 profile 的 AEAD 密钥长度。语义同 HMACKeyLen。
func AEADKeyLen(p corepb.Profile) int {
	switch p {
	case corepb.Profile_PROFILE_INTL:
		return AEADKeyLenIntl
	case corepb.Profile_PROFILE_GM:
		return AEADKeyLenGM
	default:
		return -1
	}
}

// NewHMAC 按 profile 创建 HMAC hasher（intl→SHA-256 / gm→SM3）。
func NewHMAC(p corepb.Profile, key []byte) (hash.Hash, error) {
	switch p {
	case corepb.Profile_PROFILE_INTL:
		if len(key) != HMACKeyLenIntl {
			return nil, fmt.Errorf("intl hmac key must be %d bytes, got %d", HMACKeyLenIntl, len(key))
		}
		return hmac.New(sha256.New, key), nil
	case corepb.Profile_PROFILE_GM:
		if len(key) != HMACKeyLenGM {
			return nil, fmt.Errorf("gm hmac key must be %d bytes, got %d", HMACKeyLenGM, len(key))
		}
		return hmac.New(sm3.New, key), nil
	default:
		return nil, fmt.Errorf("unsupported profile: %v", p)
	}
}

// NewAEAD 按 profile 创建 AEAD（intl→AES-256-GCM / gm→SM4-GCM）。
func NewAEAD(p corepb.Profile, key []byte) (cipher.AEAD, error) {
	switch p {
	case corepb.Profile_PROFILE_INTL:
		if len(key) != AEADKeyLenIntl {
			return nil, fmt.Errorf("intl aead key must be %d bytes, got %d", AEADKeyLenIntl, len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aes init: %w", err)
		}
		return cipher.NewGCM(block)
	case corepb.Profile_PROFILE_GM:
		if len(key) != AEADKeyLenGM {
			return nil, fmt.Errorf("gm aead key must be %d bytes, got %d", AEADKeyLenGM, len(key))
		}
		return sm4.NewGCM(key)
	default:
		return nil, fmt.Errorf("unsupported profile: %v", p)
	}
}
