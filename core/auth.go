package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"time"

	"github.com/google/uuid"
	"github.com/iuboy/pollux-go/sm3"
)

// DefaultSessionTTL is the default time-to-live for authenticated sessions.
const DefaultSessionTTL = 24 * time.Hour

// TokenValidator verifies an agent token and returns its identity.
type TokenValidator interface {
	Validate(token string) (*AgentIdentity, error)
}

// AgentIdentity is returned on successful token authentication.
type AgentIdentity struct {
	AgentID     string     // unique agent identifier
	Permissions []string  // granted permissions
	ExpiresAt   time.Time // token expiration time
}

// ErrInvalidToken is returned when token validation fails.
var ErrInvalidToken = NewError(NumAuth, ErrAuth, "invalid token")

// StaticTokenValidator validates tokens against a static map (dev/test use).
type StaticTokenValidator struct {
	tokens map[string]string // token -> agentID
}

// NewStaticTokenValidator creates a validator from a token->agentID mapping.
func NewStaticTokenValidator(tokens map[string]string) *StaticTokenValidator {
	return &StaticTokenValidator{tokens: tokens}
}

// Validate looks up the token and returns the associated agent identity.
func (v *StaticTokenValidator) Validate(token string) (*AgentIdentity, error) {
	agentID, ok := v.tokens[token]
	if !ok {
		return nil, ErrInvalidToken
	}
	return &AgentIdentity{
		AgentID:   agentID,
		ExpiresAt: time.Now().Add(DefaultSessionTTL),
	}, nil
}

// SessionKeys holds the cryptographic material for an authenticated session.
type SessionKeys struct {
	KeyID    string
	HMACKey  []byte // 32 bytes
	HMACAlgo string // sha256 or sm3
}

// GenerateSessionKeys creates fresh session keys for an authenticated agent.
// If hmacAlgo is empty, it defaults to "sha256".
func GenerateSessionKeys(hmacAlgo ...string) (*SessionKeys, error) {
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, WrapError(NumHMAC, ErrHMAC, "generate HMAC key", err)
	}

	algo := HMACAlgoSHA256
	if len(hmacAlgo) > 0 && hmacAlgo[0] != "" {
		algo = hmacAlgo[0]
	}

	return &SessionKeys{
		KeyID:    uuid.Must(uuid.NewV7()).String(),
		HMACKey:  hmacKey,
		HMACAlgo: algo,
	}, nil
}

// HMACKeyBase64 returns the HMAC key as a base64 string for AUTH_OK messages.
func (sk *SessionKeys) HMACKeyBase64() string {
	return base64.StdEncoding.EncodeToString(sk.HMACKey)
}

// ComputeChallengeResponse 计算挑战-响应值 HMAC(token, nonce)。
// 客户端使用此函数证明自己持有 token，而非仅回显 nonce。
//
// 设计权衡说明：
//   - 此函数在 AUTH 阶段使用，此时 session key 尚未建立，只能用 token 作为 HMAC 密钥。
//   - token 是长期凭证，直接参与密码学运算有理论上的侧信道风险（即使 Go 的 hmac 实现
//     是常量时间的，密钥材料仍存在于内存中更长时间）。
//   - 未来改进方向：(a) 使用 HKDF(token, nonce) 派生临时密钥，避免 token 直接参与 HMAC；
//     (b) 在 v2 中使用 SM2 签名代替 HMAC 挑战响应。
//   - 当前设计的风险等级：低。因为挑战响应仅在 TLS 1.3 加密通道内传输，且 nonce 是一次性的。
func ComputeChallengeResponse(token, nonce, algo string) string {
	var h hash.Hash
	switch algo {
	case HMACAlgoSM3:
		h = hmac.New(sm3.New, []byte(token))
	default:
		h = hmac.New(sha256.New, []byte(token))
	}
	h.Write([]byte(nonce))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
