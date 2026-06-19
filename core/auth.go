package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"time"

	"github.com/iuboy/pollux-go/sm3"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// DefaultSessionTTL is the default time-to-live for authenticated sessions.
const DefaultSessionTTL = 24 * time.Hour

// TokenValidator verifies an agent token and returns its identity.
type TokenValidator interface {
	Validate(token string) (*AgentIdentity, error)
}

// AgentIdentity is returned on successful token authentication.
type AgentIdentity struct {
	AgentID     string    // unique agent identifier
	Permissions []string  // granted permissions
	ExpiresAt   time.Time // token expiration time
}

// ErrInvalidToken is returned when token validation fails.
var ErrInvalidToken = NewError(NumAuth, CodeAuth, "invalid token")

// TokenResolver resolves a long-term token by agent identifier. Servers whose
// Auth implementation also satisfies this interface can suppress plaintext
// token transmission in the AUTH frame: the client omits Token and the server
// resolves it from the claimed AgentID, then verifies the challenge response.
// See CapAuthTokenless and v1.ConnectionHandler.handleAuth.
type TokenResolver interface {
	ResolveToken(agentID string) (token string, err error)
}

// ErrAgentNotFound is returned by TokenResolver when no token is registered for
// the agent. It shares the auth error family with ErrInvalidToken so failures
// do not reveal whether a given agentID exists (avoids agent enumeration).
var ErrAgentNotFound = NewError(NumAuth, CodeAuth, "agent not found")

// StaticTokenValidator validates tokens against a static map (dev/test use).
// It additionally implements TokenResolver via a reverse agentID->token index,
// so it supports tokenless AUTH out of the box.
type StaticTokenValidator struct {
	tokens map[string]string // token  -> agentID (Validate 路径)
	agents map[string]string // agentID-> token   (ResolveToken 路径)
}

// NewStaticTokenValidator creates a validator from a token->agentID mapping.
// It also builds a reverse agentID->token index. When one agentID has multiple
// tokens, last-write-wins applies (deterministic; production multi-token/agent
// setups should implement a custom TokenValidator+TokenResolver).
func NewStaticTokenValidator(tokens map[string]string) *StaticTokenValidator {
	agents := make(map[string]string, len(tokens))
	for tok, aid := range tokens {
		agents[aid] = tok
	}
	return &StaticTokenValidator{tokens: tokens, agents: agents}
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

// ResolveToken looks up the token associated with an agent identifier. Used by
// servers supporting tokenless AUTH (see CapAuthTokenless) to verify the
// challenge response without the client transmitting its plaintext token.
func (v *StaticTokenValidator) ResolveToken(agentID string) (string, error) {
	if tok, ok := v.agents[agentID]; ok {
		return tok, nil
	}
	return "", ErrAgentNotFound
}

// 编译期断言：StaticTokenValidator 同时满足 TokenValidator 与 TokenResolver。
var (
	_ TokenValidator = (*StaticTokenValidator)(nil)
	_ TokenResolver  = (*StaticTokenValidator)(nil)
)

// SessionKeys 持有已认证会话的密码材料（r2：CipherSuite 统一算法）。
// 密钥字段 unexport，通过访问器读取；调用方不应修改返回的 slice。
type SessionKeys struct {
	KeyID       string
	CipherSuite corepb.CipherSuite
	hmacKey     []byte // len = HMACKeyLen(cs)：intl=32 SHA-256, gm=32 SM3
	aeadKey     []byte // len = AEADKeyLen(cs)：intl=32 AES-256, gm=16 SM4
}

// HMACKey 返回 HMAC 密钥的只读 view。调用方不应修改返回的 slice。
func (k *SessionKeys) HMACKey() []byte { return k.hmacKey }

// AEADKey 返回 AEAD 密钥的只读 view。调用方不应修改返回的 slice。
func (k *SessionKeys) AEADKey() []byte { return k.aeadKey }

// SetAEADKey 设置 AEAD 密钥（用于 AUTH_OK 后从服务端响应更新）。
func (k *SessionKeys) SetAEADKey(key []byte) { k.aeadKey = key }

// NewSessionKeys 构造 SessionKeys（HMAC 密钥在构造时设置，AEAD 密钥可后续用 SetAEADKey 更新）。
// 供跨包调用方（如 protocol 包的 client/handler）在收到 AUTH_OK 后从服务端下发字段构造密钥对象。
func NewSessionKeys(keyID string, cs corepb.CipherSuite, hmacKey []byte) *SessionKeys {
	return &SessionKeys{
		KeyID:       keyID,
		CipherSuite: cs,
		hmacKey:     hmacKey,
	}
}

// Zero 清零密钥材料，用于连接关闭时的安全清理。
func (k *SessionKeys) Zero() {
	for i := range k.hmacKey {
		k.hmacKey[i] = 0
	}
	for i := range k.aeadKey {
		k.aeadKey[i] = 0
	}
}

// GenerateSessionKeys 为已认证 agent 生成会话密钥（r2 按 CipherSuite）。
func GenerateSessionKeys(cs corepb.CipherSuite) (*SessionKeys, error) {
	hmacKey := make([]byte, HMACKeyLen(cs))
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, WrapError(NumHMAC, CodeHMAC, "generate HMAC key", err)
	}
	aeadKey := make([]byte, AEADKeyLen(cs))
	if _, err := rand.Read(aeadKey); err != nil {
		return nil, WrapError(NumEnvelope, CodeEnvelope, "generate AEAD key", err)
	}
	return &SessionKeys{
		KeyID:       NewChunkID().String(),
		CipherSuite: cs,
		hmacKey:     hmacKey,
		aeadKey:     aeadKey,
	}, nil
}

// ComputeChallengeResponse 计算挑战-响应 HMAC(token, nonce)，返回 raw 字节（r2）。
// 客户端用它证明持有 token，而非仅回显 nonce。算法按协商 CipherSuite（intl=SHA-256, gm=SM3）。
//
// 注：此函数在 AUTH 阶段使用，session key 尚未建立，只能用 token 作 HMAC 密钥
// （token 长度任意，故不走 NewHMAC 的长度校验，直接 hmac.New）。挑战响应仅在
// TLS/TLCP 加密通道内传输，且 nonce 一次性，侧信道风险低。
func ComputeChallengeResponse(token, nonce string, cs corepb.CipherSuite) []byte {
	var h hash.Hash
	if cs == corepb.CipherSuite_CIPHER_SUITE_GM {
		h = hmac.New(sm3.New, []byte(token))
	} else {
		h = hmac.New(sha256.New, []byte(token))
	}
	h.Write([]byte(nonce))
	return h.Sum(nil)
}
