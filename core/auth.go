package core

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
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

// RedirectInfo carries the leader's reachable address, returned by a
// RedirectChecker when this replica is NOT the HA leader and the just-authed
// client should be redirected.
type RedirectInfo struct {
	LeaderAddr string // leader's externally-reachable address (host:port)
	LeaderID   string // leader's instance ID (for logging/diagnostics)
}

// RedirectChecker is an optional callback invoked by the server after AUTH_OK,
// right before the session enters READY. If it returns ok=true the server
// sends a TypeRedirect frame with leaderAddr/leaderID and closes the
// connection, steering the client to the elected leader (HA §4.17).
//
// A nil RedirectChecker means this server does not participate in HA redirect
// (single-replica deployment or strict mode where only the leader listens).
type RedirectChecker func(ctx context.Context) (RedirectInfo, bool)

// ErrRedirected is returned internally after sending a TypeRedirect frame to
// signal that the handler should stop and close the connection (not a real
// error — the client will reconnect to the leader).
var ErrRedirected = NewError(NumSession, CodeSession, "client redirected to leader")

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
//
// 输入 map 做防御性拷贝：validator 跨连接 goroutine 共享，若调用方后续修改原 map
// 会引发并发读写 panic。返回的 validator 不可变（无导出的修改方法）。
func NewStaticTokenValidator(tokens map[string]string) *StaticTokenValidator {
	internal := make(map[string]string, len(tokens))
	agents := make(map[string]string, len(tokens))
	for tok, aid := range tokens {
		internal[tok] = aid
		agents[aid] = tok
	}
	return &StaticTokenValidator{tokens: internal, agents: agents}
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

// HMACKey 返回 HMAC 密钥的拷贝。
//
// 返回拷贝（而非内部切片引用）以防止调用方意外修改密钥材料破坏会话密钥，
// 并保证 Zero() 能彻底清除所有副本（旧实现返回引用，外部副本无法被 Zero 清除）。
func (k *SessionKeys) HMACKey() []byte {
	cp := make([]byte, len(k.hmacKey))
	copy(cp, k.hmacKey)
	return cp
}

// AEADKey 返回 AEAD 密钥的拷贝。语义同 HMACKey，防御性拷贝。
func (k *SessionKeys) AEADKey() []byte {
	cp := make([]byte, len(k.aeadKey))
	copy(cp, k.aeadKey)
	return cp
}

// SetAEADKey 设置 AEAD 密钥（用于 AUTH_OK 后从服务端响应更新）。
// 防御性拷贝：key 可能来自 protobuf getter（返回底层切片引用），
// 若 proto 消息被复用/pool 化，原切片会被修改导致密钥材料被静默破坏。
func (k *SessionKeys) SetAEADKey(key []byte) {
	cp := make([]byte, len(key))
	copy(cp, key)
	k.aeadKey = cp
}

// NewSessionKeys 构造 SessionKeys（HMAC 密钥在构造时设置，AEAD 密钥可后续用 SetAEADKey 更新）。
// 供跨包调用方（如 protocol 包的 client/handler）在收到 AUTH_OK 后从服务端下发字段构造密钥对象。
// hmacKey 做防御性拷贝，避免外部 slice 被复用导致密钥材料破坏。
func NewSessionKeys(keyID string, cs corepb.CipherSuite, hmacKey []byte) *SessionKeys {
	cp := make([]byte, len(hmacKey))
	copy(cp, hmacKey)
	return &SessionKeys{
		KeyID:       keyID,
		CipherSuite: cs,
		hmacKey:     cp,
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
	// fail-fast：未知套件返回 0 长度，会生成空密钥。在此显式拒绝。
	if cs != corepb.CipherSuite_CIPHER_SUITE_INTL && cs != corepb.CipherSuite_CIPHER_SUITE_GM {
		return nil, NewError(NumEnvelope, CodeEnvelope, fmt.Sprintf("unsupported cipher suite: %v", cs))
	}
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
	_, _ = h.Write([]byte(nonce)) // hash.Hash.Write 永不返回错误 // #nosec G104 -- hash.Hash.Write 永不返回错误
	return h.Sum(nil)
}
