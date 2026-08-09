package core

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"sort"
	"time"

	"github.com/iuboy/pollux-go/sm3"
	"golang.org/x/crypto/hkdf"

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

// TokenResolver resolves a long-term token by agent identifier. Servers whose
// Auth implementation also satisfies this interface can suppress plaintext
// token transmission in the AUTH frame: the client omits Token and the server
// resolves it from the claimed AgentID, then verifies the challenge response.
// See CapAuthTokenless and v1.ConnectionHandler.handleAuth.
type TokenResolver interface {
	ResolveToken(agentID string) (token string, err error)
}

// StaticTokenValidator validates tokens against a static map (dev/test use).
// It additionally implements TokenResolver via a reverse agentID->token index,
// so it supports tokenless AUTH out of the box.
type StaticTokenValidator struct {
	tokens map[string]string // token  -> agentID (Validate 路径)
	agents map[string]string // agentID-> token   (ResolveToken 路径)
}

// NewStaticTokenValidator creates a validator from a token->agentID mapping.
// It also builds a reverse agentID->token index. When one agentID has multiple
// tokens, the lexicographically smallest token wins（按 token 排序确保确定性，
// 消除 map 遍历顺序随机化导致的跨进程启动不一致）。
//
// 输入 map 做防御性拷贝：validator 跨连接 goroutine 共享，若调用方后续修改原 map
// 会引发并发读写 panic。返回的 validator 不可变（无导出的修改方法）。
func NewStaticTokenValidator(tokens map[string]string) *StaticTokenValidator {
	internal := make(map[string]string, len(tokens))
	agents := make(map[string]string, len(tokens))
	// 按 token 排序遍历：保证同一 agentID 多 token 时选中的是确定性的（最小 token），
	// 而非 Go map 随机遍历序。
	sortedTokens := make([]string, 0, len(tokens))
	for tok := range tokens {
		sortedTokens = append(sortedTokens, tok)
	}
	sort.Strings(sortedTokens)
	for _, tok := range sortedTokens {
		aid := tokens[tok]
		internal[tok] = aid
		if _, exists := agents[aid]; !exists {
			agents[aid] = tok // 仅首次（最小 token）写入，后续同 agentID 的 token 不覆盖
		}
	}
	return &StaticTokenValidator{tokens: internal, agents: agents}
}

// Validate looks up the token and returns the associated agent identity.
func (v *StaticTokenValidator) Validate(token string) (*AgentIdentity, error) {
	agentID, ok := v.tokens[token]
	if !ok {
		return nil, NewError(ErrCodeInvalidToken, "invalid token")
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
	return "", NewError(ErrCodeAgentNotFound, "agent not found")
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
// 并保证 Zero() 能彻底清除所有副本（返回引用则外部副本无法被 Zero 清除）。
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

// GenerateSessionKeys 为已认证 agent 生成会话密钥（按 CipherSuite）。
func GenerateSessionKeys(cs corepb.CipherSuite) (*SessionKeys, error) {
	// fail-fast：未知套件返回 0 长度，会生成空密钥。在此显式拒绝。
	if cs != corepb.CipherSuite_CIPHER_SUITE_INTL && cs != corepb.CipherSuite_CIPHER_SUITE_GM {
		return nil, NewError(ErrCodeEnvelope, fmt.Sprintf("unsupported cipher suite: %v", cs))
	}
	hmacKey := make([]byte, HMACKeyLen(cs))
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, WrapError(ErrCodeHMAC, "generate HMAC key", err)
	}
	aeadKey := make([]byte, AEADKeyLen(cs))
	if _, err := rand.Read(aeadKey); err != nil {
		return nil, WrapError(ErrCodeEnvelope, "generate AEAD key", err)
	}
	return &SessionKeys{
		KeyID:       NewChunkID().String(),
		CipherSuite: cs,
		hmacKey:     hmacKey,
		aeadKey:     aeadKey,
	}, nil
}

// DeriveResumptionKeys 从 master 会话密钥 + 一次性 server random 派生新的 0-RTT 会话密钥。
//
// 用于 0-RTT resumption 的前向保密：票据恢复时复用 master 密钥会让捕获的票据在 master
// 生命期内可解密所有恢复会话。通过 HKDF 从 master + 每次恢复独有的 server random 派生
// 新子钥，即便票据被窃取，每次恢复产生独立子钥，限制单次泄露的影响面。
//
// info 绑定 CipherSuite + KeyID + "resumption" 用途标签，提供域分隔。
// 返回的新 SessionKeys 拥有独立 KeyID（便于审计与密钥轮换追踪）。
func DeriveResumptionKeys(master *SessionKeys, serverRandom []byte) (*SessionKeys, error) {
	if master == nil {
		return nil, NewError(ErrCodeEnvelope, "nil master keys for resumption derivation")
	}
	if len(serverRandom) == 0 {
		return nil, NewError(ErrCodeEnvelope, "empty server random for resumption derivation")
	}
	cs := master.CipherSuite
	var newHash func() hash.Hash
	if cs == corepb.CipherSuite_CIPHER_SUITE_GM {
		newHash = sm3.New
	} else {
		newHash = sha256.New
	}
	// info = "MBTA-RESUMPTION-V1\u00" ‖ cipher_suite(u8) ‖ master_key_id
	info := append([]byte("MBTA-RESUMPTION-V1\x00"), byte(cs))
	info = append(info, []byte(master.KeyID)...)
	// master 的 hmac+aead key 拼接作为 HKDF 输入密钥材料（IKM）。
	ikm := make([]byte, 0, len(master.hmacKey)+len(master.aeadKey))
	ikm = append(ikm, master.hmacKey...)
	ikm = append(ikm, master.aeadKey...)
	reader := hkdf.New(newHash, ikm, serverRandom, info)
	hmacKey := make([]byte, HMACKeyLen(cs))
	aeadKey := make([]byte, AEADKeyLen(cs))
	// io.ReadFull 从 hkdf.Reader 读取；HKDF 输出耗尽时返回错误（IKM/info 组合极端情况）。
	if _, err := io.ReadFull(reader, hmacKey); err != nil {
		return nil, WrapError(ErrCodeEnvelope, "derive resumption hmac key", err)
	}
	if _, err := io.ReadFull(reader, aeadKey); err != nil {
		return nil, WrapError(ErrCodeEnvelope, "derive resumption aead key", err)
	}
	return &SessionKeys{
		KeyID:       NewChunkID().String(),
		CipherSuite: cs,
		hmacKey:     hmacKey,
		aeadKey:     aeadKey,
	}, nil
}

// ComputeChallengeResponse 计算挑战-响应 HMAC(token, transcript)，返回 raw 字节（r2）。
// transcript = 域分隔前缀 ‖ len-prefixed(agentID ‖ sessionID ‖ nonce)，绑定本连接上下文：
// 即便 nonce 在罕见情况下跨连接重复，响应也无法被重放到不同 agent/session。
// 算法按协商 CipherSuite（intl=SHA-256, gm=SM3）。
//
// 注：此函数在 AUTH 阶段使用，session key 尚未建立，只能用 token 作 HMAC 密钥
// （token 长度任意，故不走 NewHMAC 的长度校验，直接 hmac.New）。挑战响应仅在
// TLS/TLCP 加密通道内传输，且 nonce 一次性，侧信道风险低。
func ComputeChallengeResponse(token, agentID, sessionID string, nonce []byte, cs corepb.CipherSuite) []byte {
	var h hash.Hash
	if cs == corepb.CipherSuite_CIPHER_SUITE_GM {
		h = hmac.New(sm3.New, []byte(token))
	} else {
		h = hmac.New(sha256.New, []byte(token))
	}
	// 域分隔：固定前缀，防止与 envelope MAC 等其他 HMAC 用途输出混淆。
	_, _ = h.Write(challengeResponseDomainPrefix)
	// 长度前缀的 transcript：agentID ‖ sessionID ‖ nonce。
	// 长度前缀防字段拼接歧义（例如 agentID="ab" + sessionID="c" vs "a" + "bc"）。
	writeLenPrefixed(h, []byte(agentID))
	writeLenPrefixed(h, []byte(sessionID))
	writeLenPrefixed(h, nonce)
	return h.Sum(nil)
}

// challengeResponseDomainPrefix 是 ComputeChallengeResponse 的固定域分隔前缀，
// 与 envelopeMACDomainPrefix 互不重叠，避免同密钥跨上下文的标签互换。
var challengeResponseDomainPrefix = []byte("MBTA-CHALLENGE-V1\x00")

// writeLenPrefixed 向 h 写入 4 字节 big-endian 长度前缀 + data。
func writeLenPrefixed(h hash.Hash, data []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(data)))
	_, _ = h.Write(l[:])
	_, _ = h.Write(data)
}
