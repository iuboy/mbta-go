package core

// keyschedule.go 实现 r3 密钥日程（docs/v2-design.md §4.2 + §18 H2/H3 裁决）：
//
//	zz        = ECDH(client_eph, server_eph)         // intl: X25519 32B；gm: SM2 x 坐标 32B 大端
//	th_hello  = H(lp(profile) ‖ lp(canonical(HELLO, proof 置零)))
//	psk_ck    = HKDF-Extract(HKDF-Expand(ck,"mbta/psk",32), HMAC(profileHash, token, th_hello))
//	  其中 ck = HKDF-Extract(th_hello, zz)
//	keyblock  = HKDF-Expand(psk_ck, "mbta/split", L)  // intl L=104 / gm L=72
//	nonce     = prefix(4B) ‖ seq(8B BE)                // 全宽 seq，无截断重用
//
// 已实证依赖：crypto/ecdh（X25519）、github.com/emmansun/gmsm/ecdh（SM2 原始 ECDH，
// P256() 即 sm2p256v1，ECDH() 输出 32B x 坐标）、golang.org/x/crypto/hkdf + pollux/sm3。

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	gmsecdh "github.com/emmansun/gmsm/ecdh"
	"github.com/iuboy/pollux-go/sm3"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// ProfileName 返回 profile 的注册名（transcript 与 AD 用字符串）。
func ProfileName(p corepb.Profile) string {
	switch p {
	case corepb.Profile_PROFILE_INTL:
		return "intl"
	case corepb.Profile_PROFILE_GM:
		return "gm"
	default:
		return ""
	}
}

// ProfileHash 返回 profile 的哈希构造器（intl=SHA-256 / gm=SM3）。
func ProfileHash(p corepb.Profile) func() hash.Hash {
	if p == corepb.Profile_PROFILE_GM {
		return sm3.New
	}
	return sha256.New
}

// EphemeralKey 是连接级临时密钥对（具体曲线由 profile 决定，调用方不感知库差异）。
type EphemeralKey struct {
	profile corepb.Profile
	x25519  *ecdh.PrivateKey
	sm2     *gmsecdh.PrivateKey
}

// GenerateEphemeral 生成 profile 对应的临时密钥对。
func GenerateEphemeral(p corepb.Profile) (*EphemeralKey, []byte, error) {
	switch p {
	case corepb.Profile_PROFILE_INTL:
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, WrapError(ErrCodeInternal, "generate x25519", err)
		}
		return &EphemeralKey{profile: p, x25519: priv}, priv.PublicKey().Bytes(), nil
	case corepb.Profile_PROFILE_GM:
		priv, err := gmsecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, WrapError(ErrCodeInternal, "generate sm2 eph", err)
		}
		return &EphemeralKey{profile: p, sm2: priv}, priv.PublicKey().Bytes(), nil
	default:
		return nil, nil, NewError(ErrCodeUnsupportedProfile, "unknown profile")
	}
}

// PubBytes 返回本方临时公钥的 wire 字节。
func (k *EphemeralKey) PubBytes() ([]byte, error) {
	switch k.profile {
	case corepb.Profile_PROFILE_INTL:
		return k.x25519.PublicKey().Bytes(), nil
	case corepb.Profile_PROFILE_GM:
		return k.sm2.PublicKey().Bytes(), nil
	default:
		return nil, NewError(ErrCodeUnsupportedProfile, "unknown profile")
	}
}

// DeriveZZ 计算原始共享秘密（32B）。peerWire 严格校验长度/格式：
// intl 32B；gm 65B 非压缩点（0x04‖X‖Y，拒绝压缩点）。
func DeriveZZ(p corepb.Profile, priv *EphemeralKey, peerWire []byte) ([]byte, error) {
	switch p {
	case corepb.Profile_PROFILE_INTL:
		if len(peerWire) != 32 {
			return nil, NewError(ErrCodeHelloEphInvalid, fmt.Sprintf("x25519 pubkey must be 32 bytes, got %d", len(peerWire)))
		}
		pub, err := ecdh.X25519().NewPublicKey(peerWire)
		if err != nil {
			return nil, WrapError(ErrCodeHelloEphInvalid, "parse x25519 pubkey", err)
		}
		zz, err := priv.x25519.ECDH(pub)
		if err != nil {
			return nil, WrapError(ErrCodeHelloEphInvalid, "x25519 ecdh", err)
		}
		return zz, nil
	case corepb.Profile_PROFILE_GM:
		if len(peerWire) != 65 || peerWire[0] != 0x04 {
			return nil, NewError(ErrCodeHelloEphInvalid, fmt.Sprintf("sm2 pubkey must be 65B uncompressed, got %d bytes", len(peerWire)))
		}
		pub, err := gmsecdh.P256().NewPublicKey(peerWire)
		if err != nil {
			return nil, WrapError(ErrCodeHelloEphInvalid, "parse sm2 pubkey", err)
		}
		zz, err := priv.sm2.ECDH(pub)
		if err != nil {
			return nil, WrapError(ErrCodeHelloEphInvalid, "sm2 ecdh", err)
		}
		return zz, nil
	default:
		return nil, NewError(ErrCodeUnsupportedProfile, "unknown profile")
	}
}

// canonicalMarshal 返回消息的规范字节序列（proto deterministic marshal，
// map 字段自动按键排序）。zero 回调在 marshal 前执行（proof/finished 置零）。
func canonicalMarshal[M proto.Message](m M, zero func(M)) ([]byte, error) {
	clone := proto.Clone(m).(M)
	if zero != nil {
		zero(clone)
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, WrapError(ErrCodeInternal, "canonical marshal", err)
	}
	return b, nil
}

// CanonicalHello 返回 proof 置零后的 HELLO 规范编码。
func CanonicalHello(h *corepb.Hello) ([]byte, error) {
	return canonicalMarshal(h, func(m *corepb.Hello) { m.TokenProof = nil })
}

// CanonicalHelloAck 返回 finished 置零后的 HELLO_ACK 规范编码。
func CanonicalHelloAck(a *corepb.HelloAck) ([]byte, error) {
	return canonicalMarshal(a, func(m *corepb.HelloAck) { m.Finished = nil })
}

// transcriptHash 按规范拼接各段（每段 4B BE 长度前缀）后哈希。
func transcriptHash(p corepb.Profile, chunks ...[]byte) []byte {
	h := ProfileHash(p)()
	var lp [4]byte
	for _, c := range chunks {
		binary.BigEndian.PutUint32(lp[:], uint32(len(c)))
		if _, werr := h.Write(lp[:]); werr != nil {
			return nil
		}
		_, _ = h.Write(c)
	}
	return h.Sum(nil)
}

// TranscriptHello 计算 th_hello = H(lp(profile) ‖ lp(canonical(HELLO, proof 置零)))。
func TranscriptHello(p corepb.Profile, hello *corepb.Hello) ([]byte, error) {
	cb, err := CanonicalHello(hello)
	if err != nil {
		return nil, err
	}
	return transcriptHash(p, []byte(ProfileName(p)), cb), nil
}

// TranscriptFull 计算 th_full = H(lp(profile) ‖ lp(canonical HELLO) ‖ lp(canonical ACK))。
// HELLO_ACK 全字段入链：TLS 终止点对 limits/credits/ack_mode/epoch 的任何篡改
// 都会使 finished 校验失败。
func TranscriptFull(p corepb.Profile, hello *corepb.Hello, ack *corepb.HelloAck) ([]byte, error) {
	hb, err := CanonicalHello(hello)
	if err != nil {
		return nil, err
	}
	ab, err := CanonicalHelloAck(ack)
	if err != nil {
		return nil, err
	}
	return transcriptHash(p, []byte(ProfileName(p)), hb, ab), nil
}

// TokenProof 计算 HMAC(profileHash, key=token, msg=th_hello)。
// 该值既是 Hello.token_proof 字段，也是 psk_ck 的 ikm 输入（同值，无额外前缀）。
func TokenProof(p corepb.Profile, token string, thHello []byte) []byte {
	m := hmac.New(ProfileHash(p), []byte(token))
	_, _ = m.Write(thHello) // hash.Hash.Write 不返回错误
	return m.Sum(nil)
}

// SessionKeys 是派生出的会话密钥组（密钥永不上 wire）。
type SessionKeys struct {
	Profile      corepb.Profile
	C2SKey       []byte // 数据加密（c→s envelope AEAD）
	S2CKey       []byte // 预留（首版无 s→c 数据加密帧）
	HandshakeKey []byte // finished MAC 专用（密钥用途分隔）
	NoncePrefixC [4]byte
	NoncePrefixS [4]byte
	// DualMACKey 是 dual_integrity 能力协商启用时追加派生的外层 HMAC 密钥，
	// 即 HMAC(profileHash, DualMACKey, AD‖ciphertext)，见 envelope.go。
	// nil = 未启用（该能力默认关闭，SelectedCapabilities 不含即不派生）。
	// 由协商驱动：握手双方都在 selected_capabilities 含 dual_integrity 时
	// 调 DeriveDualMACKey 填充——仅单侧派生会使 Envelope mac 字段判定不对称。
	DualMACKey []byte
}

// Wipe 就地清零全部密钥材料（best-effort 纵深防御）。
//
// 调用方必须保证调用时刻无任何并发使用者（读/写循环均已退出）：本方法直接写
// 密钥字节，与并发 Seal/Open 构成数据竞争。Go 移动式 GC 下不保证堆中不存在
// 密钥副本（slice 传参/扩容不可避免），因此这是降低堆转储/内存取证暴露面的
// 缓解措施，不是可靠销毁。客户端侧因 send 路径无完成同步（用户 goroutine 持有
// keys 引用做 Seal），当前不擦除——服务端用法见 handler.go Handle 尾部注释。
func (k *SessionKeys) Wipe() {
	if k == nil {
		return
	}
	for _, b := range [][]byte{k.C2SKey, k.S2CKey, k.HandshakeKey, k.DualMACKey} {
		for i := range b {
			b[i] = 0
		}
	}
	k.NoncePrefixC = [4]byte{}
	k.NoncePrefixS = [4]byte{}
}

// pskCK 计算密钥日程的中间链（ck → pskMix → pskCK）——DeriveSessionKeys 与
// pskCK 计算密钥日程的中间链（ck → pskMix → pskCK）——DeriveSessionKeys 与
// DeriveDualMACKey 共用（协商 dual_integrity 时不重算）。
func pskCK(p corepb.Profile, zz, thHello, tokenProof []byte) ([]byte, error) {
	h := ProfileHash(p)
	ck := hkdf.Extract(h, zz, thHello)
	pskMix := make([]byte, 32)
	if err := io_readFull(hkdf.Expand(h, ck, []byte("mbta/psk")), pskMix); err != nil {
		return nil, WrapError(ErrCodeInternal, "hkdf psk expand", err)
	}
	return hkdf.Extract(h, tokenProof, pskMix), nil
}

// DeriveSessionKeys 执行完整密钥日程（两侧调用相同函数）。
func DeriveSessionKeys(p corepb.Profile, zz, thHello, tokenProof []byte) (*SessionKeys, error) {
	h := ProfileHash(p)
	pck, err := pskCK(p, zz, thHello, tokenProof)
	if err != nil {
		return nil, err
	}
	keyLen := AEADKeyLen(p)
	splitLen := keyLen*2 + HMACKeyLen(p) + 8
	okm := make([]byte, splitLen)
	if err := io_readFull(hkdf.Expand(h, pck, []byte("mbta/split")), okm); err != nil {
		return nil, WrapError(ErrCodeInternal, "hkdf split expand", err)
	}
	keys := &SessionKeys{Profile: p}
	keys.C2SKey = append([]byte(nil), okm[:keyLen]...)
	keys.S2CKey = append([]byte(nil), okm[keyLen:keyLen*2]...)
	hsEnd := keyLen*2 + HMACKeyLen(p)
	keys.HandshakeKey = append([]byte(nil), okm[keyLen*2:hsEnd]...)
	copy(keys.NoncePrefixC[:], okm[hsEnd:hsEnd+4])
	copy(keys.NoncePrefixS[:], okm[hsEnd+4:hsEnd+8])
	return keys, nil
}

// DeriveDualMACKey 派生 dual_integrity 的外层 HMAC 密钥（独立 Expand 段，
// 不改 split 布局）。
func DeriveDualMACKey(p corepb.Profile, zz, thHello, tokenProof []byte) ([]byte, error) {
	h := ProfileHash(p)
	pck, err := pskCK(p, zz, thHello, tokenProof)
	if err != nil {
		return nil, err
	}
	dk := make([]byte, HMACKeyLen(p))
	if err := io_readFull(hkdf.Expand(h, pck, []byte("mbta/dual")), dk); err != nil {
		return nil, WrapError(ErrCodeInternal, "hkdf dual expand", err)
	}
	return dk, nil
}

// DeriveSessionKeysWithCaps 是密钥日程的完整单点（双端共用）：
// 基础 DeriveSessionKeys + selected 含 dual_integrity 时追加 DualMACKey。
// 消除 client/handler 两侧逐行复制的漂移面（一侧能力名/info 串笔误 →
// mac 判定不对称、全部 envelope 打开失败）。
func DeriveSessionKeysWithCaps(p corepb.Profile, zz, thHello, tokenProof []byte, selectedCaps []string) (*SessionKeys, error) {
	keys, err := DeriveSessionKeys(p, zz, thHello, tokenProof)
	if err != nil {
		return nil, err
	}
	if CapIn(selectedCaps, CapDualIntegrity) {
		dk, derr := DeriveDualMACKey(p, zz, thHello, tokenProof)
		if derr != nil {
			return nil, derr
		}
		keys.DualMACKey = dk
	}
	return keys, nil
}

// CapIn 报告能力列表是否含 cap。
func CapIn(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

// FinishedMAC 计算 finished = HMAC(handshake_key, th_full)。
func FinishedMAC(keys *SessionKeys, thFull []byte) []byte {
	m := hmac.New(ProfileHash(keys.Profile), keys.HandshakeKey)
	_, _ = m.Write(thFull) // hash.Hash.Write 不返回错误
	return m.Sum(nil)
}

// BuildNonce 构造确定性 nonce = prefix(4B) ‖ seq(8B BE)。全宽 seq：截断重用
// （seq=k 与 k+2^64 同 nonce）在构造上不可表达。
func BuildNonce(prefix [4]byte, seq uint64) [12]byte {
	var n [12]byte
	copy(n[:4], prefix[:])
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

// io_readFull 是 io/io.ReadFull 的本地别名（避免 frame.go 与本文件互引）。
func io_readFull(r interface{ Read([]byte) (int, error) }, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return err
		}
	}
	return nil
}
