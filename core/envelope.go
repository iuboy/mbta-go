package core

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"google.golang.org/protobuf/proto"
)

// EnvelopeVersion 是 SecureEnvelope wire 格式版本（core spec §5.2）。
const EnvelopeVersion = 1

// MaxDecompressedSize 限制解压后载荷上限，防压缩放大攻击（core spec §7）。
// 与 max_batch_bytes 对齐：解压后不可能超过 batch 上限，超过即为攻击或畸形。
const MaxDecompressedSize = 8 * 1024 * 1024

// AEADNonceSize 是 AEAD（AES-256-GCM / SM4-GCM）nonce 长度（core spec §8.4）。
const AEADNonceSize = 12

// SecureEnvelope 是 wire 层安全信封（payload/mac/nonce 原生 bytes）。
// 等价 corepb.SecureEnvelope。
type SecureEnvelope = corepb.SecureEnvelope

// BuildParams 控制 SecureEnvelope 构建（r2：CipherSuite 统一 HMAC+AEAD 算法）。
type BuildParams struct {
	SessionID    []byte
	KeyID        string
	Seq          uint64
	ChunkID      ChunkID
	Codec        corepb.Codec
	Compression  corepb.Compression
	CipherSuite  corepb.CipherSuite
	DeliveryMode corepb.DeliveryMode
	MsgType      corepb.EnvelopeMsgType
	HMACKey      []byte // 必填，长度按 CipherSuite（HMACKeyLen）
	AEADKey      []byte // nil = 不加密（仅调试）；非 nil 长度按 CipherSuite（AEADKeyLen）
	BatchPayload []byte // 已按 Codec 编码的 SignalBatch 字节
}

// Build 按 core spec §5.1 顺序构建 SecureEnvelope：
//
//	1.（codec 编码由调用方完成，BatchPayload 已是编码字节）
//	2. 可选压缩
//	3. 可选加密（AEAD）
//	4. 填充字段
//	5. 计算 HMAC（canonical wire bytes）
func Build(p BuildParams) (*SecureEnvelope, error) {
	if p.CipherSuite == corepb.CipherSuite_CIPHER_SUITE_UNSPECIFIED {
		return nil, NewError(ErrCodeEnvelope, "cipher suite unspecified")
	}
	if p.Codec == corepb.Codec_CODEC_UNSPECIFIED {
		return nil, NewError(ErrCodeEnvelope, "codec unspecified")
	}
	// 提前校验 HMACKey：非空是规范要求（core spec §5.1），空 key 会在 NewHMAC 深处
	// 才暴露错误，降低可诊断性，并可能引发 nil key 的 panic。
	if len(p.HMACKey) == 0 {
		return nil, NewError(ErrCodeEnvelope, "HMAC key is required")
	}

	env := &SecureEnvelope{
		EnvelopeVersion: EnvelopeVersion,
		MessageType:     p.MsgType,
		SessionId:       p.SessionID,
		KeyId:           []byte(p.KeyID),
		Seq:             p.Seq,
		ChunkId:         p.ChunkID.Bytes(),
		CreatedAtUnixMs: nowUnixMs(),
		Codec:           p.Codec,
		Compression:     p.Compression,
		CipherSuite:     p.CipherSuite,
		DeliveryMode:    p.DeliveryMode,
	}

	// Step 1: compress
	processed, err := compress(p.Compression, p.BatchPayload)
	if err != nil {
		return nil, err
	}

	// Step 2: encrypt（AEAD）。密文格式：nonce(12) || ciphertext || tag(16)。
	// nonce 存 env.Nonce，密文存 env.Payload。
	if len(p.AEADKey) > 0 {
		aead, err := NewAEAD(p.CipherSuite, p.AEADKey)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, AEADNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, WrapError(ErrCodeEnvelope, "generate AEAD nonce", err)
		}
		env.Nonce = nonce
		// AD 绑定 envelope 上下文（session/seq/chunk/msg_type/cipher）：封堵密文剪贴攻击。
		// AEAD 自身的完整性因此覆盖全部元数据，不再仅依赖外层 HMAC。
		env.Payload = aead.Seal(nil, nonce, processed, envelopeAAD(env))
	} else {
		env.Payload = processed
	}

	// Step 3: canonical HMAC over env(mac=∅)
	mac, err := canonicalMAC(p.CipherSuite, p.HMACKey, env)
	if err != nil {
		return nil, err
	}
	env.Mac = mac
	return env, nil
}

// Open 解析、校验 HMAC、解密、解压 SecureEnvelope，返回 SignalBatch 编码字节。
// HMAC MUST 在解密/解压前校验（core spec §5.1）。传入非空 hmacKey 时，Open 会在
// 解密前强制 VerifyMAC；校验失败立即返回错误，杜绝调用方遗漏 VerifyMAC 的安全绕过。
//
// 密钥组合策略（对标 Build，HMACKey 必填、AEADKey 可选）：
//   - hmacKey 非空 + aeadKey 非空：生产路径（encrypt-then-MAC）
//   - hmacKey 非空 + aeadKey 空  ：仅 HMAC 无加密（Build 的调试/明文模式）
//   - hmacKey 空   + aeadKey 非空：禁止——加密但无 MAC 完整性校验，fail-closed
//   - 两者都为空              ：禁止——调用方应显式选择明文/生产模式
func Open(env *SecureEnvelope, hmacKey, aeadKey []byte) ([]byte, error) {
	if env == nil {
		return nil, NewError(ErrCodeEnvelope, "nil envelope")
	}
	// 拒绝"有加密无 MAC"的降级攻击路径（encrypt-without-MAC）。
	// hmacKey 空 + aeadKey 非空 = 完整性校验完全绕过，不可接受。
	if len(hmacKey) == 0 && len(aeadKey) > 0 {
		return nil, NewError(ErrCodeEnvelope, "AEAD key present but HMAC key empty (encrypt-without-MAC forbidden)")
	}
	// 拒绝两个都空的模糊调用（调用方必须显式选择模式）。
	if len(hmacKey) == 0 && len(aeadKey) == 0 {
		return nil, NewError(ErrCodeEnvelope, "both HMAC and AEAD keys empty (use explicit mode: production or diagnostics)")
	}
	// 版本校验：拒绝不兼容协议版本的 envelope，避免字段被静默误解。
	if env.EnvelopeVersion != EnvelopeVersion {
		return nil, NewError(ErrCodeEnvelope, fmt.Sprintf("unsupported envelope version: %d", env.EnvelopeVersion))
	}
	if env.CipherSuite == corepb.CipherSuite_CIPHER_SUITE_UNSPECIFIED {
		return nil, NewError(ErrCodeEnvelope, "cipher suite unspecified")
	}
	switch env.Compression {
	case corepb.Compression_COMPRESSION_UNSPECIFIED,
		corepb.Compression_COMPRESSION_NONE,
		corepb.Compression_COMPRESSION_ZSTD,
		corepb.Compression_COMPRESSION_LZ4,
		corepb.Compression_COMPRESSION_GZIP:
	default:
		return nil, NewError(ErrCodeEnvelope, fmt.Sprintf("unsupported compression: %v", env.Compression))
	}

	// 强制 HMAC 校验：在解密/解压前。空 hmacKey 视为显式跳过（仅诊断场景）。
	if len(hmacKey) > 0 {
		ok, verr := VerifyMAC(hmacKey, env)
		if verr != nil {
			return nil, WrapError(ErrCodeEnvelope, "HMAC verify", verr)
		}
		if !ok {
			return nil, NewError(ErrCodeHMACMismatch, "HMAC verification failed")
		}
	}

	raw := env.Payload

	// Decrypt
	if len(aeadKey) > 0 {
		if len(env.Nonce) != AEADNonceSize {
			return nil, NewError(ErrCodeEnvelope, fmt.Sprintf("nonce must be %d bytes", AEADNonceSize))
		}
		aead, err := NewAEAD(env.CipherSuite, aeadKey)
		if err != nil {
			return nil, err
		}
		if len(raw) < aead.Overhead() {
			return nil, NewError(ErrCodeEnvelope, "ciphertext too short for AEAD tag")
		}
		// AD 必须与 Build 端一致：封堵密文剪贴到不同 session/seq/chunk 的攻击。
		pt, err := aead.Open(nil, env.Nonce, raw, envelopeAAD(env))
		if err != nil {
			return nil, WrapError(ErrCodeEnvelope, "AEAD decrypt", err)
		}
		raw = pt
	} else if len(env.Nonce) > 0 {
		// 防御：aeadKey 为空（明文模式）但 envelope 携带 Nonce → 发送方加密了但
		// 接收方未提供解密密钥。直接返回密文到解压器会产生令人困惑的格式错误。
		return nil, NewError(ErrCodeEnvelope, "envelope carries AEAD nonce but no AEAD key was provided (encrypted envelope opened in plaintext mode)")
	}

	// Decompress
	return decompress(env.Compression, raw)
}

// VerifyMAC 用给定 HMAC key 校验 envelope 的 MAC。
// 使用 hmac.Equal（constant-time）比较 MAC，防止时序侧信道。MUST 在 Open 前调用。
func VerifyMAC(hmacKey []byte, env *SecureEnvelope) (bool, error) {
	want, err := canonicalMAC(env.CipherSuite, hmacKey, env)
	if err != nil {
		return false, err
	}
	return hmac.Equal(env.Mac, want), nil
}

// canonicalMAC 计算 HMAC over env 的 canonical（deterministic）wire bytes。
// HMAC 输入 = 域分隔前缀 ‖ EnvelopeVersion ‖ proto.MarshalOptions{Deterministic:true}
// 对 mac 清空后的 envelope（§5.3）。
// 域分隔前缀固定 future-proof：新增字段或修订 wire 格式时 bump 版本字节，
// 保证跨实现/跨版本 HMAC 不可混淆（避免剪贴到不同字段集的 envelope）。
// SecureEnvelope 内无 map 字段，确定性序列化保证跨实现 HMAC 可验证。
func canonicalMAC(cs corepb.CipherSuite, hmacKey []byte, env *SecureEnvelope) ([]byte, error) {
	h, err := NewHMAC(cs, hmacKey)
	if err != nil {
		return nil, err
	}
	// 域分隔：固定 ASCII 前缀 + 版本字节，防止与其他用途的 HMAC 输出混淆，
	// 并在 wire 格式演进时强制重算（版本不匹配即 MAC 失败）。
	_, _ = h.Write(envelopeMACDomainPrefix)
	_, _ = h.Write([]byte{byte(env.EnvelopeVersion)})
	clone := proto.Clone(env).(*SecureEnvelope)
	clone.Mac = nil
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, WrapError(ErrCodeEnvelope, "canonical marshal", err)
	}
	_, _ = h.Write(wire) // hash.Hash.Write 永不返回错误
	return h.Sum(nil), nil
}

// envelopeMACDomainPrefix 是 canonicalMAC 的固定域分隔前缀。
// 与挑战响应（challengeResponseDomainPrefix）、AEAD AD 等其他 HMAC 用途互不重叠，
// 避免同一密钥在不同上下文产生可互换的标签。
var envelopeMACDomainPrefix = []byte("MBTA-ENVELOPE-MAC-V1\x00")

// envelopeAAD 构造 AEAD 的 Associated Data：长度前缀的规范字节序列，
// 绑定 session_id / seq / chunk_id / msg_type / cipher_suite。
// 长度前缀（big-endian uint32）防止字段拼接歧义；固定顺序保证 Build/Open 双端一致。
// 此 AD 与 canonicalMAC 的 HMAC 输入正交：MAC 覆盖全 envelope wire，AD 只覆盖关键元数据，
// 二者共同提供"密文不可剪贴 + 完整性"双重保证。
func envelopeAAD(env *SecureEnvelope) []byte {
	// 预估容量：5 字段 + 4 个长度前缀，session_id/chunk_id 通常 16B。
	buf := make([]byte, 0, 4+4+len(env.SessionId)+8+4+len(env.ChunkId)+4+1+4+1)
	// session_id
	buf = appendLenBE32(buf, uint32(len(env.SessionId)))
	buf = append(buf, env.SessionId...)
	// seq（固定 8 字节，无需长度前缀）
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], env.Seq)
	buf = append(buf, seqBuf[:]...)
	// chunk_id
	buf = appendLenBE32(buf, uint32(len(env.ChunkId)))
	buf = append(buf, env.ChunkId...)
	// message_type（固定 1 字节，proto enum 为 int32 但 wire 上变长；这里用固定 4 字节 BE）
	var mtBuf [4]byte
	binary.BigEndian.PutUint32(mtBuf[:], uint32(env.MessageType))
	buf = append(buf, mtBuf[:]...)
	// cipher_suite（固定 4 字节 BE）
	var csBuf [4]byte
	binary.BigEndian.PutUint32(csBuf[:], uint32(env.CipherSuite))
	buf = append(buf, csBuf[:]...)
	return buf
}

// appendLenBE32 追加 big-endian uint32 长度前缀。
func appendLenBE32(buf []byte, n uint32) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], n)
	return append(buf, l[:]...)
}

func nowUnixMs() int64 { return time.Now().UnixMilli() }

// ===== 压缩（none/gzip/zstd/lz4，Pool 复用）=====

var (
	gzipWriterPool = sync.Pool{
		New: func() any {
			w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
			return w
		},
	}
	gzipReaderPool = sync.Pool{New: func() any { return new(gzip.Reader) }}

	zstdEncoderPool = sync.Pool{
		New: func() any {
			enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
			return enc
		},
	}
	zstdDecoderPool = sync.Pool{
		New: func() any {
			// WithDecoderMaxMemory 限制单次解压内存，防 zstd 炸弹在大小检查前 OOM。
			dec, _ := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(MaxDecompressedSize))
			return dec
		},
	}

	// lz4 writer/reader pool：与 gzip/zstd 对齐，避免批量压缩场景每次新建 *lz4.Writer/Reader 的 GC 压力。
	lz4WriterPool = sync.Pool{New: func() any { return lz4.NewWriter(nil) }}
	lz4ReaderPool = sync.Pool{New: func() any { return lz4.NewReader(nil) }}
)

// compress 按算法压缩 src。
func compress(c corepb.Compression, src []byte) ([]byte, error) {
	switch c {
	case corepb.Compression_COMPRESSION_UNSPECIFIED, corepb.Compression_COMPRESSION_NONE:
		return src, nil
	case corepb.Compression_COMPRESSION_GZIP:
		var buf bytes.Buffer
		w := gzipWriterPool.Get().(*gzip.Writer)
		w.Reset(&buf)
		if _, err := w.Write(src); err != nil {
			_ = w.Close() // best-effort cleanup；writer 可能处于损坏状态，不放回 pool
			return nil, WrapError(ErrCodeEnvelope, "gzip compress", err)
		}
		if err := w.Close(); err != nil {
			// Close 失败：writer 可能已损坏，不放回 pool（与 Write 错误路径一致）。
			return nil, WrapError(ErrCodeEnvelope, "gzip close", err)
		}
		gzipWriterPool.Put(w)
		return buf.Bytes(), nil
	case corepb.Compression_COMPRESSION_ZSTD:
		enc := zstdEncoderPool.Get().(*zstd.Encoder)
		defer zstdEncoderPool.Put(enc)
		out := enc.EncodeAll(src, make([]byte, 0, len(src)))
		return out, nil
	case corepb.Compression_COMPRESSION_LZ4:
		var buf bytes.Buffer
		w := lz4WriterPool.Get().(*lz4.Writer)
		w.Reset(&buf)
		if _, err := w.Write(src); err != nil {
			_ = w.Close() // writer 可能已损坏，不放回 pool
			return nil, WrapError(ErrCodeEnvelope, "lz4 compress", err)
		}
		if err := w.Close(); err != nil {
			// Close 失败：writer 可能已损坏，不放回 pool（与 gzip 路径一致）。
			return nil, WrapError(ErrCodeEnvelope, "lz4 close", err)
		}
		lz4WriterPool.Put(w)
		return buf.Bytes(), nil
	default:
		return nil, NewError(ErrCodeEnvelope, fmt.Sprintf("unsupported compression: %v", c))
	}
}

// decompress 按算法解压 src，强制 MaxDecompressedSize 上限防放大攻击。
func decompress(c corepb.Compression, src []byte) ([]byte, error) {
	switch c {
	case corepb.Compression_COMPRESSION_UNSPECIFIED, corepb.Compression_COMPRESSION_NONE:
		return src, nil
	case corepb.Compression_COMPRESSION_GZIP:
		r := gzipReaderPool.Get().(*gzip.Reader)
		if err := r.Reset(bytes.NewReader(src)); err != nil {
			gzipReaderPool.Put(r)
			return nil, WrapError(ErrCodeEnvelope, "gzip reader", err)
		}
		defer gzipReaderPool.Put(r)
		var buf bytes.Buffer
		buf.Grow(len(src) * 4)
		lr := &io.LimitedReader{R: r, N: MaxDecompressedSize + 1}
		if _, err := io.Copy(&buf, lr); err != nil {
			return nil, WrapError(ErrCodeEnvelope, "gzip decompress", err)
		}
		if lr.N == 0 {
			return nil, NewError(ErrCodeEnvelope, fmt.Sprintf("decompressed exceeds %d bytes", MaxDecompressedSize))
		}
		return buf.Bytes(), nil
	case corepb.Compression_COMPRESSION_ZSTD:
		dec := zstdDecoderPool.Get().(*zstd.Decoder)
		defer zstdDecoderPool.Put(dec)
		// 用流式 + LimitedReader 防止 zstd 炸弹：DecodeAll 会在大小检查前分配完整解压内容。
		if err := dec.Reset(bytes.NewReader(src)); err != nil {
			return nil, WrapError(ErrCodeEnvelope, "zstd reset", err)
		}
		defer func() { _ = dec.Reset(nil) }() //nolint:errcheck // pool 归还前清理，错误无关紧要
		lr := &io.LimitedReader{R: dec.IOReadCloser(), N: MaxDecompressedSize + 1}
		var buf bytes.Buffer
		buf.Grow(len(src) * 4)
		if _, err := io.Copy(&buf, lr); err != nil {
			return nil, WrapError(ErrCodeEnvelope, "zstd decompress", err)
		}
		if lr.N == 0 {
			return nil, NewError(ErrCodeEnvelope, fmt.Sprintf("decompressed exceeds %d bytes", MaxDecompressedSize))
		}
		return buf.Bytes(), nil
	case corepb.Compression_COMPRESSION_LZ4:
		r := lz4ReaderPool.Get().(*lz4.Reader)
		r.Reset(bytes.NewReader(src))
		lr := &io.LimitedReader{R: r, N: MaxDecompressedSize + 1}
		var buf bytes.Buffer
		buf.Grow(len(src) * 4)
		if _, err := io.Copy(&buf, lr); err != nil {
			lz4ReaderPool.Put(r)
			return nil, WrapError(ErrCodeEnvelope, "lz4 decompress", err)
		}
		lz4ReaderPool.Put(r)
		if lr.N == 0 {
			return nil, NewError(ErrCodeEnvelope, fmt.Sprintf("decompressed exceeds %d bytes", MaxDecompressedSize))
		}
		return buf.Bytes(), nil
	default:
		return nil, NewError(ErrCodeEnvelope, fmt.Sprintf("unsupported compression: %v", c))
	}
}

// DecodeEnvelope 从 wire bytes 解析 envelope。
func DecodeEnvelope(data []byte) (*SecureEnvelope, error) {
	var env SecureEnvelope
	if err := proto.Unmarshal(data, &env); err != nil {
		return nil, WrapError(ErrCodeEnvelope, "decode envelope", err)
	}
	return &env, nil
}
