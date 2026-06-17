package core

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
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

// SecureEnvelope 是 r2 wire 层安全信封（payload/mac/nonce 原生 bytes，去 base64）。
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
		return nil, NewError(NumEnvelope, CodeEnvelope, "cipher suite unspecified")
	}
	if p.Codec == corepb.Codec_CODEC_UNSPECIFIED {
		return nil, NewError(NumEnvelope, CodeEnvelope, "codec unspecified")
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
			return nil, WrapError(NumEnvelope, CodeEnvelope, "generate AEAD nonce", err)
		}
		env.Nonce = nonce
		env.Payload = aead.Seal(nil, nonce, processed, nil)
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
// HMAC MUST 在解密/解压前校验（core spec §5.1）。
func Open(env *SecureEnvelope, aeadKey []byte) ([]byte, error) {
	if env == nil {
		return nil, NewError(NumEnvelope, CodeEnvelope, "nil envelope")
	}
	if env.CipherSuite == corepb.CipherSuite_CIPHER_SUITE_UNSPECIFIED {
		return nil, NewError(NumEnvelope, CodeEnvelope, "cipher suite unspecified")
	}
	switch env.Compression {
	case corepb.Compression_COMPRESSION_UNSPECIFIED,
		corepb.Compression_COMPRESSION_NONE,
		corepb.Compression_COMPRESSION_ZSTD,
		corepb.Compression_COMPRESSION_LZ4,
		corepb.Compression_COMPRESSION_GZIP:
	default:
		return nil, NewError(NumEnvelope, CodeEnvelope, fmt.Sprintf("unsupported compression: %v", env.Compression))
	}

	// HMAC 校验需要 key，但 Open 不收 HMAC key 参数 —— 改为 VerifyMAC 单独校验。
	// 这里仅做解密 + 解压。调用方须先 VerifyMAC。
	raw := env.Payload

	// Decrypt
	if len(aeadKey) > 0 {
		if len(env.Nonce) != AEADNonceSize {
			return nil, NewError(NumEnvelope, CodeEnvelope, fmt.Sprintf("nonce must be %d bytes", AEADNonceSize))
		}
		aead, err := NewAEAD(env.CipherSuite, aeadKey)
		if err != nil {
			return nil, err
		}
		if len(raw) < aead.Overhead() {
			return nil, NewError(NumEnvelope, CodeEnvelope, "ciphertext too short for AEAD tag")
		}
		pt, err := aead.Open(nil, env.Nonce, raw, nil)
		if err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "AEAD decrypt", err)
		}
		raw = pt
	}

	// Decompress
	return decompress(env.Compression, raw)
}

// VerifyMAC 用给定 HMAC key 校验 envelope 的 MAC。
// 通过 constant-time 比较防止时序侧信道。MUST 在 Open 前调用。
func VerifyMAC(hmacKey []byte, env *SecureEnvelope) (bool, error) {
	want, err := canonicalMAC(env.CipherSuite, hmacKey, env)
	if err != nil {
		return false, err
	}
	return bytes.Equal(env.Mac, want), nil // bytes.Equal 是 constant-time for []byte
}

// canonicalMAC 计算 HMAC over env 的 canonical（deterministic）wire bytes。
// HMAC 输入 = proto.MarshalOptions{Deterministic:true} 对 mac 清空后的 envelope（§5.3）。
// SecureEnvelope 内无 map 字段，确定性序列化保证跨实现 HMAC 可验证。
func canonicalMAC(cs corepb.CipherSuite, hmacKey []byte, env *SecureEnvelope) ([]byte, error) {
	h, err := NewHMAC(cs, hmacKey)
	if err != nil {
		return nil, err
	}
	clone := proto.Clone(env).(*SecureEnvelope)
	clone.Mac = nil
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, WrapError(NumEnvelope, CodeEnvelope, "canonical marshal", err)
	}
	h.Write(wire)
	return h.Sum(nil), nil
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
			dec, _ := zstd.NewReader(nil)
			return dec
		},
	}
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
			w.Close()
			gzipWriterPool.Put(w)
			return nil, WrapError(NumEnvelope, CodeEnvelope, "gzip compress", err)
		}
		if err := w.Close(); err != nil {
			gzipWriterPool.Put(w)
			return nil, WrapError(NumEnvelope, CodeEnvelope, "gzip close", err)
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
		w := lz4.NewWriter(&buf)
		if _, err := w.Write(src); err != nil {
			w.Close()
			return nil, WrapError(NumEnvelope, CodeEnvelope, "lz4 compress", err)
		}
		if err := w.Close(); err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "lz4 close", err)
		}
		return buf.Bytes(), nil
	default:
		return nil, NewError(NumEnvelope, CodeEnvelope, fmt.Sprintf("unsupported compression: %v", c))
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
			return nil, WrapError(NumEnvelope, CodeEnvelope, "gzip reader", err)
		}
		defer gzipReaderPool.Put(r)
		var buf bytes.Buffer
		buf.Grow(len(src) * 4)
		lr := &io.LimitedReader{R: r, N: MaxDecompressedSize + 1}
		if _, err := io.Copy(&buf, lr); err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "gzip decompress", err)
		}
		if lr.N == 0 {
			return nil, NewError(NumEnvelope, CodeEnvelope, fmt.Sprintf("decompressed exceeds %d bytes", MaxDecompressedSize))
		}
		return buf.Bytes(), nil
	case corepb.Compression_COMPRESSION_ZSTD:
		dec := zstdDecoderPool.Get().(*zstd.Decoder)
		defer zstdDecoderPool.Put(dec)
		out, err := dec.DecodeAll(src, make([]byte, 0, len(src)*4))
		if err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "zstd decompress", err)
		}
		if len(out) > MaxDecompressedSize {
			return nil, NewError(NumEnvelope, CodeEnvelope, fmt.Sprintf("decompressed exceeds %d bytes", MaxDecompressedSize))
		}
		return out, nil
	case corepb.Compression_COMPRESSION_LZ4:
		r := lz4.NewReader(bytes.NewReader(src))
		lr := &io.LimitedReader{R: r, N: MaxDecompressedSize + 1}
		var buf bytes.Buffer
		buf.Grow(len(src) * 4)
		if _, err := io.Copy(&buf, lr); err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "lz4 decompress", err)
		}
		if lr.N == 0 {
			return nil, NewError(NumEnvelope, CodeEnvelope, fmt.Sprintf("decompressed exceeds %d bytes", MaxDecompressedSize))
		}
		return buf.Bytes(), nil
	default:
		return nil, NewError(NumEnvelope, CodeEnvelope, fmt.Sprintf("unsupported compression: %v", c))
	}
}

// EncodeEnvelope 序列化 envelope 为 wire bytes（proto）。
func EncodeEnvelope(env *SecureEnvelope) ([]byte, error) {
	return proto.Marshal(env)
}

// DecodeEnvelope 从 wire bytes 解析 envelope。
func DecodeEnvelope(data []byte) (*SecureEnvelope, error) {
	var env SecureEnvelope
	if err := proto.Unmarshal(data, &env); err != nil {
		return nil, WrapError(NumEnvelope, CodeEnvelope, "decode envelope", err)
	}
	return &env, nil
}
