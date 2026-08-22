package core

// envelope.go 实现 r3 Envelope：compress-then-encrypt，确定性 nonce，AD 绑定全部
// 明文元数据（帧 type/flags、session_id、key_epoch、seq、compression、profile）。
//
//	Envelope{key_epoch, seq, compression, ciphertext=AEAD(压缩后 batch 编码)}
//	nonce = prefix(4B) ‖ seq(8B BE)
//	AD    = type(1B) ‖ flags(1B) ‖ lp(session_id) ‖ key_epoch(1B) ‖ seq(8B BE)
//	        ‖ compression(1B) ‖ lp(profile_name)

import (
	"bytes"
	"compress/gzip"
	"container/list"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"google.golang.org/protobuf/proto"
)

// MaxDecompressedSize 限制解压后载荷上限，防压缩放大攻击。
// 与 limits.max_batch_bytes 对齐：解压后超过 batch 上限即为攻击或畸形。
const MaxDecompressedSize = 8 * 1024 * 1024

// SealParams 是 Envelope 构建参数。
type SealParams struct {
	FrameType   uint8  // 帧类型（TypeBatch/TypeDgram，入 AD）
	SessionID   []byte // 会话 ID（入 AD）
	Seq         uint64 // 连接级序号（nonce 与 AD 双绑定）
	KeyEpoch    uint32 // 首版恒 0
	Compression corepb.Compression
	Keys        *SessionKeys
	Dict        *ZstdDictCodec // ZSTD_DICT 时的字典 codec（nil=fail-closed）
	BatchWire   []byte         // Batch 消息编码（未压缩）
	// DualMACKey 是 dual_integrity 能力协商启用时的外层 HMAC 密钥，通常传
	// Keys.DualMACKey。nil = 跳过，Envelope.mac 置空。
	DualMACKey []byte
}

// SealEnvelope 压缩 + 加密 batch 编码，返回 marshaled Envelope（即帧 payload）。
// DualMACKey 非 nil 时追加 mac = HMAC(profileHash, DualMACKey, AD‖ciphertext)。
func SealEnvelope(p SealParams) ([]byte, error) {
	if p.Keys == nil {
		return nil, NewError(ErrCodeInternal, "seal: nil session keys")
	}
	if p.Seq == 0 {
		return nil, NewError(ErrCodeBatchInvalid, "seal: seq must be >= 1")
	}
	// 对称拒绝（Open 侧必拒 KeyEpoch≠0）：允许 Seal 构造对端必拒的帧
	// 是本地无报错的静默故障源。
	if p.KeyEpoch != 0 {
		return nil, NewError(ErrCodeBatchInvalid, "seal: key_epoch must be 0 in first version")
	}
	if len(p.DualMACKey) > 0 && len(p.DualMACKey) != HMACKeyLen(p.Keys.Profile) {
		return nil, NewError(ErrCodeInternal, "seal: dual mac key length mismatch")
	}
	plain := p.BatchWire
	if p.Compression != corepb.Compression_COMPRESSION_NONE {
		c, err := compress(p.Compression, plain, p.Dict)
		if err != nil {
			return nil, err
		}
		plain = c
	}

	aead, err := NewAEAD(p.Keys.Profile, p.Keys.C2SKey)
	if err != nil {
		return nil, WrapError(ErrCodeInternal, "seal: new aead", err)
	}
	nonce := BuildNonce(p.Keys.NoncePrefixC, p.Seq)
	ad := envelopeAD(p.FrameType, p.SessionID, p.KeyEpoch, p.Seq, p.Compression, p.Keys.Profile)
	ct := aead.Seal(nil, nonce[:], plain, ad)

	env := &corepb.Envelope{
		KeyEpoch:    p.KeyEpoch,
		Seq:         p.Seq,
		Compression: p.Compression,
		Ciphertext:  ct,
	}
	if len(p.DualMACKey) > 0 {
		env.Mac = dualMAC(p.Keys.Profile, p.DualMACKey, ad, ct)
	}
	return proto.Marshal(env)
}

// OpenEnvelope 解密 + 解压，返回解压后的 batch 编码。
// frameType 必须与发送侧 Seal 时一致（AD 绑定），错配即 envelope_open_failed。
//
// dual_integrity 语义（keys.DualMACKey 非空 = 本地协商启用）：
//   - mac 非空但本地未启用（无 DualMACKey）→ envelope_open_failed；
//   - mac 非空且校验失败 → envelope_open_failed；
//   - 本地启用但 mac 为空（对端未按协商附加）→ envelope_open_failed（fail-closed，
//     双方由 selected_capabilities 对称驱动，缺 mac 即违约）。
func OpenEnvelope(frameType uint8, sessionID []byte, keys *SessionKeys, dict *ZstdDictCodec, env *corepb.Envelope) ([]byte, error) {
	if keys == nil {
		return nil, NewError(ErrCodeEnvelopeOpenFail, "open: nil session keys")
	}
	if env.GetKeyEpoch() != 0 {
		return nil, NewError(ErrCodeEnvelopeOpenFail, fmt.Sprintf("unsupported key_epoch %d", env.GetKeyEpoch()))
	}
	if env.GetSeq() == 0 {
		return nil, NewError(ErrCodeEnvelopeOpenFail, "envelope seq must be >= 1")
	}
	ad := envelopeAD(frameType, sessionID, env.GetKeyEpoch(), env.GetSeq(), env.GetCompression(), keys.Profile)
	if hasMAC := len(env.GetMac()) > 0; hasMAC != (len(keys.DualMACKey) > 0) {
		if hasMAC {
			return nil, NewError(ErrCodeEnvelopeOpenFail, "envelope mac present but dual_integrity not negotiated")
		}
		return nil, NewError(ErrCodeEnvelopeOpenFail, "dual_integrity negotiated but envelope mac missing")
	}
	if len(keys.DualMACKey) > 0 {
		want := dualMAC(keys.Profile, keys.DualMACKey, ad, env.GetCiphertext())
		if !hmac.Equal(want, env.GetMac()) {
			return nil, NewError(ErrCodeEnvelopeOpenFail, "dual integrity mac mismatch")
		}
	}
	aead, err := NewAEAD(keys.Profile, keys.C2SKey)
	if err != nil {
		return nil, WrapError(ErrCodeInternal, "open: new aead", err)
	}
	nonce := BuildNonce(keys.NoncePrefixC, env.GetSeq())
	plain, err := aead.Open(nil, nonce[:], env.GetCiphertext(), ad)
	if err != nil {
		return nil, WrapError(ErrCodeEnvelopeOpenFail, "aead open", err)
	}
	if env.GetCompression() == corepb.Compression_COMPRESSION_NONE {
		return plain, nil
	}
	return decompress(env.GetCompression(), plain, dict)
}

// dualMAC 计算 dual_integrity 外层 HMAC：HMAC(profileHash, key, AD‖ciphertext)。
func dualMAC(profile corepb.Profile, key, ad, ciphertext []byte) []byte {
	m := hmac.New(ProfileHash(profile), key)
	_, _ = m.Write(ad)
	_, _ = m.Write(ciphertext)
	return m.Sum(nil)
}

// envelopeAD 构造 AEAD Associated Data（字节级规范见文件头注释）。
// lp = 4B BE 长度前缀。
func envelopeAD(frameType uint8, sessionID []byte, keyEpoch uint32, seq uint64, comp corepb.Compression, profile corepb.Profile) []byte {
	profName := ProfileName(profile)
	ad := make([]byte, 0, 2+4+len(sessionID)+1+8+1+4+len(profName))
	ad = append(ad, frameType, 0) // flags 恒 0（冻结面）
	ad = appendLenPrefixed(ad, sessionID)
	ad = append(ad, byte(keyEpoch))
	var seqB [8]byte
	binary.BigEndian.PutUint64(seqB[:], seq)
	ad = append(ad, seqB[:]...)
	ad = append(ad, byte(comp))
	ad = appendLenPrefixed(ad, []byte(profName))
	return ad
}

func appendLenPrefixed(dst, b []byte) []byte {
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(b)))
	dst = append(dst, lp[:]...)
	return append(dst, b...)
}

// --- 压缩（继承 v1 全部加固：流式上限 + 预分配封顶 + zstd 内存上限）---

var (
	gzipReaderPool  = sync.Pool{New: func() any { return new(gzip.Reader) }}
	zstdEncoderPool = sync.Pool{
		New: func() any {
			// 池化为逐调用实例：单并发最优，消除每次 NewWriter 的大额内部状态分配
			// 未池化时 4KB seal 374µs / 13.5MB allocs。
			enc, _ := zstd.NewWriter(nil,
				zstd.WithEncoderConcurrency(1),
				zstd.WithEncoderLevel(zstd.SpeedDefault))
			return enc
		},
	}
	zstdDecoderPool = sync.Pool{
		New: func() any {
			dec, _ := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(MaxDecompressedSize))
			return dec
		},
	}
	lz4ReaderPool = sync.Pool{New: func() any { return lz4.NewReader(nil) }}
)

// --- zstd 字典（capability: zstd_dict，服务端 DICT 帧下发）---
//
// 进程级单例（简单优先，r3 裁决）：COMPRESSION_ZSTD_DICT 隐含"当前字典"
// （dict_id 由 DICT 帧带外声明，Envelope 不重复携带）。服务端在配置字典时
// ZstdDictCodec 是字典绑定的编解码器：池化 encoder（逐调用实例，单并发最优）
// + 共享 decoder。共享的是池（性能——dict-bound encoder 构造昂贵），
// 隔离的是选择权（正确性——连接持有指针引用，进程单例的覆盖污染不再可能）。
type ZstdDictCodec struct {
	ID      uint32
	raw     []byte
	encPool sync.Pool
	dec     *zstd.Decoder
}

// zstdDictRegistry 键控注册表：key = dict_id:sha256(raw) 前 16 字节 hex。
// 上界 zstdDictRegistryCap（LRU 淘汰）防恶意服务端字典洪水。
var (
	zstdDictMu  sync.Mutex
	zstdDictReg = map[string]*ZstdDictCodec{}
	zstdDictOrd list.List
)

const zstdDictRegistryCap = 8

// RegisterZstdDict 注册/获取字典 codec（幂等：同 (id, 内容) 返回同一实例）。
// 超出注册表上界时淘汰最久未使用条目。
func RegisterZstdDict(id uint32, dict []byte) (*ZstdDictCodec, error) {
	if id == 0 {
		return nil, NewError(ErrCodeConfig, "zstd dict id must be non-zero")
	}
	if len(dict) == 0 {
		return nil, NewError(ErrCodeConfig, "zstd dict must not be empty")
	}
	sum := sha256.Sum256(dict)
	key := fmt.Sprintf("%d:%x", id, sum[:16])
	zstdDictMu.Lock()
	defer zstdDictMu.Unlock()
	if c, ok := zstdDictReg[key]; ok {
		touchZstdDictLocked(key, c)
		return c, nil
	}
	raw := append([]byte(nil), dict...)
	c := &ZstdDictCodec{ID: id, raw: raw}
	c.encPool.New = func() any {
		enc, err := zstd.NewWriter(nil,
			zstd.WithEncoderConcurrency(1),
			zstd.WithEncoderLevel(zstd.SpeedDefault),
			zstd.WithEncoderDictRaw(id, raw))
		if err != nil {
			return err // New 返回 error 时 Pool.Get panic——构造失败在此即不可达
		}
		return enc
	}
	dec, err := zstd.NewReader(nil,
		zstd.WithDecoderMaxMemory(MaxDecompressedSize),
		zstd.WithDecoderDictRaw(id, raw))
	if err != nil {
		return nil, WrapError(ErrCodeInternal, "zstd dict decoder", err)
	}
	c.dec = dec
	zstdDictReg[key] = c
	touchZstdDictLocked(key, c)
	for zstdDictOrd.Len() > zstdDictRegistryCap {
		front := zstdDictOrd.Front()
		delete(zstdDictReg, front.Value.(string))
		zstdDictOrd.Remove(front)
	}
	return c, nil
}

func touchZstdDictLocked(key string, c *ZstdDictCodec) {
	for e := zstdDictOrd.Back(); e != nil; e = e.Prev() {
		if e.Value.(string) == key {
			zstdDictOrd.MoveToBack(e)
			return
		}
	}
	zstdDictOrd.PushBack(key)
	_ = c
}

// ResetZstdDicts 清空注册表。测试隔离专用（生产静态字典部署不轮换）；
// 公共面保留是因为 conformance 为外部包无法用 export_test——doc 声明禁用于生产。
func ResetZstdDicts() {
	zstdDictMu.Lock()
	defer zstdDictMu.Unlock()
	zstdDictReg = map[string]*ZstdDictCodec{}
	zstdDictOrd.Init()
}

// compressZstdDict 用给定字典 codec 压缩；codec 缺失时报错（fail-closed：
// 字典缺失只会让发送失败，不会静默降级到错误编码）。
func compressZstdDict(src []byte, dict *ZstdDictCodec) ([]byte, error) {
	if dict == nil {
		return nil, NewError(ErrCodeBatchInvalid, "zstd dict compression requested but no dict provided")
	}
	v := dict.encPool.Get()
	enc, ok := v.(*zstd.Encoder)
	if !ok {
		return nil, NewError(ErrCodeInternal, "zstd dict encoder pool corrupted")
	}
	defer dict.encPool.Put(enc)
	return enc.EncodeAll(src, nil), nil
}

// decompressZstdDict 用给定字典 codec 解压（DecodeAll 受 WithDecoderMaxMemory
// 上限约束——解压炸弹防护与流式路径同值）。codec 缺失时 fail-closed 报错。
func decompressZstdDict(src []byte, dict *ZstdDictCodec) ([]byte, error) {
	if dict == nil {
		return nil, NewError(ErrCodeEnvelopeOpenFail, "zstd dict compression present but no dict provided")
	}
	out, err := dict.dec.DecodeAll(src, nil)
	if err != nil {
		return nil, WrapError(ErrCodeEnvelopeOpenFail, "zstd dict decode", err)
	}
	if len(out) > MaxDecompressedSize {
		return nil, NewError(ErrCodeDecompressLimit, fmt.Sprintf("decompressed exceeds %d bytes", MaxDecompressedSize))
	}
	return out, nil
}

func compress(c corepb.Compression, src []byte, dict *ZstdDictCodec) ([]byte, error) {
	switch c {
	case corepb.Compression_COMPRESSION_GZIP:
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(src); err != nil {
			return nil, WrapError(ErrCodeInternal, "gzip compress", err)
		}
		if err := w.Close(); err != nil {
			return nil, WrapError(ErrCodeInternal, "gzip close", err)
		}
		return buf.Bytes(), nil
	case corepb.Compression_COMPRESSION_ZSTD:
		enc := zstdEncoderPool.Get().(*zstd.Encoder)
		defer zstdEncoderPool.Put(enc)
		return enc.EncodeAll(src, nil), nil
	case corepb.Compression_COMPRESSION_ZSTD_DICT:
		return compressZstdDict(src, dict)
	case corepb.Compression_COMPRESSION_LZ4:
		var buf bytes.Buffer
		w := lz4.NewWriter(&buf)
		if _, err := w.Write(src); err != nil {
			return nil, WrapError(ErrCodeInternal, "lz4 compress", err)
		}
		if err := w.Close(); err != nil {
			return nil, WrapError(ErrCodeInternal, "lz4 close", err)
		}
		return buf.Bytes(), nil
	default:
		return nil, NewError(ErrCodeBatchInvalid, fmt.Sprintf("unsupported compression %v", c))
	}
}

// decompress 按算法解压 src，强制 MaxDecompressedSize 上限防放大攻击。
func decompress(c corepb.Compression, src []byte, dict *ZstdDictCodec) ([]byte, error) {
	switch c {
	case corepb.Compression_COMPRESSION_GZIP:
		r := gzipReaderPool.Get().(*gzip.Reader)
		if err := r.Reset(bytes.NewReader(src)); err != nil {
			gzipReaderPool.Put(r)
			return nil, WrapError(ErrCodeEnvelopeOpenFail, "gzip reader", err)
		}
		defer gzipReaderPool.Put(r)
		return copyLimited(r)
	case corepb.Compression_COMPRESSION_ZSTD:
		dec := zstdDecoderPool.Get().(*zstd.Decoder)
		defer zstdDecoderPool.Put(dec)
		if err := dec.Reset(bytes.NewReader(src)); err != nil {
			return nil, WrapError(ErrCodeEnvelopeOpenFail, "zstd reset", err)
		}
		defer func() { _ = dec.Reset(nil) }()
		return copyLimited(dec.IOReadCloser())
	case corepb.Compression_COMPRESSION_ZSTD_DICT:
		return decompressZstdDict(src, dict)
	case corepb.Compression_COMPRESSION_LZ4:
		r := lz4ReaderPool.Get().(*lz4.Reader)
		r.Reset(bytes.NewReader(src))
		defer lz4ReaderPool.Put(r)
		return copyLimited(r)
	default:
		return nil, NewError(ErrCodeBatchInvalid, fmt.Sprintf("unsupported compression %v", c))
	}
}

// copyLimited 流式解压到 MaxDecompressedSize+1（超限即报错，先于任何放大分配）。
func copyLimited(r io.Reader) ([]byte, error) {
	lr := &io.LimitedReader{R: r, N: MaxDecompressedSize + 1}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, lr); err != nil {
		return nil, WrapError(ErrCodeEnvelopeOpenFail, "decompress", err)
	}
	if lr.N == 0 {
		return nil, NewError(ErrCodeDecompressLimit, fmt.Sprintf("decompressed exceeds %d bytes", MaxDecompressedSize))
	}
	return buf.Bytes(), nil
}
