package core

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/iuboy/pollux-go/sm3"
	"github.com/iuboy/pollux-go/sm4"
)

// gzipWriterPool / gzipReaderPool 复用 gzip 内部 flate 压缩表（~32KB huffman 表），
// 避免每帧 Build/Open 重建。Writer Reset 到目标 buffer，Reader Reset 到数据源。
var (
	gzipWriterPool = sync.Pool{
		New: func() any {
			// DefaultCompression 永不返回错误；io.Discard 仅作 Reset 占位。
			w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
			return w
		},
	}
	gzipReaderPool = sync.Pool{
		New: func() any { return new(gzip.Reader) },
	}
)

// EnvelopeVersion is the current wire-format version for secure envelopes.
const EnvelopeVersion = 1

// SecureEnvelope is the wire-level wrapper for BATCH payloads.
type SecureEnvelope struct {
	EnvelopeVersion int    `json:"envelope_version"`
	MessageType     string `json:"message_type"`
	SessionID       string `json:"session_id"`
	KeyID           string `json:"key_id,omitempty"`
	Seq             uint64 `json:"seq"`
	ChunkID         string `json:"chunk_id"`
	CreatedAtUnixMs int64  `json:"created_at_unix_ms"`
	Codec           string `json:"codec"`
	Compression     string `json:"compression"`
	Encryption      string `json:"encryption"`
	HMACAlgo        string `json:"hmac_algo"`
	Nonce           string `json:"nonce,omitempty"`
	Payload         string `json:"payload"`
	MAC             string `json:"mac,omitempty"`
}

// Params controls how a SecureEnvelope is built.
type Params struct {
	SessionID   string
	KeyID       string
	Seq         uint64
	ChunkID     string
	Codec       string // json
	Compression string // none, gzip
	Encryption  string // none, sm4_gcm
	HMACAlgo    string // none, sha256, sm3
	HMACKey     []byte // 32 bytes when hmac enabled
	SM4Key      []byte // 16 bytes when encryption=sm4_gcm
}

// Build creates a SecureEnvelope from a batch payload.
func Build(params Params, batchPayload []byte) (*SecureEnvelope, error) {
	// Normalize empty algorithm selectors to "none" so envelopes always carry a
	// concrete, allow-listed value (Open rejects anything else).
	compression := params.Compression
	if compression == "" {
		compression = CompressionNone
	}
	encryption := params.Encryption
	if encryption == "" {
		encryption = EncryptionNone
	}

	env := &SecureEnvelope{
		EnvelopeVersion: EnvelopeVersion,
		MessageType:     "batch",
		SessionID:       params.SessionID,
		KeyID:           params.KeyID,
		Seq:             params.Seq,
		ChunkID:         params.ChunkID,
		CreatedAtUnixMs: nowUnixMs(),
		Codec:           params.Codec,
		Compression:     compression,
		Encryption:      encryption,
		HMACAlgo:        params.HMACAlgo,
	}

	// Step 0: 当 HMAC 启用时，生成随机 nonce 增强防重放保护。
	if params.HMACAlgo == HMACAlgoSHA256 || params.HMACAlgo == HMACAlgoSM3 {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "generate nonce", err)
		}
		env.Nonce = base64.StdEncoding.EncodeToString(nonceBytes)
	}

	// Step 1: Compress
	processed := batchPayload
	if compression == CompressionGzip {
		var buf bytes.Buffer
		w := gzipWriterPool.Get().(*gzip.Writer)
		w.Reset(&buf)
		if _, err := w.Write(batchPayload); err != nil {
			w.Close()
			gzipWriterPool.Put(w)
			return nil, WrapError(NumEnvelope, CodeEnvelope, "gzip compress", err)
		}
		if err := w.Close(); err != nil {
			gzipWriterPool.Put(w)
			return nil, WrapError(NumEnvelope, CodeEnvelope, "gzip close", err)
		}
		// Close 后 writer 状态归零，可安全归还 pool。
		gzipWriterPool.Put(w)
		processed = buf.Bytes()
	}

	// Step 2: Encrypt (SM4-GCM)。密文格式：nonce(12) + ciphertext + GCM tag(16)。
	if encryption == EncryptionSM4 {
		if len(params.SM4Key) != 16 {
			return nil, NewError(NumEnvelope, CodeEnvelope,
				fmt.Sprintf("SM4 key must be 16 bytes, got %d", len(params.SM4Key)))
		}
		gcm, err := sm4.NewGCM(params.SM4Key)
		if err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "SM4-GCM init", err)
		}
		nonce := make([]byte, gcm.NonceSize()) // 12
		if _, err := rand.Read(nonce); err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "generate SM4 nonce", err)
		}
		sealed := gcm.Seal(nil, nonce, processed, nil)
		// 密文格式：nonce(12) + ciphertext + tag。prepend nonce 到 sealed。
		out := make([]byte, len(nonce)+len(sealed))
		copy(out, nonce)
		copy(out[len(nonce):], sealed)
		processed = out
	}

	// Step 3: Base64 payload
	env.Payload = base64.StdEncoding.EncodeToString(processed)

	// Step 4: HMAC
	switch params.HMACAlgo {
	case HMACAlgoSHA256:
		signingBytes := CanonicalSigningString(env)
		mac := computeHMACSHA256(params.HMACKey, signingBytes)
		env.MAC = base64.StdEncoding.EncodeToString(mac)
	case HMACAlgoSM3:
		signingBytes := CanonicalSigningString(env)
		mac := computeHMACSM3(params.HMACKey, signingBytes)
		env.MAC = base64.StdEncoding.EncodeToString(mac)
	}

	return env, nil
}

func nowUnixMs() int64 {
	return time.Now().UnixMilli()
}

// CanonicalSigningString builds the deterministic HMAC input.
// 直接 append 预分配 []byte，避免 fmt.Fprintf 的反射装箱与 bytes.Buffer 堆分配。
// 字段拼接顺序必须与历史版本逐字节一致，否则破坏 MAC 兼容性。
func CanonicalSigningString(env *SecureEnvelope) []byte {
	// 预估容量：各字符串字段长度 + 固定前缀与数字字段余量。
	const fixedOverhead = 256
	estCap := fixedOverhead + len(env.MessageType) + len(env.SessionID) + len(env.KeyID) +
		len(env.ChunkID) + len(env.Codec) + len(env.Compression) + len(env.Encryption) +
		len(env.HMACAlgo) + len(env.Nonce) + len(env.Payload)
	buf := make([]byte, 0, estCap)

	buf = append(buf, "envelope_version="...)
	buf = strconv.AppendUint(buf, uint64(env.EnvelopeVersion), 10) //nolint:gosec // G115: EnvelopeVersion 是小常量，无溢出
	buf = append(buf, '\n')

	buf = append(buf, "message_type="...)
	buf = append(buf, env.MessageType...)
	buf = append(buf, '\n')

	buf = append(buf, "session_id="...)
	buf = append(buf, env.SessionID...)
	buf = append(buf, '\n')

	buf = append(buf, "key_id="...)
	buf = append(buf, env.KeyID...)
	buf = append(buf, '\n')

	buf = append(buf, "seq="...)
	buf = strconv.AppendUint(buf, env.Seq, 10)
	buf = append(buf, '\n')

	buf = append(buf, "chunk_id="...)
	buf = append(buf, env.ChunkID...)
	buf = append(buf, '\n')

	buf = append(buf, "created_at_unix_ms="...)
	buf = strconv.AppendInt(buf, env.CreatedAtUnixMs, 10)
	buf = append(buf, '\n')

	buf = append(buf, "codec="...)
	buf = append(buf, env.Codec...)
	buf = append(buf, '\n')

	buf = append(buf, "compression="...)
	buf = append(buf, env.Compression...)
	buf = append(buf, '\n')

	buf = append(buf, "encryption="...)
	buf = append(buf, env.Encryption...)
	buf = append(buf, '\n')

	buf = append(buf, "hmac_algo="...)
	buf = append(buf, env.HMACAlgo...)
	buf = append(buf, '\n')

	buf = append(buf, "nonce="...)
	buf = append(buf, env.Nonce...)
	buf = append(buf, '\n')

	buf = append(buf, "payload="...)
	buf = append(buf, env.Payload...) // no trailing newline
	return buf
}

func computeHMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func computeHMACSM3(key, data []byte) []byte {
	h := hmac.New(sm3.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMACSHA256 checks the MAC against the envelope using HMAC-SHA256.
func VerifyHMACSHA256(key []byte, env *SecureEnvelope) bool {
	signingBytes := CanonicalSigningString(env)
	expected := computeHMACSHA256(key, signingBytes)

	got, err := base64.StdEncoding.DecodeString(env.MAC)
	if err != nil {
		return false
	}
	return hmac.Equal(got, expected)
}

// VerifyHMACSM3 checks the MAC against the envelope using HMAC-SM3.
func VerifyHMACSM3(key []byte, env *SecureEnvelope) bool {
	signingBytes := CanonicalSigningString(env)
	expected := computeHMACSM3(key, signingBytes)

	got, err := base64.StdEncoding.DecodeString(env.MAC)
	if err != nil {
		return false
	}
	return hmac.Equal(got, expected)
}

// VerifyHMAC checks the MAC using the algorithm specified in the envelope.
// Returns false if the algorithm is unknown or verification fails.
func VerifyHMAC(key []byte, env *SecureEnvelope) bool {
	switch env.HMACAlgo {
	case HMACAlgoSHA256:
		return VerifyHMACSHA256(key, env)
	case HMACAlgoSM3:
		return VerifyHMACSM3(key, env)
	default:
		return false
	}
}

// MaxDecompressedSize limits a decompressed envelope payload to 8 MiB.
//
// This is aligned with the protocol's maxBatchBytes cap: a decompressed batch
// can never legitimately exceed the batch-size limit, so anything larger is an
// attack (zip-bomb) or a malformed payload. The check runs in Open() — which
// handler.go calls *before* its own maxBatchBytes check — so this is the bound
// that actually limits peak allocation during decompression. Setting it to the
// same value as maxBatchBytes removes the previous 100 MiB window in which a
// high-ratio gzip payload could force the server to allocate far beyond the
// batch limit before being rejected.
const MaxDecompressedSize = 8 * 1024 * 1024

// Open decodes, decrypts (SM4-GCM), and decompresses an envelope's payload.
// sm4Key 在 encryption=sm4_gcm 时必须为 16 字节；encryption=none 时忽略（可 nil）。
func Open(env *SecureEnvelope, sm4Key []byte) ([]byte, error) {
	// Algorithm allow-list (defense in depth): v1 only supports none/gzip
	// compression and none/sm4_gcm encryption. Other values are rejected rather
	// than silently treated as raw bytes. The caller additionally enforces that
	// these equal the negotiated selection.
	switch env.Compression {
	case CompressionNone, CompressionGzip:
	default:
		return nil, NewError(NumEnvelope, CodeEnvelope,
			fmt.Sprintf("unsupported compression: %q", env.Compression))
	}
	switch env.Encryption {
	case EncryptionNone, EncryptionSM4:
	default:
		return nil, NewError(NumEnvelope, CodeEnvelope,
			fmt.Sprintf("unsupported encryption: %q", env.Encryption))
	}

	// Base64 decode
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, WrapError(NumEnvelope, CodeEnvelope, "base64 decode payload", err)
	}

	// Decrypt (SM4-GCM)。密文格式：nonce(12) + ciphertext + tag。
	if env.Encryption == EncryptionSM4 {
		if len(sm4Key) != 16 {
			return nil, NewError(NumEnvelope, CodeEnvelope,
				fmt.Sprintf("SM4 key must be 16 bytes, got %d", len(sm4Key)))
		}
		gcm, err := sm4.NewGCM(sm4Key)
		if err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "SM4-GCM init", err)
		}
		nonceSize := gcm.NonceSize()
		if len(raw) < nonceSize+gcm.Overhead() {
			return nil, NewError(NumEnvelope, CodeEnvelope, "ciphertext too short for SM4-GCM")
		}
		nonce, ct := raw[:nonceSize], raw[nonceSize:]
		raw, err = gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "SM4-GCM decrypt", err)
		}
	}

	// Decompress
	if env.Compression == CompressionGzip {
		r := gzipReaderPool.Get().(*gzip.Reader)
		if err := r.Reset(bytes.NewReader(raw)); err != nil {
			gzipReaderPool.Put(r)
			return nil, WrapError(NumEnvelope, CodeEnvelope, "gzip reader", err)
		}
		defer gzipReaderPool.Put(r) // Reset 会重置状态，无需 Close 即可复用

		// Limit decompressed size to prevent zip-bomb OOM
		lr := &io.LimitedReader{R: r, N: MaxDecompressedSize + 1}
		// 预分配解压缓冲（gzip 典型压缩比 3-4x），避免 io.ReadAll 的多次 grow+copy。
		var buf bytes.Buffer
		buf.Grow(len(raw) * 4)
		if _, err := io.Copy(&buf, lr); err != nil {
			return nil, WrapError(NumEnvelope, CodeEnvelope, "gzip decompress", err)
		}
		if lr.N == 0 {
			return nil, NewError(NumEnvelope, CodeEnvelope, fmt.Sprintf("decompressed payload exceeds %d bytes limit", MaxDecompressedSize))
		}
		return buf.Bytes(), nil
	}

	return raw, nil
}

// EncodeEnvelope JSON-encodes the envelope.
func EncodeEnvelope(env *SecureEnvelope) ([]byte, error) {
	return FastMarshal(env)
}

// DecodeEnvelope JSON-decodes into a SecureEnvelope.
func DecodeEnvelope(data []byte) (*SecureEnvelope, error) {
	var env SecureEnvelope
	if err := FastUnmarshal(data, &env); err != nil {
		return nil, WrapError(NumEnvelope, CodeEnvelope, "decode envelope", err)
	}
	return &env, nil
}
