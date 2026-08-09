package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// DeadlineReader 是支持读超时的 io.Reader（*quic.Stream 和 net.Conn 均满足）。
// ReadFrameCtx 据此让 ctx 取消/超时能中断阻塞读。
type DeadlineReader interface {
	io.Reader
	SetReadDeadline(t time.Time) error
}

// ReadFrameCtx 是 ctx 感知的帧读取：通过 SetReadDeadline 让 ctx 取消/超时中断阻塞读，
// 避免对端静默断开时 control loop 永久阻塞（goroutine 泄漏）。
// ctx 无 deadline 时用 DefaultReadTimeout 兜底。v1/ntls client transport 共享。
func ReadFrameCtx(ctx context.Context, r DeadlineReader) (Frame, error) {
	if err := ctx.Err(); err != nil {
		return Frame{}, err
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(DefaultReadTimeout)
	}
	if err := r.SetReadDeadline(dl); err != nil {
		return Frame{}, WrapError(ErrCodeStream, "set read deadline", err)
	}
	defer func() { _ = r.SetReadDeadline(time.Time{}) }()
	f, err := Read(r, DefaultLimits())
	if err != nil && ctx.Err() != nil {
		return Frame{}, ctx.Err()
	}
	return f, err
}

const (
	Magic                 = "MBTA"
	Version        byte   = 0x01
	FixedHeaderSz         = 8
	MaxPayloadSize uint32 = 16 << 20
	maxVarintLen          = 5
)

var magicBytes = []byte(Magic)

// versionAllowed 报告帧头 Version 是否在白名单内。
// supported 为空时回退到默认仅接受 core.Version（向后兼容）。
func versionAllowed(v byte, supported []byte) bool {
	if len(supported) == 0 {
		return v == Version
	}
	for _, s := range supported {
		if v == s {
			return true
		}
	}
	return false
}

// Header 表示帧头的定长前缀（8 字节，不含 varint length）。
// 帧格式：8B 定长前缀 + varint Length + Payload。
// 无帧层 CRC——完整性由传输层 AEAD（TLS 1.3 / TLCP）+
// 应用层 HMAC（SecureEnvelope）保证。这与 QUIC/HTTP/2 等现代协议一致。
type Header struct {
	Version   byte
	Flags     byte
	Type      uint8
	ChannelID uint8
	Length    uint32
}

type Frame struct {
	Header  Header
	Payload []byte
}

var knownTypes = map[uint8]bool{
	TypeHello: true, TypeHelloAck: true,
	TypeAuth: true, TypeAuthOK: true, TypeAuthFail: true,
	TypeBatch: true, TypeDatagram: true,
	TypeAck: true, TypeNack: true, TypePartialAck: true,
	TypeWindow: true, TypeThrottle: true,
	TypePing: true, TypePong: true,
	TypeClose: true, TypeError: true, TypeRedirect: true,
}

// ValidateFlags 校验 flags 的位组合合法性（core spec §3.1）。
func ValidateFlags(flags byte) error {
	if FlowClassOf(flags) == FlowClassOf(FlowClassReserved) {
		return NewError(ErrCodeProtocol, fmt.Sprintf("reserved FlowClass: 0x%02x", flags&FlagFlowClassMask))
	}
	if flags&FlagReserved4 != 0 {
		return NewError(ErrCodeProtocol, "reserved flag bit set (0x10)")
	}
	cd := flags & FlagControlDataMask
	if cd == 0 || cd == FlagControlDataMask {
		return NewError(ErrCodeProtocol, fmt.Sprintf("Control/Data must be exclusive: 0x%02x", flags))
	}
	if flags&FlagMoreFollows != 0 && flags&FlagCoalesced != 0 {
		return NewError(ErrCodeProtocol, "MoreFollows and Coalesced are mutually exclusive")
	}
	return nil
}

type Limits struct {
	MaxPayloadSize uint32
}

func DefaultLimits() Limits {
	return Limits{MaxPayloadSize: MaxPayloadSize}
}

// Write 编码并写入单个 MBTA 帧。
// 帧格式：8B 定长前缀 + varint Length + Payload。
//
// version 写入帧头 Version 字段（offset 4）。各 binding 传 core.Version(0x01)。
// version 白名单含 0x02 仅为让 TestReadMultiVersion 验证 Read 端的 supportedVersions
// 扩展机制（Write 能生成非默认版本帧，Read 按白名单决定是否接受）。
func Write(w io.Writer, version byte, typ uint8, flags byte, channelID uint8, payload []byte) error {
	// 写入端 version 白名单：与 Read 端对称校验，避免生成对端无法解析的帧。
	if version != Version && version != 0x02 {
		return NewError(ErrCodeProtocol, fmt.Sprintf("unsupported frame version 0x%02x", version))
	}
	if err := ValidateFlags(flags); err != nil {
		return err
	}
	if !knownTypes[typ] {
		return NewError(ErrCodeProtocol, fmt.Sprintf("unknown frame type 0x%02x", typ))
	}
	if uint32(len(payload)) > MaxPayloadSize {
		return NewError(ErrCodeProtocol, fmt.Sprintf("payload exceeds max size (%d > %d)", len(payload), MaxPayloadSize))
	}

	var hdr [FixedHeaderSz]byte
	copy(hdr[0:4], magicBytes)
	hdr[4] = version
	hdr[5] = flags
	hdr[6] = typ
	hdr[7] = channelID

	var lenBuf [maxVarintLen]byte
	lenN := putVarint(lenBuf[:], uint64(len(payload)))

	if _, err := w.Write(hdr[:]); err != nil {
		return WrapError(ErrCodeProtocol, "write header", err)
	}
	if _, err := w.Write(lenBuf[:lenN]); err != nil {
		return WrapError(ErrCodeProtocol, "write length", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return WrapError(ErrCodeProtocol, "write payload", err)
		}
	}
	return nil
}

// Read 读取并校验单个 MBTA 帧。
//
// supportedVersions 是本端接受的帧版本白名单：
//   - 为空（默认）：仅接受 core.Version(0x01)；
//   - 非空：校验帧头 Version ∈ supportedVersions，否则报错。
//
// 各 binding 按自身支持的版本传入：v1/ntls 不传或传 core.Version。
// 未来新增版本时在此扩展白名单，使读取端能拒绝不支持的版本而非误解析。
func Read(r io.Reader, lim Limits, supportedVersions ...byte) (Frame, error) {
	var hdr [FixedHeaderSz]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, WrapError(ErrCodeProtocol, "read header", err)
	}

	if string(hdr[0:4]) != Magic {
		return Frame{}, NewError(ErrCodeProtocol, fmt.Sprintf("invalid magic %q", hdr[0:4]))
	}
	if !versionAllowed(hdr[4], supportedVersions) {
		return Frame{}, NewError(ErrCodeProtocol, fmt.Sprintf("unsupported version 0x%02x", hdr[4]))
	}
	flags := hdr[5]
	if err := ValidateFlags(flags); err != nil {
		return Frame{}, err
	}
	typ := hdr[6]
	channelID := hdr[7]
	if !knownTypes[typ] {
		return Frame{}, NewError(ErrCodeProtocol, fmt.Sprintf("unknown frame type 0x%02x", typ))
	}

	length, err := readVarint(r)
	if err != nil {
		return Frame{}, WrapError(ErrCodeProtocol, "read length", err)
	}
	if length > uint64(lim.MaxPayloadSize) {
		return Frame{}, NewError(ErrCodeProtocol, fmt.Sprintf("payload too large (%d bytes)", length))
	}

	payload := make([]byte, length)
	if length > 0 {
		n, err := io.ReadFull(r, payload)
		if err != nil {
			// 短读：drain 声明的剩余字节以维持帧边界对齐（core spec §2.2 / tcp-binding §3.3）。
			// 必须用实际读取数 n（非 len(payload)，后者恒等于 length 致 drain 恒为 0）。
			if remaining := int64(length) - int64(n); remaining > 0 {
				_, _ = io.CopyN(io.Discard, r, remaining)
			}
			return Frame{}, WrapError(ErrCodeProtocol, "read payload", err)
		}
	}

	return Frame{
		Header: Header{
			Version:   hdr[4],
			Flags:     flags,
			Type:      typ,
			ChannelID: channelID,
			Length:    uint32(length),
		},
		Payload: payload,
	}, nil
}

// putVarint 编码 varint 到调用方提供的 buffer（零分配）。
// 底层使用 protowire.AppendVarint（protobuf 标准库实现）。
func putVarint(buf []byte, v uint64) int {
	return len(protowire.AppendVarint(buf[:0], v))
}

// readVarint 从 io.Reader 流式读取 varint，拒绝非最短编码。
// 不能直接用 protowire.ConsumeVarint（它消费 []byte 切片，不读 io.Reader，
// 且不检测非最短编码）。此实现专为 io.Reader + 安全校验设计。
func readVarint(r io.Reader) (uint64, error) {
	var buf [1]byte
	var encoded []byte
	for i := range maxVarintLen {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, errors.New("varint: short read")
		}
		encoded = append(encoded, buf[0])
		if buf[0]&0x80 == 0 {
			v, n := protowire.ConsumeVarint(encoded)
			if n <= 0 {
				return 0, errors.New("varint: decode failed")
			}
			// 非最短编码检测（protobuf 规则）。
			if i > 0 && v < (uint64(1)<<uint(7*i)) {
				return 0, errors.New("varint: non-canonical encoding")
			}
			return v, nil
		}
	}
	// 读了 maxVarintLen 字节仍有 continuation bit → 过长。
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, errors.New("varint: short read")
	}
	if buf[0]&0x80 != 0 || buf[0]&0x0f != 0 {
		return 0, errors.New("varint: too long")
	}
	encoded = append(encoded, buf[0])
	v, n := protowire.ConsumeVarint(encoded)
	if n <= 0 {
		return 0, errors.New("varint: decode failed")
	}
	// 非最短编码检测：与 1-5 字节路径一致（旧 6 字节分支遗漏此校验，
	// 允许恶意对端用非规范 6 字节编码绕过非最短检测）。
	if v < (uint64(1) << uint(7*maxVarintLen)) {
		return 0, errors.New("varint: non-canonical encoding")
	}
	return v, nil
}
