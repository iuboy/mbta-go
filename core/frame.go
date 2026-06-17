package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	// Magic 是 MBTA 协议的 4 字节魔数标识（core spec §2）。
	Magic = "MBTA"
	// Version 是当前协议帧版本。
	Version byte = 0x01
	// FixedHeaderSz 是帧头定长前缀大小（8 字节：4 magic + 1 version + 1 flags + 1 type + 1 channelID）。
	FixedHeaderSz = 8

	// MaxPayloadSize 是单个帧的最大载荷大小（16 MiB）。
	MaxPayloadSize uint32 = 16 << 20

	// maxVarintLen 是 length 字段 varint 最多占用的字节数（覆盖 MaxPayloadSize）。
	maxVarintLen = 5
)

// magicBytes 缓存 Magic 为 []byte，零分配比较。
var magicBytes = []byte(Magic)

// Header 表示帧头的定长前缀（不含 varint length 与可选 CRC16）。
type Header struct {
	Version    byte
	Flags      byte
	Type       uint8
	ChannelID  uint8
	Length     uint32
	CRCPresent bool // = Flags&FlagNoCRC == 0
	CRC16      uint16
}

// Frame 是一个解码后的 MBTA 帧。
//
// 帧级 CRC16 仅提供传输错误检测（快速预检），无密码学安全保证。
// 协议的安全完整性由 SecureEnvelope 层的 HMAC 提供（core spec §2.2）。
type Frame struct {
	Header  Header
	Payload []byte
}

// knownTypes 是合法的帧 type 值集合。
var knownTypes = map[uint8]bool{
	TypeHello: true, TypeHelloAck: true,
	TypeAuth: true, TypeAuthOK: true, TypeAuthFail: true,
	TypeBatch: true, TypeDatagram: true,
	TypeAck: true, TypeNack: true, TypePartialAck: true,
	TypeWindow: true, TypeThrottle: true,
	TypePing: true, TypePong: true,
	TypeClose: true, TypeError: true,
}

// ValidateFlags 校验 flags 的位组合合法性（core spec §3.1）。
// 返回 nil 表示合法。
func ValidateFlags(flags byte) error {
	// FlowClass = 3（reserved）MUST 拒绝。
	if FlowClassOf(flags) == 3 {
		return NewError(NumProtocol, CodeProtocol, fmt.Sprintf("reserved FlowClass value: 0x%02x", flags&FlagFlowClassMask))
	}
	// Control 与 Data 互斥：不可同时为 0，也不可同时非 0。
	cd := flags & FlagControlDataMask
	if cd == 0 || cd == FlagControlDataMask {
		return NewError(NumProtocol, CodeProtocol, fmt.Sprintf("Control/Data flags must be exclusive: 0x%02x", flags))
	}
	// MoreFollows 与 Coalesced 互斥。
	if flags&FlagMoreFollows != 0 && flags&FlagCoalesced != 0 {
		return NewError(NumProtocol, CodeProtocol, "MoreFollows and Coalesced are mutually exclusive")
	}
	return nil
}

// Limits 控制读取时的帧大小校验。
type Limits struct {
	MaxPayloadSize uint32
}

// DefaultLimits 返回生产默认 Limits。
func DefaultLimits() Limits {
	return Limits{MaxPayloadSize: MaxPayloadSize}
}

// Write 编码并写入单个 MBTA 帧。
//
// typ       : 消息类型（uint8，core spec §4）。
// flags     : 帧标志（core spec §3）。置 FlagNoCRC 时省略 CRC16。
// channelID : 帧 channel（control=0, data≥1，core spec §3/§10.1）。
// payload   : 载荷字节。
func Write(w io.Writer, typ uint8, flags byte, channelID uint8, payload []byte) error {
	if err := ValidateFlags(flags); err != nil {
		return err
	}
	if !knownTypes[typ] {
		return NewError(NumProtocol, CodeProtocol, fmt.Sprintf("unknown frame type 0x%02x", typ))
	}
	if uint32(len(payload)) > MaxPayloadSize {
		return NewError(NumProtocol, CodeProtocol, fmt.Sprintf("payload exceeds max size (%d > %d)", len(payload), MaxPayloadSize))
	}

	// 定长前缀 8 字节。
	var hdr [FixedHeaderSz]byte
	copy(hdr[0:4], magicBytes)
	hdr[4] = Version
	hdr[5] = flags
	hdr[6] = typ
	hdr[7] = channelID

	// varint length。
	var lenBuf [maxVarintLen]byte
	lenN := putVarint(lenBuf[:], uint64(len(payload)))

	if _, err := w.Write(hdr[:]); err != nil {
		return WrapError(NumProtocol, CodeProtocol, "write header", err)
	}
	if _, err := w.Write(lenBuf[:lenN]); err != nil {
		return WrapError(NumProtocol, CodeProtocol, "write length", err)
	}

	// 可选 CRC16（NoCRC=0 时）。大端，覆盖 payload。
	if flags&FlagNoCRC == 0 {
		var crcBuf [2]byte
		binary.BigEndian.PutUint16(crcBuf[:], crc16MBTA(payload))
		if _, err := w.Write(crcBuf[:]); err != nil {
			return WrapError(NumProtocol, CodeProtocol, "write crc16", err)
		}
	}

	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return WrapError(NumProtocol, CodeProtocol, "write payload", err)
		}
	}
	return nil
}

// Read 读取并校验单个 MBTA 帧。
//
// 若定长前缀与 varint length 已读但 payload 读取失败，剩余声明字节被排空，
// 以维持帧边界对齐（便于下一帧解析）。
func Read(r io.Reader, lim Limits) (Frame, error) {
	var hdr [FixedHeaderSz]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, WrapError(NumProtocol, CodeProtocol, "read header", err)
	}

	// Step 1: Magic
	if string(hdr[0:4]) != Magic {
		return Frame{}, NewError(NumProtocol, CodeProtocol, fmt.Sprintf("invalid magic %q", hdr[0:4]))
	}
	// Step 2: Version
	if hdr[4] != Version {
		return Frame{}, NewError(NumProtocol, CodeProtocol, fmt.Sprintf("unsupported version 0x%02x", hdr[4]))
	}
	// Step 3: Flags
	flags := hdr[5]
	if err := ValidateFlags(flags); err != nil {
		return Frame{}, err
	}
	typ := hdr[6]
	channelID := hdr[7]
	if !knownTypes[typ] {
		return Frame{}, NewError(NumProtocol, CodeProtocol, fmt.Sprintf("unknown frame type 0x%02x", typ))
	}

	// Step 4: varint length（拒绝非最短编码与超限）。
	length, lenBytes, err := readVarint(r)
	if err != nil {
		return Frame{}, WrapError(NumProtocol, CodeProtocol, "read length", err)
	}
	if length > uint64(lim.MaxPayloadSize) {
		return Frame{}, NewError(NumProtocol, CodeProtocol, fmt.Sprintf("payload too large (%d bytes)", length))
	}
	_ = lenBytes

	crcPresent := flags&FlagNoCRC == 0
	var expectedCRC uint16
	if crcPresent {
		var crcBuf [2]byte
		if _, err := io.ReadFull(r, crcBuf[:]); err != nil {
			return Frame{}, WrapError(NumProtocol, CodeProtocol, "read crc16", err)
		}
		expectedCRC = binary.BigEndian.Uint16(crcBuf[:])
	}

	// Step 5: payload
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			// 排空剩余声明字节，维持帧边界对齐。
			_, _ = io.CopyN(io.Discard, r, int64(length)-int64(len(payload)))
			return Frame{}, WrapError(NumProtocol, CodeProtocol, "read payload", err)
		}
	}

	// Step 6: CRC16（若存在）
	if crcPresent && crc16MBTA(payload) != expectedCRC {
		return Frame{}, NewError(NumProtocol, CodeProtocol, "crc16 mismatch")
	}

	return Frame{
		Header: Header{
			Version:    hdr[4],
			Flags:      flags,
			Type:       typ,
			ChannelID:  channelID,
			Length:     uint32(length),
			CRCPresent: crcPresent,
			CRC16:      expectedCRC,
		},
		Payload: payload,
	}, nil
}

// putVarint 写入 LEB128 varint，返回写入字节数。
func putVarint(buf []byte, v uint64) int {
	n := 0
	for v >= 0x80 {
		buf[n] = byte(v) | 0x80
		v >>= 7
		n++
	}
	buf[n] = byte(v)
	return n + 1
}

// readVarint 读取 LEB128 varint。拒绝非最短编码（protobuf 规则）与过长编码。
// 返回 (值, 占用字节数, error)。
func readVarint(r io.Reader) (uint64, int, error) {
	var v uint64
	var s uint
	var b [1]byte
	for i := 0; i < maxVarintLen+1; i++ {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, 0, errors.New("varint: short read")
		}
		if i == maxVarintLen && b[0]&0x80 != 0 {
			return 0, 0, errors.New("varint: too long")
		}
		if s >= 64 && b[0]&0x7f != 0 {
			return 0, 0, errors.New("varint: overflow")
		}
		v |= uint64(b[0]&0x7f) << s
		if b[0]&0x80 == 0 {
			// 非最短编码检测（protobuf 规则）：n 字节编码可表示的最小值是 1<<(7*(n-1))。
			// 若实际值小于该阈值，说明用了多余字节，拒绝（防恶意 length 编码，§2.2）。
			if i > 0 && v < (uint64(1)<<uint(7*i)) {
				return 0, 0, errors.New("varint: non-canonical encoding")
			}
			return v, i + 1, nil
		}
		s += 7
	}
	return 0, 0, errors.New("varint: too long")
}

// crc16MBTA 计算 payload 的 CRC16（CRC-16/CCITT-FALSE：poly 0x1021，init 0xFFFF）。
// 大端写入 wire。core spec §2.2 声明大端序。
//
// 注：crc32 引入仅为保留旧 import 兼容过渡，将在后续阶段移除（r2 帧用 CRC16）。
var _ = crc32.ChecksumIEEE

func crc16MBTA(data []byte) uint16 {
	const poly = 0x1021
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ poly
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
