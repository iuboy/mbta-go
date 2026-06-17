package core

import (
	"errors"
	"fmt"
	"io"
)

const (
	Magic                 = "MBTA"
	Version        byte   = 0x01
	FixedHeaderSz         = 8
	MaxPayloadSize uint32 = 16 << 20
	maxVarintLen          = 5
)

var magicBytes = []byte(Magic)

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
	TypeClose: true, TypeError: true,
}

// ValidateFlags 校验 flags 的位组合合法性（core spec §3.1）。
func ValidateFlags(flags byte) error {
	if FlowClassOf(flags) == 3 {
		return NewError(NumProtocol, CodeProtocol, fmt.Sprintf("reserved FlowClass: 0x%02x", flags&FlagFlowClassMask))
	}
	cd := flags & FlagControlDataMask
	if cd == 0 || cd == FlagControlDataMask {
		return NewError(NumProtocol, CodeProtocol, fmt.Sprintf("Control/Data must be exclusive: 0x%02x", flags))
	}
	if flags&FlagMoreFollows != 0 && flags&FlagCoalesced != 0 {
		return NewError(NumProtocol, CodeProtocol, "MoreFollows and Coalesced are mutually exclusive")
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

	var hdr [FixedHeaderSz]byte
	copy(hdr[0:4], magicBytes)
	hdr[4] = Version
	hdr[5] = flags
	hdr[6] = typ
	hdr[7] = channelID

	var lenBuf [maxVarintLen]byte
	lenN := putVarint(lenBuf[:], uint64(len(payload)))

	if _, err := w.Write(hdr[:]); err != nil {
		return WrapError(NumProtocol, CodeProtocol, "write header", err)
	}
	if _, err := w.Write(lenBuf[:lenN]); err != nil {
		return WrapError(NumProtocol, CodeProtocol, "write length", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return WrapError(NumProtocol, CodeProtocol, "write payload", err)
		}
	}
	return nil
}

// Read 读取并校验单个 MBTA 帧。
func Read(r io.Reader, lim Limits) (Frame, error) {
	var hdr [FixedHeaderSz]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, WrapError(NumProtocol, CodeProtocol, "read header", err)
	}

	if string(hdr[0:4]) != Magic {
		return Frame{}, NewError(NumProtocol, CodeProtocol, fmt.Sprintf("invalid magic %q", hdr[0:4]))
	}
	if hdr[4] != Version {
		return Frame{}, NewError(NumProtocol, CodeProtocol, fmt.Sprintf("unsupported version 0x%02x", hdr[4]))
	}
	flags := hdr[5]
	if err := ValidateFlags(flags); err != nil {
		return Frame{}, err
	}
	typ := hdr[6]
	channelID := hdr[7]
	if !knownTypes[typ] {
		return Frame{}, NewError(NumProtocol, CodeProtocol, fmt.Sprintf("unknown frame type 0x%02x", typ))
	}

	length, _, err := readVarint(r)
	if err != nil {
		return Frame{}, WrapError(NumProtocol, CodeProtocol, "read length", err)
	}
	if length > uint64(lim.MaxPayloadSize) {
		return Frame{}, NewError(NumProtocol, CodeProtocol, fmt.Sprintf("payload too large (%d bytes)", length))
	}

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			_, _ = io.CopyN(io.Discard, r, int64(length)-int64(len(payload)))
			return Frame{}, WrapError(NumProtocol, CodeProtocol, "read payload", err)
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
			if i > 0 && v < (uint64(1)<<uint(7*i)) {
				return 0, 0, errors.New("varint: non-canonical encoding")
			}
			return v, i + 1, nil
		}
		s += 7
	}
	return 0, 0, errors.New("varint: too long")
}
