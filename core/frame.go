package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	// Magic 是MBTA协议的魔数标识。
	Magic = "MBTA"
	// Version 是当前协议版本。
	Version byte = 0x01
	// HeaderSz 是帧头部固定大小（16字节）。
	HeaderSz = 16 // 4 magic + 1 version + 1 flags + 2 type + 4 length + 4 crc32

	// MaxPayloadSize 是单个帧的最大载荷大小（16 MiB）。
	MaxPayloadSize uint32 = 16 << 20 // 16 MiB

	// maxInt32 is the maximum positive value of a 32-bit signed integer.
	// Used to guard against uint32→int overflow on 32-bit platforms.
	maxInt32 uint32 = 1<<31 - 1
)

// Frame flags. Compression/encryption algorithms are declared in SecureEnvelope, not here.
const (
	FlagEnvelope    byte = 0x01 // payload is SecureEnvelope JSON
	FlagControl     byte = 0x02 // control-plane message
	FlagData        byte = 0x04 // data-plane message
	FlagMoreFollows byte = 0x08 // reserved, must NOT be set in v1

	flagReservedMask byte = 0xF0 // bits 4-7 must be zero
)

// magicBytes caches the Magic string as a []byte for zero-allocation comparisons.
var magicBytes = []byte(Magic)

// Header represents the 16-byte MBTA frame header.
type Header struct {
	Version byte
	Flags   byte
	Type    uint16
	Length  uint32
	CRC32   uint32
}

// Frame is a decoded MBTA frame.
// 注意：帧级 CRC32 仅提供传输错误检测（快速预检），
// 不具备密码学安全保证。协议的安全完整性由 SecureEnvelope 层的 HMAC 提供。
type Frame struct {
	Header  Header
	Payload []byte
}

// knownTypes is the set of valid frame type values.
var knownTypes = map[uint16]bool{
	TypeHello: true, TypeHelloAck: true,
	TypeAuth: true, TypeAuthOK: true, TypeAuthFail: true,
	TypeBatch: true, TypeAck: true, TypeNack: true, TypePartialAck: true,
	TypeWindow: true, TypeThrottle: true,
	TypePing: true, TypePong: true,
	TypeClose: true, TypeError: true,
}

// Write encodes and writes a single MBTA frame.
func Write(w io.Writer, typ uint16, flags byte, payload []byte) error {
	if err := validateFlags(flags); err != nil {
		return err
	}
	if !knownTypes[typ] {
		return NewError(NumProtocol, CodeProtocol, fmt.Sprintf("unknown frame type 0x%04x", typ))
	}
	if len(payload) > int(MaxPayloadSize) {
		return NewError(NumProtocol, CodeProtocol, fmt.Sprintf("payload exceeds max size (%d > %d)", len(payload), MaxPayloadSize))
	}

	hdr := make([]byte, HeaderSz)
	copy(hdr[0:4], Magic)
	hdr[4] = Version
	hdr[5] = flags
	binary.BigEndian.PutUint16(hdr[6:8], typ)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(payload))) // #nosec G115 -- payload size checked above
	binary.BigEndian.PutUint32(hdr[12:16], crc32.ChecksumIEEE(payload))

	if _, err := w.Write(hdr); err != nil {
		return WrapError(NumProtocol, CodeProtocol, "write header", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return WrapError(NumProtocol, CodeProtocol, "write payload", err)
		}
	}
	return nil
}

// Limits controls frame-size validation during reads.
type Limits struct {
	MaxPayloadSize uint32
}

// DefaultLimits returns production defaults.
func DefaultLimits() Limits {
	return Limits{MaxPayloadSize: MaxPayloadSize}
}

// Read reads and validates a single MBTA frame.
// If the header is read successfully but payload reading fails (e.g. deadline),
// the remaining declared payload bytes are drained so the reader stays aligned
// for the next frame.
func Read(r io.Reader, lim Limits) (Frame, error) {
	hdr := make([]byte, HeaderSz)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return Frame{}, WrapError(NumProtocol, CodeProtocol, "read header", err)
	}

	// Step 1: Magic
	if !bytes.Equal(hdr[0:4], magicBytes) {
		return Frame{}, NewError(NumProtocol, CodeProtocol, fmt.Sprintf("invalid magic %q", hdr[0:4]))
	}
	// Step 2: Version
	if hdr[4] != Version {
		return Frame{}, NewError(NumProtocol, CodeProtocol, fmt.Sprintf("unsupported version 0x%02x", hdr[4]))
	}
	// Step 3: Flags
	flags := hdr[5]
	if err := validateFlags(flags); err != nil {
		return Frame{}, err
	}

	typ := binary.BigEndian.Uint16(hdr[6:8])
	length := binary.BigEndian.Uint32(hdr[8:12])
	expectedCRC := binary.BigEndian.Uint32(hdr[12:16])

	// Step 4: Length
	if length > lim.MaxPayloadSize {
		return Frame{}, NewError(NumProtocol, CodeProtocol, fmt.Sprintf("payload too large (%d bytes)", length))
	}
	// Guard against int overflow on 32-bit platforms where int is 32 bits
	// but uint32 can hold values up to 4294967295 (> MaxInt32 = 2147483647).
	if length > maxInt32 {
		return Frame{}, NewError(NumProtocol, CodeProtocol, fmt.Sprintf("payload length overflow (%d bytes)", length))
	}

	// Step 5: Read payload
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			// Partial payload read: drain the remaining declared bytes so the
			// next Read call finds a valid frame boundary.  io.Copy reads up to
			// (length - alreadyRead) bytes; if the underlying reader is a QUIC
			// stream with a deadline, the deadline error will propagate and the
			// stream position will at least be past what we already consumed.
			_, _ = io.CopyN(io.Discard, r, int64(length)-int64(len(payload)))
			return Frame{}, WrapError(NumProtocol, CodeProtocol, "read payload", err)
		}
	}

	// Step 6: CRC32
	if crc32.ChecksumIEEE(payload) != expectedCRC {
		return Frame{}, NewError(NumProtocol, CodeProtocol, "crc32 mismatch")
	}

	return Frame{
		Header: Header{
			Version: hdr[4],
			Flags:   flags,
			Type:    typ,
			Length:  length,
			CRC32:   expectedCRC,
		},
		Payload: payload,
	}, nil
}

func validateFlags(flags byte) error {
	if flags&flagReservedMask != 0 {
		return NewError(NumProtocol, CodeProtocol, fmt.Sprintf("reserved flags bits set: 0x%02x", flags&flagReservedMask))
	}
	if flags&FlagMoreFollows != 0 {
		return NewError(NumProtocol, CodeProtocol, "FlagMoreFollows is not supported in v1")
	}
	return nil
}
