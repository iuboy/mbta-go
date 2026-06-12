package mbta_test

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"time"

	"github.com/iuboy/mbta-go/core"
)

const (
	MBTAALPN = "mbta/1"

	// Test ports
	TestServerPort = 15150
)

// writeTestFrame writes a single MBTA frame using the canonical wire format
// (identical to core.Write). Used by E2E tests that operate at the QUIC level.
func writeTestFrame(stream io.Writer, typ uint16, flags byte, payload []byte) error {
	hdr := make([]byte, core.HeaderSz)
	copy(hdr[0:4], core.Magic)
	hdr[4] = core.Version
	hdr[5] = flags
	binary.BigEndian.PutUint16(hdr[6:8], typ)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	binary.BigEndian.PutUint32(hdr[12:16], crc32.ChecksumIEEE(payload))

	if _, err := stream.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := stream.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// readTestFrameWithTimeout reads a single MBTA frame with timeout control.
// Uses the canonical wire format (identical to core.Read).
func readTestFrameWithTimeout(stream io.Reader, timeout time.Duration) (typ uint16, flags byte, payload []byte, err error) {
	// Set QUIC stream read deadline if supported.
	if ds, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = ds.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = ds.SetReadDeadline(time.Time{}) }()
	}

	hdr := make([]byte, core.HeaderSz)
	if _, err := io.ReadFull(stream, hdr); err != nil {
		return 0, 0, nil, err
	}

	// Validate magic
	if string(hdr[0:4]) != core.Magic {
		return 0, 0, nil, ErrInvalidFrame
	}
	// Validate version
	if hdr[4] != core.Version {
		return 0, 0, nil, ErrInvalidVersion
	}

	parsedFlags := hdr[5]
	parsedType := binary.BigEndian.Uint16(hdr[6:8])
	length := binary.BigEndian.Uint32(hdr[8:12])
	expectedCRC := binary.BigEndian.Uint32(hdr[12:16])

	// Read payload
	data := make([]byte, length)
	if length > 0 {
		n, readErr := io.ReadFull(stream, data)
		if readErr != nil {
			// Drain remaining bytes to keep stream aligned.
			remaining := int64(length) - int64(n)
			if remaining > 0 {
				_, _ = io.CopyN(io.Discard, stream, remaining)
			}
			return 0, 0, nil, readErr
		}
	}

	// Verify CRC32
	if crc32.ChecksumIEEE(data) != expectedCRC {
		return 0, 0, nil, ErrCRCMismatch
	}

	return parsedType, parsedFlags, data, nil
}

// readTestFrameOfType reads frames until one matching the expected type is found.
// Skips intermediate frames (e.g., WINDOW updates). Returns the first matching frame.
func readTestFrameOfType(stream io.Reader, expectedType uint16, timeout time.Duration) (byte, []byte, error) {
	deadline := time.Now().Add(timeout)
	for i := 0; i < 64; i++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, nil, fmt.Errorf("timeout waiting for frame type 0x%04x", expectedType)
		}
		typ, flags, data, err := readTestFrameWithTimeout(stream, remaining)
		if err != nil {
			return 0, nil, err
		}
		if typ == expectedType {
			return flags, data, nil
		}
		// Skip non-matching frame types.
	}
	return 0, nil, fmt.Errorf("too many unexpected frames while waiting for frame type 0x%04x", expectedType)
}

// Errors
var (
	ErrInvalidVersion = &ProtocolError{Code: 0x01, Message: "invalid protocol version"}
	ErrCRCMismatch    = &ProtocolError{Code: 0x02, Message: "CRC32 mismatch"}
	ErrInvalidFrame   = &ProtocolError{Code: 0x03, Message: "invalid frame format"}
)

// ProtocolError protocol error
type ProtocolError struct {
	Code    uint8
	Message string
}

func (e *ProtocolError) Error() string {
	return e.Message
}
