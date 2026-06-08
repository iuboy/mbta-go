package core

import (
	"bytes"
	"hash/crc32"
	"io"
	"strings"
	"testing"

	mbtatest "github.com/iuboy/mbta-go/testing"
)

// TestWriteFrame tests the Write function with various configurations.
func TestWriteFrame(t *testing.T) {
	tests := []struct {
		name      string
		typ       uint16
		flags     byte
		payload   []byte
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid HELLO frame",
			typ:     0x01, // HelloMessageType
			flags:   FlagControl,
			payload: []byte("agent-123"),
			wantErr: false,
		},
		{
			name:    "valid BATCH frame with envelope flag",
			typ:     0x10, // BatchMessageType
			flags:   FlagData | FlagEnvelope,
			payload: []byte("batch data"),
			wantErr: false,
		},
		{
			name:    "empty payload",
			typ:     0x01,
			flags:   FlagControl,
			payload: []byte{},
			wantErr: false,
		},
		{
			name:      "reserved flags set",
			typ:       0x01,
			flags:     0xF0, // bits 4-7 set
			payload:   []byte("test"),
			wantErr:   true,
			errSubstr: "reserved flags",
		},
		{
			name:      "FlagMoreFollows not supported",
			typ:       0x01,
			flags:     FlagMoreFollows,
			payload:   []byte("test"),
			wantErr:   true,
			errSubstr: "FlagMoreFollows",
		},
		{
			name:    "large payload (1MB)",
			typ:     0x10,
			flags:   FlagData,
			payload: make([]byte, 1<<20), // 1 MB
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			err := Write(buf, tt.typ, tt.flags, tt.payload)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Write() expected error containing %q, got nil", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Write() error = %v, want error containing %q", err, tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Write() unexpected error: %v", err)
			}

			// Verify written data
			written := buf.Bytes()
			if len(written) < int(HeaderSz) {
				t.Errorf("Write() wrote %d bytes, want at least %d", len(written), HeaderSz)
			}

			// Verify magic
			if magic := string(written[0:4]); magic != Magic {
				t.Errorf("Write() magic = %q, want %q", magic, Magic)
			}

			// Verify version
			if version := written[4]; version != Version {
				t.Errorf("Write() version = 0x%02x, want 0x%02x", version, Version)
			}

			// Verify flags
			if flags := written[5]; flags != tt.flags {
				t.Errorf("Write() flags = 0x%02x, want 0x%02x", flags, tt.flags)
			}

			// Verify type
			typ := (uint16(written[6]) << 8) | uint16(written[7])
			if typ != tt.typ {
				t.Errorf("Write() type = %d, want %d", typ, tt.typ)
			}

			// Verify payload
			payloadLen := int((uint32(written[8]) << 24) |
				(uint32(written[9]) << 16) |
				(uint32(written[10]) << 8) |
				uint32(written[11]))
			if payloadLen != len(tt.payload) {
				t.Errorf("Write() payload length = %d, want %d", payloadLen, len(tt.payload))
			}

			if len(tt.payload) > 0 {
				payloadStart := HeaderSz
				payloadEnd := payloadStart + len(tt.payload)
				if payloadEnd > len(written) {
					t.Errorf("Write() payload extends beyond written data")
				}
				gotPayload := written[payloadStart:payloadEnd]
				if !bytes.Equal(gotPayload, tt.payload) {
					t.Errorf("Write() payload mismatch, got %q, want %q", gotPayload, tt.payload)
				}
			}
		})
	}
}

// TestReadFrame tests the Read function with various frame configurations.
func TestReadFrame(t *testing.T) {
	tests := []struct {
		name      string
		frame     []byte // complete frame (header + payload)
		limits    Limits
		wantErr   bool
		errSubstr string
		check     func(*testing.T, Frame)
	}{
		{
			name:    "valid frame with payload",
			frame:   buildTestFrame(0x01, FlagControl, []byte("hello")),
			limits:  DefaultLimits(),
			wantErr: false,
			check: func(t *testing.T, f Frame) {
				mbtatest.AssertEqual(t, f.Header.Version, Version, "version")
				mbtatest.AssertEqual(t, f.Header.Flags, FlagControl, "flags")
				mbtatest.AssertEqual(t, f.Header.Type, uint16(0x01), "type")
				mbtatest.AssertEqual(t, f.Header.Length, uint32(5), "length")
				if !bytes.Equal(f.Payload, []byte("hello")) {
					t.Errorf("payload = %q, want %q", f.Payload, "hello")
				}
			},
		},
		{
			name:    "valid frame with empty payload",
			frame:   buildTestFrame(0x10, FlagData, []byte{}),
			limits:  DefaultLimits(),
			wantErr: false,
			check: func(t *testing.T, f Frame) {
				mbtatest.AssertEqual(t, f.Header.Length, uint32(0), "length")
				if len(f.Payload) != 0 {
					t.Errorf("payload length = %d, want 0", len(f.Payload))
				}
			},
		},
		{
			name:      "invalid magic",
			frame:     buildTestFrameWithMagic("XXXX", 0x01, FlagControl, []byte("test")),
			limits:    DefaultLimits(),
			wantErr:   true,
			errSubstr: "invalid magic",
		},
		{
			name:      "unsupported version",
			frame:     buildTestFrameWithVersion(0xFF, 0x01, FlagControl, []byte("test")),
			limits:    DefaultLimits(),
			wantErr:   true,
			errSubstr: "unsupported version",
		},
		{
			name:      "reserved flags set",
			frame:     buildTestFrame(0x01, 0xF0, []byte("test")),
			limits:    DefaultLimits(),
			wantErr:   true,
			errSubstr: "reserved flags",
		},
		{
			name:      "payload too large",
			frame:     buildTestFrameWithLength(0x01, FlagControl, MaxPayloadSize+1),
			limits:    DefaultLimits(),
			wantErr:   true,
			errSubstr: "payload too large",
		},
		{
			name:      "crc32 mismatch",
			frame:     buildTestFrameWithCRC(0x01, FlagControl, []byte("test"), 0xdeadbeef),
			limits:    DefaultLimits(),
			wantErr:   true,
			errSubstr: "crc32 mismatch",
		},
		{
			name:    "large payload within limit",
			frame:   buildTestFrame(0x10, FlagData, make([]byte, 1024*1024)),
			limits:  DefaultLimits(),
			wantErr: false,
		},
		{
			name:      "custom limit smaller than payload",
			frame:     buildTestFrame(0x10, FlagData, make([]byte, 1024)),
			limits:    Limits{MaxPayloadSize: 512},
			wantErr:   true,
			errSubstr: "payload too large",
		},
		{
			name:      "incomplete header",
			frame:     []byte{0x4D, 0x42, 0x54, 0x41}, // only magic
			limits:    DefaultLimits(),
			wantErr:   true,
			errSubstr: "read header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.frame)
			frame, err := Read(r, tt.limits)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Read() expected error containing %q, got nil", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Read() error = %v, want error containing %q", err, tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Read() unexpected error: %v", err)
			}

			if tt.check != nil {
				tt.check(t, frame)
			}
		})
	}
}

// TestValidateFlags tests the validateFlags function.
func TestValidateFlags(t *testing.T) {
	tests := []struct {
		name    string
		flags   byte
		wantErr bool
	}{
		{name: "no flags", flags: 0x00, wantErr: false},
		{name: "FlagEnvelope only", flags: FlagEnvelope, wantErr: false},
		{name: "FlagControl only", flags: FlagControl, wantErr: false},
		{name: "FlagData only", flags: FlagData, wantErr: false},
		{name: "FlagEnvelope | FlagData", flags: FlagEnvelope | FlagData, wantErr: false},
		{name: "all valid flags", flags: FlagEnvelope | FlagControl | FlagData, wantErr: false},
		{name: "reserved bit 4 set", flags: 0x10, wantErr: true},
		{name: "reserved bit 5 set", flags: 0x20, wantErr: true},
		{name: "reserved bit 6 set", flags: 0x40, wantErr: true},
		{name: "reserved bit 7 set", flags: 0x80, wantErr: true},
		{name: "FlagMoreFollows", flags: FlagMoreFollows, wantErr: true},
		{name: "FlagMoreFollows with valid flag", flags: FlagData | FlagMoreFollows, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFlags(tt.flags)
			if tt.wantErr {
				if err == nil {
					t.Error("validateFlags() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("validateFlags() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestWriteReadRoundTrip tests that Write and Read are inverses.
func TestWriteReadRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		typ     uint16
		flags   byte
		payload []byte
	}{
		{
			name:    "HELLO message",
			typ:     0x01,
			flags:   FlagControl,
			payload: []byte("agent-id-123"),
		},
		{
			name:    "BATCH message",
			typ:     0x10,
			flags:   FlagData | FlagEnvelope,
			payload: []byte(`{"signals":[{"type":"log","message":"test"}]}`),
		},
		{
			name:    "ACK message",
			typ:     0x11,
			flags:   FlagControl,
			payload: []byte("chunk-123:durable"),
		},
		{
			name:    "empty payload",
			typ:     0x20,
			flags:   FlagControl,
			payload: []byte{},
		},
		{
			name:    "large payload",
			typ:     0x10,
			flags:   FlagData,
			payload: make([]byte, 100*1024), // 100 KB
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write
			buf := &bytes.Buffer{}
			err := Write(buf, tt.typ, tt.flags, tt.payload)
			mbtatest.AssertNoError(t, err, "Write()")

			// Read
			r := bytes.NewReader(buf.Bytes())
			frame, err := Read(r, DefaultLimits())
			mbtatest.AssertNoError(t, err, "Read()")

			// Verify
			if frame.Header.Type != tt.typ {
				t.Errorf("Type = %d, want %d", frame.Header.Type, tt.typ)
			}
			if frame.Header.Flags != tt.flags {
				t.Errorf("Flags = 0x%02x, want 0x%02x", frame.Header.Flags, tt.flags)
			}
			if frame.Header.Length != uint32(len(tt.payload)) {
				t.Errorf("Length = %d, want %d", frame.Header.Length, len(tt.payload))
			}
			if !bytes.Equal(frame.Payload, tt.payload) {
				t.Errorf("Payload mismatch, got %d bytes, want %d bytes", len(frame.Payload), len(tt.payload))
			}
		})
	}
}

// TestDefaultLimits tests the DefaultLimits function.
func TestDefaultLimits(t *testing.T) {
	limits := DefaultLimits()
	if limits.MaxPayloadSize != MaxPayloadSize {
		t.Errorf("MaxPayloadSize = %d, want %d", limits.MaxPayloadSize, MaxPayloadSize)
	}
}

// TestHeaderConstants tests that header constants are correctly defined.
func TestHeaderConstants(t *testing.T) {
	if Magic != "MBTA" {
		t.Errorf("Magic = %q, want %q", Magic, "MBTA")
	}
	if Version != 0x01 {
		t.Errorf("Version = 0x%02x, want 0x01", Version)
	}
	if HeaderSz != 16 {
		t.Errorf("HeaderSz = %d, want 16", HeaderSz)
	}
	if MaxPayloadSize != 16<<20 {
		t.Errorf("MaxPayloadSize = %d, want %d", MaxPayloadSize, 16<<20)
	}
}

// TestFlagConstants tests that flag constants are correctly defined.
func TestFlagConstants(t *testing.T) {
	tests := []struct {
		flag    byte
		wantVal byte
	}{
		{FlagEnvelope, 0x01},
		{FlagControl, 0x02},
		{FlagData, 0x04},
		{FlagMoreFollows, 0x08},
	}
	for _, tt := range tests {
		if tt.flag != tt.wantVal {
			t.Errorf("Flag = 0x%02x, want 0x%02x", tt.flag, tt.wantVal)
		}
	}
}

// ===== Test Helpers =====

// buildTestFrame constructs a valid test frame with given parameters.
func buildTestFrame(typ uint16, flags byte, payload []byte) []byte {
	buf := &bytes.Buffer{}

	// Write magic
	buf.WriteString(Magic)

	// Write version
	buf.WriteByte(Version)

	// Write flags
	buf.WriteByte(flags)

	// Write type
	buf.WriteByte(byte(typ >> 8))
	buf.WriteByte(byte(typ))

	// Write length
	length := uint32(len(payload))
	buf.WriteByte(byte(length >> 24))
	buf.WriteByte(byte(length >> 16))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length))

	// Write CRC32
	crc := crc32.ChecksumIEEE(payload)
	buf.WriteByte(byte(crc >> 24))
	buf.WriteByte(byte(crc >> 16))
	buf.WriteByte(byte(crc >> 8))
	buf.WriteByte(byte(crc))

	// Write payload
	buf.Write(payload)

	return buf.Bytes()
}

// buildTestFrameWithMagic builds a frame with custom magic (for error testing).
func buildTestFrameWithMagic(magic string, typ uint16, flags byte, payload []byte) []byte {
	buf := &bytes.Buffer{}
	buf.WriteString(magic)
	buf.WriteByte(Version)
	buf.WriteByte(flags)
	buf.WriteByte(byte(typ >> 8))
	buf.WriteByte(byte(typ))

	length := uint32(len(payload))
	buf.WriteByte(byte(length >> 24))
	buf.WriteByte(byte(length >> 16))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length))

	crc := crc32.ChecksumIEEE(payload)
	buf.WriteByte(byte(crc >> 24))
	buf.WriteByte(byte(crc >> 16))
	buf.WriteByte(byte(crc >> 8))
	buf.WriteByte(byte(crc))

	buf.Write(payload)
	return buf.Bytes()
}

// buildTestFrameWithVersion builds a frame with custom version (for error testing).
func buildTestFrameWithVersion(version byte, typ uint16, flags byte, payload []byte) []byte {
	buf := &bytes.Buffer{}
	buf.WriteString(Magic)
	buf.WriteByte(version)
	buf.WriteByte(flags)
	buf.WriteByte(byte(typ >> 8))
	buf.WriteByte(byte(typ))

	length := uint32(len(payload))
	buf.WriteByte(byte(length >> 24))
	buf.WriteByte(byte(length >> 16))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length))

	crc := crc32.ChecksumIEEE(payload)
	buf.WriteByte(byte(crc >> 24))
	buf.WriteByte(byte(crc >> 16))
	buf.WriteByte(byte(crc >> 8))
	buf.WriteByte(byte(crc))

	buf.Write(payload)
	return buf.Bytes()
}

// buildTestFrameWithLength builds a frame with custom length field (for error testing).
func buildTestFrameWithLength(typ uint16, flags byte, length uint32) []byte {
	buf := &bytes.Buffer{}
	buf.WriteString(Magic)
	buf.WriteByte(Version)
	buf.WriteByte(flags)
	buf.WriteByte(byte(typ >> 8))
	buf.WriteByte(byte(typ))

	buf.WriteByte(byte(length >> 24))
	buf.WriteByte(byte(length >> 16))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length))

	// Zero CRC (invalid)
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	// Write dummy payload to match length
	for i := uint32(0); i < length; i++ {
		buf.WriteByte(0x00)
	}

	return buf.Bytes()
}

// buildTestFrameWithCRC builds a frame with custom CRC (for error testing).
func buildTestFrameWithCRC(typ uint16, flags byte, payload []byte, crc uint32) []byte {
	buf := &bytes.Buffer{}
	buf.WriteString(Magic)
	buf.WriteByte(Version)
	buf.WriteByte(flags)
	buf.WriteByte(byte(typ >> 8))
	buf.WriteByte(byte(typ))

	length := uint32(len(payload))
	buf.WriteByte(byte(length >> 24))
	buf.WriteByte(byte(length >> 16))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length))

	buf.WriteByte(byte(crc >> 24))
	buf.WriteByte(byte(crc >> 16))
	buf.WriteByte(byte(crc >> 8))
	buf.WriteByte(byte(crc))

	buf.Write(payload)
	return buf.Bytes()
}

// TestReadFromPartialStream tests reading from a stream that delivers data in chunks.
func TestReadFromPartialStream(t *testing.T) {
	// Create a valid frame
	payload := []byte("test payload data")
	frameData := buildTestFrame(0x10, FlagData, payload)

	// Create a reader that returns data in 3-byte chunks
	chunkedReader := &chunkReader{data: frameData, chunkSize: 3}

	frame, err := Read(chunkedReader, DefaultLimits())
	mbtatest.AssertNoError(t, err, "Read() from chunked stream")

	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("Payload = %q, want %q", frame.Payload, payload)
	}
}

// chunkReader implements io.Reader but returns data in fixed-size chunks.
type chunkReader struct {
	data      []byte
	chunkSize int
	offset    int
}

func (cr *chunkReader) Read(p []byte) (int, error) {
	if cr.offset >= len(cr.data) {
		return 0, io.EOF
	}

	remaining := len(cr.data) - cr.offset
	chunk := cr.chunkSize
	if remaining < chunk {
		chunk = remaining
	}
	if chunk > len(p) {
		chunk = len(p)
	}

	copied := copy(p, cr.data[cr.offset:cr.offset+chunk])
	cr.offset += copied
	return copied, nil
}
