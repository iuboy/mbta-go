package core

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestWriteFrame(t *testing.T) {
	tests := []struct {
		name      string
		typ       uint8
		flags     byte
		channelID uint8
		payload   []byte
		wantErr   bool
		errSubstr string
	}{
		{name: "valid HELLO frame", typ: TypeHello, flags: FlagControl, channelID: ChannelControl, payload: []byte("agent-123")},
		{name: "valid BATCH frame with envelope flag", typ: TypeBatch, flags: FlagData | FlagEnvelope, channelID: ChannelData, payload: []byte("batch data")},
		{name: "valid DATAGRAM frame", typ: TypeDatagram, flags: FlagData | FlagEnvelope, channelID: ChannelData, payload: []byte("dg")},
		{name: "empty payload", typ: TypeHello, flags: FlagControl, channelID: ChannelControl, payload: []byte{}},
		{name: "reserved FlowClass=3", typ: TypeHello, flags: FlagControl | (3 << FlagFlowClassShift), channelID: ChannelControl, payload: []byte("t"), wantErr: true, errSubstr: "FlowClass"},
		{name: "Control and Data both set", typ: TypeHello, flags: FlagControl | FlagData, channelID: ChannelControl, payload: []byte("t"), wantErr: true, errSubstr: "exclusive"},
		{name: "MoreFollows and Coalesced both set", typ: TypeBatch, flags: FlagData | FlagMoreFollows | FlagCoalesced, channelID: ChannelData, payload: []byte("t"), wantErr: true, errSubstr: "exclusive"},
		{name: "neither Control nor Data", typ: TypeHello, flags: FlagEnvelope, channelID: ChannelControl, payload: []byte("t"), wantErr: true, errSubstr: "exclusive"},
		{name: "large payload (1MB)", typ: TypeBatch, flags: FlagData, channelID: ChannelData, payload: make([]byte, 1<<20)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			err := Write(buf, Version, tt.typ, tt.flags, tt.channelID, tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Write() expected error containing %q, got nil", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Write() error = %v, want containing %q", err, tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Write() unexpected error: %v", err)
			}
			written := buf.Bytes()
			if len(written) < FixedHeaderSz {
				t.Fatalf("wrote %d bytes, want >= %d", len(written), FixedHeaderSz)
			}
			if string(written[0:4]) != Magic {
				t.Errorf("magic = %q, want %q", written[0:4], Magic)
			}
			if written[4] != Version {
				t.Errorf("version = 0x%02x, want 0x%02x", written[4], Version)
			}
			if written[5] != tt.flags {
				t.Errorf("flags = 0x%02x, want 0x%02x", written[5], tt.flags)
			}
			if written[6] != tt.typ {
				t.Errorf("type = 0x%02x, want 0x%02x", written[6], tt.typ)
			}
			if written[7] != tt.channelID {
				t.Errorf("channelID = 0x%02x, want 0x%02x", written[7], tt.channelID)
			}
		})
	}
}

func TestReadFrame(t *testing.T) {
	tests := []struct {
		name      string
		frame     []byte
		limits    Limits
		wantErr   bool
		errSubstr string
		check     func(*testing.T, Frame)
	}{
		{
			name:   "valid frame with payload",
			frame:  buildTestFrame(TypeHello, FlagControl, ChannelControl, []byte("hello")),
			limits: DefaultLimits(),
			check: func(t *testing.T, f Frame) {
				if f.Header.Version != Version {
					t.Errorf("%s: got %v, want %v", "version", f.Header.Version, Version)
				}
				if f.Header.Flags != FlagControl {
					t.Errorf("%s: got %v, want %v", "flags", f.Header.Flags, FlagControl)
				}
				if f.Header.Type != TypeHello {
					t.Errorf("%s: got %v, want %v", "type", f.Header.Type, TypeHello)
				}
				if f.Header.ChannelID != ChannelControl {
					t.Errorf("%s: got %v, want %v", "channelID", f.Header.ChannelID, ChannelControl)
				}
				if f.Header.Length != uint32(5) {
					t.Errorf("%s: got %v, want %v", "length", f.Header.Length, uint32(5))
				}
				if !bytes.Equal(f.Payload, []byte("hello")) {
					t.Errorf("payload = %q, want %q", f.Payload, "hello")
				}
			},
		},
		{
			name:   "valid frame with empty payload",
			frame:  buildTestFrame(TypeBatch, FlagData, ChannelData, []byte{}),
			limits: DefaultLimits(),
			check: func(t *testing.T, f Frame) {
				if f.Header.Length != uint32(0) {
					t.Errorf("%s: got %v, want %v", "length", f.Header.Length, uint32(0))
				}
			},
		},
		{name: "invalid magic", frame: buildTestFrameWithMagic("XXXX", TypeHello, FlagControl, ChannelControl, []byte("t")), limits: DefaultLimits(), wantErr: true, errSubstr: "invalid magic"},
		{name: "unsupported version", frame: buildTestFrameWithVersion(0xFF, TypeHello, FlagControl, ChannelControl, []byte("t")), limits: DefaultLimits(), wantErr: true, errSubstr: "unsupported version"},
		{name: "reserved FlowClass", frame: buildTestFrame(TypeHello, FlagControl|(3<<FlagFlowClassShift), ChannelControl, []byte("t")), limits: DefaultLimits(), wantErr: true, errSubstr: "FlowClass"},
		{name: "payload too large", frame: buildTestFrameWithLength(TypeHello, FlagControl, ChannelControl, MaxPayloadSize+1), limits: DefaultLimits(), wantErr: true, errSubstr: "payload too large"},
		{name: "large payload within limit", frame: buildTestFrame(TypeBatch, FlagData, ChannelData, make([]byte, 1<<20)), limits: DefaultLimits()},
		{name: "custom limit smaller than payload", frame: buildTestFrame(TypeBatch, FlagData, ChannelData, make([]byte, 1024)), limits: Limits{MaxPayloadSize: 512}, wantErr: true, errSubstr: "payload too large"},
		{name: "incomplete header", frame: []byte{'M', 'B', 'T', 'A'}, limits: DefaultLimits(), wantErr: true, errSubstr: "read header"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Read(bytes.NewReader(tt.frame), tt.limits)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Read() expected error containing %q, got nil", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Read() error = %v, want containing %q", err, tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Read() unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, f)
			}
		})
	}
}

func TestValidateFlags(t *testing.T) {
	tests := []struct {
		name    string
		flags   byte
		wantErr bool
	}{
		{name: "FlagControl only", flags: FlagControl, wantErr: false},
		{name: "FlagData only", flags: FlagData, wantErr: false},
		{name: "FlagControl | Envelope", flags: FlagControl | FlagEnvelope, wantErr: false},
		{name: "FlagData | MoreFollows", flags: FlagData | FlagMoreFollows, wantErr: false},
		{name: "FlagControl | Coalesced", flags: FlagControl | FlagCoalesced, wantErr: false},
		{name: "FlowClass critical", flags: FlagControl | FlowClassCritical, wantErr: false},
		{name: "FlowClass best-effort", flags: FlagControl | FlowClassBestEffort, wantErr: false},
		{name: "neither Control nor Data", flags: FlagEnvelope, wantErr: true},
		{name: "Control and Data both", flags: FlagControl | FlagData, wantErr: true},
		{name: "FlowClass reserved=3", flags: FlagControl | (3 << FlagFlowClassShift), wantErr: true},
		{name: "MoreFollows and Coalesced", flags: FlagData | FlagMoreFollows | FlagCoalesced, wantErr: true},
		{name: "Reserved flag bit 0x10", flags: FlagControl | FlagReserved4, wantErr: true},
		{name: "Reserved4 with Data", flags: FlagData | FlagReserved4, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFlags(tt.flags)
			if tt.wantErr && err == nil {
				t.Error("ValidateFlags() expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateFlags() unexpected error: %v", err)
			}
		})
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		typ       uint8
		flags     byte
		channelID uint8
		payload   []byte
	}{
		{name: "HELLO", typ: TypeHello, flags: FlagControl, channelID: ChannelControl, payload: []byte("agent-id-123")},
		{name: "BATCH envelope", typ: TypeBatch, flags: FlagData | FlagEnvelope, channelID: ChannelData, payload: []byte(`{"signals":[]}`)},
		{name: "ACK", typ: TypeAck, flags: FlagControl, channelID: ChannelControl, payload: []byte("chunk-123:durable")},
		{name: "empty payload", typ: TypeWindow, flags: FlagControl, channelID: ChannelControl, payload: []byte{}},
		{name: "large payload", typ: TypeBatch, flags: FlagData, channelID: ChannelData, payload: make([]byte, 100*1024)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			if err := Write(buf, Version, tt.typ, tt.flags, tt.channelID, tt.payload); err != nil {
				t.Errorf("%s: %v", "Write()", err)
			}

			f, err := Read(bytes.NewReader(buf.Bytes()), DefaultLimits())
			if err != nil {
				t.Errorf("%s: %v", "Read()", err)
			}

			if f.Header.Type != tt.typ {
				t.Errorf("Type = %d, want %d", f.Header.Type, tt.typ)
			}
			if f.Header.Flags != tt.flags {
				t.Errorf("Flags = 0x%02x, want 0x%02x", f.Header.Flags, tt.flags)
			}
			if f.Header.ChannelID != tt.channelID {
				t.Errorf("ChannelID = %d, want %d", f.Header.ChannelID, tt.channelID)
			}
			if f.Header.Length != uint32(len(tt.payload)) {
				t.Errorf("Length = %d, want %d", f.Header.Length, len(tt.payload))
			}
			if !bytes.Equal(f.Payload, tt.payload) {
				t.Errorf("Payload mismatch, got %d bytes, want %d", len(f.Payload), len(tt.payload))
			}
		})
	}
}

func TestDefaultLimits(t *testing.T) {
	if limits := DefaultLimits(); limits.MaxPayloadSize != MaxPayloadSize {
		t.Errorf("MaxPayloadSize = %d, want %d", limits.MaxPayloadSize, MaxPayloadSize)
	}
}

func TestHeaderConstants(t *testing.T) {
	if Magic != "MBTA" {
		t.Errorf("Magic = %q, want MBTA", Magic)
	}
	if Version != 0x01 {
		t.Errorf("Version = 0x%02x, want 0x01", Version)
	}
	if FixedHeaderSz != 8 {
		t.Errorf("FixedHeaderSz = %d, want 8", FixedHeaderSz)
	}
	if MaxPayloadSize != 16<<20 {
		t.Errorf("MaxPayloadSize = %d, want %d", MaxPayloadSize, 16<<20)
	}
}

func TestFlagConstants(t *testing.T) {
	want := map[byte]byte{
		FlagEnvelope: 0x01, FlagControl: 0x02, FlagData: 0x04,
		FlagMoreFollows: 0x08, FlagCoalesced: 0x20,
	}
	for flag, wantVal := range want {
		if flag != wantVal {
			t.Errorf("Flag = 0x%02x, want 0x%02x", flag, wantVal)
		}
	}
	if FlowClassOf(FlowClassCritical) != 2 {
		t.Errorf("FlowClassOf(critical) = %d, want 2", FlowClassOf(FlowClassCritical))
	}
}

// ===== Test Helpers =====

func buildTestFrame(typ uint8, flags byte, channelID uint8, payload []byte) []byte {
	buf := &bytes.Buffer{}
	buf.WriteString(Magic)
	buf.WriteByte(Version)
	buf.WriteByte(flags)
	buf.WriteByte(typ)
	buf.WriteByte(channelID)
	writeVarintBuf(buf, uint64(len(payload)))
	buf.Write(payload)
	return buf.Bytes()
}

func buildTestFrameWithMagic(magic string, typ uint8, flags byte, channelID uint8, payload []byte) []byte {
	b := buildTestFrame(typ, flags, channelID, payload)
	copy(b[0:4], []byte(magic))
	return b
}

func buildTestFrameWithVersion(version byte, typ uint8, flags byte, channelID uint8, payload []byte) []byte {
	b := buildTestFrame(typ, flags, channelID, payload)
	b[4] = version
	return b
}

func buildTestFrameWithLength(typ uint8, flags byte, channelID uint8, length uint32) []byte {
	buf := &bytes.Buffer{}
	buf.WriteString(Magic)
	buf.WriteByte(Version)
	buf.WriteByte(flags)
	buf.WriteByte(typ)
	buf.WriteByte(channelID)
	writeVarintBuf(buf, uint64(length))
	return buf.Bytes()
}

func writeVarintBuf(buf *bytes.Buffer, v uint64) {
	var tmp [maxVarintLen]byte
	n := putVarint(tmp[:], v)
	buf.Write(tmp[:n])
}

func TestReadFromPartialStream(t *testing.T) {
	payload := []byte("test payload data")
	frameData := buildTestFrame(TypeBatch, FlagData, ChannelData, payload)
	frame, err := Read(&chunkReader{data: frameData, chunkSize: 3}, DefaultLimits())
	if err != nil {
		t.Errorf("%s: %v", "Read() from chunked stream", err)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("Payload = %q, want %q", frame.Payload, payload)
	}
}

// TestReadMultiVersion 验证帧层多版本支持：
//   - 默认 Read（无 supportedVersions）仅接受 0x01，拒绝 0x02；
//   - Read 带白名单 [0x01, 0x02] 同时接受 v1/v2 帧；
//   - Write 用传入 version 写入帧头，wire 层真正反映协议版本。
//
// 回归：此前 Version 硬编码为常量，v2 帧无法生成也无法解析。
func TestReadMultiVersion(t *testing.T) {
	const v2 = byte(0x02)
	payload := []byte("multi-version payload")

	// v2 帧由 Write(version=0x02) 生成
	buf := &bytes.Buffer{}
	if err := Write(buf, v2, TypeBatch, FlagData, ChannelData, payload); err != nil {
		t.Fatalf("Write v2: %v", err)
	}
	if buf.Bytes()[4] != v2 {
		t.Fatalf("frame version byte = 0x%02x, want 0x%02x", buf.Bytes()[4], v2)
	}

	// 默认 Read（仅 0x01）：拒绝 v2 帧
	_, err := Read(bytes.NewReader(buf.Bytes()), DefaultLimits())
	if err == nil {
		t.Fatal("default Read should reject v2 frame")
	}

	// Read 带白名单 [0x01, 0x02]：接受 v2 帧
	f, err := Read(bytes.NewReader(buf.Bytes()), DefaultLimits(), Version, v2)
	if err != nil {
		t.Fatalf("Read with [0x01,0x02] whitelist: %v", err)
	}
	if f.Header.Version != v2 {
		t.Errorf("frame version = 0x%02x, want 0x%02x", f.Header.Version, v2)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Errorf("payload mismatch: got %q, want %q", f.Payload, payload)
	}

	// v1 帧仍被默认 Read 接受（向后兼容）
	v1Buf := &bytes.Buffer{}
	if err := Write(v1Buf, Version, TypeBatch, FlagData, ChannelData, payload); err != nil {
		t.Fatalf("Write v1: %v", err)
	}
	if _, err := Read(bytes.NewReader(v1Buf.Bytes()), DefaultLimits()); err != nil {
		t.Fatalf("default Read should accept v1 frame: %v", err)
	}
}

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

func TestVarintRoundTrip(t *testing.T) {
	values := []uint64{0, 1, 127, 128, 16383, 16384, 1 << 20, uint64(MaxPayloadSize)}
	for _, v := range values {
		var buf [maxVarintLen]byte
		n := putVarint(buf[:], v)
		got, gotN, err := readVarint(bytes.NewReader(buf[:n]))
		if err != nil {
			t.Errorf("readVarint(%d) error: %v", v, err)
		}
		if got != v {
			t.Errorf("readVarint = %d, want %d", got, v)
		}
		if gotN != n {
			t.Errorf("readVarint bytes = %d, want %d", gotN, n)
		}
	}
}

func TestVarintRejectsNonCanonical(t *testing.T) {
	_, _, err := readVarint(bytes.NewReader([]byte{0x81, 0x00}))
	if err == nil {
		t.Error("readVarint should reject non-canonical encoding")
	}
}

// TestFrameTypeRedirect verifies the HA cluster-redirect control frame
// (TypeRedirect=17) round-trips through Write/Read with the control-channel
// conventions used by a follower replica redirecting an agent to the leader.
func TestFrameTypeRedirect(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte(`{"leaderAddr":"10.0.0.1:8443","leaderId":"pod-abc"}`)
	if err := Write(&buf, Version, TypeRedirect, FlagControl, ChannelControl, payload); err != nil {
		t.Fatal(err)
	}
	f, err := Read(&buf, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if f.Header.Type != TypeRedirect {
		t.Errorf("type = %d, want %d", f.Header.Type, TypeRedirect)
	}
	if f.Header.Flags != FlagControl {
		t.Errorf("flags = %x, want %x (FlagControl)", f.Header.Flags, FlagControl)
	}
	if f.Header.ChannelID != ChannelControl {
		t.Errorf("channel = %d, want %d (ChannelControl)", f.Header.ChannelID, ChannelControl)
	}
	if string(f.Payload) != string(payload) {
		t.Errorf("payload round-trip failed")
	}
}
