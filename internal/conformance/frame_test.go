package conformance

// frame_test.go：core 帧层接收 MUST 清单（v2-design §2.1 / §16-6）。
//
//   - 2B 头 + varint 长度读写往返；
//   - 长度上限校验先于分配（防声明式 varint 长度直接 OOM）；
//   - varint 非最短编码拒绝 + 最大字节数限制；
//   - 非零 flags 拒绝（读写两侧）；
//   - payload 短读按声明长度 drain 维持帧边界。

import (
	"bytes"
	"io"
	"testing"

	"github.com/iuboy/mbta-go/core"
)

// countReader 统计实际读取字节数（断言「校验先于分配/读取」）。
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func putVarintBytes(v uint64) []byte {
	var buf [10]byte
	n := 0
	x := v
	for {
		b := byte(x & 0x7f)
		x >>= 7
		if x != 0 {
			buf[n] = b | 0x80
			n++
			continue
		}
		buf[n] = b
		n++
		break
	}
	return append([]byte(nil), buf[:n]...)
}

// TestFrame_WriteRead_RoundTrip 验证 2B 头 + varint 长度跨数量级往返。
func TestFrame_WriteRead_RoundTrip(t *testing.T) {
	sizes := []int{0, 1, 127, 128, 300, 16383, 16384, 65536, 1 << 20}
	for _, sz := range sizes {
		payload := bytes.Repeat([]byte{0xA5}, sz)
		var buf bytes.Buffer
		if err := core.Write(&buf, core.TypeBatch, 0, payload); err != nil {
			t.Fatalf("size %d: write: %v", sz, err)
		}
		f, err := core.Read(&buf, core.DefaultLimits())
		if err != nil {
			t.Fatalf("size %d: read: %v", sz, err)
		}
		if f.Header.Type != core.TypeBatch || f.Header.Flags != 0 || f.Header.Length != uint64(sz) {
			t.Fatalf("size %d: header = %+v", sz, f.Header)
		}
		if !bytes.Equal(f.Payload, payload) {
			t.Fatalf("size %d: payload mismatch", sz)
		}
		if buf.Len() != 0 {
			t.Fatalf("size %d: %d bytes left in stream", sz, buf.Len())
		}
	}
}

// TestFrame_Write_RejectsNonZeroFlags 验证写侧拒绝非零 flags（r3 全部位保留）。
func TestFrame_Write_RejectsNonZeroFlags(t *testing.T) {
	var buf bytes.Buffer
	for _, flags := range []byte{0x01, 0x80, 0xFF} {
		err := core.Write(&buf, core.TypeBatch, flags, []byte("x"))
		if err == nil {
			t.Fatalf("flags 0x%02x: write accepted", flags)
		}
		if core.CodeNumOf(err) != core.CodeProtocolError {
			t.Errorf("flags 0x%02x: code = %d, want %d", flags, core.CodeNumOf(err), core.CodeProtocolError)
		}
	}
}

// TestFrame_Write_RejectsOversizePayload 验证写侧 payload 超 MaxFrameBytes 拒绝。
func TestFrame_Write_RejectsOversizePayload(t *testing.T) {
	var buf bytes.Buffer
	payload := make([]byte, core.MaxFrameBytes+1)
	if err := core.Write(&buf, core.TypeBatch, 0, payload); err == nil {
		t.Fatal("oversize payload accepted")
	}
}

// TestFrame_Read_RejectsNonZeroFlags 验证读侧未知 flags 位 → 拒绝（ABORT 语义入口）。
func TestFrame_Read_RejectsNonZeroFlags(t *testing.T) {
	for _, flags := range []byte{0x01, 0x40, 0xFF} {
		stream := io.MultiReader(
			bytes.NewReader([]byte{core.TypeBatch, flags}),
			bytes.NewReader(putVarintBytes(0)),
		)
		if _, err := core.Read(stream, core.DefaultLimits()); err == nil {
			t.Fatalf("flags 0x%02x: read accepted", flags)
		}
	}
}

// TestFrame_Read_LengthLimitBeforeAllocation 验证长度上限校验先于分配：
// 声明超限的帧在读到 varint 后立即拒绝——payload 字节未被读取（无 make、无 drain），
// 且后续流内容不受影响。
func TestFrame_Read_LengthLimitBeforeAllocation(t *testing.T) {
	oversize := uint64(1 << 40) // 远超任何合理分配
	hdr := append([]byte{core.TypeBatch, 0x00}, putVarintBytes(oversize)...)
	validFrame := func() []byte {
		var b bytes.Buffer
		if err := core.Write(&b, core.TypeClose, 0, []byte("next")); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}()

	cr := &countReader{r: bytes.NewReader(append(append([]byte{}, hdr...), validFrame...))}
	_, err := core.Read(cr, core.DefaultLimits())
	if err == nil {
		t.Fatal("oversize declared length accepted")
	}
	if want := int64(len(hdr)); cr.n != want {
		t.Errorf("read %d bytes before rejecting, want %d（校验必须先于 payload 读取/分配）", cr.n, want)
	}
	// 拒绝后流位置保持在 varint 之后：后续合法帧可正常读出。
	f, err := core.Read(cr, core.DefaultLimits())
	if err != nil {
		t.Fatalf("next frame after rejection: %v", err)
	}
	if f.Header.Type != core.TypeClose {
		t.Errorf("next frame type = 0x%02x, want CLOSE", f.Header.Type)
	}
}

// TestFrame_Read_VarintNonCanonical 验证 varint 非最短编码拒绝。
func TestFrame_Read_VarintNonCanonical(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte // varint 字节
	}{
		{"0 用 2 字节", []byte{0x80, 0x00}},
		{"1 用 2 字节", []byte{0x81, 0x00}},
		{"127 用 2 字节", []byte{0xFF, 0x00}},
		{"128 用 3 字节", []byte{0x80, 0x81, 0x00}},
	}
	for _, tc := range cases {
		raw := append([]byte{core.TypeBatch, 0x00}, tc.raw...)
		if _, err := core.Read(bytes.NewReader(raw), core.DefaultLimits()); err == nil {
			t.Errorf("%s: accepted non-canonical varint", tc.name)
		}
	}
	// 对照组合法最短编码应通过（补足声明长度的 payload 字节）。
	for _, tc := range []struct {
		raw  []byte // varint 字节
		size int    // 声明的 payload 长度
	}{
		{[]byte{0x00}, 0},
		{[]byte{0x7F}, 127},
		{[]byte{0x80, 0x01}, 128},
		{[]byte{0xFF, 0x01}, 255},
	} {
		raw := append(append([]byte{core.TypeBatch, 0x00}, tc.raw...), bytes.Repeat([]byte{0x5A}, tc.size)...)
		if _, err := core.Read(bytes.NewReader(raw), core.DefaultLimits()); err != nil {
			t.Errorf("canonical varint % X rejected: %v", tc.raw, err)
		}
	}
}

// TestFrame_Read_VarintTooLong 验证 varint 超过 10 字节上限拒绝。
func TestFrame_Read_VarintTooLong(t *testing.T) {
	raw := append([]byte{core.TypeBatch, 0x00}, bytes.Repeat([]byte{0x80}, 11)...)
	if _, err := core.Read(bytes.NewReader(raw), core.DefaultLimits()); err == nil {
		t.Fatal("11-byte varint accepted")
	}
}

// shortPayloadReader 模拟 TCP 场景：当前帧 payload 中途错误（已给 2 字节后
// 返回 ErrUnexpectedEOF），后续字节属于"下一帧"——Read 的 drain 逻辑必须跳过
// 声明长度的剩余部分（2 字节）再让下一帧从正确边界开始。
type shortPayloadReader struct {
	pre    []byte    // header + varint + 部分 payload
	post   io.Reader // 后续流（模拟 drain 应消费的字节 + 下一帧）
	preEOF bool
}

func (s *shortPayloadReader) Read(p []byte) (int, error) {
	if !s.preEOF {
		if len(s.pre) > 0 {
			n := copy(p, s.pre)
			s.pre = s.pre[n:]
			return n, nil
		}
		s.preEOF = true
		return 0, io.ErrUnexpectedEOF // 当前帧 payload 中断
	}
	return s.post.Read(p)
}

// TestFrame_Read_ShortReadDrains 验证 payload 短读：按声明的剩余长度 drain，
// 维持帧边界（后续帧仍可解析）。
func TestFrame_Read_ShortReadDrains(t *testing.T) {
	var next bytes.Buffer
	if err := core.Write(&next, core.TypeClose, 0, []byte("boundary")); err != nil {
		t.Fatal(err)
	}
	// 声明 payload 4 字节，只给 2 字节；drain 应再消费 2 字节（"XX"）后对齐下一帧。
	stream := &shortPayloadReader{
		pre:  []byte{core.TypeBatch, 0x00, 0x04, 'a', 'b'},
		post: io.MultiReader(bytes.NewReader([]byte{'X', 'X'}), &next),
	}

	if _, err := core.Read(stream, core.DefaultLimits()); err == nil {
		t.Fatal("short payload read accepted")
	}
	f, err := core.Read(stream, core.DefaultLimits())
	if err != nil {
		t.Fatalf("frame boundary lost after short read: %v", err)
	}
	if f.Header.Type != core.TypeClose {
		t.Errorf("next frame type = 0x%02x, want CLOSE（drain 应跳过声明长度后对齐）", f.Header.Type)
	}
}

// TestFrame_Read_LimitsOverride 验证 FrameLimits.MaxFrameBytes 覆盖生效。
func TestFrame_Read_LimitsOverride(t *testing.T) {
	var buf bytes.Buffer
	if err := core.Write(&buf, core.TypeBatch, 0, bytes.Repeat([]byte{1}, 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := core.Read(&buf, core.FrameLimits{MaxFrameBytes: 64}); err == nil {
		t.Error("frame of 100B accepted under 64B limit")
	}
}
