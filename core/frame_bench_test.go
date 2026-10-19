package core

// frame_bench_test.go：r3 帧编解码往返基准。
//
// 帧格式 [type(1)][flags(1)][varint Length][Payload]，无帧层 CRC（完整性由
// 传输层 AEAD + envelope AEAD 承担）。Write+Read 往返覆盖：定长头写入、
// varint 编码/最短编码校验、长度上限校验、payload 分配与读取。
// 数量级预期：1KB 往返 ~百纳秒-微秒级（bytes.Buffer 内存拷贝主导），
// allocs/op 主要来自 Read 侧 payload 分配（协议必需——帧载荷交由上层持有）。

import (
	"bytes"
	"testing"
)

// BenchmarkFrameRoundTrip Write→Read 单帧往返（1KB/16KB payload）。
func BenchmarkFrameRoundTrip(b *testing.B) {
	for _, tc := range []struct {
		name string
		n    int
	}{
		{"1KB", 1 * 1024},
		{"16KB", 16 * 1024},
	} {
		b.Run(tc.name, func(b *testing.B) {
			payload := bytes.Repeat([]byte{0xA5}, tc.n)
			var buf bytes.Buffer
			lim := DefaultLimits()

			// 正确性哨兵：往返保真 + 头字段正确。
			if err := Write(&buf, TypeBatch, 0, payload); err != nil {
				b.Fatalf("write: %v", err)
			}
			f, err := Read(&buf, lim)
			if err != nil {
				b.Fatalf("read: %v", err)
			}
			if f.Header.Type != TypeBatch || f.Header.Length != uint64(tc.n) || !bytes.Equal(f.Payload, payload) {
				b.Fatalf("roundtrip mismatch: type=0x%02x len=%d", f.Header.Type, f.Header.Length)
			}
			buf.Reset()

			b.SetBytes(int64(tc.n))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				buf.Reset()
				if err := Write(&buf, TypeBatch, 0, payload); err != nil {
					b.Fatal(err)
				}
				if _, err := Read(&buf, lim); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkFrameWrite 单压 Write（编码路径，无读侧分配）。
func BenchmarkFrameWrite(b *testing.B) {
	for _, tc := range []struct {
		name string
		n    int
	}{
		{"1KB", 1 * 1024},
		{"16KB", 16 * 1024},
	} {
		b.Run(tc.name, func(b *testing.B) {
			payload := bytes.Repeat([]byte{0xA5}, tc.n)
			var buf bytes.Buffer
			buf.Grow(tc.n + FixedHeaderSz + 8)

			b.SetBytes(int64(tc.n))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				buf.Reset()
				if err := Write(&buf, TypeBatch, 0, payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
