package core

import (
	"bytes"
	"io"
	"testing"
)

func BenchmarkWrite(b *testing.B) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var buf bytes.Buffer
		if err := Write(&buf, TypeBatch, FlagEnvelope|FlagData, ChannelData, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRead(b *testing.B) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	var buf bytes.Buffer
	if err := Write(&buf, TypeBatch, FlagEnvelope|FlagData, ChannelData, payload); err != nil {
		b.Fatal(err)
	}
	data := buf.Bytes()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := Read(bytes.NewReader(data), DefaultLimits())
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteLargePayload(b *testing.B) {
	payload := make([]byte, 64*1024) // 64 KiB
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var buf bytes.Buffer
		if err := Write(&buf, TypeBatch, FlagEnvelope|FlagData, ChannelData, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadLargePayload(b *testing.B) {
	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	var buf bytes.Buffer
	if err := Write(&buf, TypeBatch, FlagEnvelope|FlagData, ChannelData, payload); err != nil {
		b.Fatal(err)
	}
	data := buf.Bytes()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := Read(bytes.NewReader(data), DefaultLimits())
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWriteDiscard 用 io.Discard（无内部 grow）隔离 frame.Write 自身的分配。
// 真实场景下 writer 是持久的 quic.Stream（无 grow），此处的 1 alloc/16B 即 hdr
// 因 io.Writer 接口调用逃逸的开销——bytes.Buffer 版（BenchmarkWrite）的其余 allocs
// 来自 Buffer 内部 grow，属测试方法产物，非 frame.Write 真实开销。
func BenchmarkWriteDiscard(b *testing.B) {
	payload := make([]byte, 1024)
	b.ReportAllocs()
	for b.Loop() {
		if err := Write(io.Discard, TypeBatch, FlagEnvelope|FlagData, ChannelData, payload); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReadPersistent 用可 Reset 的 bytes.Reader，避免每次循环 bytes.NewReader
// 的分配，隔离 frame.Read 自身开销（hdr 逃逸 + payload 分配）。
func BenchmarkReadPersistent(b *testing.B) {
	payload := make([]byte, 1024)
	var buf bytes.Buffer
	if err := Write(&buf, TypeBatch, FlagEnvelope|FlagData, ChannelData, payload); err != nil {
		b.Fatal(err)
	}
	data := buf.Bytes()
	reader := bytes.NewReader(data)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		reader.Reset(data)
		if _, err := Read(reader, DefaultLimits()); err != nil {
			b.Fatal(err)
		}
	}
}
