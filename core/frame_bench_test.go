package core

import (
	"bytes"
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
		if err := Write(&buf, TypeBatch, FlagEnvelope|FlagData, payload); err != nil {
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
	if err := Write(&buf, TypeBatch, FlagEnvelope|FlagData, payload); err != nil {
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
		if err := Write(&buf, TypeBatch, FlagEnvelope|FlagData, payload); err != nil {
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
	if err := Write(&buf, TypeBatch, FlagEnvelope|FlagData, payload); err != nil {
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
