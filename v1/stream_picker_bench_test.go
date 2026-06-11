package v1

import (
	"testing"

	"github.com/iuboy/mbta-go/core"
)

func BenchmarkSingleStream_Pick(b *testing.B) {
	p := NewSingleStream(&mockStream{idx: 0})
	batch := core.BatchMessage{Seq: 1, ChunkID: "c1", Tag: "tag", Source: "src"}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := p.Pick(batch)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashStreamPicker_Pick(b *testing.B) {
	p := NewHashStreamPicker()
	for i := range 8 {
		p.AddStream(&mockStream{idx: i})
	}
	batch := core.BatchMessage{Seq: 1, ChunkID: "c1", Tag: "tag", Source: "src"}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := p.Pick(batch)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashStreamPicker_ConcurrentPick(b *testing.B) {
	p := NewHashStreamPicker()
	for i := range 8 {
		p.AddStream(&mockStream{idx: i})
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			batch := core.BatchMessage{
				Seq:     uint64(i),
				ChunkID: "c",
				Tag:     "tag",
				Source:  "src",
			}
			_, err := p.Pick(batch)
			if err != nil {
				b.Fatal(err)
			}
			i++
		}
	})
}
