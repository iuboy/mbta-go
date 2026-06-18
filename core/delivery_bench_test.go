package core

import (
	"fmt"
	"testing"
)

func BenchmarkReplayCache_SeenOrAdd(b *testing.B) {
	rc := NewReplayCache()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		rc.SeenOrAdd("agent", fmt.Sprintf("chunk-%d", b.N))
	}
}

func BenchmarkReplayCache_SeenOrAdd_Hit(b *testing.B) {
	rc := NewReplayCache()
	// Pre-populate
	for i := range 1000 {
		rc.SeenOrAdd("agent", fmt.Sprintf("chunk-%d", i))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		rc.SeenOrAdd("agent", fmt.Sprintf("chunk-%d", b.N%1000))
	}
}

func BenchmarkReplayCache_ConcurrentSeenOrAdd(b *testing.B) {
	rc := NewReplayCache()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			rc.SeenOrAdd("agent", fmt.Sprintf("chunk-%d", i))
			i++
		}
	})
}
