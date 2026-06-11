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
		key := Key("agent", fmt.Sprintf("chunk-%d", b.N))
		rc.SeenOrAdd(key)
	}
}

func BenchmarkReplayCache_SeenOrAdd_Hit(b *testing.B) {
	rc := NewReplayCache()
	// Pre-populate
	for i := range 1000 {
		key := Key("agent", fmt.Sprintf("chunk-%d", i))
		rc.SeenOrAdd(key)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		key := Key("agent", fmt.Sprintf("chunk-%d", b.N%1000))
		rc.SeenOrAdd(key)
	}
}

func BenchmarkReplayCache_ConcurrentSeenOrAdd(b *testing.B) {
	rc := NewReplayCache()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := Key("agent", fmt.Sprintf("chunk-%d", i))
			rc.SeenOrAdd(key)
			i++
		}
	})
}
