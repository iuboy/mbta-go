package core

import (
	"testing"
)

func BenchmarkWindow_CanSend(b *testing.B) {
	w := NewWindow(100, 10000, 16*1024*1024)
	inf := &Inflight{}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		w.CanSend(inf, 10, 1024)
	}
}

func BenchmarkWindow_CanSend_Contented(b *testing.B) {
	w := NewWindow(100, 10000, 16*1024*1024)
	inf := &Inflight{}
	inf.Add(50, 5*1024*1024)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		w.CanSend(inf, 10, 1024)
	}
}

func BenchmarkInflight_AddRemove(b *testing.B) {
	inf := &Inflight{}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		inf.Add(10, 1024)
		inf.Remove(10, 1024)
	}
}

func BenchmarkInflight_Concurrent(b *testing.B) {
	inf := &Inflight{}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			inf.Add(1, 100)
			inf.Remove(1, 100)
		}
	})
}

func BenchmarkThrottleState_Active(b *testing.B) {
	ts := &ThrottleState{}
	ts.Apply(5000)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		ts.Active()
	}
}
