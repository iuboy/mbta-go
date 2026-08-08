package core

import (
	"sync/atomic"
	"testing"
	"time"
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

// BenchmarkAckTracker_ReserveRelease 量化 client 端流控单次发送往返开销
// （CanSend + Reserve + Release），替代原 window.CanSend + inflight.Add/Remove +
// pendingAcks.Store/LoadAndDelete 三步。零分配。
func BenchmarkAckTracker_ReserveRelease(b *testing.B) {
	tr := NewAckTracker(AckRingSize, AckRingSize*100, int64(AckRingSize)*1024)
	now := time.Now()
	dead := now.Add(time.Minute)

	b.ResetTimer()
	b.ReportAllocs()
	var i uint64
	for range b.N {
		// seq 循环用 1..99（跨度 < AckRingSize，避免 CanSend 拒绝）。
		seq := i%99 + 1
		i++
		cid := mkChunkID(seq)
		tr.CanSend(seq, 1, 100)
		tr.Reserve(seq, cid, 1, 100, now, dead)
		tr.Release(seq, cid)
	}
}

// BenchmarkAckTracker_Concurrent 量化高并发 Reserve/Release 的锁竞争开销，
// 对照 BenchmarkInflight_Concurrent（原无锁 atomic 方案）。
func BenchmarkAckTracker_Concurrent(b *testing.B) {
	tr := NewAckTracker(AckRingSize, AckRingSize*1000, int64(AckRingSize)*10000)
	now := time.Now()
	dead := now.Add(time.Hour)

	b.ResetTimer()
	b.ReportAllocs()
	var seqCtr uint64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// 每个迭代用独立 seq 槽（跨度内），先 Reserve 再 Release。
			// 并发可能因跨度/容量检查失败跳过 Reserve，Release 容错返回 false。
			seq := atomic.AddUint64(&seqCtr, 1) % 99
			if seq == 0 {
				seq = 99
			}
			cid := mkChunkID(seq)
			if tr.CanSend(seq, 1, 100) {
				tr.Reserve(seq, cid, 1, 100, now, dead)
			}
			tr.Release(seq, cid)
		}
	})
}
