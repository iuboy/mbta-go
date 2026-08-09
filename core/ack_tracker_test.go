package core

import (
	"sync"
	"testing"
	"time"
)

// mkChunkID 构造一个可区分的 ChunkID：把 seq 的低 16 字节填入（测试专用）。
func mkChunkID(seq uint64) ChunkID {
	var c ChunkID
	for i := 0; i < 8; i++ {
		c[i] = byte(seq >> (i * 8))
	}
	// 高 8 字节填固定标记，避免与全零混淆。
	c[8] = 0xAB
	return c
}

func TestAckTracker_ReserveRelease_RoundTrip(t *testing.T) {
	tr := NewAckTracker(10, 100, 1000)
	now := time.Now()
	cid := mkChunkID(1)

	if !tr.CanSend(1, 5, 100) {
		t.Fatal("CanSend should allow within limits")
	}
	tr.Reserve(1, cid, 5, 100, now, now.Add(time.Minute))

	if tr.PendingCount() != 1 {
		t.Errorf("PendingCount after reserve = %d, want 1", tr.PendingCount())
	}
	if tr.Empty() {
		t.Error("Empty should be false after reserve")
	}

	slot, ok := tr.Release(1, cid)
	if !ok {
		t.Fatal("Release should succeed for matching seq+chunkID")
	}
	if slot.Events != 5 || slot.Bytes != 100 {
		t.Errorf("released slot = (events=%d, bytes=%d), want (5, 100)", slot.Events, slot.Bytes)
	}
	if !slot.SentAt.Equal(now) {
		t.Errorf("sentAt not preserved: got %v want %v", slot.SentAt, now)
	}
	if tr.PendingCount() != 0 {
		t.Errorf("PendingCount after release = %d, want 0", tr.PendingCount())
	}
	if !tr.Empty() {
		t.Error("Empty should be true after release")
	}
}

func TestAckTracker_CanSend_CapacityBoundaries(t *testing.T) {
	tr := NewAckTracker(10, 100, 1000)
	now := time.Now()

	// 恰好等于上限：batches 0+1<=10, events 0+100<=100, bytes 0+1000<=1000。
	if !tr.CanSend(1, 100, 1000) {
		t.Error("CanSend should allow batch exactly at all limits")
	}

	// events 超限。
	if tr.CanSend(2, 101, 1000) {
		t.Error("CanSend should reject events exceeding limit")
	}
	// bytes 超限。
	if tr.CanSend(3, 100, 1001) {
		t.Error("CanSend should reject bytes exceeding limit")
	}
	// batches 超限：占满 10 个后再发应拒绝。
	for seq := uint64(1); seq <= 10; seq++ {
		tr.Reserve(seq, mkChunkID(seq), 1, 10, now, now.Add(time.Minute))
	}
	// 跨度检查会先拦截（seq 11 - oldest 1 = 10 >= AckRingSize=100 不成立，故不拦），
	// 但 batches 计数 10+1 > 10 应拦截。
	if tr.CanSend(11, 1, 10) {
		t.Error("CanSend should reject when batch count exceeds limit")
	}
}

func TestAckTracker_CanSend_PausedDimension(t *testing.T) {
	// max=0 表示该维度暂停。
	tr := NewAckTracker(0, 100, 1000)
	if tr.CanSend(1, 1, 1) {
		t.Error("CanSend should reject when maxBatches=0 (paused)")
	}
}

func TestAckTracker_CanSend_SeqSpanCheck(t *testing.T) {
	// 用 AckRingSize=100 作为跨度上界。设 maxBatches 足够大，隔离跨度检查的效果。
	tr := NewAckTracker(AckRingSize, AckRingSize*100, int64(AckRingSize)*1000)
	now := time.Now()

	// 占用 seq=1（队头）。
	tr.Reserve(1, mkChunkID(1), 1, 1, now, now.Add(time.Hour))

	// 跨度 = 99（seq 100 - 1）：可通过。
	if !tr.CanSend(100, 1, 1) {
		t.Error("CanSend should allow span=99 (< AckRingSize)")
	}
	// 跨度 = 100（seq 101 - 1）：应拒绝（>= AckRingSize）。
	if tr.CanSend(101, 1, 1) {
		t.Error("CanSend should reject span=100 (>= AckRingSize)")
	}

	// 释放队头后，跨度检查应放宽。
	if _, ok := tr.Release(1, mkChunkID(1)); !ok {
		t.Fatal("Release seq=1 failed")
	}
	// 现在 oldestSeq 重新计算（tracker 空 → 0），seq 101 可过。
	if !tr.CanSend(101, 1, 1) {
		t.Error("CanSend should allow seq=101 after head released")
	}
}

func TestAckTracker_Release_WrongChunkID(t *testing.T) {
	tr := NewAckTracker(10, 100, 1000)
	now := time.Now()
	tr.Reserve(1, mkChunkID(1), 5, 100, now, now.Add(time.Minute))

	// seq 对但 chunkID 错：不应释放。
	if _, ok := tr.Release(1, mkChunkID(999)); ok {
		t.Error("Release should fail with mismatched chunkID")
	}
	if tr.PendingCount() != 1 {
		t.Errorf("PendingCount after failed release = %d, want 1", tr.PendingCount())
	}

	// seq 错（指向空 slot）。
	if _, ok := tr.Release(2, mkChunkID(2)); ok {
		t.Error("Release should fail for unreserved seq")
	}
}

func TestAckTracker_Release_IdempotentUnderConcurrentClaims(t *testing.T) {
	// 模拟三路并发 claim（handleAck / handleNack / ackReaper）。
	tr := NewAckTracker(10, 100, 1000)
	now := time.Now()
	tr.Reserve(1, mkChunkID(1), 5, 100, now, now.Add(time.Minute))

	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := tr.Release(1, mkChunkID(1)); ok {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Errorf("exactly one claim should succeed, got %d", successCount)
	}
	if tr.PendingCount() != 0 {
		t.Errorf("PendingCount after concurrent claims = %d, want 0", tr.PendingCount())
	}
}

func TestAckTracker_ReapExpired(t *testing.T) {
	tr := NewAckTracker(10, 100, 1000)
	base := time.Now()

	// seq=1 已过期，seq=2 未过期。
	tr.Reserve(1, mkChunkID(1), 5, 50, base, base.Add(-time.Minute)) // deadline 在过去
	tr.Reserve(2, mkChunkID(2), 3, 30, base, base.Add(time.Minute))  // deadline 在未来

	if tr.PendingCount() != 2 {
		t.Fatalf("PendingCount = %d, want 2 before reap", tr.PendingCount())
	}

	reaped := tr.ReapExpired(base)
	if len(reaped) != 1 {
		t.Fatalf("ReapExpired returned %d slots, want 1", len(reaped))
	}
	if reaped[0].Seq != 1 {
		t.Errorf("reaped slot seq = %d, want 1", reaped[0].Seq)
	}
	if tr.PendingCount() != 1 {
		t.Errorf("PendingCount after reap = %d, want 1", tr.PendingCount())
	}

	// 队头变为 seq=2。
	if !tr.CanSend(102, 1, 1) { // 跨度 102-2=100 >= 100 → 应拒绝（队头未释放）
		// 注：跨度=100 被拒，验证 oldestSeq 已更新为 2。
		// 反向验证：跨度=99（seq 101）应通过。
		if !tr.CanSend(101, 1, 1) {
			t.Error("CanSend should allow span=99 after reap updated oldestSeq")
		}
	} else {
		t.Error("CanSend should reject span=100 (seq 102 vs oldest 2)")
	}
}

func TestAckTracker_ReapExpired_All(t *testing.T) {
	tr := NewAckTracker(10, 100, 1000)
	base := time.Now()
	tr.Reserve(1, mkChunkID(1), 5, 50, base, base.Add(-time.Minute))
	tr.Reserve(2, mkChunkID(2), 3, 30, base, base.Add(-time.Minute))

	reaped := tr.ReapExpired(base)
	if len(reaped) != 2 {
		t.Fatalf("ReapExpired returned %d, want 2", len(reaped))
	}
	if !tr.Empty() {
		t.Error("tracker should be empty after reaping all")
	}
}

func TestAckTracker_Reset(t *testing.T) {
	tr := NewAckTracker(10, 100, 1000)
	now := time.Now()
	tr.Reserve(1, mkChunkID(1), 5, 100, now, now.Add(time.Minute))
	tr.Reserve(2, mkChunkID(2), 3, 50, now, now.Add(time.Minute))

	tr.Reset()

	if !tr.Empty() {
		t.Error("Empty should be true after Reset")
	}
	if tr.PendingCount() != 0 {
		t.Errorf("PendingCount after Reset = %d, want 0", tr.PendingCount())
	}
	// Reset 后 seq=1 的 slot 应已空，Release 失败。
	if _, ok := tr.Release(1, mkChunkID(1)); ok {
		t.Error("Release should fail after Reset (slot cleared)")
	}
	// 容量阈值保留：仍可 Reserve。
	if !tr.CanSend(1, 1, 1) {
		t.Error("CanSend should work after Reset (limits preserved)")
	}
}

func TestAckTracker_UpdateLimits(t *testing.T) {
	tr := NewAckTracker(10, 100, 1000)
	tr.UpdateLimits(5, 50, 500)

	now := time.Now()
	// 占 5 个 batch（新上限）。
	for seq := uint64(1); seq <= 5; seq++ {
		tr.Reserve(seq, mkChunkID(seq), 1, 1, now, now.Add(time.Minute))
	}
	// 第 6 个应被拒（batches 超限）。
	if tr.CanSend(6, 1, 1) {
		t.Error("CanSend should reject after UpdateLimits lowered maxBatches")
	}
}

func TestAckTracker_OldestSeq_UpdateOnHeadRelease(t *testing.T) {
	tr := NewAckTracker(AckRingSize, AckRingSize*100, int64(AckRingSize)*1000)
	now := time.Now()

	// 占 seq 1,2,3。
	tr.Reserve(1, mkChunkID(1), 1, 1, now, now.Add(time.Hour))
	tr.Reserve(2, mkChunkID(2), 1, 1, now, now.Add(time.Hour))
	tr.Reserve(3, mkChunkID(3), 1, 1, now, now.Add(time.Hour))

	// 释放队头 seq=1，oldestSeq 应变为 2。
	if _, ok := tr.Release(1, mkChunkID(1)); !ok {
		t.Fatal("Release seq=1 failed")
	}
	// 跨度验证：seq 102（102-2=100）应拒，seq 101（101-2=99）应过。
	if tr.CanSend(102, 1, 1) {
		t.Error("CanSend should reject span=100 after head release (oldest=2)")
	}
	if !tr.CanSend(101, 1, 1) {
		t.Error("CanSend should allow span=99 after head release (oldest=2)")
	}

	// 释放中间 seq=3（非队头），oldestSeq 应仍为 2。
	if _, ok := tr.Release(3, mkChunkID(3)); !ok {
		t.Fatal("Release seq=3 failed")
	}
	if tr.CanSend(102, 1, 1) {
		t.Error("CanSend should still reject span=100 (oldest still 2)")
	}
}

func TestAckTracker_RingWrapAround(t *testing.T) {
	// 验证 ring 环绕：seq 跨过 AckRingSize 边界后索引正确复用 slot。
	tr := NewAckTracker(AckRingSize, AckRingSize*100, int64(AckRingSize)*1000)
	now := time.Now()

	// 占 seq=1，然后释放，使 slot 1 空出但 oldestSeq 归零。
	tr.Reserve(1, mkChunkID(1), 1, 1, now, now.Add(time.Hour))
	tr.Release(1, mkChunkID(1))

	// seq=101 映射到同一 slot 1（101%100=1），此时 tracker 空应可 Reserve。
	if !tr.CanSend(101, 1, 1) {
		t.Fatal("CanSend should allow seq=101 after slot 1 freed")
	}
	tr.Reserve(101, mkChunkID(101), 2, 20, now, now.Add(time.Hour))

	// Release seq=101 应命中正确 slot（带 chunkID 校验）。
	slot, ok := tr.Release(101, mkChunkID(101))
	if !ok {
		t.Fatal("Release seq=101 should succeed after wrap-around")
	}
	if slot.Events != 2 {
		t.Errorf("wrapped slot events = %d, want 2", slot.Events)
	}
}

func TestAckTracker_ConcurrentReserveRelease(t *testing.T) {
	// 高并发场景：多 goroutine 交替 Reserve/Release，验证无 data race 与计数一致性。
	tr := NewAckTracker(AckRingSize, AckRingSize*1000, int64(AckRingSize)*10000)
	now := time.Now()

	const goroutines = 8
	const opsPerG = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < opsPerG; i++ {
				// 每次操作用一个唯一 seq（gid*opsPerG + i + 1，全局唯一且 < AckRingSize 跨度）。
				// 注意：8*50=400 > AckRingSize=100，跨度检查会拒绝部分，这是预期行为。
				// 这里只验证无 race + 计数非负，不强制全部成功。
				seq := uint64(gid*opsPerG + i + 1)
				cid := mkChunkID(seq)
				if tr.CanSend(seq, 1, 1) {
					tr.Reserve(seq, cid, 1, 1, now, now.Add(time.Hour))
				}
				// 立即尝试释放（可能失败，无害）。
				tr.Release(seq, cid)
			}
		}(g)
	}
	wg.Wait()

	// 最终状态：inflight 不应为负（PendingCount >= 0）。
	if pc := tr.PendingCount(); pc < 0 {
		t.Errorf("PendingCount = %d, must not be negative", pc)
	}
	if !tr.Empty() {
		// 残留的 slot（已 Reserve 未 Release）是允许的；清空验证 Reset 可用。
		tr.Reset()
		if !tr.Empty() {
			t.Error("Reset should clear all slots")
		}
	}
}

func TestAckTracker_AggregateCountersAccurate(t *testing.T) {
	// 验证 events/bytes 聚合计数随 Reserve/Release 精确变化。
	tr := NewAckTracker(100, 10000, 1024*1024)
	now := time.Now()

	tr.Reserve(1, mkChunkID(1), 10, 100, now, now.Add(time.Minute))
	tr.Reserve(2, mkChunkID(2), 20, 200, now, now.Add(time.Minute))

	// 释放 seq=1 后，聚合计数应仅剩 seq=2 的贡献。
	if _, ok := tr.Release(1, mkChunkID(1)); !ok {
		t.Fatal("Release seq=1 failed")
	}

	// 通过 CanSend 间接验证剩余容量：events 余量 = 10000-20，应允许 9980 events。
	if !tr.CanSend(3, 9980, 1) {
		t.Error("CanSend should reflect aggregate after partial release")
	}
	if tr.CanSend(3, 9981, 1) {
		t.Error("CanSend should reject exceeding remaining events aggregate")
	}
}

// TestAckTracker_MarkAccepted 验证 ACK 升级机制：MarkAccepted 标记 slot 为 Accepted
// 但不释放（slot 保留，count 不减），后续 durable ACK 的 Release 才释放。
// 模拟 Durable sink 连接（useAckLevel=true）的 accepted→durable 序列。
func TestAckTracker_MarkAccepted(t *testing.T) {
	tr := NewAckTracker(10, 100, 1000)
	now := time.Now()
	cid := mkChunkID(1)

	tr.Reserve(1, cid, 5, 100, now, now.Add(time.Minute))
	if tr.PendingCount() != 1 {
		t.Fatalf("PendingCount after reserve = %d, want 1", tr.PendingCount())
	}

	// accepted：MarkAccepted 标记，不释放 slot。
	if !tr.MarkAccepted(1, cid) {
		t.Fatal("MarkAccepted should succeed for matching seq+chunkID")
	}
	if tr.PendingCount() != 1 {
		t.Errorf("PendingCount after MarkAccepted = %d, want 1 (slot retained)", tr.PendingCount())
	}
	if tr.Empty() {
		t.Error("Empty should be false after MarkAccepted (slot retained)")
	}
	// slot 仍在且 AckLevel=Accepted。
	idx := 1 % AckRingSize
	if tr.slots[idx].AckLevel != AckLevelAccepted { //nolint:gosec // 测试直接读 slot 验证级别
		t.Errorf("AckLevel = %d, want AckLevelAccepted", tr.slots[idx].AckLevel)
	}

	// durable：Release 释放 slot。
	slot, ok := tr.Release(1, cid)
	if !ok {
		t.Fatal("Release should succeed for durable ACK after MarkAccepted")
	}
	if slot.AckLevel != AckLevelAccepted {
		t.Errorf("released slot AckLevel = %d, want AckLevelAccepted", slot.AckLevel)
	}
	if tr.PendingCount() != 0 {
		t.Errorf("PendingCount after Release = %d, want 0", tr.PendingCount())
	}
	if !tr.Empty() {
		t.Error("Empty should be true after durable Release")
	}
}

// TestAckTracker_MarkAccepted_WrongChunkID 验证 MarkAccepted 对不匹配的 chunkID 返回 false。
func TestAckTracker_MarkAccepted_WrongChunkID(t *testing.T) {
	tr := NewAckTracker(10, 100, 1000)
	now := time.Now()
	tr.Reserve(1, mkChunkID(1), 5, 100, now, now.Add(time.Minute))

	if tr.MarkAccepted(1, mkChunkID(2)) {
		t.Error("MarkAccepted should fail for wrong chunkID")
	}
	if tr.PendingCount() != 1 {
		t.Errorf("PendingCount = %d, want 1 (unchanged after failed MarkAccepted)", tr.PendingCount())
	}
}
