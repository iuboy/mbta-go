package core

import (
	"sync"
	"testing"

	"github.com/iuboy/mbta-go/internal/testutil"
)

// TestSeqGenerator tests the SeqGenerator functionality.
func TestSeqGenerator(t *testing.T) {
	t.Run("Next returns monotonically increasing values", func(t *testing.T) {
		g := NewSeqGenerator()
		expected := uint64(1)
		for range 100 {
			got := g.Next()
			if got != expected {
				t.Errorf("Next() = %d, want %d", got, expected)
			}
			expected++
		}
	})

	t.Run("Next is thread-safe", func(t *testing.T) {
		g := NewSeqGenerator()
		var wg sync.WaitGroup
		concurrency := 10
		unique := make(chan uint64, concurrency*100)

		for range concurrency {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 100 {
					unique <- g.Next()
				}
			}()
		}
		wg.Wait()
		close(unique)

		// 应产生 1000 个唯一序号（无重复即证明原子性）。
		seen := make(map[uint64]bool, 1000)
		for v := range unique {
			if seen[v] {
				t.Errorf("duplicate sequence number: %d", v)
			}
			seen[v] = true
		}
		if len(seen) != 1000 {
			t.Errorf("unique sequence count = %d, want 1000", len(seen))
		}
	})
}

// TestReplayKey tests the replayKey function.
func TestReplayKey(t *testing.T) {
	agentA := testutil.RandAgentID()
	chunkX := testutil.RandChunkLabel()
	tests := []struct {
		name    string
		agentID string
		chunkID string
		want    string
	}{
		{
			name:    "basic key generation",
			agentID: agentA,
			chunkID: chunkX,
			want:    agentA + "\x00" + chunkX,
		},
		{
			name:    "empty chunkID",
			agentID: agentA,
			chunkID: "",
			want:    agentA + "\x00",
		},
		{
			name:    "both empty",
			agentID: "",
			chunkID: "",
			want:    "\x00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := replayKey(tt.agentID, tt.chunkID)
			if got != tt.want {
				t.Errorf("replayKey() = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("Keys are unique for different combinations", func(t *testing.T) {
		a1, a2 := testutil.RandAgentID(), testutil.RandAgentID()
		c1, c2 := testutil.RandChunkLabel(), testutil.RandChunkLabel()
		k1 := replayKey(a1, c1)
		k2 := replayKey(a1, c2)
		k3 := replayKey(a2, c1)
		k4 := replayKey(a2, c2)

		if k1 == k2 || k1 == k3 || k1 == k4 {
			t.Error("k1 should be unique")
		}
		if k2 == k3 || k2 == k4 {
			t.Error("k2 should be unique")
		}
		if k3 == k4 {
			t.Error("k3 and k4 should be different")
		}
	})

	t.Run("No collision for valid inputs (\\x00 separator safe by validation)", func(t *testing.T) {
		// \x00 分隔符安全性依赖 validateAgentID（拒绝 <0x20 含 \x00）和 chunkID
		// hex 校验（仅 [0-9a-f]）的不变量。此处测试合法输入不碰撞。
		prefix := testutil.RandAgentID()
		k1 := replayKey(prefix, "01")
		k2 := replayKey(prefix[:len(prefix)-1], string(prefix[len(prefix)-1])+"01")
		if k1 == k2 {
			t.Error("different valid inputs should not collide")
		}
	})
}

// TestNewReplayCache tests the ReplayCache constructor.
func TestNewReplayCache(t *testing.T) {
	rc := NewReplayCache()
	if rc == nil {
		t.Fatal("NewReplayCache() returned nil")
		return
	}
	if rc.entries == nil {
		t.Error("entries map is not initialized")
	}
}

// TestReplayCacheSeenOrAdd tests the SeenOrAdd method.
func TestReplayCacheSeenOrAdd(t *testing.T) {
	t.Run("first call returns nil (not seen)", func(t *testing.T) {
		rc := NewReplayCache()

		entry := rc.SeenOrAdd(testutil.RandAgentID(), testutil.RandChunkLabel())
		if entry != nil {
			t.Errorf("SeenOrAdd() = %v, want nil (first call)", entry)
		}
	})

	t.Run("second call returns existing entry", func(t *testing.T) {
		rc := NewReplayCache()
		agent, chunk := testutil.RandAgentID(), testutil.RandChunkLabel()

		// First call - creates entry
		first := rc.SeenOrAdd(agent, chunk)
		if first != nil {
			t.Errorf("First SeenOrAdd() = %v, want nil", first)
		}

		// Second call - should return existing entry
		second := rc.SeenOrAdd(agent, chunk)
		if second == nil {
			t.Fatal("Second SeenOrAdd() = nil, want existing entry")
			return
		}
		if second.Status != ReplayProcessing {
			t.Errorf("Entry Status = %v, want ReplayProcessing", second.Status)
		}
	})

	t.Run("different keys are independent", func(t *testing.T) {
		rc := NewReplayCache()
		agent := testutil.RandAgentID()
		chunk1, chunk2 := testutil.RandChunkLabel(), testutil.RandChunkLabel()

		entry1 := rc.SeenOrAdd(agent, chunk1)
		entry2 := rc.SeenOrAdd(agent, chunk2)

		if entry1 != nil || entry2 != nil {
			t.Error("Both first calls should return nil")
		}

		// Both should now exist
		entry1 = rc.SeenOrAdd(agent, chunk1)
		entry2 = rc.SeenOrAdd(agent, chunk2)

		if entry1 == nil || entry2 == nil {
			t.Error("Both second calls should return entries")
		}
	})

	t.Run("same chunk from different agents creates separate entries", func(t *testing.T) {
		rc := NewReplayCache()
		agent1, agent2 := testutil.RandAgentID(), testutil.RandAgentID()
		chunk := testutil.RandChunkLabel()

		entry1 := rc.SeenOrAdd(agent1, chunk)
		entry2 := rc.SeenOrAdd(agent2, chunk)

		if entry1 != nil || entry2 != nil {
			t.Error("Both first calls should return nil")
		}

		// Verify they are different entries
		entry1 = rc.SeenOrAdd(agent1, chunk)
		entry2 = rc.SeenOrAdd(agent2, chunk)

		if entry1 == nil || entry2 == nil {
			t.Error("Both second calls should return entries")
		}

		// Update one and verify the other is unchanged
		rc.Update(agent1, chunk, ReplayAccepted)
		updated1 := rc.SeenOrAdd(agent1, chunk)
		updated2 := rc.SeenOrAdd(agent2, chunk)

		if updated1.Status != ReplayAccepted {
			t.Errorf("agent-1 entry Status = %v, want ReplayAccepted", updated1.Status)
		}
		if updated2.Status != ReplayProcessing {
			t.Errorf("agent-2 entry Status = %v, want ReplayProcessing", updated2.Status)
		}
	})
}

// TestReplayCacheUpdate tests the Update method.
func TestReplayCacheUpdate(t *testing.T) {
	t.Run("update existing entry", func(t *testing.T) {
		rc := NewReplayCache()
		agent, chunk := testutil.RandAgentID(), testutil.RandChunkLabel()

		rc.SeenOrAdd(agent, chunk)
		rc.Update(agent, chunk, ReplayAccepted)

		entry := rc.SeenOrAdd(agent, chunk)
		if entry.Status != ReplayAccepted {
			t.Errorf("Status = %v, want ReplayAccepted", entry.Status)
		}
	})

	t.Run("update through status transitions", func(t *testing.T) {
		rc := NewReplayCache()
		agent, chunk := testutil.RandAgentID(), testutil.RandChunkLabel()

		rc.SeenOrAdd(agent, chunk)

		// Processing -> Accepted
		rc.Update(agent, chunk, ReplayAccepted)
		entry := rc.SeenOrAdd(agent, chunk)
		if entry.Status != ReplayAccepted {
			t.Errorf("Status = %v, want ReplayAccepted", entry.Status)
		}

		// Accepted -> Durable
		rc.Update(agent, chunk, ReplayDurable)
		entry = rc.SeenOrAdd(agent, chunk)
		if entry.Status != ReplayDurable {
			t.Errorf("Status = %v, want ReplayDurable", entry.Status)
		}
	})

	t.Run("update non-existent entry is no-op", func(t *testing.T) {
		rc := NewReplayCache()
		agent, chunk := testutil.RandAgentID(), testutil.RandChunkLabel()

		// Update without adding first
		rc.Update(agent, chunk, ReplayAccepted)

		// Should still not exist
		entry := rc.SeenOrAdd(agent, chunk)
		if entry != nil {
			t.Errorf("Entry should not exist, got Status = %v", entry.Status)
		}
	})
}

// TestReplayCacheReverseTransition 回归：done→Processing 反向转换。
// 修复 throttle 数据丢失：applyRouteResult 在 throttle 时将 done 条目移回 processingList，
// 否则条目会被当作已完成驱逐、且 processingList 计数不一致。
func TestReplayCacheReverseTransition(t *testing.T) {
	rc := NewReplayCache()
	agent, chunk := testutil.RandAgentID(), testutil.RandChunkLabel()
	rc.SeenOrAdd(agent, chunk)             // 初始 Processing
	rc.Update(agent, chunk, ReplayDurable) // → doneList

	// 反向：done → Processing（throttle 重试场景）。
	rc.Update(agent, chunk, ReplayProcessing)

	// 用 SeenOrAdd 读取已存在条目（Get 已移除）：对已存在 key 返回非 nil entry。
	existing := rc.SeenOrAdd(agent, chunk)
	if existing == nil {
		t.Fatal("entry should exist after reverse transition")
	}
	if existing.Status != ReplayProcessing {
		t.Errorf("Status = %v, want ReplayProcessing", existing.Status)
	}
}

// TestReplayCacheConcurrentAccess tests thread safety.
func TestReplayCacheConcurrentAccess(t *testing.T) {
	rc := NewReplayCache()
	done := make(chan bool)
	concurrency := 10
	opsPerGoroutine := 100
	agent := testutil.RandAgentID()

	for i := range concurrency {
		go func(workerID int) {
			chunkID := string(rune(workerID))
			for range opsPerGoroutine {
				rc.SeenOrAdd(agent, chunkID)
				rc.Update(agent, chunkID, ReplayAccepted)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for range concurrency {
		<-done
	}

	// 每个-worker 用唯一 chunkID，SeenOrAdd 应收敛到 concurrency 个唯一条目（无重复、无 panic）。
	// 用 SeenOrAdd 验证：对已存在条目返回非 nil，对每个 workerID 的二次查效应命中。
	for i := range concurrency {
		chunkID := string(rune(i))
		if existing := rc.SeenOrAdd(agent, chunkID); existing == nil {
			t.Errorf("worker %d: SeenOrAdd returned nil for existing entry", i)
		}
	}
}

// TestReplayStatusValues tests ReplayStatus enum values.
func TestReplayStatusValues(t *testing.T) {
	tests := []struct {
		status ReplayStatus
		value  int
	}{
		{ReplayProcessing, 0},
		{ReplayAccepted, 1},
		{ReplayDurable, 2},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if int(tt.status) != tt.value {
				t.Errorf("ReplayStatus = %d, want %d", int(tt.status), tt.value)
			}
		})
	}
}
