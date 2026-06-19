package core

import (
	"strings"
	"testing"
)

// TestSeqGenerator tests the SeqGenerator functionality.
func TestSeqGenerator(t *testing.T) {
	t.Run("NewSeqGenerator starts at 0", func(t *testing.T) {
		g := NewSeqGenerator()
		if got := g.Current(); got != 0 {
			t.Errorf("Current() = %d, want 0", got)
		}
	})

	t.Run("Next returns monotonically increasing values", func(t *testing.T) {
		g := NewSeqGenerator()
		expected := uint64(1)
		for i := 0; i < 100; i++ {
			got := g.Next()
			if got != expected {
				t.Errorf("Next() = %d, want %d", got, expected)
			}
			expected++
		}
	})

	t.Run("Current returns last issued sequence", func(t *testing.T) {
		g := NewSeqGenerator()
		g.Next()
		g.Next()
		g.Next()
		if got := g.Current(); got != 3 {
			t.Errorf("Current() = %d, want 3", got)
		}
	})

	t.Run("Next is thread-safe", func(t *testing.T) {
		g := NewSeqGenerator()
		done := make(chan bool)
		concurrency := 10

		for i := 0; i < concurrency; i++ {
			go func() {
				for j := 0; j < 100; j++ {
					g.Next()
				}
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < concurrency; i++ {
			<-done
		}

		// Should have exactly 1000 entries
		if got := g.Current(); got != 1000 {
			t.Errorf("Current() = %d, want 1000", got)
		}
	})
}

// TestReplayKey tests the replayKey function.
func TestReplayKey(t *testing.T) {
	tests := []struct {
		name    string
		agentID string
		chunkID string
		want    string
	}{
		{
			name:    "basic key generation",
			agentID: "agent-123",
			chunkID: "chunk-456",
			want:    "agent-123\x00chunk-456",
		},
		{
			name:    "empty chunkID",
			agentID: "agent-123",
			chunkID: "",
			want:    "agent-123\x00",
		},
		{
			name:    "chunkID with null byte",
			agentID: "agent-123",
			chunkID: "chunk\x00456",
			want:    "agent-123\x00chunk\x00456",
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
		k1 := replayKey("agent1", "chunk1")
		k2 := replayKey("agent1", "chunk2")
		k3 := replayKey("agent2", "chunk1")
		k4 := replayKey("agent2", "chunk2")

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

		entry := rc.SeenOrAdd("agent-1", "chunk-1")
		if entry != nil {
			t.Errorf("SeenOrAdd() = %v, want nil (first call)", entry)
		}
	})

	t.Run("second call returns existing entry", func(t *testing.T) {
		rc := NewReplayCache()

		// First call - creates entry
		first := rc.SeenOrAdd("agent-1", "chunk-1")
		if first != nil {
			t.Errorf("First SeenOrAdd() = %v, want nil", first)
		}

		// Second call - should return existing entry
		second := rc.SeenOrAdd("agent-1", "chunk-1")
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

		entry1 := rc.SeenOrAdd("agent-1", "chunk-1")
		entry2 := rc.SeenOrAdd("agent-1", "chunk-2")

		if entry1 != nil || entry2 != nil {
			t.Error("Both first calls should return nil")
		}

		// Both should now exist
		entry1 = rc.SeenOrAdd("agent-1", "chunk-1")
		entry2 = rc.SeenOrAdd("agent-1", "chunk-2")

		if entry1 == nil || entry2 == nil {
			t.Error("Both second calls should return entries")
		}
	})

	t.Run("same chunk from different agents creates separate entries", func(t *testing.T) {
		rc := NewReplayCache()

		entry1 := rc.SeenOrAdd("agent-1", "chunk-1")
		entry2 := rc.SeenOrAdd("agent-2", "chunk-1")

		if entry1 != nil || entry2 != nil {
			t.Error("Both first calls should return nil")
		}

		// Verify they are different entries
		entry1 = rc.SeenOrAdd("agent-1", "chunk-1")
		entry2 = rc.SeenOrAdd("agent-2", "chunk-1")

		if entry1 == nil || entry2 == nil {
			t.Error("Both second calls should return entries")
		}

		// Update one and verify the other is unchanged
		rc.Update("agent-1", "chunk-1", ReplayAccepted)
		updated1 := rc.SeenOrAdd("agent-1", "chunk-1")
		updated2 := rc.SeenOrAdd("agent-2", "chunk-1")

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

		rc.SeenOrAdd("agent-1", "chunk-1")
		rc.Update("agent-1", "chunk-1", ReplayAccepted)

		entry := rc.SeenOrAdd("agent-1", "chunk-1")
		if entry.Status != ReplayAccepted {
			t.Errorf("Status = %v, want ReplayAccepted", entry.Status)
		}
	})

	t.Run("update through status transitions", func(t *testing.T) {
		rc := NewReplayCache()

		rc.SeenOrAdd("agent-1", "chunk-1")

		// Processing -> Accepted
		rc.Update("agent-1", "chunk-1", ReplayAccepted)
		entry := rc.SeenOrAdd("agent-1", "chunk-1")
		if entry.Status != ReplayAccepted {
			t.Errorf("Status = %v, want ReplayAccepted", entry.Status)
		}

		// Accepted -> Durable
		rc.Update("agent-1", "chunk-1", ReplayDurable)
		entry = rc.SeenOrAdd("agent-1", "chunk-1")
		if entry.Status != ReplayDurable {
			t.Errorf("Status = %v, want ReplayDurable", entry.Status)
		}

		// Durable -> Rejected (should work even if unusual)
		rc.Update("agent-1", "chunk-1", ReplayRejected)
		entry = rc.SeenOrAdd("agent-1", "chunk-1")
		if entry.Status != ReplayRejected {
			t.Errorf("Status = %v, want ReplayRejected", entry.Status)
		}
	})

	t.Run("update non-existent entry is no-op", func(t *testing.T) {
		rc := NewReplayCache()

		// Update without adding first
		rc.Update("agent-1", "chunk-1", ReplayAccepted)

		// Should still not exist
		entry := rc.SeenOrAdd("agent-1", "chunk-1")
		if entry != nil {
			t.Errorf("Entry should not exist, got Status = %v", entry.Status)
		}
	})
}

// TestReplayCacheGet tests the Get method.
func TestReplayCacheGet(t *testing.T) {
	t.Run("get existing entry", func(t *testing.T) {
		rc := NewReplayCache()

		rc.SeenOrAdd("agent-1", "chunk-1")
		rc.Update("agent-1", "chunk-1", ReplayDurable)

		entry := rc.Get("agent-1", "chunk-1")
		if entry == nil {
			t.Fatal("Get() should return entry for existing key")
		}
		if entry.Status != ReplayDurable {
			t.Errorf("Status = %v, want ReplayDurable", entry.Status)
		}
	})

	t.Run("get non-existent entry", func(t *testing.T) {
		rc := NewReplayCache()

		entry := rc.Get("agent-1", "chunk-1")
		if entry != nil {
			t.Error("Get() should return nil for non-existent entry")
		}
	})
}

// TestReplayCacheLen tests the Len method.
func TestReplayCacheLen(t *testing.T) {
	rc := NewReplayCache()

	if got := rc.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}

	// Add entries
	for i := 0; i < 5; i++ {
		rc.SeenOrAdd("agent-1", strings.Repeat("c", i+1))
	}

	if got := rc.Len(); got != 5 {
		t.Errorf("Len() = %d, want 5", got)
	}

	// Add duplicate (should not increase length)
	rc.SeenOrAdd("agent-1", "ccc")

	if got := rc.Len(); got != 5 {
		t.Errorf("Len() = %d, want 5 (duplicate should not increase)", got)
	}
}

// TestReplayCacheConcurrentAccess tests thread safety.
func TestReplayCacheConcurrentAccess(t *testing.T) {
	rc := NewReplayCache()
	done := make(chan bool)
	concurrency := 10
	opsPerGoroutine := 100

	for i := 0; i < concurrency; i++ {
		go func(workerID int) {
			chunkID := string(rune(workerID))
			for j := 0; j < opsPerGoroutine; j++ {
				rc.SeenOrAdd("agent", chunkID)
				rc.Update("agent", chunkID, ReplayAccepted)
				rc.Get("agent", chunkID)
				rc.Len()
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < concurrency; i++ {
		<-done
	}

	// Should have exactly 'concurrency' unique entries
	if got := rc.Len(); got != concurrency {
		t.Errorf("Len() = %d, want %d", got, concurrency)
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
		{ReplayRejected, 3},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if int(tt.status) != tt.value {
				t.Errorf("ReplayStatus = %d, want %d", int(tt.status), tt.value)
			}
		})
	}
}
