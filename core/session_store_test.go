package core

import (
	"sync"
	"testing"
	"time"
)

// TestSessionStore_PutGetDelete 覆盖基础存取删语义。
func TestSessionStore_PutGetDelete(t *testing.T) {
	s := NewSessionStore()
	defer s.Close()

	ticket, _ := NewTicket()
	state := &SessionState{
		Keys:    &SessionKeys{KeyID: "k1"},
		AgentID: "agent-1",
		Expiry:  time.Now().Add(time.Hour),
	}

	// 未存入 → not found
	if _, ok := s.Get(ticket); ok {
		t.Fatal("Get before Put should miss")
	}

	s.Put(ticket, state)
	got, ok := s.Get(ticket)
	if !ok {
		t.Fatal("Get after Put should hit")
	}
	if got.AgentID != "agent-1" {
		t.Errorf("AgentID = %q, want agent-1", got.AgentID)
	}

	s.Delete(ticket)
	if _, ok := s.Get(ticket); ok {
		t.Fatal("Get after Delete should miss")
	}
}

// TestSessionStore_ExpiredNotReturned 验证过期 ticket 在 Get 时被识别为未命中。
func TestSessionStore_ExpiredNotReturned(t *testing.T) {
	s := NewSessionStore()
	defer s.Close()

	ticket, _ := NewTicket()
	s.Put(ticket, &SessionState{
		Keys:    &SessionKeys{KeyID: "k1"},
		AgentID: "agent-1",
		Expiry:  time.Now().Add(-time.Minute), // 已过期
	})

	if _, ok := s.Get(ticket); ok {
		t.Fatal("expired ticket should not be returned")
	}
}

// TestSessionStore_ReaperEvictsExpired 验证后台 reaper 周期性淘汰过期条目，
// 不影响未过期条目。
func TestSessionStore_ReaperEvictsExpired(t *testing.T) {
	s := NewSessionStore(WithReaperInterval(20 * time.Millisecond))
	defer s.Close()

	freshTicket, _ := NewTicket()
	expiredTicket, _ := NewTicket()

	s.Put(freshTicket, &SessionState{
		Keys: &SessionKeys{KeyID: "fresh"}, AgentID: "a-fresh",
		Expiry: time.Now().Add(time.Hour),
	})
	s.Put(expiredTicket, &SessionState{
		Keys: &SessionKeys{KeyID: "expired"}, AgentID: "a-expired",
		Expiry: time.Now().Add(-time.Minute),
	})

	// 轮询内部 map，等待后台 reaper 至少跑一轮淘汰过期条目（最多 500ms）。
	deadline := time.Now().Add(500 * time.Millisecond)
	evicted := false
	for time.Now().Before(deadline) {
		s.mu.Lock()
		_, expiredStillThere := s.sessions[string(expiredTicket)]
		_, freshStillThere := s.sessions[string(freshTicket)]
		s.mu.Unlock()
		if !expiredStillThere {
			if !freshStillThere {
				t.Fatal("reaper evicted fresh entry (should be preserved)")
			}
			evicted = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !evicted {
		t.Fatal("reaper did not evict expired entry within timeout")
	}

	// 未过期条目仍可命中。
	if _, ok := s.Get(freshTicket); !ok {
		t.Fatal("fresh ticket should still be present")
	}
}

// TestSessionStore_CloseIdempotent 验证 Close 可重复调用而不 panic（包括未启用 reaper 的实例）。
func TestSessionStore_CloseIdempotent(t *testing.T) {
	// 未启用 reaper
	s1 := NewSessionStore()
	s1.Close() // 应为 no-op，不 panic
	s1.Close()

	// 启用 reaper
	s2 := NewSessionStore(WithReaperInterval(100 * time.Millisecond))
	s2.Close()
	s2.Close() // 重复关闭不 panic
}

// TestSessionStore_ReaperPreservesFresh 确认 reaper 不会误删未过期条目。
func TestSessionStore_ReaperPreservesFresh(t *testing.T) {
	s := NewSessionStore(WithReaperInterval(20 * time.Millisecond))
	defer s.Close()

	ticket, _ := NewTicket()
	s.Put(ticket, &SessionState{
		Keys: &SessionKeys{KeyID: "k"}, AgentID: "a",
		Expiry: time.Now().Add(time.Hour),
	})

	// 经过若干 reaper 周期后，条目仍应存在。
	time.Sleep(80 * time.Millisecond)
	if _, ok := s.Get(ticket); !ok {
		t.Fatal("fresh ticket evicted by reaper")
	}
}

// TestChunkID_ConcurrentUnique 验证 NewChunkID 在高并发下不 panic 且产出唯一 ID。
// 回归 P0 修复：ulid.Monotonic 非线程安全，曾导致 panic: slice bounds out of range。
func TestChunkID_ConcurrentUnique(t *testing.T) {
	const goroutines = 32
	const perG = 500

	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[ChunkID]struct{}, goroutines*perG)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				id := NewChunkID()
				mu.Lock()
				seen[id] = struct{}{}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	want := goroutines * perG
	if len(seen) != want {
		t.Fatalf("unique ChunkID count = %d, want %d (collision or non-monotonic entropy)", len(seen), want)
	}
}
