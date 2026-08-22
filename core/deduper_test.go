package core

import (
	"sync"
	"testing"
	"time"
)

// TestCorrelationDeduper 基本语义：首次放行、重复拒绝、空 key 恒放行。
func TestCorrelationDeduper(t *testing.T) {
	t.Parallel()
	d := NewCorrelationDeduper(0, 0) // 默认容量、不过期
	if !d.Dedup("ord-1") {
		t.Error("first Dedup(ord-1) = false, want true")
	}
	if d.Dedup("ord-1") {
		t.Error("second Dedup(ord-1) = true, want false")
	}
	if !d.Dedup("ord-2") {
		t.Error("Dedup(ord-2) = false, want true（不同 key 互不影响）")
	}
	if !d.Dedup("") {
		t.Error("empty key must always pass（不去重语义）")
	}
	if !d.Seen("ord-1") || d.Seen("nope") {
		t.Error("Seen misbehaving")
	}
	if d.Len() != 2 { // ord-1 + ord-2；空 key 不登记
		t.Errorf("Len = %d, want 2", d.Len())
	}
}

// TestCorrelationDeduper_TTL 过期后重新放行。
func TestCorrelationDeduper_TTL(t *testing.T) {
	t.Parallel()
	d := NewCorrelationDeduper(0, 30*time.Millisecond)
	if !d.Dedup("k") {
		t.Fatal("first pass failed")
	}
	if d.Dedup("k") {
		t.Fatal("within TTL: duplicate must be rejected")
	}
	time.Sleep(50 * time.Millisecond)
	if !d.Dedup("k") {
		t.Fatal("after TTL: must pass again（视作首次）")
	}
}

// TestCorrelationDeduper_CapacityEviction 容量淘汰最旧条目。
func TestCorrelationDeduper_CapacityEviction(t *testing.T) {
	t.Parallel()
	d := NewCorrelationDeduper(2, 0)
	d.Dedup("a")
	d.Dedup("b")
	d.Dedup("c") // 淘汰 a
	if d.Seen("a") {
		t.Error("a should have been evicted (cap=2)")
	}
	if !d.Seen("b") || !d.Seen("c") {
		t.Error("b/c must survive")
	}
	if !d.Dedup("a") {
		t.Error("evicted key must pass again")
	}
}

// TestCorrelationDeduper_Concurrent 并发安全烟测（-race 下有效）。
func TestCorrelationDeduper_Concurrent(t *testing.T) {
	t.Parallel()
	d := NewCorrelationDeduper(128, 0)
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 1000 {
				d.Dedup(string(rune('a' + (i+w)%26)))
			}
		}()
	}
	wg.Wait()
}
