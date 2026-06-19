package core

import (
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"testing"
)

func init() {
	// 压测期间 ReplayCache 的 Processing 淘汰会打 slog.Warn；规模级下百万次日志会
	// 严重拖慢并污染输出。统一丢弃日志，保证压测只度量算法本身。
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// 本文件做规模级压测（1万 / 10万 / 百万），重点验证本次优化的两个 O(n)→O(1) 退化点：
// ReplayCache 淘汰与 Spool 增量计数。ReplayCache 用旧实现 baseline 直观对比收益。

// =====================================================================
// ReplayCache —— 当前实现（list 双链表，淘汰 O(1)）
// =====================================================================

// BenchmarkReplayCache_FullEviction_New：缓存填满（全部 Processing）后持续插入，
// 每次都触发淘汰。当前实现走 processingList 队首 O(1)。
func BenchmarkReplayCache_FullEviction_New(b *testing.B) {
	for _, n := range []int{10_000, 100_000, 1_000_000} {
		b.Run(scaleName(n), func(b *testing.B) {
			rc := NewReplayCacheWithSize(n)
			for i := 0; i < n; i++ {
				rc.SeenOrAdd("a", strconv.Itoa(i))
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				rc.SeenOrAdd("a", fmt.Sprintf("n%d", i))
			}
		})
	}
}

// BenchmarkReplayCache_MixedEviction_New：一半 Processing / 一半 已完成 的混合状态。
// 这是旧实现 O(n) 退化的真实触发场景（淘汰需扫描前段 Processing）。当前实现从 doneList
// 队首 O(1) 取，性能与规模无关。
func BenchmarkReplayCache_MixedEviction_New(b *testing.B) {
	for _, n := range []int{10_000, 100_000, 1_000_000} {
		b.Run(scaleName(n), func(b *testing.B) {
			rc := NewReplayCacheWithSize(n)
			for i := 0; i < n; i++ {
				rc.SeenOrAdd("a", strconv.Itoa(i))
			}
			// 将后半标记为已完成 -> doneList。
			for i := n / 2; i < n; i++ {
				rc.Update("a", strconv.Itoa(i), ReplayAccepted)
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				rc.SeenOrAdd("a", fmt.Sprintf("n%d", i))
			}
		})
	}
}

// =====================================================================
// ReplayCache —— 旧实现 baseline（order []string + 线性扫描 + append 搬移，淘汰 O(n)）
// 用于直观对比优化前后的规模级差异。仅复制 bb63c01 之前的淘汰逻辑。
// =====================================================================

type oldReplayCache struct {
	mu      sync.Mutex
	entries map[string]*ReplayEntry
	maxSize int
	order   []string
}

func newOldReplayCache(maxSize int) *oldReplayCache {
	return &oldReplayCache{
		entries: make(map[string]*ReplayEntry, 1024),
		maxSize: maxSize,
		order:   make([]string, 0, maxSize),
	}
}

func (rc *oldReplayCache) SeenOrAdd(key string) *ReplayEntry {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if e, ok := rc.entries[key]; ok {
		return e
	}
	for len(rc.entries) >= rc.maxSize && len(rc.order) > 0 {
		evicted := false
		for i, k := range rc.order {
			if e, ok := rc.entries[k]; ok && e.Status != ReplayProcessing {
				delete(rc.entries, k)
				rc.order = append(rc.order[:i], rc.order[i+1:]...)
				evicted = true
				break
			}
		}
		if !evicted {
			oldest := rc.order[0]
			rc.order = rc.order[1:]
			delete(rc.entries, oldest)
			_ = slog.Default // 保持与历史实现一致的语义（旧版在此 slog.Warn）
		}
	}
	rc.entries[key] = &ReplayEntry{Status: ReplayProcessing}
	rc.order = append(rc.order, key)
	return nil
}

func (rc *oldReplayCache) Update(key string, status ReplayStatus) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if e, ok := rc.entries[key]; ok {
		e.Status = status
	}
}

// BenchmarkReplayCache_MixedEviction_Old：旧实现 baseline，混合状态淘汰。
// 旧实现每次淘汰需线性扫描前段 Processing + append 切片搬移，O(n)。
// 百万级会慢到不可用，故仅跑到 10万。
func BenchmarkReplayCache_MixedEviction_Old(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		b.Run(scaleName(n), func(b *testing.B) {
			rc := newOldReplayCache(n)
			for i := 0; i < n; i++ {
				rc.SeenOrAdd(replayKey("a", strconv.Itoa(i)))
			}
			for i := n / 2; i < n; i++ {
				rc.Update(replayKey("a", strconv.Itoa(i)), ReplayAccepted)
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				rc.SeenOrAdd(replayKey("a", fmt.Sprintf("n%d", i)))
			}
		})
	}
}

// =====================================================================
// Inflight —— 高并发 atomic 计数吞吐
// =====================================================================

func BenchmarkInflight_HighContention(b *testing.B) {
	for _, p := range []int{8, 64, 256} {
		b.Run(fmt.Sprintf("procs=%d", p), func(b *testing.B) {
			inf := &Inflight{}
			b.SetParallelism(p)
			b.ResetTimer()
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					inf.Add(10, 1024)
					inf.Remove(10, 1024)
				}
			})
		})
	}
}

func scaleName(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%dM", n/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%dk", n/1_000)
	default:
		return strconv.Itoa(n)
	}
}
