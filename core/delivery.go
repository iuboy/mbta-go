package core

import (
	"log/slog"
	"sync"
	"sync/atomic"
)

// SeqGenerator generates monotonically increasing sequence numbers for a session.
type SeqGenerator struct {
	seq atomic.Uint64
}

// NewSeqGenerator creates a generator starting at 0. First Next() returns 1.
func NewSeqGenerator() *SeqGenerator {
	return &SeqGenerator{}
}

// Next returns the next sequence number (starting at 1).
func (g *SeqGenerator) Next() uint64 {
	return g.seq.Add(1)
}

// Current returns the last issued sequence number.
func (g *SeqGenerator) Current() uint64 {
	return g.seq.Load()
}

// ReplayStatus represents the processing state of a chunk.
type ReplayStatus int

const (
	// ReplayProcessing 表示数据块正在处理中。
	ReplayProcessing ReplayStatus = iota
	// ReplayAccepted 表示数据块已被接受。
	ReplayAccepted
	// ReplayDurable 表示数据块已持久化。
	ReplayDurable
	// ReplayRejected 表示数据块被拒绝。
	ReplayRejected
)

// ReplayEntry tracks the status of a processed chunk_id.
type ReplayEntry struct {
	Status ReplayStatus
	// ACK/NACK response is stored for duplicate returns.
}

// ReplayCache prevents duplicate processing of the same chunk_id from an agent.
type ReplayCache struct {
	mu      sync.Mutex
	entries map[string]*ReplayEntry // key: agent_id + chunk_id
	maxSize int
	order   []string // FIFO insertion order for bounded eviction
}

const defaultReplayMaxSize = 50000

// NewReplayCache creates a new replay cache with the default capacity (50000).
func NewReplayCache() *ReplayCache {
	return NewReplayCacheWithSize(defaultReplayMaxSize)
}

// NewReplayCacheWithSize creates a new replay cache with a custom capacity.
// A larger cache provides a longer dedup window at the cost of more memory.
func NewReplayCacheWithSize(maxSize int) *ReplayCache {
	if maxSize <= 0 {
		maxSize = defaultReplayMaxSize
	}
	return &ReplayCache{
		entries: make(map[string]*ReplayEntry, min(maxSize, 1024)),
		maxSize: maxSize,
		order:   make([]string, 0, maxSize),
	}
}

// Key builds the dedup key.
func Key(agentID, chunkID string) string {
	return agentID + "\x00" + chunkID
}

// SeenOrAdd checks if a key has been seen. Returns the entry if so.
// If not seen, creates a new Processing entry and returns nil.
// When the cache exceeds maxSize, evicts the oldest entry regardless of status.
func (rc *ReplayCache) SeenOrAdd(key string) *ReplayEntry {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if e, ok := rc.entries[key]; ok {
		return e
	}

	// 当缓存超过容量时，优先驱逐非 Processing 的条目。
	// 如果全部为 Processing，则回退驱逐最早的条目（防止内存无限增长）。
	//
	// TODO(perf): 当前淘汰逻辑最坏情况 O(n)——当 maxSize=50000 且全部为 Processing 时，
	// 每次插入新条目都遍历整个 order 列表。改进方案：
	//   1. 维护两个链表：processingList 和 completedList，分别跟踪不同状态的条目
	//   2. 或使用 container/list + map 的双向链表实现 O(1) 淘汰
	//   3. 当前 maxSize=50000 在正常负载下几乎不会全部为 Processing，因此实际影响有限
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
			// 全部为 Processing，回退驱逐最早的条目。
			// 这意味着有一个正在处理的 batch 可能被重复处理——记录警告。
			oldest := rc.order[0]
			rc.order = rc.order[1:]
			delete(rc.entries, oldest)
			slog.Warn("replay cache evicted processing entry",
				"evicted_key", oldest,
				"cache_size", len(rc.entries),
				"max_size", rc.maxSize,
			)
		}
	}

	rc.entries[key] = &ReplayEntry{Status: ReplayProcessing}
	rc.order = append(rc.order, key)
	return nil
}

// Update changes the status of an existing entry.
func (rc *ReplayCache) Update(key string, status ReplayStatus) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if e, ok := rc.entries[key]; ok {
		e.Status = status
	}
}

// Get retrieves the current entry for a key.
func (rc *ReplayCache) Get(key string) *ReplayEntry {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.entries[key]
}

// Len returns the number of entries.
func (rc *ReplayCache) Len() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return len(rc.entries)
}
