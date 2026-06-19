package core

import (
	"container/list"
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

// replayNode 是 ReplayCache 中的条目节点，承载状态与所在双向链表的元素指针。
// Processing 条目挂在 processingList，已完成（非 Processing）条目挂在 doneList，
// 两链表均按各自插入序 FIFO，使淘汰可在 O(1) 完成。
type replayNode struct {
	key   string
	entry ReplayEntry
	el    *list.Element // 在 processingList 或 doneList 中
}

// ReplayCache prevents duplicate processing of the same chunk_id from an agent.
type ReplayCache struct {
	mu             sync.Mutex
	entries        map[string]*replayNode // key: agent_id + chunk_id
	maxSize        int
	processingList *list.List // Processing 条目，FIFO（最早插入在队首）
	doneList       *list.List // 已完成条目，FIFO（最早完成在队首），淘汰优先取此
	metrics        Metrics    // 可选：驱逐计数上报（nil=不上报）
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
		entries:        make(map[string]*replayNode, min(maxSize, 1024)),
		maxSize:        maxSize,
		processingList: list.New(),
		doneList:       list.New(),
	}
}

// replayKey builds the dedup key from agentID and chunkID.
func replayKey(agentID, chunkID string) string {
	return agentID + "\x00" + chunkID
}

// SetMetrics 注入可观测性接口，用于上报缓存驱逐次数。可选；nil 表示不上报。
func (rc *ReplayCache) SetMetrics(m Metrics) { rc.metrics = m }

// SeenOrAdd checks if a (agentID, chunkID) pair has been seen. Returns the entry if so.
// If not seen, creates a new Processing entry and returns nil.
//
// 淘汰策略（O(1)）：缓存满时优先从 doneList 队首驱逐一个已完成条目；
// 若 doneList 为空（全部 Processing），则从 processingList 队首驱逐最早条目并记录告警。
func (rc *ReplayCache) SeenOrAdd(agentID, chunkID string) *ReplayEntry {
	key := replayKey(agentID, chunkID)
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if n, ok := rc.entries[key]; ok {
		return &n.entry
	}

	// 容量满时淘汰：优先已完成条目，O(1)。
	var evicted int
	for len(rc.entries) >= rc.maxSize {
		if rc.doneList.Len() > 0 {
			el := rc.doneList.Front()
			n := el.Value.(*replayNode)
			rc.doneList.Remove(el)
			delete(rc.entries, n.key)
			evicted++
			continue
		}
		// 全部为 Processing：驱逐最早的 Processing 条目。
		// 这意味着有一个正在处理的 batch 可能被重复处理——记录警告。
		el := rc.processingList.Front()
		if el == nil {
			break // entries 非空则必在某一链表，防御性退出
		}
		n := el.Value.(*replayNode)
		rc.processingList.Remove(el)
		delete(rc.entries, n.key)
		evicted++
		slog.Warn("replay cache evicted processing entry",
			"evicted_key", n.key,
			"cache_size", len(rc.entries),
			"max_size", rc.maxSize,
		)
	}
	if evicted > 0 && rc.metrics != nil {
		rc.metrics.ReplayCacheEvictions().Add(float64(evicted))
	}

	n := &replayNode{key: key, entry: ReplayEntry{Status: ReplayProcessing}}
	n.el = rc.processingList.PushBack(n)
	rc.entries[key] = n
	return nil
}

// Update changes the status of an existing (agentID, chunkID) entry.
// 条目从 Processing 迁移到完成态时，同步从 processingList 移到 doneList。
func (rc *ReplayCache) Update(agentID, chunkID string, status ReplayStatus) {
	key := replayKey(agentID, chunkID)
	rc.mu.Lock()
	defer rc.mu.Unlock()

	n, ok := rc.entries[key]
	if !ok {
		return
	}
	wasProcessing := n.entry.Status == ReplayProcessing
	n.entry.Status = status
	if wasProcessing && status != ReplayProcessing {
		rc.processingList.Remove(n.el)
		n.el = rc.doneList.PushBack(n)
	}
}

// Get retrieves the current entry for a (agentID, chunkID) pair.
func (rc *ReplayCache) Get(agentID, chunkID string) *ReplayEntry {
	key := replayKey(agentID, chunkID)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if n, ok := rc.entries[key]; ok {
		return &n.entry
	}
	return nil
}

// Len returns the number of entries.
func (rc *ReplayCache) Len() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return len(rc.entries)
}
