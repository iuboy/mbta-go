package core

import (
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
}

const defaultReplayMaxSize = 50000

// NewReplayCache creates a new replay cache.
func NewReplayCache() *ReplayCache {
	return &ReplayCache{
		entries: make(map[string]*ReplayEntry),
		maxSize: defaultReplayMaxSize,
	}
}

// Key builds the dedup key.
func Key(agentID, chunkID string) string {
	return agentID + "\x00" + chunkID
}

// SeenOrAdd checks if a key has been seen. Returns the entry if so.
// If not seen, creates a new Processing entry and returns nil.
// Evicts oldest Processing entries when the cache exceeds maxSize.
func (rc *ReplayCache) SeenOrAdd(key string) *ReplayEntry {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if e, ok := rc.entries[key]; ok {
		return e
	}

	// Evict Processing entries when over capacity to prevent unbounded growth.
	if len(rc.entries) >= rc.maxSize {
		for k, v := range rc.entries {
			if v.Status == ReplayProcessing {
				delete(rc.entries, k)
				break
			}
		}
	}

	rc.entries[key] = &ReplayEntry{Status: ReplayProcessing}
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
