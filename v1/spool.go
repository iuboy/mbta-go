package v1

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// writeFileAtomic writes data to a file atomically by writing to a temp file
// and renaming, preventing data corruption on crash mid-write.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".mbta-spool-*")
	if err != nil {
		return core.WrapError(core.NumSpool, core.ErrSpool, "create temp file", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		if cerr := tmp.Close(); cerr != nil {
			slog.Debug("temp file close error", "path", tmpName, "error", cerr)
		}
		if rerr := os.Remove(tmpName); rerr != nil {
			slog.Debug("temp file remove error", "path", tmpName, "error", rerr)
		}
		return core.WrapError(core.NumSpool, core.ErrSpool, "write temp file", err)
	}
	if err := tmp.Sync(); err != nil {
		if cerr := tmp.Close(); cerr != nil {
			slog.Debug("temp file close error", "path", tmpName, "error", cerr)
		}
		if rerr := os.Remove(tmpName); rerr != nil {
			slog.Debug("temp file remove error", "path", tmpName, "error", rerr)
		}
		return core.WrapError(core.NumSpool, core.ErrSpool, "sync temp file", err)
	}
	if err := tmp.Close(); err != nil {
		if rerr := os.Remove(tmpName); rerr != nil {
			slog.Debug("temp file remove error", "path", tmpName, "error", rerr)
		}
		return core.WrapError(core.NumSpool, core.ErrSpool, "close temp file", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		if rerr := os.Remove(tmpName); rerr != nil {
			slog.Debug("temp file remove error", "path", tmpName, "error", rerr)
		}
		return core.WrapError(core.NumSpool, core.ErrSpool, "chmod temp file", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		if rerr := os.Remove(tmpName); rerr != nil {
			slog.Debug("temp file remove error", "path", tmpName, "error", rerr)
		}
		return core.WrapError(core.NumSpool, core.ErrSpool, "rename temp file", err)
	}
	return nil
}

// Record is a single event waiting to be sent.
type Record struct {
	RecordID        string             `json:"record_id"`
	AgentID         string             `json:"agent_id"`
	Event           *core.SignalRecord `json:"event"`
	Tag             string             `json:"tag"`
	Source          string             `json:"source"`
	CreatedAtUnixMs int64              `json:"created_at_unix_ms"`
	AttemptCount    int                `json:"attempt_count"`
	LastErrorCode   string             `json:"last_error_code,omitempty"`
}

// Batch groups records into a sendable unit.
type Batch struct {
	Seq             uint64   `json:"seq"`
	ChunkID         string   `json:"chunk_id"`
	RecordIDs       []string `json:"record_ids"`
	CreatedAtUnixMs int64    `json:"created_at_unix_ms"`
	AttemptCount    int      `json:"attempt_count"`
}

// SpoolOption configures spool behavior.
type SpoolOption func(*Spool)

// WithFlushInterval sets the interval for periodic disk flushes.
// Default is 500ms. Set to 0 to disable background flushing (synchronous mode).
func WithFlushInterval(d time.Duration) SpoolOption {
	return func(s *Spool) {
		s.flushInterval = d
	}
}

// WithMaxSize sets the maximum estimated spool size in bytes.
// When the spool exceeds this limit, Put/PutBatch return an error.
// Default is 512 MiB. Set to 0 to disable the size limit.
func WithMaxSize(bytes int64) SpoolOption {
	return func(s *Spool) {
		s.maxSize = bytes
	}
}

// Spool stores events durably before they are ACKed.
//
// NOTE: 当前实现使用全量 JSON 重写（每次 flush 重写整个文件）。
// 当 spool 接近 512 MiB 上限时，这会成为性能瓶颈。
// 未来改进方向：
//   1. 仅 flush dirty records（增量写入）
//   2. 使用 append-only 格式 + 定期 compaction
//   3. 使用更高效的序列化格式（如 msgpack 或 protobuf）
//
// When flushInterval > 0, writes are buffered and flushed periodically by a
// background goroutine. When flushInterval == 0, every mutation flushes
// synchronously to disk using the same "marshal under lock, write outside lock"
// pattern as the buffered path — no file I/O is performed while holding the mutex.
type Spool struct {
	mu      sync.Mutex
	dir     string
	records map[string]*Record // keyed by RecordID
	batches map[string]*Batch  // keyed by ChunkID

	// Buffered flush fields
	dirty         bool
	dirtyRecords  bool
	dirtyBatches  bool
	flushInterval time.Duration
	stopCh        chan struct{}
	doneCh        chan struct{}

	// Disk protection
	maxSize int64 // maximum estimated spool size (default 512 MiB)
}

const defaultSpoolMaxSize int64 = 512 * 1024 * 1024 // 512 MiB

// New creates or opens a spool in the given directory.
// By default, writes are buffered and flushed every 500ms.
// Pass WithFlushInterval(0) to flush synchronously on every mutation.
func New(dir string, opts ...SpoolOption) (*Spool, error) {
	// Validate directory to prevent path traversal.
	cleanDir := filepath.Clean(dir)
	if cleanDir != dir {
		return nil, core.NewError(core.NumSpool, core.ErrSpool, fmt.Sprintf("spool directory path contains suspicious elements: %s", dir))
	}

	if err := os.MkdirAll(cleanDir, 0700); err != nil {
		return nil, core.WrapError(core.NumSpool, core.ErrSpool, "create spool dir", err)
	}

	s := &Spool{
		dir:           dir,
		records:       make(map[string]*Record),
		batches:       make(map[string]*Batch),
		flushInterval: 500 * time.Millisecond,
		maxSize:       defaultSpoolMaxSize,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}

	for _, opt := range opts {
		opt(s)
	}

	if err := s.load(); err != nil {
		return nil, core.WrapError(core.NumSpool, core.ErrSpool, "load spool", err)
	}

	// Start background flush loop when buffered mode is enabled.
	if s.flushInterval > 0 {
		go s.flushLoop()
	} else {
		// Synchronous mode: no background goroutine.
		close(s.doneCh)
	}

	return s, nil
}

// Put stores a new event record.
func (s *Spool) Put(rec Record) error {
	s.mu.Lock()

	// Disk protection: check size before write.
	if s.maxSize > 0 && s.estimatedSize() >= s.maxSize {
		s.mu.Unlock()
		return core.NewError(core.NumSpool, core.ErrSpool, "spool size limit exceeded")
	}

	s.records[rec.RecordID] = &rec

	if s.flushInterval == 0 {
		return s.syncAndUnlock(s.flushRecordsLocked, s.flushBatchesLocked, true, false)
	}
	s.markDirty(true, false)
	s.mu.Unlock()
	return nil
}

// PutBatch stores multiple records and creates a batch.
func (s *Spool) PutBatch(records []Record, batch Batch) error {
	s.mu.Lock()

	// Disk protection: check size before write.
	if s.maxSize > 0 && s.estimatedSize() >= s.maxSize {
		s.mu.Unlock()
		return core.NewError(core.NumSpool, core.ErrSpool, "spool size limit exceeded")
	}

	for i := range records {
		s.records[records[i].RecordID] = &records[i]
	}
	s.batches[batch.ChunkID] = &batch

	if s.flushInterval == 0 {
		return s.syncAndUnlock(s.flushRecordsLocked, s.flushBatchesLocked, true, true)
	}
	s.markDirty(true, true)
	s.mu.Unlock()
	return nil
}

// DeleteRecords removes records after durable ACK.
func (s *Spool) DeleteRecords(ids []string) error {
	s.mu.Lock()

	for _, id := range ids {
		delete(s.records, id)
	}

	if s.flushInterval == 0 {
		return s.syncAndUnlock(s.flushRecordsLocked, nil, true, false)
	}
	s.markDirty(true, false)
	s.mu.Unlock()
	return nil
}

// DeleteBatch removes a batch entry.
func (s *Spool) DeleteBatch(chunkID string) error {
	s.mu.Lock()

	delete(s.batches, chunkID)

	if s.flushInterval == 0 {
		return s.syncAndUnlock(nil, s.flushBatchesLocked, false, true)
	}
	s.markDirty(false, true)
	s.mu.Unlock()
	return nil
}

// PendingRecords returns all unACKed records.
func (s *Spool) PendingRecords() []*Record {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]*Record, 0, len(s.records))
	for _, r := range s.records {
		result = append(result, r)
	}
	return result
}

// PendingBatches returns all unACKed batches.
func (s *Spool) PendingBatches() []*Batch {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]*Batch, 0, len(s.batches))
	for _, b := range s.batches {
		result = append(result, b)
	}
	return result
}

// Len returns the number of pending records.
func (s *Spool) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// Sync flushes any dirty data to disk immediately.
// Call this when durability is required before returning to the caller.
// Snapshot is taken under the lock; I/O happens outside the lock (same pattern as flushIfNeeded).
func (s *Spool) Sync() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}

	dirtyRec := s.dirtyRecords
	dirtyBat := s.dirtyBatches
	s.dirty = false
	s.dirtyRecords = false
	s.dirtyBatches = false

	var recordsData, batchesData []byte
	var err error
	if dirtyRec {
		recordsData, err = json.Marshal(s.records)
		if err != nil {
			s.dirty = true
			s.dirtyRecords = true
			s.mu.Unlock()
			return err
		}
	}
	if dirtyBat {
		batchesData, err = json.Marshal(s.batches)
		if err != nil {
			s.dirty = true
			s.dirtyBatches = true
			s.mu.Unlock()
			return err
		}
	}
	s.mu.Unlock()

	// Write outside the lock (writeFileAtomic is already atomic).
	if recordsData != nil {
		if err := writeFileAtomic(filepath.Join(s.dir, "records.json"), recordsData, 0600); err != nil {
			s.mu.Lock()
			s.dirty = true
			s.dirtyRecords = true
			s.mu.Unlock()
			return err
		}
	}
	if batchesData != nil {
		if err := writeFileAtomic(filepath.Join(s.dir, "batches.json"), batchesData, 0600); err != nil {
			s.mu.Lock()
			s.dirty = true
			s.dirtyBatches = true
			s.mu.Unlock()
			return err
		}
	}
	return nil
}

// Close stops the background flush goroutine and performs a final flush.
// The Spool must not be used after Close.
func (s *Spool) Close() error {
	if s.flushInterval > 0 {
		close(s.stopCh)
		<-s.doneCh
	}

	// Final synchronous flush.
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushAllLocked()
}

// markDirty sets the dirty flags. Must be called with s.mu held.
func (s *Spool) markDirty(records, batches bool) {
	s.dirty = true
	if records {
		s.dirtyRecords = true
	}
	if batches {
		s.dirtyBatches = true
	}
}

// flushLoop runs in a background goroutine, periodically flushing dirty data.
func (s *Spool) flushLoop() {
	defer close(s.doneCh)

	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.flushIfNeeded()
		case <-s.stopCh:
			// Final flush on shutdown.
			s.flushIfNeeded()
			return
		}
	}
}

// flushIfNeeded flushes dirty data to disk.
// Snapshot is taken under the lock; I/O happens outside the lock.
// If I/O fails, dirty flags are restored so the next flush cycle retries.
func (s *Spool) flushIfNeeded() {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return
	}

	dirtyRec := s.dirtyRecords
	dirtyBat := s.dirtyBatches
	s.dirty = false
	s.dirtyRecords = false
	s.dirtyBatches = false

	var recordsData, batchesData []byte
	var err error
	if dirtyRec {
		recordsData, err = json.Marshal(s.records)
		if err != nil {
			s.dirty = true
			s.dirtyRecords = true
			s.mu.Unlock()
			slog.Error("flush: marshal records", "error", err)
			return
		}
	}
	if dirtyBat {
		batchesData, err = json.Marshal(s.batches)
		if err != nil {
			s.dirty = true
			s.dirtyBatches = true
			s.mu.Unlock()
			slog.Error("flush: marshal batches", "error", err)
			return
		}
	}
	s.mu.Unlock()

	// Write outside the lock (writeFileAtomic is already atomic).
	if recordsData != nil {
		if err := writeFileAtomic(filepath.Join(s.dir, "records.json"), recordsData, 0600); err != nil {
			slog.Error("flush: write records", "error", err)
			// Restore dirty flag so next flush cycle retries.
			s.mu.Lock()
			s.dirty = true
			s.dirtyRecords = true
			s.mu.Unlock()
		}
	}
	if batchesData != nil {
		if err := writeFileAtomic(filepath.Join(s.dir, "batches.json"), batchesData, 0600); err != nil {
			slog.Error("flush: write batches", "error", err)
			// Restore dirty flag so next flush cycle retries.
			s.mu.Lock()
			s.dirty = true
			s.dirtyBatches = true
			s.mu.Unlock()
		}
	}
}

// syncAndUnlock is the synchronous mode flush: marshal under lock, write outside lock.
// Caller must hold s.mu. On return, s.mu is NOT held (even on error).
// marshalRec/marshalBat functions capture the serialized data under lock.
// This eliminates file I/O while holding the mutex.
func (s *Spool) syncAndUnlock(marshalRec, marshalBat func() ([]byte, error), dirtyRec, dirtyBat bool) error {
	var recordsData, batchesData []byte
	var err error

	if marshalRec != nil {
		recordsData, err = marshalRec()
		if err != nil {
			s.mu.Unlock()
			return err
		}
	}
	if marshalBat != nil {
		batchesData, err = marshalBat()
		if err != nil {
			s.mu.Unlock()
			return err
		}
	}
	s.mu.Unlock()

	// Write outside the lock.
	if recordsData != nil {
		if err := writeFileAtomic(filepath.Join(s.dir, "records.json"), recordsData, 0600); err != nil {
			s.mu.Lock()
			s.markDirty(dirtyRec, dirtyBat)
			s.mu.Unlock()
			return err
		}
	}
	if batchesData != nil {
		if err := writeFileAtomic(filepath.Join(s.dir, "batches.json"), batchesData, 0600); err != nil {
			s.mu.Lock()
			s.markDirty(dirtyRec, dirtyBat)
			s.mu.Unlock()
			return err
		}
	}
	return nil
}

// flushRecordsLocked marshals records while the lock is held. Must be called with s.mu held.
func (s *Spool) flushRecordsLocked() ([]byte, error) {
	return json.Marshal(s.records)
}

// flushBatchesLocked marshals batches while the lock is held. Must be called with s.mu held.
func (s *Spool) flushBatchesLocked() ([]byte, error) {
	return json.Marshal(s.batches)
}

func (s *Spool) load() error {
	recordsPath := filepath.Join(s.dir, "records.json")
	data, err := os.ReadFile(recordsPath) // #nosec G304 -- s.dir validated in New()
	if err == nil {
		if err := json.Unmarshal(data, &s.records); err != nil {
			return core.WrapError(core.NumSpool, core.ErrSpool, "unmarshal records", err)
		}
	} else if !os.IsNotExist(err) {
		return core.WrapError(core.NumSpool, core.ErrSpool, "read records", err)
	}

	batchesPath := filepath.Join(s.dir, "batches.json")
	data, err = os.ReadFile(batchesPath) // #nosec G304 -- s.dir validated in New()
	if err == nil {
		if err := json.Unmarshal(data, &s.batches); err != nil {
			return core.WrapError(core.NumSpool, core.ErrSpool, "unmarshal batches", err)
		}
	} else if !os.IsNotExist(err) {
		return core.WrapError(core.NumSpool, core.ErrSpool, "read batches", err)
	}

	return nil
}

// flushAllLocked flushes both records and batches. Must be called with s.mu held.
// Used by Close() which manages its own lock lifecycle — does I/O while holding
// the lock for simplicity since Close is a one-shot operation during shutdown.
func (s *Spool) flushAllLocked() error {
	recData, err := json.Marshal(s.records)
	if err != nil {
		return err
	}
	batData, err := json.Marshal(s.batches)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(s.dir, "records.json"), recData, 0600); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.dir, "batches.json"), batData, 0600)
}

// estimatedSize returns a rough estimate of the spool's memory footprint in bytes.
// Must be called with s.mu held.
func (s *Spool) estimatedSize() int64 {
	var size int64
	for _, r := range s.records {
		// Approximate: RecordID + AgentID + overhead per record.
		size += int64(len(r.RecordID) + len(r.AgentID) + 256)
	}
	for _, b := range s.batches {
		// Approximate: ChunkID + RecordIDs + overhead per batch.
		size += int64(len(b.ChunkID) + len(b.RecordIDs)*36 + 128)
	}
	return size
}
