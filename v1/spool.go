package v1

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

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
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return core.WrapError(core.NumSpool, core.ErrSpool, "write temp file", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return core.WrapError(core.NumSpool, core.ErrSpool, "sync temp file", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return core.WrapError(core.NumSpool, core.ErrSpool, "close temp file", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		_ = os.Remove(tmpName)
		return core.WrapError(core.NumSpool, core.ErrSpool, "chmod temp file", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
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

// Spool stores events durably before they are ACKed.
type Spool struct {
	mu      sync.Mutex
	dir     string
	records map[string]*Record // keyed by RecordID
	batches map[string]*Batch  // keyed by ChunkID
}

// New creates or opens a spool in the given directory.
func New(dir string) (*Spool, error) {
	// Validate directory to prevent path traversal.
	cleanDir := filepath.Clean(dir)
	if cleanDir != dir {
		return nil, core.NewError(core.NumSpool, core.ErrSpool, fmt.Sprintf("spool directory path contains suspicious elements: %s", dir))
	}

	if err := os.MkdirAll(cleanDir, 0700); err != nil {
		return nil, core.WrapError(core.NumSpool, core.ErrSpool, "create spool dir", err)
	}

	s := &Spool{
		dir:     dir,
		records: make(map[string]*Record),
		batches: make(map[string]*Batch),
	}

	if err := s.load(); err != nil {
		return nil, core.WrapError(core.NumSpool, core.ErrSpool, "load spool", err)
	}

	return s, nil
}

// Put stores a new event record.
func (s *Spool) Put(rec Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records[rec.RecordID] = &rec
	return s.flushRecords()
}

// PutBatch stores multiple records and creates a batch.
func (s *Spool) PutBatch(records []Record, batch Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range records {
		s.records[records[i].RecordID] = &records[i]
	}
	s.batches[batch.ChunkID] = &batch
	return s.flushAll()
}

// DeleteRecords removes records after durable ACK.
func (s *Spool) DeleteRecords(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, id := range ids {
		delete(s.records, id)
	}
	return s.flushRecords()
}

// DeleteBatch removes a batch entry.
func (s *Spool) DeleteBatch(chunkID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.batches, chunkID)
	return s.flushBatches()
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

func (s *Spool) flushRecords() error {
	data, err := json.Marshal(s.records)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.dir, "records.json"), data, 0600)
}

func (s *Spool) flushBatches() error {
	data, err := json.Marshal(s.batches)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.dir, "batches.json"), data, 0600)
}

func (s *Spool) flushAll() error {
	if err := s.flushRecords(); err != nil {
		return err
	}
	return s.flushBatches()
}
