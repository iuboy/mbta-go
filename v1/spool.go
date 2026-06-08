package v1

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/iuboy/mbta-go/core"
)

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
		return nil, fmt.Errorf("spool directory path contains suspicious elements: %s", dir)
	}

	if err := os.MkdirAll(cleanDir, 0700); err != nil {
		return nil, fmt.Errorf("create spool dir: %w", err)
	}

	s := &Spool{
		dir:     dir,
		records: make(map[string]*Record),
		batches: make(map[string]*Batch),
	}

	if err := s.load(); err != nil {
		return nil, fmt.Errorf("load spool: %w", err)
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
			return fmt.Errorf("unmarshal records: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read records: %w", err)
	}

	batchesPath := filepath.Join(s.dir, "batches.json")
	data, err = os.ReadFile(batchesPath) // #nosec G304 -- s.dir validated in New()
	if err == nil {
		if err := json.Unmarshal(data, &s.batches); err != nil {
			return fmt.Errorf("unmarshal batches: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read batches: %w", err)
	}

	return nil
}

func (s *Spool) flushRecords() error {
	data, err := json.Marshal(s.records)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "records.json"), data, 0600) // #nosec G304
}

func (s *Spool) flushBatches() error {
	data, err := json.Marshal(s.batches)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "batches.json"), data, 0600) // #nosec G304
}

func (s *Spool) flushAll() error {
	if err := s.flushRecords(); err != nil {
		return err
	}
	return s.flushBatches()
}
