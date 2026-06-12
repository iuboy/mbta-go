package v1

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// getTempSpoolDir returns a temporary directory for spool testing.
func getTempSpoolDir(t *testing.T) string {
	dir := filepath.Join(os.TempDir(), "mbta-spool-test-"+t.Name())
	// Clean up before test
	os.RemoveAll(dir)
	return dir
}

// cleanupTempSpoolDir removes the temporary spool directory.
func cleanupTempSpoolDir(dir string) {
	os.RemoveAll(dir)
}

// TestNewSpool tests creating a new spool.
func TestNewSpool(t *testing.T) {
	dir := getTempSpoolDir(t)
	defer cleanupTempSpoolDir(dir)

	spool, err := New(dir)
	if err != nil {
		t.Fatalf("New spool failed: %v", err)
	}

	if spool == nil {
		t.Fatal("Spool should not be nil")
	}

	if spool.dir != dir {
		t.Errorf("Spool dir = %s, want %s", spool.dir, dir)
	}

	// Verify directory was created
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("Spool directory should be created")
	}
}

// TestSpoolPutAndGet tests storing and retrieving records.
func TestSpoolPutAndGet(t *testing.T) {
	dir := getTempSpoolDir(t)
	defer cleanupTempSpoolDir(dir)

	spool, err := New(dir)
	if err != nil {
		t.Fatalf("New spool failed: %v", err)
	}

	record := Record{
		RecordID:        "test-record-1",
		AgentID:         "test-agent",
		Event:           &core.SignalRecord{SignalType: "log"},
		Tag:             "test-tag",
		Source:          "test-source",
		CreatedAtUnixMs: time.Now().UnixMilli(),
	}

	err = spool.Put(record)
	if err != nil {
		t.Fatalf("Put record failed: %v", err)
	}

	pending := spool.PendingRecords()
	if len(pending) != 1 {
		t.Errorf("PendingRecords count = %d, want 1", len(pending))
	}

	if pending[0].RecordID != "test-record-1" {
		t.Errorf("RecordID = %s, want 'test-record-1'", pending[0].RecordID)
	}
}

// TestSpoolPutBatch tests storing multiple records and a batch.
func TestSpoolPutBatch(t *testing.T) {
	dir := getTempSpoolDir(t)
	defer cleanupTempSpoolDir(dir)

	spool, err := New(dir)
	if err != nil {
		t.Fatalf("New spool failed: %v", err)
	}

	records := []Record{
		{
			RecordID: "record-1",
			AgentID:  "agent-1",
			Event:    &core.SignalRecord{SignalType: "log"},
		},
		{
			RecordID: "record-2",
			AgentID:  "agent-1",
			Event:    &core.SignalRecord{SignalType: "metric"},
		},
	}

	batch := Batch{
		Seq:             1,
		ChunkID:         "chunk-1",
		RecordIDs:       []string{"record-1", "record-2"},
		CreatedAtUnixMs: time.Now().UnixMilli(),
	}

	err = spool.PutBatch(records, batch)
	if err != nil {
		t.Fatalf("PutBatch failed: %v", err)
	}

	pendingRecords := spool.PendingRecords()
	if len(pendingRecords) != 2 {
		t.Errorf("PendingRecords count = %d, want 2", len(pendingRecords))
	}

	pendingBatches := spool.PendingBatches()
	if len(pendingBatches) != 1 {
		t.Errorf("PendingBatches count = %d, want 1", len(pendingBatches))
	}

	if pendingBatches[0].ChunkID != "chunk-1" {
		t.Errorf("ChunkID = %s, want 'chunk-1'", pendingBatches[0].ChunkID)
	}
}

// TestSpoolDeleteRecords tests deleting records.
func TestSpoolDeleteRecords(t *testing.T) {
	dir := getTempSpoolDir(t)
	defer cleanupTempSpoolDir(dir)

	spool, err := New(dir)
	if err != nil {
		t.Fatalf("New spool failed: %v", err)
	}

	// Put two records
	record1 := Record{RecordID: "record-1", AgentID: "agent-1"}
	record2 := Record{RecordID: "record-2", AgentID: "agent-1"}

	_ = spool.Put(record1)
	_ = spool.Put(record2)

	if spool.Len() != 2 {
		t.Errorf("Len after Put = %d, want 2", spool.Len())
	}

	// Delete one record
	err = spool.DeleteRecords([]string{"record-1"})
	if err != nil {
		t.Fatalf("DeleteRecords failed: %v", err)
	}

	if spool.Len() != 1 {
		t.Errorf("Len after Delete = %d, want 1", spool.Len())
	}

	pending := spool.PendingRecords()
	if len(pending) != 1 {
		t.Errorf("PendingRecords count = %d, want 1", len(pending))
	}

	if pending[0].RecordID != "record-2" {
		t.Errorf("Remaining RecordID = %s, want 'record-2'", pending[0].RecordID)
	}
}

// TestSpoolDeleteBatch tests deleting batches.
func TestSpoolDeleteBatch(t *testing.T) {
	dir := getTempSpoolDir(t)
	defer cleanupTempSpoolDir(dir)

	spool, err := New(dir)
	if err != nil {
		t.Fatalf("New spool failed: %v", err)
	}

	batch := Batch{
		Seq:             1,
		ChunkID:         "chunk-1",
		RecordIDs:       []string{"record-1"},
		CreatedAtUnixMs: time.Now().UnixMilli(),
	}

	_ = spool.PutBatch([]Record{}, batch)

	pendingBatches := spool.PendingBatches()
	if len(pendingBatches) != 1 {
		t.Errorf("PendingBatches count = %d, want 1", len(pendingBatches))
	}

	err = spool.DeleteBatch("chunk-1")
	if err != nil {
		t.Fatalf("DeleteBatch failed: %v", err)
	}

	pendingBatches = spool.PendingBatches()
	if len(pendingBatches) != 0 {
		t.Errorf("PendingBatches count after delete = %d, want 0", len(pendingBatches))
	}
}

// TestSpoolLen tests the Len method.
func TestSpoolLen(t *testing.T) {
	dir := getTempSpoolDir(t)
	defer cleanupTempSpoolDir(dir)

	spool, err := New(dir)
	if err != nil {
		t.Fatalf("New spool failed: %v", err)
	}

	if spool.Len() != 0 {
		t.Errorf("Initial Len = %d, want 0", spool.Len())
	}

	// Add records
	for i := 0; i < 5; i++ {
		record := Record{
			RecordID: "record-" + string(rune('0'+i)),
			AgentID:  "agent-1",
		}
		_ = spool.Put(record)
	}

	if spool.Len() != 5 {
		t.Errorf("Len after adding 5 records = %d, want 5", spool.Len())
	}
}

// TestSpoolPersistence tests that spool data persists across instances.
func TestSpoolPersistence(t *testing.T) {
	dir := getTempSpoolDir(t)
	defer cleanupTempSpoolDir(dir)

	// Create first spool instance (synchronous mode for test determinism)
	spool1, err := New(dir, WithFlushInterval(0))
	if err != nil {
		t.Fatalf("New spool failed: %v", err)
	}

	record := Record{
		RecordID: "persistent-record",
		AgentID:  "agent-1",
		Event:    &core.SignalRecord{SignalType: "log"},
	}

	err = spool1.Put(record)
	if err != nil {
		t.Fatalf("Put record failed: %v", err)
	}

	// Create second spool instance (should load from disk)
	spool2, err := New(dir)
	if err != nil {
		t.Fatalf("New spool (second instance) failed: %v", err)
	}

	pending := spool2.PendingRecords()
	if len(pending) != 1 {
		t.Errorf("PendingRecords count after reload = %d, want 1", len(pending))
	}

	if pending[0].RecordID != "persistent-record" {
		t.Errorf("RecordID after reload = %s, want 'persistent-record'", pending[0].RecordID)
	}
}

// TestRecordStructure tests Record structure.
func TestRecordStructure(t *testing.T) {
	record := Record{
		RecordID:        "test-record",
		AgentID:         "test-agent",
		Event:           &core.SignalRecord{SignalType: "log"},
		Tag:             "test-tag",
		Source:          "test-source",
		CreatedAtUnixMs: time.Now().UnixMilli(),
		AttemptCount:    1,
		LastErrorCode:   "test-error",
	}

	if record.RecordID == "" {
		t.Error("RecordID should not be empty")
	}
	if record.AgentID == "" {
		t.Error("AgentID should not be empty")
	}
	if record.Event == nil {
		t.Error("Event should not be nil")
	}
}

// TestBatchStructure tests Batch structure.
func TestBatchStructure(t *testing.T) {
	batch := Batch{
		Seq:             1,
		ChunkID:         "test-chunk",
		RecordIDs:       []string{"record-1", "record-2"},
		CreatedAtUnixMs: time.Now().UnixMilli(),
		AttemptCount:    1,
	}

	if batch.Seq == 0 {
		t.Error("Seq should be set")
	}
	if batch.ChunkID == "" {
		t.Error("ChunkID should not be empty")
	}
	if len(batch.RecordIDs) == 0 {
		t.Error("RecordIDs should not be empty")
	}
}

// TestSpoolEmptyDelete tests deleting non-existent records.
func TestSpoolEmptyDelete(t *testing.T) {
	dir := getTempSpoolDir(t)
	defer cleanupTempSpoolDir(dir)

	spool, err := New(dir)
	if err != nil {
		t.Fatalf("New spool failed: %v", err)
	}

	// Delete non-existent record
	err = spool.DeleteRecords([]string{"non-existent"})
	if err != nil {
		t.Fatalf("DeleteRecords with non-existent ID should not error, got %v", err)
	}

	// Delete non-existent batch
	err = spool.DeleteBatch("non-existent")
	if err != nil {
		t.Fatalf("DeleteBatch with non-existent ID should not error, got %v", err)
	}
}

// TestSpoolMultipleOperations tests multiple spool operations.
func TestSpoolMultipleOperations(t *testing.T) {
	dir := getTempSpoolDir(t)
	defer cleanupTempSpoolDir(dir)

	spool, err := New(dir)
	if err != nil {
		t.Fatalf("New spool failed: %v", err)
	}

	// Add multiple records
	for i := 0; i < 10; i++ {
		record := Record{
			RecordID: "record-" + string(rune('0'+i)),
			AgentID:  "agent-1",
			Event:    &core.SignalRecord{SignalType: "log"},
		}
		_ = spool.Put(record)
	}

	if spool.Len() != 10 {
		t.Errorf("Len after adding 10 records = %d, want 10", spool.Len())
	}

	// Delete some records
	deleteIDs := []string{"record-0", "record-1", "record-2"}
	err = spool.DeleteRecords(deleteIDs)
	if err != nil {
		t.Fatalf("DeleteRecords failed: %v", err)
	}

	if spool.Len() != 7 {
		t.Errorf("Len after deleting 3 records = %d, want 7", spool.Len())
	}
}
