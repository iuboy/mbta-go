package v1

import (
	"hash/fnv"
	"io"
	"sync"

	"github.com/iuboy/mbta-go/core"
)

// DataStream represents an opened QUIC data stream with an integer index.
type DataStream interface {
	io.Writer
	Index() int
}

// StreamPicker selects which data stream a batch should be sent on.
type StreamPicker interface {
	Pick(batch core.BatchMessage) (DataStream, error)
	AddStream(ds DataStream)
	RemoveStream(index int)
	Len() int
}

// --- SingleStream: always uses stream index 0 ---

type singleStream struct {
	ds DataStream
}

// NewSingleStream returns a StreamPicker that always routes to the given single stream.
func NewSingleStream(ds DataStream) StreamPicker {
	return &singleStream{ds: ds}
}

func (s *singleStream) Pick(_ core.BatchMessage) (DataStream, error) {
	return s.ds, nil
}

func (s *singleStream) AddStream(_ DataStream) {}
func (s *singleStream) RemoveStream(_ int)     {}
func (s *singleStream) Len() int               { return 1 }

// --- HashStreamPicker: distributes by tag+source hash ---

type hashStreamPicker struct {
	mu      sync.RWMutex
	streams map[int]DataStream
	indices []int
}

// NewHashStreamPicker creates a StreamPicker that distributes batches across streams using a tag+source hash.
func NewHashStreamPicker() StreamPicker {
	return &hashStreamPicker{
		streams: make(map[int]DataStream),
	}
}

func (h *hashStreamPicker) Pick(batch core.BatchMessage) (DataStream, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.streams) == 0 {
		return nil, ErrNoStreams
	}

	key := batch.Tag + "\x00" + batch.Source
	idx := hashKey(key, len(h.indices))
	return h.streams[h.indices[idx]], nil
}

func (h *hashStreamPicker) AddStream(ds DataStream) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.streams[ds.Index()] = ds
	h.rebuildIndices()
}

func (h *hashStreamPicker) RemoveStream(index int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.streams, index)
	h.rebuildIndices()
}

func (h *hashStreamPicker) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.streams)
}

func (h *hashStreamPicker) rebuildIndices() {
	h.indices = make([]int, 0, len(h.streams))
	for idx := range h.streams {
		h.indices = append(h.indices, idx)
	}
	// Sort for determinism
	sortInts(h.indices)
}

func hashKey(key string, buckets int) int {
	if buckets <= 0 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % uint32(buckets)) // #nosec G115 -- buckets > 0 and bounded by stream count
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
