package v1

import (
	"hash/fnv"
	"io"
	"sort"
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

func (s *singleStream) Pick(_ core.BatchMessage) (DataStream, error) { return s.ds, nil }
func (s *singleStream) AddStream(_ DataStream)                       {}
func (s *singleStream) RemoveStream(_ int)                           {}
func (s *singleStream) Len() int                                      { return 1 }

// --- HashStreamPicker: distributes by tag+source hash ---

type hashStreamPicker struct {
	mu      sync.RWMutex
	streams map[int]DataStream
	ring    []ringEntry // sorted hash ring for consistent hashing
}

type ringEntry struct {
	hash    uint32
	stream  DataStream
	indexID int // original stream index for removal
}

const virtualNodes = 40 // virtual nodes per real stream for balanced distribution

// NewHashStreamPicker creates a StreamPicker that distributes batches across streams
// using consistent hashing on tag+source. Adding or removing a stream only remaps
// ~1/N of the keys, avoiding wholesale redistribution.
func NewHashStreamPicker() StreamPicker {
	return &hashStreamPicker{
		streams: make(map[int]DataStream),
	}
}

func (h *hashStreamPicker) Pick(batch core.BatchMessage) (DataStream, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.ring) == 0 {
		return nil, ErrNoStreams
	}

	key := batch.Tag + "\x00" + batch.Source
	target := hashKey(key)
	idx := sort.Search(len(h.ring), func(i int) bool {
		return h.ring[i].hash >= target
	})
	if idx == len(h.ring) {
		idx = 0 // wrap around
	}
	return h.ring[idx].stream, nil
}

func (h *hashStreamPicker) AddStream(ds DataStream) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.streams[ds.Index()] = ds
	h.rebuildRing()
}

func (h *hashStreamPicker) RemoveStream(index int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.streams, index)
	h.rebuildRing()
}

func (h *hashStreamPicker) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.streams)
}

func (h *hashStreamPicker) rebuildRing() {
	h.ring = h.ring[:0]
	for idx, ds := range h.streams {
		for vn := range virtualNodes {
			vkey := fnvHash(uint32(idx), uint32(vn)) //nolint:gosec // idx bounded by number of streams, cannot overflow uint32
			h.ring = append(h.ring, ringEntry{hash: vkey, stream: ds, indexID: idx})
		}
	}
	sort.Slice(h.ring, func(i, j int) bool {
		return h.ring[i].hash < h.ring[j].hash
	})
}

// hashKey produces a 32-bit hash from a string key for ring lookup.
func hashKey(key string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(key)) // fnv.Write never returns an error
	return h.Sum32()
}

// fnvHash produces a deterministic 32-bit hash from a stream index + virtual node number.
func fnvHash(streamIdx, vnode uint32) uint32 {
	h := fnv.New32a()
	var buf [8]byte
	buf[0] = byte(streamIdx >> 24)
	buf[1] = byte(streamIdx >> 16)
	buf[2] = byte(streamIdx >> 8)
	buf[3] = byte(streamIdx)
	buf[4] = byte(vnode >> 24)
	buf[5] = byte(vnode >> 16)
	buf[6] = byte(vnode >> 8)
	buf[7] = byte(vnode)
	h.Write(buf[:])
	return h.Sum32()
}
