package v1

import (
	"io"
	"sort"
	"sync"

	"github.com/iuboy/mbta-go/core"
)

// FNV-1a 32-bit 常量。手写以消除 hash/fnv 的对象分配（每帧一次的发送热路径）。
const (
	fnvOffset32 = 2166136261
	fnvPrime32  = 16777619
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
func (s *singleStream) Len() int                                     { return 1 }

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

	target := hashTagSource(batch.Tag, batch.Source)
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

// hashTagSource 对 tag + '\x00' + source 计算 FNV-1a 32 位哈希，
// 直接按字节遍历两段字符串，避免拼接分配。与原 hashKey(tag+"\x00"+source) 结果一致。
func hashTagSource(tag, source string) uint32 {
	h := uint32(fnvOffset32)
	for i := 0; i < len(tag); i++ {
		h ^= uint32(tag[i])
		h *= fnvPrime32
	}
	h ^= 0 // 分隔符 '\x00'：XOR 0 不变值，仅乘 prime
	h *= fnvPrime32
	for i := 0; i < len(source); i++ {
		h ^= uint32(source[i])
		h *= fnvPrime32
	}
	return h
}

// fnvHash produces a deterministic 32-bit hash from a stream index + virtual node number.
func fnvHash(streamIdx, vnode uint32) uint32 {
	h := uint32(fnvOffset32)
	var buf [8]byte
	buf[0] = byte(streamIdx >> 24)
	buf[1] = byte(streamIdx >> 16)
	buf[2] = byte(streamIdx >> 8)
	buf[3] = byte(streamIdx)
	buf[4] = byte(vnode >> 24)
	buf[5] = byte(vnode >> 16)
	buf[6] = byte(vnode >> 8)
	buf[7] = byte(vnode)
	for i := 0; i < len(buf); i++ {
		h ^= uint32(buf[i])
		h *= fnvPrime32
	}
	return h
}
