package v1

import (
	"fmt"
	"testing"

	"github.com/iuboy/mbta-go/core"
)

type mockStream struct {
	idx int
}

func (m *mockStream) Index() int { return m.idx }

func TestSingleStream(t *testing.T) {
	ds := &mockStream{idx: 0}
	p := NewSingleStream(ds)

	batch := core.BatchMessage{Seq: 1, ChunkID: "c1", Tag: "t", Source: "s"}
	got, err := p.Pick(batch)
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	if got.Index() != 0 {
		t.Fatalf("expected index 0, got %d", got.Index())
	}
	if p.Len() != 1 {
		t.Fatalf("expected len 1, got %d", p.Len())
	}
}

func TestHashPickerDistribution(t *testing.T) {
	h := NewHashStreamPicker()
	s0 := &mockStream{idx: 0}
	s1 := &mockStream{idx: 1}
	s2 := &mockStream{idx: 2}
	h.AddStream(s0)
	h.AddStream(s1)
	h.AddStream(s2)

	if h.Len() != 3 {
		t.Fatalf("expected 3 streams, got %d", h.Len())
	}

	counts := make(map[int]int)
	for i := 0; i < 300; i++ {
		tag := fmt.Sprintf("tag-%03d", i)
		batch := core.BatchMessage{Seq: 1, ChunkID: "c", Tag: tag, Source: "src"}
		ds, err := h.Pick(batch)
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		counts[ds.Index()]++
	}

	// Each stream should get at least some traffic
	for idx := 0; idx < 3; idx++ {
		if counts[idx] == 0 {
			t.Errorf("stream %d got zero batches", idx)
		}
	}
}

func TestHashPickerDeterministic(t *testing.T) {
	h := NewHashStreamPicker()
	h.AddStream(&mockStream{idx: 0})
	h.AddStream(&mockStream{idx: 1})

	batch := core.BatchMessage{Seq: 1, ChunkID: "c", Tag: "fixed-tag", Source: "fixed-src"}
	first, _ := h.Pick(batch)
	for i := 0; i < 100; i++ {
		got, _ := h.Pick(batch)
		if got.Index() != first.Index() {
			t.Fatalf("same tag/source must always pick same stream")
		}
	}
}

func TestHashPickerNoStreams(t *testing.T) {
	h := NewHashStreamPicker()
	_, err := h.Pick(core.BatchMessage{Seq: 1, ChunkID: "c"})
	if err != ErrNoStreams {
		t.Fatalf("expected ErrNoStreams, got %v", err)
	}
}

func TestHashPickerRemove(t *testing.T) {
	h := NewHashStreamPicker()
	h.AddStream(&mockStream{idx: 0})
	h.AddStream(&mockStream{idx: 1})
	h.RemoveStream(0)

	if h.Len() != 1 {
		t.Fatalf("expected 1 after remove, got %d", h.Len())
	}

	// Should only ever pick stream 1 now
	for i := 0; i < 50; i++ {
		ds, err := h.Pick(core.BatchMessage{Seq: 1, ChunkID: "c", Tag: "t", Source: "s"})
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		if ds.Index() != 1 {
			t.Fatalf("expected stream 1 after removal, got %d", ds.Index())
		}
	}
}
