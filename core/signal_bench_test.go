package core

import (
	"encoding/json"
	"strconv"
	"testing"
)

// 量化 SignalBatch / BatchMessage / SecureEnvelope 各层序列化开销，
// 定位 e2e 端到端 allocs 的主要来源（events=1000 时 19798 allocs）。

func makeBenchBatch(n int) *SignalBatch {
	signals := make([]*SignalRecord, n)
	for i := range signals {
		signals[i] = &SignalRecord{
			SignalType: "log",
			EventID:    "evt-" + strconv.Itoa(i),
			Body:       "log line payload",
			Attributes: map[string]any{"k": "v", "i": i},
		}
	}
	return &SignalBatch{Signals: signals}
}

func BenchmarkMarshalSignalBatch(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		batch := makeBenchBatch(n)
		b.Run(scaleName(n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := MarshalSignalBatch(batch); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkUnmarshalSignalBatch(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		batch := makeBenchBatch(n)
		data, _ := MarshalSignalBatch(batch) // proto 编码（baseline 默认）
		b.Run(scaleName(n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := UnmarshalSignalBatch(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkMarshalBatchWrapper：BatchMessage（含 RawMessage 透传）的 marshal，
// 量化 wrapper 层是否对 RawMessage 做 compact 扫描（二次开销）。
func BenchmarkMarshalBatchWrapper(b *testing.B) {
	batchJSON, _ := json.Marshal(makeBenchBatch(1000))
	batch := BatchMessage{
		Seq:     1,
		ChunkId: []byte("chunk-1"),
		Tag:     "tag",
		Source:  "src",
		Batch:   json.RawMessage(batchJSON),
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Encode(&batch); err != nil {
			b.Fatal(err)
		}
	}
}
