package core

import (
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// CBOR 解码上限收紧回归（审查 P2-1）：解码器不再使用库默认上限（131072 对 /
// 元素），恶意载荷在分配放大发生前即被拒绝。上限对齐协议约束：map ≤ 256
// （attributes ≤ 128 的裕量）、array ≤ 10000（maxBatchEvents）。
func TestCborUnmarshal_RejectsOversizedMap(t *testing.T) {
	// 构造 300 对的顶层 CBOR map（> 256 上限）。
	huge := make(map[int]int, 300)
	for i := range 300 {
		huge[i] = i
	}
	wire, err := cbor.Marshal(huge)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	var sb SignalBatch
	err = cborDecMode.Unmarshal(wire, &sb)
	if err == nil {
		t.Fatal("oversized map accepted; decoder limits not enforced")
	}
	var limitErr *cbor.MaxMapPairsError
	if !errors.As(err, &limitErr) && !strings.Contains(err.Error(), "map") {
		t.Fatalf("err = %v, want map-pairs limit error", err)
	}
}

func TestCborUnmarshal_RejectsOversizedArray(t *testing.T) {
	huge := make([]int, 10001)
	wire, err := cbor.Marshal(huge)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	var sb SignalBatch
	if err := cborDecMode.Unmarshal(wire, &sb); err == nil {
		t.Fatal("oversized array accepted; decoder limits not enforced")
	}
}

// 合法形状不受限：10000 条 signals 的批次必须仍可解码（上限不得误伤协议允许值）。
func TestCborUnmarshal_AllowsMaxBatchEvents(t *testing.T) {
	sb := &SignalBatch{Signals: make([]*SignalRecord, 10000)}
	wire, err := cborEncMode.Marshal(sb)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := cborDecMode.Unmarshal(wire, &sb); err != nil {
		t.Fatalf("exactly-max batch rejected: %v", err)
	}
	if len(sb.Signals) != 10000 {
		t.Fatalf("signals = %d, want 10000", len(sb.Signals))
	}
}
