package v1

import (
	"testing"
)

// mockStream 是测试用 DataStream（实现 Write + Index）。
type mockStream struct{ idx int }

func (m *mockStream) Write(p []byte) (int, error) { return len(p), nil }
func (m *mockStream) Index() int                  { return m.idx }

// TestSingleStream_Pick 验证 single 策略：始终返回同一条流。
func TestSingleStream_Pick(t *testing.T) {
	ds := &mockStream{idx: 0}
	picker := NewSingleStream(ds)

	for _, tc := range []struct{ tag, source string }{
		{"a", "b"}, {"c", "d"}, {"", ""},
	} {
		got, err := picker.Pick(tc.tag, tc.source)
		if err != nil {
			t.Fatalf("Pick(%q,%q): %v", tc.tag, tc.source, err)
		}
		if got.Index() != 0 {
			t.Errorf("Pick(%q,%q) = stream %d, want 0", tc.tag, tc.source, got.Index())
		}
	}
}

// TestHashStreamPicker_Consistency 验证 hash 策略一致性：
// 同 tag+source 始终映射到同一条流（一致哈希核心性质）。
func TestHashStreamPicker_Consistency(t *testing.T) {
	picker := NewHashStreamPicker()
	for i := 0; i < 4; i++ {
		picker.AddStream(&mockStream{idx: i})
	}

	cases := []struct{ tag, source string }{
		{"logs", "host-1"}, {"metrics", "host-2"}, {"traces", "svc-a"},
	}
	results := make(map[string]int)
	for _, tc := range cases {
		ds, err := picker.Pick(tc.tag, tc.source)
		if err != nil {
			t.Fatalf("Pick(%q,%q): %v", tc.tag, tc.source, err)
		}
		key := tc.tag + "/" + tc.source
		results[key] = ds.Index()
	}

	// 二次 Pick 应返回相同结果
	for _, tc := range cases {
		ds, _ := picker.Pick(tc.tag, tc.source)
		key := tc.tag + "/" + tc.source
		if ds.Index() != results[key] {
			t.Errorf("Pick(%q,%q) inconsistent: first=%d second=%d", tc.tag, tc.source, results[key], ds.Index())
		}
	}
}

// TestHashStreamPicker_Empty 验证空 picker 返回 ErrNoStreams。
func TestHashStreamPicker_Empty(t *testing.T) {
	picker := NewHashStreamPicker()
	_, err := picker.Pick("tag", "source")
	if err == nil {
		t.Error("Pick on empty picker should return ErrNoStreams")
	}
}

// TestHashStreamPicker_Remove 验证移除流后 Pick 不返回已移除的流。
func TestHashStreamPicker_Remove(t *testing.T) {
	picker := NewHashStreamPicker()
	for i := 0; i < 4; i++ {
		picker.AddStream(&mockStream{idx: i})
	}
	picker.RemoveStream(1)
	if picker.Len() != 3 {
		t.Errorf("Len after remove = %d, want 3", picker.Len())
	}

	// 所有 Pick 不应返回已移除的 index 1
	for i := 0; i < 100; i++ {
		ds, err := picker.Pick("tag", string(rune('a'+i)))
		if err != nil {
			continue
		}
		if ds.Index() == 1 {
			t.Error("Pick returned removed stream index 1")
			break
		}
	}
}
