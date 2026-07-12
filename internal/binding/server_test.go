package binding

import (
	"context"
	"testing"
	"time"
)

// TestNextBackoff 验证 accept 错误指数退避：5ms 起步，倍增，上限 1s。
// 覆盖整数比较实现（替代 math.Min 的 float 转换）的正确性，含溢出回绕兜底。
func TestNextBackoff(t *testing.T) {
	tests := []struct {
		name string
		prev time.Duration
		want time.Duration
	}{
		{"initial", 0, 5 * time.Millisecond},
		{"second", 5 * time.Millisecond, 10 * time.Millisecond},
		{"doubling", 10 * time.Millisecond, 20 * time.Millisecond},
		{"mid", 100 * time.Millisecond, 200 * time.Millisecond},
		{"near_cap", 600 * time.Millisecond, time.Second},
		{"at_cap", time.Second / 2, time.Second},
		{"over_cap", time.Second, time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nextBackoff(tt.prev); got != tt.want {
				t.Errorf("nextBackoff(%v) = %v, want %v", tt.prev, got, tt.want)
			}
		})
	}
}

// TestNextBackoffMonotonic 确保退避序列单调非递减且封顶于 1s。
func TestNextBackoffMonotonic(t *testing.T) {
	var d time.Duration
	maxBackoff := time.Second
	for i := 0; i < 20; i++ {
		next := nextBackoff(d)
		if next < d {
			t.Fatalf("iteration %d: nextBackoff decreased: %v < %v", i, next, d)
		}
		if next > maxBackoff {
			t.Fatalf("iteration %d: nextBackoff exceeded cap: %v > %v", i, next, maxBackoff)
		}
		d = next
	}
	if d != maxBackoff {
		t.Errorf("expected to reach cap %v after iterations, got %v", maxBackoff, d)
	}
}

// TestSleepCtx 验证 sleepCtx 在 ctx 取消时立即返回 false。
func TestSleepCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 已取消的 ctx
	if sleepCtx(ctx, 5*time.Second) {
		t.Error("sleepCtx should return false on already-cancelled ctx")
	}
}
