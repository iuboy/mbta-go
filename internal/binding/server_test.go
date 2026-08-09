package binding

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/internal/protocol"
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
	for i := range 20 {
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

// TestRun_NilRunSpecFields 验证 Run 在 RunSpec 任一闭包为 nil 时 fail-fast 返回错误，
// 而非后续调用 nil 闭包触发 panic。
func TestRun_NilRunSpecFields(t *testing.T) {
	srv := NewServer[net.Listener, net.Conn](1, HandlerConfig{})
	ctx := context.Background()

	// 所有字段都缺省（nil）的 spec。
	spec := RunSpec[net.Listener, net.Conn]{}
	err := srv.Run(ctx, spec)
	if err == nil {
		t.Fatal("Run with nil RunSpec fields expected error, got nil")
	}
	if !strings.Contains(err.Error(), "non-nil") {
		t.Fatalf("error %q does not mention non-nil requirement", err.Error())
	}
}

// TestRun_NilRunSpecEachField 验证 6 个 RunSpec 字段逐个为 nil 时都触发错误。
// 确保复合 nil 检查没有字段被遗漏。
func TestRun_NilRunSpecEachField(t *testing.T) {
	noop := func() {} // 占位非 nil func
	addrOf := func(net.Listener) net.Addr { return nil }
	// 完整合法 spec 基线（所有字段非 nil），各子测试逐个置 nil。
	full := func() RunSpec[net.Listener, net.Conn] {
		return RunSpec[net.Listener, net.Conn]{
			Listen:        func(context.Context) (net.Listener, error) { return nil, nil },
			Accept:        func(context.Context, net.Listener) (net.Conn, error) { return nil, nil },
			NewTransport:  func(context.Context, net.Conn) (protocol.Transport, error) { return nil, nil },
			CloseConn:     func(net.Conn) { noop() },
			AddrOf:        addrOf,
			CloseListener: func(net.Listener) error { return nil },
		}
	}
	// 每个字段名对应一个 mutate，把该字段置 nil。
	cases := []struct {
		name   string
		mutate func(RunSpec[net.Listener, net.Conn]) RunSpec[net.Listener, net.Conn]
	}{
		{"Listen nil", func(s RunSpec[net.Listener, net.Conn]) RunSpec[net.Listener, net.Conn] { s.Listen = nil; return s }},
		{"Accept nil", func(s RunSpec[net.Listener, net.Conn]) RunSpec[net.Listener, net.Conn] { s.Accept = nil; return s }},
		{"NewTransport nil", func(s RunSpec[net.Listener, net.Conn]) RunSpec[net.Listener, net.Conn] {
			s.NewTransport = nil
			return s
		}},
		{"CloseConn nil", func(s RunSpec[net.Listener, net.Conn]) RunSpec[net.Listener, net.Conn] { s.CloseConn = nil; return s }},
		{"AddrOf nil", func(s RunSpec[net.Listener, net.Conn]) RunSpec[net.Listener, net.Conn] { s.AddrOf = nil; return s }},
		{"CloseListener nil", func(s RunSpec[net.Listener, net.Conn]) RunSpec[net.Listener, net.Conn] {
			s.CloseListener = nil
			return s
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewServer[net.Listener, net.Conn](1, HandlerConfig{})
			err := srv.Run(context.Background(), tc.mutate(full()))
			if err == nil {
				t.Fatalf("expected non-nil error when %s", tc.name)
			}
			if !strings.Contains(err.Error(), "non-nil") {
				t.Fatalf("error %q does not mention non-nil requirement", err.Error())
			}
		})
	}
}
