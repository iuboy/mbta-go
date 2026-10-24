package binding

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/internal/protocol"
)

// unusedRunSpec 返回除 Listen 外全部为最小实现的 RunSpec（Accept 随 ctx 退出）。
func minimalSpec(listen func(ctx context.Context) (net.Conn, error)) RunSpec[net.Conn, net.Conn] {
	return RunSpec[net.Conn, net.Conn]{
		Listen: listen,
		Accept: func(ctx context.Context, c net.Conn) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		NewTransport: func(ctx context.Context, c net.Conn) (protocol.Transport, error) {
			return nil, errors.New("unused in this test")
		},
		CloseConn:     func(c net.Conn) { _ = c.Close() },
		AddrOf:        func(c net.Conn) net.Addr { return c.RemoteAddr() },
		CloseListener: func(c net.Conn) error { return c.Close() },
	}
}

// Close 在 starting 态（Run 已进入、Listen 未收敛）必须等待收敛后再关闭——
// 此前直接返回 nil 且不阻止 Run 继续监听：调用方坚信已关闭而服务器永远运行
// （审查 F3 裁决）。
func TestServer_CloseDuringStartingWaitsThenCloses(t *testing.T) {
	s := NewServer[net.Conn, net.Conn](4, HandlerConfig{})
	listenStarted := make(chan struct{})
	release := make(chan struct{})
	spec := minimalSpec(func(ctx context.Context) (net.Conn, error) {
		close(listenStarted)
		<-release
		c1, _ := net.Pipe()
		return c1, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(ctx, spec) }()
	<-listenStarted

	closeDone := make(chan error, 1)
	go func() { closeDone <- s.Close(func(c net.Conn) error { return c.Close() }) }()

	select {
	case err := <-closeDone:
		t.Fatalf("Close returned while Run still starting (err=%v); must wait for convergence (F3 regression)", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after Listen converged")
	}

	// 解除 AcceptLoop 并确认状态机收敛（ stopped）：随后可重新 Run（无状态滞留）。
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after listener close + ctx cancel")
	}
	s.mu.Lock()
	st := s.runState.Load()
	s.mu.Unlock()
	if st != runStateStopped {
		t.Fatalf("runState = %d, want stopped after Run exit", st)
	}
}

// 旧代 Run 的退出兜底不得把新一代 Run 的 starting 状态踩回 stopped（审查 F4）。
// 直接驱动状态机复现交错序列：Run1(running) → Close→stopped → Run2(starting)
// → 模拟 Run1 退出兜底 → Run2 的 starting 必须原样保留。
func TestServer_StaleRunExitDoesNotStompNextGeneration(t *testing.T) {
	s := NewServer[net.Conn, net.Conn](4, HandlerConfig{})

	// Run1 已 running（gen=1）。
	s.mu.Lock()
	s.runState.Store(runStateRunning)
	gen1 := s.runGen.Add(1)
	s.startingChanged.Broadcast()
	s.mu.Unlock()

	// Close：running→stopped（模拟 Run1 期间的外部关闭）。
	if err := s.Close(func(net.Conn) error { return nil }); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Run2 启动：CAS stopped→starting + 登记新代（与 Run 入口同序，锁内完成）。
	s.mu.Lock()
	if !s.runState.CompareAndSwap(runStateStopped, runStateStarting) {
		s.mu.Unlock()
		t.Fatal("Run2 CAS failed; state machine did not converge to stopped")
	}
	gen2 := s.runGen.Add(1)
	s.startingChanged.Broadcast()
	s.mu.Unlock()

	// 模拟 Run1 的退出兜底（与 Run defer 相同逻辑）：仅本代生效。
	if !s.runState.CompareAndSwap(runStateRunning, runStateStopped) &&
		s.runGen.Load() == gen1 && s.runState.Load() == runStateStarting {
		s.runState.Store(runStateStopped)
	}

	s.mu.Lock()
	st := s.runState.Load()
	s.mu.Unlock()
	if st != runStateStarting {
		t.Fatalf("runState = %d, want starting (stale generation stomped Run2, F4 regression)", st)
	}
	_ = gen2

	// Run2 正常收敛到 running 后，Close 必须能关闭（F3 正向语义）。
	go func() {
		s.mu.Lock()
		s.runState.Store(runStateRunning)
		s.startingChanged.Broadcast()
		s.mu.Unlock()
	}()
	if err := s.Close(func(net.Conn) error { return nil }); err != nil {
		t.Fatalf("Close after Run2 running: %v", err)
	}
}
