package binding

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/iuboy/mbta-go/internal/protocol"
)

// Server 是 binding 无关的服务端外壳，对称于客户端 Phase 2 下沉。
//
// 类型参数：
//   - L：binding 特有的 listener 类型（v1.*Listener / ntls.*Listener）
//   - C：binding 特有的连接类型（v1.*Conn / net.Conn）
//
// 各 binding 仅需：
//   - 定义 type Server = binding.Server[*xxxListener, *xxConn]
//   - 在 NewServer 做 binding 专属校验后调用 binding.NewServer 填默认值
//   - 在 Start 调用 Run，传入 5 个闭包
//   - Addr/Close 委托本包方法，传入 binding 特有的 addr/close 函数
//
// 消除 v1/server.go 与 ntls/transport.go 中 Server 结构体、NewServer 默认值、
// Start 前言（log + ctx-cancel goroutine）、Addr/Close 的 ~40 行重复。
type Server[L, C any] struct {
	mu       sync.Mutex
	listener L
	// runState 是原子状态机，替代旧 listenerSet bool，消除 Run 的 TOCTOU：
	//   stopped(0) → starting(1) → running(2) → stopped(0)
	// CAS stopped→starting 保证只有一个 goroutine 进入 Listen；若 CAS 失败说明
	// 另一个 Run 正在进行（旧实现「检查 bool → 解锁 → Listen → 加锁置 bool」
	// 允许两个并发 Run 都通过检查，各自 Listen 导致 fd/ctx-cancel goroutine 泄漏）。
	runState atomic.Uint32
	connSem  chan struct{}
	hcfg     HandlerConfig
}

// runState 取值。
const (
	runStateStopped  uint32 = 0
	runStateStarting uint32 = 1
	runStateRunning  uint32 = 2
)

// NewServer 构造 Server[L,C]：填充 maxConns 默认值与 connSem。
func NewServer[L, C any](maxConns int, hcfg HandlerConfig) *Server[L, C] {
	if maxConns <= 0 {
		maxConns = DefaultMaxConcurrentConns
	}
	return &Server[L, C]{
		connSem: make(chan struct{}, maxConns),
		hcfg:    hcfg,
	}
}

// RunSpec 是 Run 的配置：5 个 binding 特有的闭包，描述如何 listen/accept/包装/关闭。
type RunSpec[L, C any] struct {
	// Listen 构造 listener 并返回（Start 成功后注入 Server.listener）。
	Listen func(ctx context.Context) (L, error)
	// Accept 从 listener 取下一连接（ctx 取消时返回 error）。
	Accept func(ctx context.Context, l L) (C, error)
	// NewTransport 把连接包装成 protocol.Transport。
	NewTransport func(ctx context.Context, c C) (protocol.Transport, error)
	// CloseConn 在 transport 构造失败时关闭连接（v1 用 CloseWithError，ntls 用 Close）。
	CloseConn func(c C)
	// AddrOf 返回 listener 的监听地址（Addr() 用）。
	AddrOf func(l L) net.Addr
	// CloseListener 关闭 listener（Close() 与 ctx-cancel 都用）。
	CloseListener func(l L) error
}

// Run 启动 listener 并驱动 AcceptLoop，直到 ctx 取消。阻塞返回。
//
// 各 binding 的 Start 只需：校验配置 → 调 NewServer → 调 Run。
//
// 并发安全：用 CAS 状态机（stopped→starting→running）保证同一时刻只有一个
// Run 进入 Listen，消除旧实现「检查 listenerSet → 解锁 → Listen → 加锁置位」
// 的 TOCTOU 窗口（两个并发 Run 都能通过检查，各自 Listen 导致 fd/goroutine 泄漏）。
func (s *Server[L, C]) Run(ctx context.Context, spec RunSpec[L, C]) error {
	// CAS stopped→starting：只有一个 goroutine 能进入 Listen。
	if !s.runState.CompareAndSwap(runStateStopped, runStateStarting) {
		return errors.New("binding.Server.Run: already running")
	}
	// 确保异常退出（Listen 失败或 AcceptLoop 返回）时重置状态，允许后续 Run/重启。
	defer func() {
		// AcceptLoop 返回（含 ctx 取消的「正常」退出）后回到 stopped。
		// 优先 CAS running→stopped（正常退出路径）；若仍处于 starting（Listen panic
		// 导致状态滞留）则兜底 Store stopped，保证任何退出路径都能恢复状态机。
		if !s.runState.CompareAndSwap(runStateRunning, runStateStopped) {
			s.runState.Store(runStateStopped)
		}
	}()

	l, err := spec.Listen(ctx)
	if err != nil {
		// Listen 失败：重置 starting→stopped，允许重试（defer 也会兜底）。
		s.runState.Store(runStateStopped)
		return err
	}
	// listener 赋值与状态转换 runState=running 必须在同一锁内原子完成，
	// 否则 Addr() 可能读到 starting 态返回空串、Close() CAS 失败导致 listener 泄漏。
	s.mu.Lock()
	s.listener = l
	s.runState.Store(runStateRunning)
	s.mu.Unlock()
	slog.Info("MBTA server listening", "addr", spec.AddrOf(l))

	// ctx 取消时关闭 listener：被 Accept 阻塞的循环因此解除并退出。
	// 监听器 Close 幂等，与 Server.Close 并发调用安全。
	go func() {
		<-ctx.Done()
		_ = spec.CloseListener(l)
	}()

	return AcceptLoop(ctx, s.connSem,
		func(ctx context.Context) (C, error) { return spec.Accept(ctx, l) },
		spec.NewTransport,
		spec.CloseConn,
		s.hcfg,
	)
}

// Addr 返回监听地址（Start 成功后有效；启动前返回空串）。
func (s *Server[L, C]) Addr(addrOf func(l L) net.Addr) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 仅在 running 态返回地址；starting/stopped 态 listener 未就绪或已关闭。
	if s.runState.Load() != runStateRunning {
		return ""
	}
	a := addrOf(s.listener)
	if a == nil {
		return ""
	}
	return a.String()
}

// Close 关闭 listener（幂等：多次调用安全）。
//
// 用 CAS running→stopped 保证只有一个 Close 实际关闭 listener；并发 Close 或
// 在 stopped 态调用直接返回 nil。Run 的 defer 也会 CAS running→stopped，与
// Close 互斥（任一先执行完成关闭，另一者看到 stopped 返回 nil）。
//
// 注意：若在 starting 态调用 Close（listener 尚未就绪），Close 返回 nil 且
// 不关闭任何资源，也不阻止 Run 继续执行。调用方应确保在 Run 返回后调用 Close，
// 或通过 ctx 取消来终止运行中的 Run。
func (s *Server[L, C]) Close(closeListener func(l L) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.runState.CompareAndSwap(runStateRunning, runStateStopped) {
		// 非 running 态（stopped/starting）：listener 未就绪或已被关闭，幂等返回 nil。
		return nil
	}
	return closeListener(s.listener)
}
