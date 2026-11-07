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

// Server 是 binding 无关的服务端外壳。
//
// 类型参数：
//   - L：binding 特有的 listener 类型（v1.*Listener / ntls.*Listener）
//   - C：binding 特有的连接类型（v1.*Conn / net.Conn）
//
// 各 binding 仅需：
//   - 定义 type Server = binding.Server[*xxxListener, *xxConn]
//   - 在 NewServer 做 binding 专属校验后调用 binding.NewServer 填默认值
//   - 在 Start 调用 Run，传入 6 个闭包（RunSpec）
//   - Addr/Close 委托本包方法，传入 binding 特有的 addr/close 函数
//
// 消除 v1/server.go 与 ntls/transport.go 中 Server 结构体、NewServer 默认值、
// Start 前言（log + ctx-cancel goroutine）、Addr/Close 的 ~40 行重复。
type Server[L, C any] struct {
	mu       sync.RWMutex
	listener L
	// runState 是原子状态机（而非 listenerSet bool），消除 Run 的 TOCTOU：
	//   stopped(0) → starting(1) → running(2) → stopped(0)
	// CAS stopped→starting 保证只有一个 goroutine 进入 Listen；若 CAS 失败说明
	// 另一个 Run 正在进行（「检查 bool → 解锁 → Listen → 加锁置 bool」
	// 允许两个并发 Run 都通过检查，各自 Listen 导致 fd/ctx-cancel goroutine 泄漏）。
	runState atomic.Uint32
	// runGen 是 Run 的代次号（Run 进入 starting 后递增）：退出路径的兜底状态
	// 复位仅对本代生效——新一代 Run 已接管状态机时，旧代的 defer 不得越权把
	// starting 踩回 stopped（审查 F4 裁决）。
	runGen atomic.Uint64
	// startingChanged 在 Run 离开 starting（→running 或 →stopped）时广播：
	// Close 据此等待 starting 收敛后再关闭——starting 态的 Close 此前返回 nil
	// 但服务器随后照常监听（审查 F3 裁决：Close 返回 nil 是最强的「已关闭」信号）。
	startingChanged *sync.Cond
	connSem         chan struct{}
	hcfg            HandlerConfig
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
	s := &Server[L, C]{
		connSem: make(chan struct{}, maxConns),
		hcfg:    hcfg,
	}
	s.startingChanged = sync.NewCond(&s.mu)
	return s
}

// RunSpec 是 Run 的配置：6 个 binding 特有的闭包，描述如何 listen/accept/包装/关闭。
type RunSpec[L, C any] struct {
	// Listen 构造 listener 并返回（Start 成功后注入 Server.listener）。
	// 无 ctx：listener 创建非阻塞，取消语义由 Accept 承担——与 v1/ntls
	// 的 Listen(cfg) 导出面同构（ctx 死参数破坏性收口）。
	Listen func() (L, error)
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
// Run 进入 Listen，消除「检查 listenerSet → 解锁 → Listen → 加锁置位」
// 的 TOCTOU 窗口（两个并发 Run 都能通过检查，各自 Listen 导致 fd/goroutine 泄漏）。
func (s *Server[L, C]) Run(ctx context.Context, spec RunSpec[L, C]) error {
	// fail-fast：RunSpec 任一闭包未设置会在后续 Listen/Accept 调用时 nil panic，
	// 在此集中校验，给出明确错误而非运行时 panic。
	if spec.Listen == nil || spec.Accept == nil || spec.NewTransport == nil ||
		spec.CloseConn == nil || spec.AddrOf == nil || spec.CloseListener == nil {
		return errors.New("binding.Server.Run: RunSpec fields must all be non-nil")
	}
	// CAS stopped→starting：只有一个 goroutine 能进入 Listen（锁内完成代次登记，
	// 与退出路径的兜底判定互斥，消除「Run2 已 CAS、尚未登记代次」的踩踏窗口）。
	s.mu.Lock()
	if !s.runState.CompareAndSwap(runStateStopped, runStateStarting) {
		s.mu.Unlock()
		return errors.New("binding.Server.Run: already running")
	}
	myGen := s.runGen.Add(1)
	s.startingChanged.Broadcast()
	s.mu.Unlock()
	// 确保异常退出（Listen 失败或 AcceptLoop 返回）时重置状态，允许后续 Run/重启。
	defer func() {
		// AcceptLoop 返回（含 ctx 取消的「正常」退出）后回到 stopped。
		// 优先 CAS running→stopped（正常退出路径）；若仍处于 starting（Listen panic
		// 导致状态滞留）则兜底 Store stopped——仅限本代：新一代 Run 已接管时跳过。
		if !s.runState.CompareAndSwap(runStateRunning, runStateStopped) &&
			s.runGen.Load() == myGen && s.runState.Load() == runStateStarting {
			s.runState.Store(runStateStopped)
		}
		s.mu.Lock()
		s.startingChanged.Broadcast()
		s.mu.Unlock()
	}()

	l, err := spec.Listen()
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
	s.startingChanged.Broadcast()
	s.mu.Unlock()
	slog.Info("MBTA server listening", "addr", spec.AddrOf(l))

	// ctx 取消时关闭 listener：被 Accept 阻塞的循环因此解除并退出。
	// 监听器 Close 幂等，与 Server.Close 并发调用安全。
	// done channel 让此 goroutine 在 Run 返回后也退出，即便调用方忘记取消 ctx。
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
			// Run 已返回，但 ctx.Done 同时就绪时 select 可能恰好选中 done（随机）。
			// 此时若不关闭，Run 的 defer 已把状态回置 stopped，Close() 的 CAS 会失败
			// 跳过关闭——listener fd 泄漏。ctx 已取消时仍需关闭。
			if ctx.Err() == nil {
				return
			}
		}
		if err := spec.CloseListener(l); err != nil {
			// 关闭失败须留痕：此路径是防 listener fd 泄漏的兜底，静默吞错会让
			// 泄漏无从排查（Close 的返回错误另经调用方通道上报）。
			slog.Debug("close listener on ctx cancel", "error", err)
		}
	}()
	defer close(done)

	AcceptLoop(ctx, s.connSem,
		func(ctx context.Context) (C, error) { return spec.Accept(ctx, l) },
		spec.NewTransport,
		spec.CloseConn,
		s.hcfg,
	)
	return nil
}

// Addr 返回监听地址（Start 成功后有效；启动前返回空串）。读多写少，读锁即可。
func (s *Server[L, C]) Addr(addrOf func(l L) net.Addr) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
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
// starting 态（Run 已进入但 listener 未就绪）：等待 Run 收敛到 running 或
// stopped 后再执行关闭——此前此态直接返回 nil 且不阻止 Run 继续监听，
// 调用方坚信已关闭而服务器永远运行（审查 F3 裁决）。Listen 闭包按约定只做
// 本地 bind（快速返回），等待窗口为毫秒级；若自定义 Listen 闭包长期阻塞，
// Close 将随之等待。
func (s *Server[L, C]) Close(closeListener func(l L) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.runState.Load() == runStateStarting {
		s.startingChanged.Wait()
	}
	if !s.runState.CompareAndSwap(runStateRunning, runStateStopped) {
		// stopped 态：listener 未就绪或已被关闭（含 Run defer 已收敛），幂等返回 nil。
		return nil
	}
	return closeListener(s.listener)
}
