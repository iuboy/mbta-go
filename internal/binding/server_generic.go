package binding

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"

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
	mu          sync.Mutex
	listener    L
	listenerSet bool // 避免类型化 nil 指针（如 *Listener）经 any() 包装后非 nil 的陷阱
	connSem     chan struct{}
	hcfg        HandlerConfig
}

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
func (s *Server[L, C]) Run(ctx context.Context, spec RunSpec[L, C]) error {
	// 拒绝重复调用 Run：第二次会覆盖 s.listener 且不关闭旧的，泄漏 fd 和 ctx-cancel goroutine。
	s.mu.Lock()
	if s.listenerSet {
		s.mu.Unlock()
		return errors.New("binding.Server.Run: already running")
	}
	s.mu.Unlock()

	l, err := spec.Listen(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = l
	s.listenerSet = true
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
	if !s.listenerSet {
		return ""
	}
	a := addrOf(s.listener)
	if a == nil {
		return ""
	}
	return a.String()
}

// Close 关闭 listener（幂等：多次调用安全）。
func (s *Server[L, C]) Close(closeListener func(l L) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.listenerSet {
		return nil
	}
	s.listenerSet = false // 标记已关闭，使 Close 真正幂等 + Addr 返回空串
	return closeListener(s.listener)
}
