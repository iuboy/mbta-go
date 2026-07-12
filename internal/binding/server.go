package binding

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// HandlerConfig 是 binding 层共享的 handler 配置，各 binding 从自己的 ServerConfig 构造。
type HandlerConfig struct {
	Auth            core.TokenValidator
	Policy          core.Policy
	Sink            core.EventSink
	Metrics         *core.MBTAMetrics
	ServerID        string
	RedirectChecker core.RedirectChecker
}

// AcceptLoop 是泛型 accept 循环骨架，消除 v1/ntls 的 ~50 行重复。
//
// 类型参数 C 是 binding 特有的连接类型（v1.*Conn / net.Conn）。
// 调用方提供：
//   - accept: 从 listener 取下一连接（ctx 取消时返回 error）
//   - newTransport: 把连接包装成 protocol.Transport
//   - closeConn: transport 构造失败时关闭连接（v1 用 CloseWithError，ntls 用 Close）
//
// connSem 由调用方持有，用于并发连接上限控制。
func AcceptLoop[C any](
	ctx context.Context,
	connSem chan struct{},
	accept func(context.Context) (C, error),
	newTransport func(context.Context, C) (protocol.Transport, error),
	closeConn func(C),
	hcfg HandlerConfig,
) error {
	// accept 错误指数退避（5ms→1s），防止 listener 持久错误（EMFILE 等）导致 CPU 空转。
	var backoff time.Duration
	for {
		select {
		case connSem <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		conn, err := accept(ctx)
		if err != nil {
			<-connSem
			if ctx.Err() != nil {
				return nil //nolint:nilerr // ctx 取消属优雅关闭
			}
			slog.Warn("accept error", "error", err)
			backoff = nextBackoff(backoff)
			if !sleepCtx(ctx, backoff) {
				return nil
			}
			continue
		}
		backoff = 0 // accept 成功，重置退避
		go handleConn(ctx, conn, connSem, newTransport, closeConn, hcfg)
	}
}

// nextBackoff 计算下一次 accept 退避（指数 5ms→1s）。
// 用整数比较替代 math.Min 的 float 转换，避免精度与开销问题。
func nextBackoff(prev time.Duration) time.Duration {
	if prev == 0 {
		return 5 * time.Millisecond
	}
	next := prev * 2
	if next > time.Second || next <= 0 { // <=0 兼容溢出回绕
		return time.Second
	}
	return next
}

// sleepCtx 睡眠 d 或直到 ctx 取消；ctx 取消返回 false。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

// handleConn 处理单个连接的完整生命周期（transport 建立 → 协议处理），
// 含 panic recover 防 single 连接崩溃整个服务。提取自 AcceptLoop 降低认知复杂度。
func handleConn[C any](
	ctx context.Context,
	conn C,
	connSem chan struct{},
	newTransport func(context.Context, C) (protocol.Transport, error),
	closeConn func(C),
	hcfg HandlerConfig,
) {
	defer func() { <-connSem }()
	// recover 防止单个连接的 panic 崩溃整个服务进程。
	defer func() {
		if r := recover(); r != nil {
			slog.Error("handler panic recovered", "panic", r)
			if closeConn != nil {
				closeConn(conn)
			}
		}
	}()
	tr, err := newTransport(ctx, conn)
	if err != nil {
		slog.Error("transport setup", "error", err)
		if closeConn != nil {
			closeConn(conn)
		}
		return
	}
	h := protocol.NewCoreHandler(tr, protocol.HandlerConfig{
		Auth:            hcfg.Auth,
		Policy:          hcfg.Policy,
		Sink:            hcfg.Sink,
		Metrics:         hcfg.Metrics,
		ServerID:        hcfg.ServerID,
		RedirectChecker: hcfg.RedirectChecker,
	})
	if err := h.Handle(ctx); err != nil {
		// ErrRedirected is normal HA flow (follower steered a client to
		// the leader), not a handler error — suppress the noisy log.
		if errors.Is(err, core.ErrRedirected) {
			slog.Debug("connection redirected to leader")
		} else {
			slog.Error("handler error", "error", err)
		}
	}
}
