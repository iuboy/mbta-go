package binding

import (
	"context"
	"errors"
	"log/slog"
	"math"
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
			// 指数退避：首次 5ms，每次翻倍上限 1s。
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else {
				backoff = time.Duration(math.Min(float64(backoff*2), float64(time.Second)))
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		backoff = 0 // accept 成功，重置退避
		go func(conn C) {
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
		}(conn)
	}
}
