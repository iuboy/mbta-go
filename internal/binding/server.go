package binding

// server.go：binding 层服务端外壳（accept 循环 + handleConn + 泛型 Server）。

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// DefaultMaxConcurrentConns 是并发连接上限默认值。
const DefaultMaxConcurrentConns = 10000

// HandlerConfig 是 binding 层共享的 handler 配置。
type HandlerConfig struct {
	Auth              core.TokenValidator
	Policy            core.ServerPolicy
	Metrics           core.Metrics
	ServerID          string
	RedirectChecker   core.RedirectChecker
	OnSession         core.OnSession
	SinkOpts          core.SinkOptions
	SinkHandler       core.BatchHandler
	SinkDeadline      time.Duration
	SinkQueueSize     int
	SinkQueueMaxBytes int64
	Epochs            *protocol.EpochAllocator
}

// ResolveHandlerConfig 校验并填充公共字段。
func ResolveHandlerConfig(hcfg *HandlerConfig) error {
	if hcfg.Auth == nil {
		return core.NewError(core.ErrCodeConfig, "Auth (TokenValidator) is required")
	}
	if hcfg.SinkHandler == nil {
		return core.NewError(core.ErrCodeConfig, "SinkHandler is required")
	}
	if err := hcfg.Policy.Validate(); err != nil {
		return core.WrapError(core.ErrCodeConfig, "Policy", err)
	}
	if hcfg.ServerID == "" {
		hcfg.ServerID = core.NewChunkID().String()
	}
	return nil
}

// AcceptLoop 是泛型 accept 循环骨架。
func AcceptLoop[C any](
	ctx context.Context,
	connSem chan struct{},
	accept func(context.Context) (C, error),
	newTransport func(context.Context, C) (protocol.Transport, error),
	closeConn func(C),
	hcfg HandlerConfig,
) error {
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
			if errors.Is(err, net.ErrClosed) {
				slog.Debug("listener closed, accept loop exiting")
				return nil //nolint:nilerr // listener 关闭属正常停止路径
			}
			slog.Warn("accept error", "error", err)
			backoff = nextBackoff(backoff)
			if !sleepCtx(ctx, backoff) {
				return nil
			}
			continue
		}
		backoff = 0
		go handleConn(ctx, conn, connSem, newTransport, closeConn, hcfg)
	}
}

func nextBackoff(prev time.Duration) time.Duration {
	if prev == 0 {
		return 5 * time.Millisecond
	}
	next := prev * 2
	if next > time.Second || next <= 0 {
		return time.Second
	}
	return next
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// handleConn 处理单连接生命周期。
func handleConn[C any](
	ctx context.Context,
	conn C,
	connSem chan struct{},
	newTransport func(context.Context, C) (protocol.Transport, error),
	closeConn func(C),
	hcfg HandlerConfig,
) {
	defer func() { <-connSem }()
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
	if tr == nil {
		slog.Error("transport setup returned nil transport")
		if closeConn != nil {
			closeConn(conn)
		}
		return
	}
	defer func() {
		if err := tr.Close(); err != nil {
			slog.Debug("transport close after handle", "error", err)
		}
	}()
	h := protocol.NewCoreHandler(tr, protocol.HandlerConfig{
		Auth:              hcfg.Auth,
		Policy:            hcfg.Policy,
		Metrics:           hcfg.Metrics,
		ServerID:          hcfg.ServerID,
		RedirectChecker:   hcfg.RedirectChecker,
		OnSession:         hcfg.OnSession,
		Epochs:            hcfg.Epochs,
		SinkOpts:          hcfg.SinkOpts,
		SinkHandler:       hcfg.SinkHandler,
		SinkDeadline:      hcfg.SinkDeadline,
		SinkQueueSize:     hcfg.SinkQueueSize,
		SinkQueueMaxBytes: hcfg.SinkQueueMaxBytes,
	})
	if err := h.Handle(ctx); err != nil {
		if core.CodeNumOf(err) == core.CodeProtocolError || core.CodeNumOf(err) == core.CodeServerDraining {
			slog.Debug("connection ended")
		} else {
			slog.Error("handler error", "error", err)
		}
	}
}
