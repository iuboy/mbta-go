package binding

// server.go：binding 层服务端外壳（accept 循环 + handleConn + 泛型 Server）。

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// safeClose 带 recover 的连接关闭：closeConn 闭包（binding 注入）若对零值
// conn panic，会发生在 recover 分支内——recover 期间的 panic 不再被捕获，
// 直接击穿进程（review F16 裁决：防御链不允许在恢复层断掉）。
func safeClose[C any](closeConn func(C), conn C) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("closeConn panicked during cleanup", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	if closeConn != nil {
		closeConn(conn)
	}
}

// DefaultMaxConcurrentConns 是并发连接上限默认值。
const DefaultMaxConcurrentConns = 10000

// EpochAlloc 归一化纪元分配器（nil = 新建独立分配器）。v1/ntls 的 NewServer
// 各自需要同一逻辑——此前两处逐字重复（review P3 裁决上提）。
func EpochAlloc(e *protocol.EpochAllocator) *protocol.EpochAllocator {
	if e != nil {
		return e
	}
	return &protocol.EpochAllocator{}
}

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
	Commands          *protocol.CommandRegistry
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

// AcceptLoop 是泛型 accept 循环骨架。无返回值：accept 级错误经 backoff 循环
// 消化，循环只随 ctx 取消/listener 关闭退出（此前签名承诺 error 但全部路径
// 返回 nil，误导读者寻找「致命错误」分支——review F15 裁决）。
func AcceptLoop[C any](
	ctx context.Context,
	connSem chan struct{},
	accept func(context.Context) (C, error),
	newTransport func(context.Context, C) (protocol.Transport, error),
	closeConn func(C),
	hcfg HandlerConfig,
) {
	var backoff time.Duration
	for {
		select {
		case connSem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		conn, err := accept(ctx)
		if err != nil {
			<-connSem
			if ctx.Err() != nil {
				return // ctx 取消属优雅关闭
			}
			if errors.Is(err, net.ErrClosed) {
				slog.Debug("listener closed, accept loop exiting")
				return // listener 关闭属正常停止路径
			}
			slog.Warn("accept error", "error", err)
			backoff = nextBackoff(backoff)
			if !sleepCtx(ctx, backoff) {
				return
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
			// panic 值之外记录完整堆栈（线上排查靠它定位 panic 源）。
			slog.Error("handler panic recovered", "panic", r, "stack", string(debug.Stack()))
			safeClose(closeConn, conn)
		}
	}()
	tr, err := newTransport(ctx, conn)
	if err != nil {
		slog.Error("transport setup", "error", err)
		safeClose(closeConn, conn)
		return
	}
	if tr == nil {
		slog.Error("transport setup returned nil transport")
		safeClose(closeConn, conn)
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
		Commands:          hcfg.Commands,
	})
	if err := h.Handle(ctx); err != nil {
		if core.CodeNumOf(err) == core.CodeProtocolError || core.CodeNumOf(err) == core.CodeServerDraining {
			slog.Debug("connection ended")
		} else {
			slog.Error("handler error", "error", err)
		}
	}
}
