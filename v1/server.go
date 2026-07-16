package v1

import (
	"context"
	"net"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/binding"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// ServerConfig holds configuration for an MBTA server.
type ServerConfig struct {
	Transport          QUICServerConfig
	Auth               core.TokenValidator
	Policy             core.Policy
	ServerID           string
	Metrics            *core.MBTAMetrics
	Sink               core.EventSink       // 上层注入的事件投递接口
	RedirectChecker    core.RedirectChecker // HA：AUTH_OK 后检查角色，非 leader 发 TypeRedirect（可选）
	MaxConcurrentConns int                  // 并发连接上限，0 = 使用 binding.DefaultMaxConcurrentConns
}

// Server accepts and handles MBTA agent connections.
// 内嵌 binding.Server（消除与 ntls 的服务端外壳重复，对称客户端 Phase 2），
// 自身仅保留 QUIC 专属的 Start/Addr/Close 入口。
type Server struct {
	*binding.Server[*Listener, *Conn]
	config ServerConfig
}

// NewServer creates a new MBTA server.
func NewServer(cfg ServerConfig) (*Server, error) {
	// fail-fast 校验：Auth/Sink/Policy 为空时静默接受任意连接或丢弃全部数据，
	// 属严重误配，应在构造时暴露而非在生产中静默失败。
	if cfg.Auth == nil {
		return nil, core.NewError(core.NumConfig, core.CodeConfig, "Auth (TokenValidator) is required")
	}
	if cfg.Sink == nil {
		return nil, core.NewError(core.NumConfig, core.CodeConfig, "Sink (EventSink) is required")
	}
	if len(cfg.Policy.SupportedCapabilities) == 0 {
		return nil, core.NewError(core.NumConfig, core.CodeConfig, "Policy.SupportedCapabilities is required")
	}
	if cfg.ServerID == "" {
		cfg.ServerID = core.NewChunkID().String()
	}
	hcfg := binding.HandlerConfig{
		Auth:            cfg.Auth,
		Policy:          cfg.Policy,
		Sink:            cfg.Sink,
		Metrics:         cfg.Metrics,
		ServerID:        cfg.ServerID,
		RedirectChecker: cfg.RedirectChecker,
	}
	return &Server{
		Server: binding.NewServer[*Listener, *Conn](cfg.MaxConcurrentConns, hcfg),
		config: cfg,
	}, nil
}

// Start begins listening for QUIC connections and runs the accept loop.
// Blocks until the context is cancelled. Each accepted connection is handled
// in its own goroutine via CoreHandler.Handle.
func (s *Server) Start(ctx context.Context) error {
	return s.Run(ctx, binding.RunSpec[*Listener, *Conn]{
		Listen: func(ctx context.Context) (*Listener, error) {
			l, err := Listen(ctx, s.config.Transport)
			if err != nil {
				return nil, core.WrapError(core.NumTransport, core.CodeTransport, "listen", err)
			}
			return l, nil
		},
		Accept:       func(ctx context.Context, l *Listener) (*Conn, error) { return l.Accept(ctx) },
		NewTransport: func(ctx context.Context, c *Conn) (protocol.Transport, error) { return newQuicTransport(c) },
		// CloseConn 用非零 application error code 关闭连接：code 0 在 QUIC 语义中表示
		// "no error"/正常关闭，会误导对端以为连接是优雅终止而非异常清理。
		CloseConn:     func(c *Conn) { _ = c.CloseWithError(1, "transport setup failure") },
		AddrOf:        func(l *Listener) net.Addr { return l.Addr() },
		CloseListener: func(l *Listener) error { return l.Close() },
	})
}

// Addr 返回服务器监听地址（Start 完成监听后有效；启动前返回空串）。
func (s *Server) Addr() string {
	return s.Server.Addr(func(l *Listener) net.Addr { return l.Addr() })
}

// Close shuts down the server.
func (s *Server) Close() error {
	return s.Server.Close(func(l *Listener) error { return l.Close() })
}
