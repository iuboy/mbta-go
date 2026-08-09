package v1

import (
	"context"
	"net"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/binding"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// ServerConfig holds configuration for an MBTA server.
type ServerConfig struct {
	Transport          QUICServerConfig
	Auth               core.TokenValidator
	Policy             core.Policy
	ServerID           string
	Metrics            core.Metrics
	Sink               core.EventSink       // 上层注入的事件投递接口
	RedirectChecker    core.RedirectChecker // HA：AUTH_OK 后检查角色，非 leader 发 TypeRedirect（可选）
	OnSession          core.OnSession       // 会话生命周期回调（可选，nil=禁用）
	SessionStore       *core.SessionStore   // 0-RTT 会话票据存储（nil=禁用 0-RTT）
	MaxConcurrentConns int                  // 并发连接上限，0 = 使用 binding.DefaultMaxConcurrentConns
}

// Server accepts and handles MBTA agent connections.
// 内嵌 binding.Server（消除与 ntls 的服务端外壳重复），
// 自身仅保留 QUIC 专属的 Start/Addr/Close 入口。
type Server struct {
	*binding.Server[*Listener, *Conn]
	config ServerConfig
}

// NewServer creates a new MBTA server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := core.ValidateListenAddr(cfg.Transport.Address); err != nil {
		return nil, core.WrapError(core.ErrCodeConfig, "Transport.Address", err)
	}
	hcfg := binding.HandlerConfig{
		Auth: cfg.Auth, Policy: cfg.Policy, Sink: cfg.Sink, Metrics: cfg.Metrics,
		ServerID: cfg.ServerID, RedirectChecker: cfg.RedirectChecker,
		OnSession: cfg.OnSession, SessionStore: cfg.SessionStore,
	}
	policy, err := binding.ResolveHandlerConfig(&hcfg, corepb.CipherSuite_CIPHER_SUITE_INTL)
	if err != nil {
		return nil, err
	}
	cfg.Policy = policy
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
				return nil, core.WrapError(core.ErrCodeTransport, "listen", err)
			}
			return l, nil
		},
		Accept:       func(ctx context.Context, l *Listener) (*Conn, error) { return l.Accept(ctx) },
		NewTransport: func(ctx context.Context, c *Conn) (protocol.Transport, error) { return newQuicTransport(c) },
		// CloseConn 用非零 error code 关闭连接（code 0 表示 "no error"，会误导对端）。
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
