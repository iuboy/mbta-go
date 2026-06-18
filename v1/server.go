package v1

import (
	"context"
	"log/slog"
	"sync"

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
	Sink               core.EventSink // 上层注入的事件投递接口
	MaxConcurrentConns int            // 并发连接上限，0 = 使用 binding.DefaultMaxConcurrentConns (H-3)
}

// Server accepts and handles MBTA agent connections.
type Server struct {
	config   ServerConfig
	mu       sync.Mutex
	listener *Listener
	connSem  chan struct{} // 并发连接上限信号量 (H-3)
}

// NewServer creates a new MBTA server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.ServerID == "" {
		cfg.ServerID = core.NewChunkID().String()
	}
	maxConns := cfg.MaxConcurrentConns
	if maxConns <= 0 {
		maxConns = binding.DefaultMaxConcurrentConns
	}
	return &Server{config: cfg, connSem: make(chan struct{}, maxConns)}, nil
}

// Start begins listening for QUIC connections and runs the accept loop.
// Blocks until the context is cancelled. Each accepted connection is handled
// in its own goroutine via CoreHandler.Handle.
func (s *Server) Start(ctx context.Context) error {
	l, err := Listen(ctx, s.config.Transport)
	if err != nil {
		return core.WrapError(core.NumTransport, core.CodeTransport, "listen", err)
	}
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()
	slog.Info("MBTA server listening", "addr", l.Addr(), "server_id", s.config.ServerID)

	// ctx 取消时关闭 listener：被 l.Accept(ctx) 阻塞的循环因此解除并退出。
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	return binding.AcceptLoop[*Conn](ctx, s.connSem,
		func(ctx context.Context) (*Conn, error) {
			return s.listener.Accept(ctx)
		},
		func(ctx context.Context, conn *Conn) (protocol.Transport, error) {
			return newQuicTransport(conn)
		},
		func(conn *Conn) { _ = conn.CloseWithError(0, "transport") },
		binding.HandlerConfig{
			Auth:     s.config.Auth,
			Policy:   s.config.Policy,
			Sink:     s.config.Sink,
			Metrics:  s.config.Metrics,
			ServerID: s.config.ServerID,
		},
	)
}

// Addr 返回服务器监听地址（Start 完成监听后有效；启动前返回空串）。
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Close shuts down the server.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
