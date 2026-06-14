package v1

import (
	"context"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"github.com/iuboy/mbta-go/core"
)

// ServerConfig holds configuration for an MBTA server.
type ServerConfig struct {
	Transport          QUICServerConfig
	Auth               core.TokenValidator
	Policy             core.Policy
	ServerID           string
	Metrics            *core.MBTAMetrics
	Sink               core.EventSink // 上层注入的事件投递接口
	MaxConcurrentConns int            // 并发连接上限，0 = 使用 defaultMaxConcurrentConns (H-3)
}

// defaultMaxConcurrentConns is the concurrent connection cap applied when
// ServerConfig.MaxConcurrentConns is unset. Bounds memory/goroutine usage
// against connection-flood DoS. (H-3)
const defaultMaxConcurrentConns = 10000

// Server accepts and handles MBTA agent connections.
type Server struct {
	config   ServerConfig
	mu       sync.Mutex
	listener *Listener
	connSem  chan struct{} // 并发连接上限信号量 (H-3)
}

// NewServer creates a new MBTA server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.ServerID == "" {
		cfg.ServerID = uuid.Must(uuid.NewV7()).String()
	}
	maxConns := cfg.MaxConcurrentConns
	if maxConns <= 0 {
		maxConns = defaultMaxConcurrentConns
	}
	return &Server{config: cfg, connSem: make(chan struct{}, maxConns)}
}

// Start begins listening for QUIC connections and runs the accept loop.
// Blocks until the context is cancelled. Each accepted connection is handled
// in its own goroutine via ConnectionHandler.HandleConnection.
func (s *Server) Start(ctx context.Context) error {
	l, err := Listen(ctx, s.config.Transport)
	if err != nil {
		return core.WrapError(core.NumTransport, core.CodeTransport, "listen", err)
	}
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()
	slog.Info("MBTA server listening", "addr", l.Addr(), "server_id", s.config.ServerID)

	// Accept connections until context is cancelled.
	for {
		// 并发连接上限 (H-3)：先占一个槽位再 accept，handler 结束时释放。
		// ctx 取消时立即返回，不会阻塞在满载的信号量上。
		select {
		case s.connSem <- struct{}{}:
		case <-ctx.Done():
			return nil
		}

		handler, err := s.Accept(ctx)
		if err != nil {
			<-s.connSem // accept 失败，归还槽位
			// Context cancelled means graceful shutdown — not an error.
			if ctx.Err() != nil {
				return nil //nolint:nilerr // ctx 取消属优雅关闭，accept 错误不应上抛
			}
			slog.Warn("accept error", "error", err)
			continue
		}
		go func() {
			defer func() { <-s.connSem }()
			if err := handler.HandleConnection(ctx); err != nil {
				slog.Error("handler error", "error", err)
			}
		}()
	}
}

// Addr 返回服务器监听地址（Start 完成监听后有效；启动前返回空串）。
// 便于端到端测试与外部客户端在 OS 分配端口（Address 含 :0）的场景下发现实际端口。
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Accept waits for and returns the next connection handler.
// This is a low-level API for callers who want to manage the accept loop
// themselves. When using Start(), the accept loop is handled automatically
// and there is no need to call Accept.
func (s *Server) Accept(ctx context.Context) (*ConnectionHandler, error) {
	conn, err := s.listener.Accept(ctx)
	if err != nil {
		return nil, core.WrapError(core.NumTransport, core.CodeTransport, "accept", err)
	}

	handler := NewConnectionHandler(ConnectionHandlerConfig{
		Conn:     conn,
		Auth:     s.config.Auth,
		Policy:   s.config.Policy,
		Sink:     s.config.Sink,
		Metrics:  s.config.Metrics,
		ServerID: s.config.ServerID,
	})
	return handler, nil
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
