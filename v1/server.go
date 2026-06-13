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
	Transport QUICServerConfig
	Auth      core.TokenValidator
	Policy    core.Policy
	SpoolDir  string
	ServerID  string
	Metrics   *core.MBTAMetrics
	Sink      core.EventSink // 上层注入的事件投递接口
}

// Server accepts and handles MBTA agent connections.
type Server struct {
	config   ServerConfig
	mu       sync.Mutex
	listener *Listener
}

// NewServer creates a new MBTA server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.ServerID == "" {
		cfg.ServerID = uuid.Must(uuid.NewV7()).String()
	}
	return &Server{config: cfg}
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
		handler, err := s.Accept(ctx)
		if err != nil {
			// Context cancelled means graceful shutdown — not an error.
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("accept error", "error", err)
			continue
		}
		go func() {
			if err := handler.HandleConnection(ctx); err != nil {
				slog.Error("handler error", "error", err)
			}
		}()
	}
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
		SpoolDir: s.config.SpoolDir,
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
