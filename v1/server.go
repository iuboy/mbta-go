package v1

import (
	"context"
	"fmt"
	"log/slog"

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
	listener *Listener
}

// NewServer creates a new MBTA server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.ServerID == "" {
		cfg.ServerID = uuid.Must(uuid.NewV7()).String()
	}
	return &Server{config: cfg}
}

// Start begins listening for QUIC connections.
func (s *Server) Start(ctx context.Context) error {
	l, err := Listen(ctx, s.config.Transport)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = l
	slog.Info("MBTA server listening", "addr", l.Addr(), "server_id", s.config.ServerID)
	return nil
}

// Accept waits for and handles the next connection.
func (s *Server) Accept(ctx context.Context) (*ConnectionHandler, error) {
	conn, err := s.listener.Accept(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept: %w", err)
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
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
