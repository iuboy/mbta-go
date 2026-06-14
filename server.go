package mbta

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/iuboy/mbta-go/core"
	ntls "github.com/iuboy/mbta-go/ntls"
	v1 "github.com/iuboy/mbta-go/v1"
	v2 "github.com/iuboy/mbta-go/v2"
)

// ServerOption configures a Server.
// Follows the functional options pattern used in gRPC and Kubernetes.
type ServerOption func(*ServerConfig) error

// Server supports multiple MBTA protocol versions simultaneously.
// Each version runs on its own listener with appropriate ALPN configuration.
type Server struct {
	cfg        *ServerConfig
	v1Server   *v1.Server
	v2Server   *v2.Server
	ntlsServer *ntls.Server
	mu         sync.RWMutex
	started    bool
}

// ServerConfig holds the server configuration.
// Shared settings are used across all versions, version-specific settings
// are applied only to that version.
type ServerConfig struct {
	// Version selection
	EnableV1   bool
	EnableV2   bool
	EnableNTLS bool

	// Shared configuration (all versions)
	Auth    core.TokenValidator
	Policy  core.Policy
	Sink    core.EventSink
	Metrics *core.MBTAMetrics

	// V1 specific configuration
	V1QUIC v1.QUICServerConfig

	// V2 specific configuration
	V2QUIC v2.QUICServerConfig

	// NTLS specific configuration
	NTLSCfg ntls.ServerConfig
}

// NewServer creates a multi-version MBTA server.
// Returns an error if no versions are enabled or if configuration is invalid.
func NewServer(opts ...ServerOption) (*Server, error) {
	cfg := &ServerConfig{
		// Apply defaults
		EnableV1: true, // v1 is enabled by default for backward compatibility
	}

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, core.WrapError(core.NumConfig, core.CodeConfig, "server option", err)
		}
	}

	// Validate at least one version is enabled
	if !cfg.EnableV1 && !cfg.EnableV2 && !cfg.EnableNTLS {
		return nil, core.NewError(core.NumConfig, core.CodeConfig, "at least one version must be enabled")
	}

	return &Server{cfg: cfg}, nil
}

// Start starts all enabled version servers concurrently.
// Uses errgroup to manage goroutines and propagate errors.
// Server init is done serially before the accept loops to avoid concurrent field writes.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return core.NewError(core.NumSession, core.CodeSession, "server already started")
	}
	s.started = true
	s.mu.Unlock()

	// Initialize all version servers serially to avoid concurrent field writes.
	if s.cfg.EnableV1 {
		if err := s.initV1Server(); err != nil {
			s.mu.Lock()
			s.started = false
			s.mu.Unlock()
			return core.WrapError(core.NumConfig, core.CodeConfig, "init v1", err)
		}
	}
	if s.cfg.EnableV2 {
		if err := s.initV2Server(); err != nil {
			s.mu.Lock()
			s.started = false
			s.mu.Unlock()
			return core.WrapError(core.NumConfig, core.CodeConfig, "init v2", err)
		}
	}
	if s.cfg.EnableNTLS {
		if err := s.initNTLSServer(); err != nil {
			s.mu.Lock()
			s.started = false
			s.mu.Unlock()
			return core.WrapError(core.NumConfig, core.CodeConfig, "init ntls", err)
		}
	}

	// Launch accept loops concurrently.
	g, ctx := errgroup.WithContext(ctx)

	if s.v1Server != nil {
		g.Go(func() error {
			return core.WrapError(core.NumTransport, core.CodeTransport, "v1", s.v1Server.Start(ctx))
		})
	}
	if s.v2Server != nil {
		g.Go(func() error {
			return core.WrapError(core.NumTransport, core.CodeTransport, "v2", s.v2Server.Start(ctx))
		})
	}
	if s.ntlsServer != nil {
		g.Go(func() error {
			return core.WrapError(core.NumTransport, core.CodeTransport, "ntls", s.ntlsServer.Start(ctx))
		})
	}

	if err := g.Wait(); err != nil {
		s.mu.Lock()
		s.started = false
		s.mu.Unlock()
		return core.WrapError(core.NumTransport, core.CodeTransport, "server accept loop", err)
	}

	return nil
}

// Close gracefully shuts down all version servers.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error

	if s.v1Server != nil {
		if err := s.v1Server.Close(); err != nil {
			errs = append(errs, fmt.Errorf("v1 close: %w", err))
		}
	}

	if s.v2Server != nil {
		if err := s.v2Server.Close(); err != nil {
			errs = append(errs, fmt.Errorf("v2 close: %w", err))
		}
	}

	if s.ntlsServer != nil {
		if err := s.ntlsServer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("ntls close: %w", err))
		}
	}

	s.started = false

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}

// initV1Server initializes the V1 server.
func (s *Server) initV1Server() error {
	cfg := v1.ServerConfig{
		Transport: s.cfg.V1QUIC,
		Auth:      s.cfg.Auth,
		Policy:    s.cfg.Policy,
		Sink:      s.cfg.Sink,
		Metrics:   s.cfg.Metrics,
	}

	// v1.NewServer returns *Server, not (*Server, error)
	s.v1Server = v1.NewServer(cfg)
	return nil
}

// initV2Server initializes the V2 server.
func (s *Server) initV2Server() error {
	cfg := v2.ServerConfig{
		Transport: s.cfg.V2QUIC,
		Auth:      s.cfg.Auth,
		Policy:    s.cfg.Policy,
		Sink:      s.cfg.Sink,
		Metrics:   s.cfg.Metrics,
	}

	server, err := v2.NewServer(cfg)
	if err != nil {
		return err
	}

	s.v2Server = server
	return nil
}

// initNTLSServer initializes the NTLS server.
func (s *Server) initNTLSServer() error {
	cfg := s.cfg.NTLSCfg
	cfg.Auth = s.cfg.Auth
	cfg.Policy = s.cfg.Policy
	cfg.Sink = s.cfg.Sink
	cfg.Metrics = s.cfg.Metrics

	server, err := ntls.NewServer(cfg)
	if err != nil {
		return err
	}

	s.ntlsServer = server
	return nil
}

// Server Options (functional options pattern)

// WithV1 enables V1 support with custom QUIC configuration.
func WithV1(cfg v1.QUICServerConfig) ServerOption {
	return func(sc *ServerConfig) error {
		sc.EnableV1 = true
		sc.V1QUIC = cfg
		return nil
	}
}

// WithV2 enables V2 support with custom QUIC configuration.
func WithV2(cfg v2.QUICServerConfig) ServerOption {
	return func(sc *ServerConfig) error {
		sc.EnableV2 = true
		sc.V2QUIC = cfg
		return nil
	}
}

// WithNTLS enables NTLS support with custom configuration.
func WithNTLS(cfg ntls.ServerConfig) ServerOption {
	return func(sc *ServerConfig) error {
		sc.EnableNTLS = true
		sc.NTLSCfg = cfg
		return nil
	}
}

// WithAuth sets the token validator for all versions.
func WithAuth(auth core.TokenValidator) ServerOption {
	return func(sc *ServerConfig) error {
		sc.Auth = auth
		return nil
	}
}

// WithPolicy sets the session policy for all versions.
func WithPolicy(policy core.Policy) ServerOption {
	return func(sc *ServerConfig) error {
		sc.Policy = policy
		return nil
	}
}

// WithEventSink sets the event sink for all versions.
func WithEventSink(sink core.EventSink) ServerOption {
	return func(sc *ServerConfig) error {
		sc.Sink = sink
		return nil
	}
}

// WithMetrics sets the metrics collector for all versions.
func WithMetrics(metrics *core.MBTAMetrics) ServerOption {
	return func(sc *ServerConfig) error {
		sc.Metrics = metrics
		return nil
	}
}
