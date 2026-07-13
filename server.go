package mbta

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/iuboy/mbta-go/core"
	ntls "github.com/iuboy/mbta-go/ntls"
	v1 "github.com/iuboy/mbta-go/v1"
)

// ServerOption configures a Server.
// Follows the functional options pattern used in gRPC and Kubernetes.
type ServerOption func(*ServerConfig) error

// Server supports multiple MBTA protocol versions simultaneously.
// Each version runs on its own listener with appropriate ALPN configuration.
type Server struct {
	cfg        *ServerConfig
	v1Server   *v1.Server
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
	EnableNTLS bool

	// Shared configuration (all versions)
	Auth            core.TokenValidator
	Policy          core.Policy
	Sink            core.EventSink
	Metrics         *core.MBTAMetrics
	RedirectChecker core.RedirectChecker // HA：AUTH_OK 后检查角色，非 leader 发 TypeRedirect（可选，nil=禁用）

	// V1 specific configuration
	V1QUIC v1.QUICServerConfig

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
	if !cfg.EnableV1 && !cfg.EnableNTLS {
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

	// 初始化在锁内完成：initV1Server/initNTLSServer 写 s.v1Server/s.ntlsServer，
	// 与 Close 的锁内读必须同步，避免 data race（旧实现 init 在锁外写）。
	if s.cfg.EnableV1 {
		if err := s.initV1Server(); err != nil {
			s.started = false
			s.mu.Unlock()
			return core.WrapError(core.NumConfig, core.CodeConfig, "init v1", err)
		}
	}
	if s.cfg.EnableNTLS {
		if err := s.initNTLSServer(); err != nil {
			// initNTLSServer 失败：清理已初始化的 v1Server，避免资源残留。
			if s.v1Server != nil {
				_ = s.v1Server.Close()
				s.v1Server = nil
			}
			s.started = false
			s.mu.Unlock()
			return core.WrapError(core.NumConfig, core.CodeConfig, "init ntls", err)
		}
	}
	// 捕获子服务器引用，accept-loop goroutine 用局部变量读，避免与 Close 竞态。
	v1srv := s.v1Server
	ntlsSrv := s.ntlsServer
	s.mu.Unlock()

	// Launch accept loops concurrently.
	g, ctx := errgroup.WithContext(ctx)

	if v1srv != nil {
		g.Go(func() error {
			if err := v1srv.Start(ctx); err != nil {
				return core.WrapError(core.NumTransport, core.CodeTransport, "v1", err)
			}
			return nil
		})
	}
	if ntlsSrv != nil {
		g.Go(func() error {
			if err := ntlsSrv.Start(ctx); err != nil {
				return core.WrapError(core.NumTransport, core.CodeTransport, "ntls", err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		// errgroup 任一失败：清理已启动的子服务器，避免 goroutine/监听泄漏。
		s.mu.Lock()
		s.started = false
		s.mu.Unlock()
		// 显式 Close 触发子服务器清理（errgroup cancel 已使 ctx.Done，但 Close 保证资源释放）。
		_ = s.Close()
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

	if s.ntlsServer != nil {
		if err := s.ntlsServer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("ntls close: %w", err))
		}
	}

	s.started = false

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %w", errors.Join(errs...))
	}
	return nil
}

// initV1Server initializes the V1 server.
func (s *Server) initV1Server() error {
	cfg := v1.ServerConfig{
		Transport:       s.cfg.V1QUIC,
		Auth:            s.cfg.Auth,
		Policy:          s.cfg.Policy,
		Sink:            s.cfg.Sink,
		Metrics:         s.cfg.Metrics,
		RedirectChecker: s.cfg.RedirectChecker,
	}

	v1srv, err := v1.NewServer(cfg)
	if err != nil {
		return core.WrapError(core.NumConfig, core.CodeConfig, "v1 server init", err)
	}
	s.v1Server = v1srv
	return nil
}

// initNTLSServer initializes the NTLS server.
func (s *Server) initNTLSServer() error {
	cfg := s.cfg.NTLSCfg
	cfg.Auth = s.cfg.Auth
	cfg.Policy = s.cfg.Policy
	cfg.Sink = s.cfg.Sink
	cfg.Metrics = s.cfg.Metrics
	cfg.RedirectChecker = s.cfg.RedirectChecker

	server, err := ntls.NewServer(cfg)
	if err != nil {
		return core.WrapError(core.NumConfig, core.CodeConfig, "ntls server init", err)
	}

	s.ntlsServer = server
	return nil
}

// Server Options (functional options pattern)

// WithoutV1 disables V1 (QUIC + TLS 1.3). V1 is enabled by default for backward
// compatibility; use this option when only NTLS is needed, to avoid意外拉起 v1 listener。
func WithoutV1() ServerOption {
	return func(sc *ServerConfig) error {
		sc.EnableV1 = false
		return nil
	}
}

// WithV1 enables V1 support with custom QUIC configuration.
func WithV1(cfg v1.QUICServerConfig) ServerOption {
	return func(sc *ServerConfig) error {
		sc.EnableV1 = true
		sc.V1QUIC = cfg
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

// WithRedirectChecker sets the HA redirect checker. After a client authenticates,
// the server calls the checker; if it returns ok=true (this replica is a follower,
// not the leader) the server sends a TypeRedirect frame and closes the connection,
// steering the client to the elected leader. Nil (default) disables redirect.
func WithRedirectChecker(checker core.RedirectChecker) ServerOption {
	return func(sc *ServerConfig) error {
		sc.RedirectChecker = checker
		return nil
	}
}
