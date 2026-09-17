package mbta

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/protocol"
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
	epochs     *protocol.EpochAllocator // v1+ntls 双监听共享（同 agent 跨 binding 纪元单调）
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
	Policy          core.ServerPolicy // 零值 = 各版本按 ProfileFor 取默认（v1=intl、ntls=gm）
	Metrics         core.Metrics
	RedirectChecker core.RedirectChecker      // HA：握手完成后检查角色，非 leader 发 REDIRECT（可选，nil=禁用）
	OnSession       core.OnSession            // 会话生命周期回调（可选，nil=禁用）：CONNECTED/DISCONNECTED
	Commands        *protocol.CommandRegistry // 运维命令通道（按 agentID 寻址；nil=禁用）

	// Sink 注册面（替代旧 EventSink 接口）：opts 声明供给偏好，handler 是投递回调。
	SinkOpts    core.SinkOptions
	SinkHandler core.BatchHandler

	// V1 specific configuration
	V1QUIC v1.QUICServerConfig

	// NTLS specific configuration
	NTLSCfg ntls.ServerConfig

	// MaxConcurrentConns 可选：并发连接上限（各版本共用）。0 = 使用各版本默认
	// （binding.DefaultMaxConcurrentConns）。达到上限时新连接在 accept 处背压
	// （transport 层握手完成但 HELLO 不被读取），而非直接拒绝。
	MaxConcurrentConns int

	// SinkDeadline 可选：sink handler 的 done 调用超时（0=默认 60s，超时合成 released）。
	SinkDeadline time.Duration
	// SinkQueueSize 可选：sink 异步投递队列容量（0=默认 256，负=禁用异步退回同步调用）。
	SinkQueueSize int
	// SinkQueueMaxBytes 可选：sink 异步投递队列字节上限（0=默认 32MB，负=不限）。
	SinkQueueMaxBytes int64

	// ZstdDict/ZstdDictID 可选：zstd_dict 能力的服务端静态字典（WithZstdDict 设置）。
	// 配置后各版本把 zstd_dict 加入协商能力集；客户端协商成功即收到 DICT 帧。
	ZstdDict   []byte
	ZstdDictID uint32
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
			return nil, core.WrapError(core.ErrCodeConfig, "server option", err)
		}
	}

	// Validate at least one version is enabled
	if !cfg.EnableV1 && !cfg.EnableNTLS {
		return nil, core.NewError(core.ErrCodeConfig, "at least one version must be enabled")
	}
	// Auth/SinkHandler 非空校验在 facade fail-fast，避免错误延迟到 Start() 才暴露。
	// 子层 v1/ntls NewServer 保留各自校验作为防御性兜底。
	if cfg.Auth == nil {
		return nil, core.NewError(core.ErrCodeConfig, "Auth (TokenValidator) is required")
	}
	if cfg.SinkHandler == nil {
		return nil, core.NewError(core.ErrCodeConfig, "SinkHandler is required")
	}

	return &Server{cfg: cfg}, nil
}

// Start starts all enabled version servers concurrently.
// Uses errgroup to manage goroutines and propagate errors.
// Server init is done serially before the accept loops to avoid concurrent field writes.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	s.epochs = &protocol.EpochAllocator{}
	if s.started {
		s.mu.Unlock()
		return core.NewError(core.ErrCodeSession, "server already started")
	}
	s.started = true

	// init 在锁内完成，与 Close 的锁内读同步（避免 data race）。
	if s.cfg.EnableV1 {
		if err := s.initV1Server(); err != nil {
			s.started = false
			s.mu.Unlock()
			return core.WrapError(core.ErrCodeConfig, "init v1", err)
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
			return core.WrapError(core.ErrCodeConfig, "init ntls", err)
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
				return core.WrapError(core.ErrCodeTransport, "v1", err)
			}
			return nil
		})
	}
	if ntlsSrv != nil {
		g.Go(func() error {
			if err := ntlsSrv.Start(ctx); err != nil {
				return core.WrapError(core.ErrCodeTransport, "ntls", err)
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
		return core.WrapError(core.ErrCodeTransport, "server accept loop", err)
	}

	return nil
}

// Addr 返回已启用版本的监听地址（Start 完成监听后有效；启动前返回空串）。
// 同时启用 v1+ntls 时返回 v1 地址。用于黑盒测试在 :0 随机端口启动后拿到实际地址。
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.v1Server != nil {
		return s.v1Server.Addr()
	}
	if s.ntlsServer != nil {
		return s.ntlsServer.Addr()
	}
	return ""
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

// derivePolicy 从共享 Policy 推导 binding 专属策略：零值时取 profile 对应默认，
// 显式配置时仅覆盖 Profile 字段（profile 是 binding 内禀属性：v1=intl、ntls=gm，
// 由版本映射决定，防止 v1/ntls 监听器与声明的密码组合错配）。
func derivePolicy(base core.ServerPolicy, prof core.Profile) core.ServerPolicy {
	if base.IsZero() {
		return core.DefaultServerPolicy(prof)
	}
	p := base
	p.Profile = prof
	return p
}

// withZstdDict 把静态字典并入派生策略：设置 ZstdDict/ZstdDictID 并把 zstd_dict
// 加入 SupportedCapabilities（幂等）。未配置字典时原样返回（handler 侧的协商
// 守卫会在无字典时剔除该能力，双保险）。
func withZstdDict(p core.ServerPolicy, dictID uint32, dict []byte) core.ServerPolicy {
	if len(dict) == 0 || dictID == 0 {
		return p
	}
	p.ZstdDict = dict
	p.ZstdDictID = dictID
	if !slices.Contains(p.SupportedCapabilities, core.CapZstdDict) {
		p.SupportedCapabilities = append(slices.Clone(p.SupportedCapabilities), core.CapZstdDict)
	}
	return p
}

// initV1Server initializes the V1 server.
func (s *Server) initV1Server() error {
	profile, err := ProfileFor(Version1)
	if err != nil {
		return err
	}
	cfg := v1.ServerConfig{
		Transport:          s.cfg.V1QUIC,
		Auth:               s.cfg.Auth,
		Policy:             withZstdDict(derivePolicy(s.cfg.Policy, profile), s.cfg.ZstdDictID, s.cfg.ZstdDict),
		Metrics:            s.cfg.Metrics,
		RedirectChecker:    s.cfg.RedirectChecker,
		OnSession:          s.cfg.OnSession,
		SinkOpts:           s.cfg.SinkOpts,
		SinkHandler:        s.cfg.SinkHandler,
		SinkDeadline:       s.cfg.SinkDeadline,
		MaxConcurrentConns: s.cfg.MaxConcurrentConns,
		SinkQueueSize:      s.cfg.SinkQueueSize,
		SinkQueueMaxBytes:  s.cfg.SinkQueueMaxBytes,
		Epochs:             s.epochs, // facade 双监听共享（同 agent 跨 binding 纪元单调）
		Commands:           s.cfg.Commands,
	}

	v1srv, err := v1.NewServer(cfg)
	if err != nil {
		return err // v1.NewServer 已 wrap ErrCodeConfig + 具体字段，无需再包一层
	}
	s.v1Server = v1srv
	return nil
}

// initNTLSServer initializes the NTLS server.
func (s *Server) initNTLSServer() error {
	profile := NTLSProfileFor(s.cfg.NTLSCfg.TLSMode)
	cfg := s.cfg.NTLSCfg
	cfg.Auth = s.cfg.Auth
	cfg.Epochs = s.epochs // facade 双监听共享
	cfg.Policy = withZstdDict(derivePolicy(s.cfg.Policy, profile), s.cfg.ZstdDictID, s.cfg.ZstdDict)
	cfg.Metrics = s.cfg.Metrics
	cfg.RedirectChecker = s.cfg.RedirectChecker
	cfg.OnSession = s.cfg.OnSession
	cfg.SinkOpts = s.cfg.SinkOpts
	cfg.SinkHandler = s.cfg.SinkHandler
	cfg.SinkDeadline = s.cfg.SinkDeadline
	cfg.MaxConcurrentConns = s.cfg.MaxConcurrentConns
	cfg.SinkQueueSize = s.cfg.SinkQueueSize
	cfg.SinkQueueMaxBytes = s.cfg.SinkQueueMaxBytes

	server, err := ntls.NewServer(cfg)
	if err != nil {
		return err // ntls.NewServer 已 wrap ErrCodeConfig + 具体字段
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

// WithPolicy sets the server policy for all versions.
// 零值 Policy（不调用本 option）时各版本按版本映射取默认 profile 的默认策略；
// Profile 字段会被版本映射覆盖（v1=intl、ntls=gm），其余字段（ack_mode/credits/
// limits/capabilities）按调用方声明生效。
func WithPolicy(policy core.ServerPolicy) ServerOption {
	return func(sc *ServerConfig) error {
		if err := policy.Validate(); err != nil {
			return core.WrapError(core.ErrCodeConfig, "policy", err)
		}
		sc.Policy = policy
		return nil
	}
}

// WithSink registers the batch delivery handler for all versions（替代旧
// WithEventSink）。opts 声明供给偏好（Raw/Durable/Async——Raw+Async 组合静默丢
// 数据这类缺陷在结构上不可表达），handler 通过 done 报告投递结果。
func WithSink(opts core.SinkOptions, handler core.BatchHandler) ServerOption {
	return func(sc *ServerConfig) error {
		if handler == nil {
			return core.NewError(core.ErrCodeConfig, "sink handler must not be nil")
		}
		sc.SinkOpts = opts
		sc.SinkHandler = handler
		return nil
	}
}

// WithMaxConcurrentConns sets the concurrent connection limit (shared by all
// enabled versions). n <= 0 uses the version default. At the limit, new
// connections are back-pressured at accept rather than rejected.
func WithMaxConcurrentConns(n int) ServerOption {
	return func(sc *ServerConfig) error {
		sc.MaxConcurrentConns = n
		return nil
	}
}

// WithSinkQueue sets the async sink delivery queue bounds (shared by all
// enabled versions). size < 0 disables async delivery; maxBytes < 0 disables
// the byte bound. See v1/ntls ServerConfig docs for semantics.
func WithSinkQueue(size int, maxBytes int64) ServerOption {
	return func(sc *ServerConfig) error {
		sc.SinkQueueSize = size
		sc.SinkQueueMaxBytes = maxBytes
		return nil
	}
}

// WithSinkDeadline sets the sink handler done-call timeout (shared by all
// enabled versions). 0 uses the default (60s); on timeout the protocol layer
// synthesizes Outcome{Released} for the in-flight batch.
func WithSinkDeadline(d time.Duration) ServerOption {
	return func(sc *ServerConfig) error {
		if d < 0 {
			return core.NewError(core.ErrCodeConfig, "sink deadline must not be negative")
		}
		sc.SinkDeadline = d
		return nil
	}
}

// WithZstdDict 配置 zstd_dict 能力的服务端静态字典（所有启用版本共享）。
// 配置后：各版本把 zstd_dict 加入协商能力集；客户端协商成功即在 HELLO_ACK 后
// 收到 DICT 帧，并对 > 512B 的 batch 选用字典压缩。dictID 必须非 0；字典尺寸
// 上限 core.MaxZstdDictBytes（1MB）。字典是 raw content dictionary——任意高冗余
// 语料字节即可，无需 zstd --train 训练格式。清除传 nil。
func WithZstdDict(dictID uint32, dict []byte) ServerOption {
	return func(sc *ServerConfig) error {
		if len(dict) == 0 {
			if dictID != 0 {
				return core.NewError(core.ErrCodeConfig, "zstd dict must not be empty")
			}
			sc.ZstdDict = nil
			sc.ZstdDictID = 0
			return nil
		}
		if dictID == 0 {
			return core.NewError(core.ErrCodeConfig, "zstd dict id must be non-zero")
		}
		if len(dict) > core.MaxZstdDictBytes {
			return core.NewError(core.ErrCodeConfig, fmt.Sprintf("zstd dict %d bytes exceeds max %d", len(dict), core.MaxZstdDictBytes))
		}
		sc.ZstdDict = dict
		sc.ZstdDictID = dictID
		return nil
	}
}

// WithMetrics sets the metrics collector for all versions.
// 接受 core.Metrics 接口（nil=NoOp）。New(reg) 返回的 *MBTAMetrics 自动满足接口。
func WithMetrics(metrics core.Metrics) ServerOption {
	return func(sc *ServerConfig) error {
		sc.Metrics = metrics
		return nil
	}
}

// WithRedirectChecker sets the HA redirect checker. After a client completes
// the handshake, the server calls the checker; if it returns ok=true (this
// replica is a follower, not the leader) the server sends a REDIRECT frame and
// closes the connection, steering the client to the elected leader. Nil
// (default) disables redirect.
func WithRedirectChecker(checker core.RedirectChecker) ServerOption {
	return func(sc *ServerConfig) error {
		sc.RedirectChecker = checker
		return nil
	}
}

// WithOnSession sets the session lifecycle callback. The server fires
// SessionConnected right after the handshake completes (before any BATCH), and
// SessionDisconnected when the connection ends (only for connections that
// authenticated successfully). Nil (default) disables lifecycle observation.
// The callback runs on the connection goroutine; it must be non-blocking.
func WithOnSession(fn core.OnSession) ServerOption {
	return func(sc *ServerConfig) error {
		sc.OnSession = fn
		return nil
	}
}

// WithCommandRegistry 启用运维命令通道（COMMAND/COMMAND_ACK 帧）：
// 注册表按 agentID 寻址活动连接，调用方经 Registry.SendCommand 下发命令
// 并等待 agent 的 ACK。nil（默认）= 关闭，agent 不注册、命令不可寻址。
func WithCommandRegistry(reg *protocol.CommandRegistry) ServerOption {
	return func(sc *ServerConfig) error {
		sc.Commands = reg
		return nil
	}
}

// NewCommandRegistry 创建运维命令注册表（配合 WithCommandRegistry 使用）。
// 返回内部实现的不透明值——调用方无需命名其类型。
func NewCommandRegistry() *protocol.CommandRegistry {
	return protocol.NewCommandRegistry()
}

// SendCommand 向指定 agent 的活动连接下发运维命令并等待其 ACK
// （仅当 WithCommandRegistry 启用且 v1 server 已启动时有意义）。
func (s *Server) SendCommand(ctx context.Context, agentID string, cmd *corepb.ControlCommand) (*corepb.ControlCommandAck, error) {
	s.mu.RLock()
	v1srv := s.v1Server
	s.mu.RUnlock()
	if v1srv == nil {
		return nil, protocol.ErrAgentNotConnected
	}
	return v1srv.SendCommand(ctx, agentID, cmd)
}
