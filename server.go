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

// ServerOption 配置 [Server]（函数式选项，gRPC/Kubernetes 同款模式）。
type ServerOption func(*ServerConfig) error

// Server 同时托管多个 MBTA 协议版本。各版本运行在独立 listener 上，
// 配置各自的 ALPN。
type Server struct {
	cfg        *ServerConfig
	v1Server   *v1.Server
	ntlsServer *ntls.Server
	epochs     *protocol.EpochAllocator // v1+ntls 双监听共享（同 agent 跨 binding 纪元单调）
	mu         sync.RWMutex
	started    bool
}

// ServerConfig 是服务器配置。共享设置对所有启用版本生效，
// 版本专属设置仅作用于对应版本。
type ServerConfig struct {
	// 版本开关。
	EnableV1   bool
	EnableNTLS bool

	// 共享配置（所有版本）。
	Auth            core.TokenValidator
	Policy          core.ServerPolicy // 零值 = 各版本按 ProfileFor 取默认（v1=intl、ntls=gm）
	Metrics         core.Metrics
	RedirectChecker core.RedirectChecker      // HA：握手完成后检查角色，非 leader 发 REDIRECT（可选，nil=禁用）
	OnSession       core.OnSession            // 会话生命周期回调（可选，nil=禁用）：CONNECTED/DISCONNECTED
	Commands        *protocol.CommandRegistry // 运维命令通道（按 agentID 寻址；nil=禁用）

	// Sink 注册面（替代旧 EventSink 接口）：opts 声明供给偏好，handler 是投递回调。
	SinkOpts    core.SinkOptions
	SinkHandler core.BatchHandler

	// 版本专属配置。
	V1QUIC  v1.QUICServerConfig
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

// NewServer 创建多版本 MBTA 服务器（仅构造不启动；启动用 [Server.Start]）。
// 未启用任何版本或配置非法时返回错误。
func NewServer(opts ...ServerOption) (*Server, error) {
	cfg := &ServerConfig{
		// 默认值
		EnableV1: true, // 兼容旧用法，默认启用 v1
	}

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, core.WrapError(core.ErrCodeConfig, "server option", err)
		}
	}

	// 至少启用一个版本
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
	// EnableV1 默认开启且 V1QUIC.Address 必填：仅想启用 NTLS 的用户若忘记
	// WithoutV1()，此前要到 Start() 才报出一条指向从未配置的 v1 的地址错误——
	// 构造期 fail-fast 并提示关闭路径（同文件自述的 fail-fast 原则）。
	if cfg.EnableV1 && cfg.V1QUIC.Address == "" {
		return nil, core.NewError(core.ErrCodeConfig,
			"EnableV1 (default on) requires V1QUIC.Address; configure it or disable v1 via the WithoutV1 option")
	}

	return &Server{cfg: cfg}, nil
}

// Start 并发启动所有已启用版本的服务器，用 errgroup 管理 goroutine 并汇聚错误。
// 各子服务器的初始化在锁内串行完成后再进入 accept 循环，避免并发写实例字段。
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return core.NewError(core.ErrCodeSession, "server already started")
	}
	// epochs 分配器在 started 检查之后创建：被拒的 Start 不得替换运行中实例
	// 持有的分配器字段。epoch 单调性以服务进程生命周期为界（重启清零）。
	s.epochs = &protocol.EpochAllocator{}
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

	// 并发启动各版本的 accept 循环。
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

	// 优雅退出（ctx 取消驱动的正常返回）：复位 started 允许重启——此前此路径
	// 保持 started=true，重启撞 "server already started"，调用方必须记得手动
	// Close（review F6 裁决）。子服务器 listener 已随 ctx 取消关闭，引用在
	// 下次 Start 的 init* 中被新实例覆盖（旧实例已无持有资源）。
	s.mu.Lock()
	s.started = false
	s.mu.Unlock()
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

// Close 优雅关闭所有版本的服务器并释放监听资源。
// 各版本独立关闭，任一失败不影响其余；多个错误经 errors.Join 汇聚返回。
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

// initV1Server 构造 v1 子服务器（仅赋值字段，不启动；须在锁内调用）。
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

// initNTLSServer 构造 ntls 子服务器（仅赋值字段，不启动；须在锁内调用）。
func (s *Server) initNTLSServer() error {
	profile := NTLSProfileFor(s.cfg.NTLSCfg.Mode)
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
	cfg.Commands = s.cfg.Commands

	server, err := ntls.NewServer(cfg)
	if err != nil {
		return err // ntls.NewServer 已 wrap ErrCodeConfig + 具体字段
	}

	s.ntlsServer = server
	return nil
}

// —— 服务端选项（函数式选项模式）——

// WithoutV1 禁用 v1（QUIC + TLS 1.3）。v1 默认启用（兼容旧用法）；
// 仅需 NTLS 时用本选项关闭，避免意外拉起 v1 listener。
func WithoutV1() ServerOption {
	return func(sc *ServerConfig) error {
		sc.EnableV1 = false
		return nil
	}
}

// WithV1 启用 v1 并指定 QUIC 配置（覆盖默认的 V1QUIC 零值）。
func WithV1(cfg v1.QUICServerConfig) ServerOption {
	return func(sc *ServerConfig) error {
		sc.EnableV1 = true
		sc.V1QUIC = cfg
		return nil
	}
}

// WithNTLS 启用 ntls（TCP + TLCP/TLS1.3）并指定配置。
func WithNTLS(cfg ntls.ServerConfig) ServerOption {
	return func(sc *ServerConfig) error {
		sc.EnableNTLS = true
		sc.NTLSCfg = cfg
		return nil
	}
}

// WithAuth 为所有版本设置 token 校验器（必填，见 [ServerConfig.Auth]）。
func WithAuth(auth core.TokenValidator) ServerOption {
	return func(sc *ServerConfig) error {
		sc.Auth = auth
		return nil
	}
}

// WithPolicy 为所有版本设置服务端策略（构造期校验，非法即报错）。
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

// WithSink 为所有版本注册批次投递回调（替代旧 WithEventSink）。
// opts 声明供给偏好（Raw/Durable/Async——Raw+Async 组合静默丢数据这类缺陷
// 在结构上不可表达），handler 通过 done 报告投递结果。
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

// WithMaxConcurrentConns 设置并发连接上限（所有启用版本共享）。
// n <= 0 用各版本默认；达到上限时新连接在 accept 处背压而非拒绝。
func WithMaxConcurrentConns(n int) ServerOption {
	return func(sc *ServerConfig) error {
		sc.MaxConcurrentConns = n
		return nil
	}
}

// WithSinkQueue 设置 sink 异步投递队列边界（所有启用版本共享）。
// size < 0 关闭异步投递；maxBytes < 0 取消字节上限。语义详见 v1/ntls 的
// ServerConfig 文档。
func WithSinkQueue(size int, maxBytes int64) ServerOption {
	return func(sc *ServerConfig) error {
		sc.SinkQueueSize = size
		sc.SinkQueueMaxBytes = maxBytes
		return nil
	}
}

// WithSinkDeadline 设置 sink handler 的 done 调用超时（所有启用版本共享）。
// 0 用默认（60s）；超时后协议层为在途批次合成 Outcome{Released}。
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

// WithMetrics 为所有版本设置指标收集器。
// 接受 core.Metrics 接口（nil=NoOp）。New(reg) 返回的 *MBTAMetrics 自动满足接口。
func WithMetrics(metrics core.Metrics) ServerOption {
	return func(sc *ServerConfig) error {
		sc.Metrics = metrics
		return nil
	}
}

// WithRedirectChecker 设置 HA 重定向检查器。客户端完成握手后服务端调用
// checker；返回 ok=true（本副本是从机、非 leader）时发送 REDIRECT 帧并关闭
// 连接，把客户端引向当选 leader。nil（默认）= 禁用重定向。
func WithRedirectChecker(checker core.RedirectChecker) ServerOption {
	return func(sc *ServerConfig) error {
		sc.RedirectChecker = checker
		return nil
	}
}

// WithOnSession 设置会话生命周期回调。握手完成即（任何 BATCH 之前）触发
// SessionConnected；连接结束时触发 SessionDisconnected（仅认证成功的连接）。
// nil（默认）= 关闭生命周期观测。回调在连接 goroutine 上执行，不得阻塞。
func WithOnSession(fn core.OnSession) ServerOption {
	return func(sc *ServerConfig) error {
		sc.OnSession = fn
		return nil
	}
}

// WithCommandRegistry 启用运维命令通道（COMMAND/COMMAND_ACK 帧）：
// 注册表按 agentID 寻址活动连接，调用方经 Registry.SendCommand 下发命令
// 并等待 agent 的 ACK。v1/ntls 双 binding 均生效（协议层注册与分发是
// binding 无关的）。nil（默认）= 关闭，agent 不注册、命令不可寻址。
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
