package v1

import (
	"context"
	"net"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/binding"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// ServerConfig holds configuration for an MBTA server.
//
// Policy 零值时 NewServer 回填 core.DefaultServerPolicy(PROFILE_INTL)——v1 binding
// 即国际密码组合（X25519+AES-GCM），默认策略与 binding 语义一致；显式配置则原样
// 经 binding.ResolveHandlerConfig 校验（不回填，避免半配置静默取默认）。
type ServerConfig struct {
	Transport QUICServerConfig
	Auth      core.TokenValidator // token 认证（必填，ResolveToken+Validate）
	Policy    core.ServerPolicy   // 服务端策略（零值 = DefaultServerPolicy(intl)）
	ServerID  string              // 服务端标识；空则 ResolveHandlerConfig 生成 ULID
	Metrics   core.Metrics        // 可选可观测性指标（nil=NoOp）

	RedirectChecker core.RedirectChecker // HA：握手完成后检查角色，非 leader 发 REDIRECT（可选）
	OnSession       core.OnSession       // 会话生命周期回调（可选，nil=禁用）

	// Sink 三件套：注册式投递面（替代旧 6 接口 sink 矩阵）。
	SinkOpts     core.SinkOptions // 供给偏好（Raw/Durable/Async）
	SinkHandler  core.BatchHandler
	SinkDeadline time.Duration // handler done 超时（0 = core.DefaultSinkDeadline）

	MaxConcurrentConns int   // 并发连接上限，0 = 使用 binding.DefaultMaxConcurrentConns
	SinkQueueSize      int   // sink 队列容量（0=默认 256，负=同步调用）
	SinkQueueMaxBytes  int64 // sink 队列字节上限（0=默认 32MB，负=不限）

	// Epochs 可选：连接纪元分配器（facade 双监听时共享一份，保证同 agent
	// 跨 v1/ntls 的纪元单调；nil = 本 server 独立分配）。
	Epochs *protocol.EpochAllocator
}

// Server accepts and handles MBTA agent connections.
// 内嵌 binding.Server（消除与 ntls 的服务端外壳重复），
// 自身仅保留 QUIC 专属的 Start/Addr/Close 入口。
type Server struct {
	*binding.Server[*Listener, *Conn]
	config ServerConfig
}

// Config 返回服务端配置（facade 测试与诊断用；返回副本）。
func (s *Server) Config() ServerConfig { return s.config }

// NewServer creates a new MBTA server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := core.ValidateListenAddr(cfg.Transport.Address); err != nil {
		return nil, core.WrapError(core.ErrCodeConfig, "Transport.Address", err)
	}
	// 零值策略回退默认（intl）：便捷面不强制调用方手写 policy；binding 只校验不回填。
	if cfg.Policy.IsZero() {
		cfg.Policy = core.DefaultServerPolicy(corepb.Profile_PROFILE_INTL)
	}
	hcfg := binding.HandlerConfig{
		Auth: cfg.Auth, Policy: cfg.Policy, Metrics: cfg.Metrics,
		ServerID: cfg.ServerID, RedirectChecker: cfg.RedirectChecker,
		OnSession: cfg.OnSession,
		SinkOpts:  cfg.SinkOpts, SinkHandler: cfg.SinkHandler, SinkDeadline: cfg.SinkDeadline,
		SinkQueueSize: cfg.SinkQueueSize, SinkQueueMaxBytes: cfg.SinkQueueMaxBytes,
		// epoch 必须服务端级共享分配（r2 审查裁决）：票据丢失的 agent 也要拿到
		// 单调递增的 epoch，否则被围栏死锁。每个 Server 一份，跨连接复用。
		Epochs: epochAlloc(cfg.Epochs),
	}
	if err := binding.ResolveHandlerConfig(&hcfg); err != nil {
		return nil, err
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
				return nil, core.WrapError(core.ErrCodeTransport, "listen", err)
			}
			return l, nil
		},
		Accept: func(ctx context.Context, l *Listener) (*Conn, error) { return l.Accept(ctx) },
		NewTransport: func(ctx context.Context, c *Conn) (protocol.Transport, error) {
			return newQuicTransport(ctx, c, s.config.Policy.MaxFrameBytes)
		},
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

// epochAlloc 返回共享分配器或独立新实例。
func epochAlloc(e *protocol.EpochAllocator) *protocol.EpochAllocator {
	if e != nil {
		return e
	}
	return &protocol.EpochAllocator{}
}
