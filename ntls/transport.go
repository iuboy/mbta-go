// Package ntls 实现 MBTA ntls binding：TCP 传输 + TLCP（ALPN mbta-ntls/1）或
// TLS 1.3（ALPN mbta-tls/1）安全通道，由 [Mode] 选择。
//
// 所有协议语义（1-RTT 握手/Envelope/RESULT+CREDIT/sink 契约）共享 core 包，
// 协议状态机委托 internal/protocol。ntls 与 v1 的核心区别：单 TCP 连接帧多路复用
// （control/data 帧按 type 高位通道域在同连接交替分流），而非 QUIC 多流分离；
// PING/PONG 保活为本 binding 的 MUST（读侧空闲超时依赖它刷新活性）。
// TLCP 要求双 SM2 证书（签名+加密）。默认 profile 为国密组合（SM2+HKDF-SM3+SM4-GCM）。
package ntls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/binding"
	"github.com/iuboy/mbta-go/internal/protocol"
	"github.com/iuboy/mbta-go/internal/tlshelper"
	"github.com/iuboy/pollux-go/cert"
	smx509 "github.com/iuboy/pollux-go/smx509"
	"github.com/iuboy/pollux-go/tlcp"
)

// tlcpHandshakeTimeout 是客户端 TLCP 握手的整体上限（见 Dial 内注释）。
const tlcpHandshakeTimeout = 30 * time.Second

// ALPNProtocol 是 ntls binding TLCP 模式（mbta-ntls/1）的 ALPN 标识。
const ALPNProtocol = "mbta-ntls/1"

// ALPNProtocolTLS 是 ntls binding TLS 1.3 模式（mbta-tls/1）的 ALPN 标识。
const ALPNProtocolTLS = "mbta-tls/1"

// Mode 是 ntls binding 的传输安全模式（一个值同时确定 ALPN 身份、密码栈与
// 证书形态——bool 双值无法容纳第三种模式，review 裁决枚举化）。
type Mode string

const (
	// ModeTLCP：mbta-ntls/1，TCP + TLCP 国密（双 SM2 证书）。零值缺省。
	ModeTLCP Mode = "tlcp"
	// ModeTLS13：mbta-tls/1，TCP + TLS 1.3 国际（单证书 CertFile/KeyFile）。
	ModeTLS13 Mode = "tls1.3"
)

// normalized 解析空值为缺省模式。
func (m Mode) normalized() Mode {
	if m == "" {
		return ModeTLCP
	}
	return m
}

// IsTLS13 报告模式是否 TLS 1.3（未注册值按校验层拒绝前的保守判定为 false）。
func (m Mode) IsTLS13() bool { return m.normalized() == ModeTLS13 }

// validate 校验模式值为已注册枚举（空值 = 缺省 TLCP 合法）。
func (m Mode) validate() error {
	switch m.normalized() {
	case ModeTLCP, ModeTLS13:
		return nil
	default:
		return core.NewError(core.ErrCodeConfig,
			fmt.Sprintf("unknown ntls mode %q (want %q or %q)", string(m), ModeTLCP, ModeTLS13))
	}
}

// ServerConfig 是 ntls 服务端配置。
//
// Mode 切换两个 ALPN：
//   - ModeTLCP（零值缺省）：mbta-ntls/1，TCP + TLCP 国密（双 SM2 证书）；
//   - ModeTLS13：mbta-tls/1，TCP + TLS 1.3 国际（单证书 CertFile/KeyFile）。
//
// Policy 零值时 NewServer 回填 core.DefaultServerPolicy(PROFILE_GM)——ntls binding
// 默认国密组合（SM2+SM4-GCM）；显式配置则原样经 ResolveHandlerConfig 校验。
type ServerConfig struct {
	Address         string
	Mode            Mode                 // 缺省（空串）= ModeTLCP；未注册值在 NewServer fail-fast
	CertFile        string               // TLS1.3 证书 PEM（ModeTLS13；单证书）
	KeyFile         string               // TLS1.3 私钥 PEM（ModeTLS13）
	SignCertFile    string               // SM2 签名证书 PEM（ModeTLCP）
	SignKeyFile     string               // SM2 签名私钥 PEM（ModeTLCP）
	EncCertFile     string               // SM2 加密证书 PEM（ModeTLCP）
	EncKeyFile      string               // SM2 加密私钥 PEM（ModeTLCP）
	CAFile          string               // 可选 CA 根证书（两种模式共用）
	Auth            core.TokenValidator  // token 认证（必填）
	Policy          core.ServerPolicy    // 服务端策略（零值 = DefaultServerPolicy(gm)）
	Metrics         core.Metrics         // 可选可观测性指标（nil=NoOp）
	RedirectChecker core.RedirectChecker // HA：握手完成后检查角色，非 leader 发 REDIRECT（可选）
	OnSession       core.OnSession       // 会话生命周期回调（可选，nil=禁用）
	ServerID        string               // 服务端标识；空则 ResolveHandlerConfig 生成 ULID

	// Sink 三件套：注册式投递面（替代旧 6 接口 sink 矩阵）。
	SinkOpts     core.SinkOptions // 供给偏好（Raw/Durable/Async）
	SinkHandler  core.BatchHandler
	SinkDeadline time.Duration // handler done 超时（0 = core.DefaultSinkDeadline）

	MaxConcurrentConns int   // 并发连接上限，0 = 使用 binding.DefaultMaxConcurrentConns
	SinkQueueSize      int   // sink 队列容量（0=默认 256，负=同步调用）
	SinkQueueMaxBytes  int64 // sink 队列字节上限（0=默认 32MB，负=不限）

	// Epochs 可选：连接纪元分配器（facade 双监听共享；nil = 独立）。
	Epochs *protocol.EpochAllocator

	// Commands 可选：运维命令通道注册表（COMMAND/COMMAND_ACK 帧按 agentID 寻址；
	// 协议层 READY 即登记，OnSession(CONNECTED) 后即可下发）。nil = 关闭。
	Commands *protocol.CommandRegistry
}

// ClientCredentials 是 ntls 客户端 TLS 凭证（TLCP 双 SM2 证书，或 TLS 1.3 单证书）。
type ClientCredentials struct {
	Mode               Mode // 缺省（空串）= ModeTLCP；未注册值在 NewClient fail-fast
	CertFile           string
	KeyFile            string
	SignCertFile       string
	SignKeyFile        string
	EncCertFile        string
	EncKeyFile         string
	CAFile             string
	ServerName         string
	InsecureSkipVerify bool
}

// ClientConfig 是 ntls 客户端配置。
type ClientConfig struct {
	Server       string
	Credentials  *ClientCredentials
	AgentID      string
	Token        string            // 认证 token（不上 wire，仅参与 token_proof HMAC）
	Meta         map[string]string // HELLO 元数据（hostname/os/agent_version 等，可选）
	Capabilities []string          // 客户端能力（与服务端 policy 协商取交集）
	// Profile 是应用层密码组合。0 = 默认 PROFILE_GM（ntls binding 即国密套件）。
	Profile corepb.Profile

	Metrics      core.Metrics  // 可选：客户端可观测性指标（nil=NoOp）
	DrainTimeout time.Duration // Close 时等待未终态 batch 的上限。0=默认(30s)
}

// --- TLCP 配置构建 ---

// buildServerTLCP 构建 TLCP 服务端配置（加载双 SM2 证书；配置 CAFile 即
// 要求并校验客户端证书，启用 mTLS）。
func buildServerTLCP(cfg *ServerConfig) (*tlcp.Config, error) {
	tc := tlcp.NewConfig()
	// 用 pollux-go/cert 加载 SM2 双证书（标准 tls.LoadX509KeyPair 不识别 SM2 曲线）
	dual, err := cert.LoadDualCertificateFiles(cfg.SignCertFile, cfg.SignKeyFile, cfg.EncCertFile, cfg.EncKeyFile)
	if err != nil {
		return nil, core.WrapError(core.ErrCodeTLS, "load dual SM2 cert", err)
	}
	tc.SignCertificate = &dual.Sign
	tc.EncCertificate = &dual.Enc
	if cfg.CAFile != "" {
		if err := tc.LoadRootCAs(cfg.CAFile, cfg.CAFile); err != nil {
			return nil, core.WrapError(core.ErrCodeTLS, "load root CA", err)
		}
		// mTLS：配置 CAFile 即要求并校验客户端证书——与 buildServerTLS13 的
		// ClientCAs+RequireAndVerifyClientCert 语义对齐。LoadRootCAs 只填
		// Sign/EncRootCAs（校验服务端证书链的信任锚），不触碰 ClientAuth
		// （默认 NoClientCert）：漏设这两项时 mTLS 静默失效（P0 审查裁决）。
		clientCAs, cerr := loadClientCACerts(cfg.CAFile)
		if cerr != nil {
			return nil, core.WrapError(core.ErrCodeTLS, "load client CA", cerr)
		}
		tc.ClientCACertificates = clientCAs
		tc.ClientAuth = tlcp.RequireAndVerifyClientCert
	}
	if err := tc.Validate(); err != nil {
		return nil, core.WrapError(core.ErrCodeTLS, "validate tlcp config", err)
	}
	return tc, nil
}

// loadClientCACerts 从 PEM 文件解析客户端 CA 证书（SM2-aware：stdlib
// crypto/x509 拒绝 SM2 曲线，用 pollux smx509 解析，返回 stdlib 证书类型，
// 与 tlcp.Config.ClientCACertificates 字段类型一致）。
func loadClientCACerts(path string) ([]*x509.Certificate, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, perr := smx509.ParseCertificate(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("parse certificate in %q: %w", path, perr)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%q contains no CERTIFICATE block", path)
	}
	return certs, nil
}

// buildClientTLCP 构建客户端 TLCP 配置。serverAddr 用于在未显式指定 ServerName
// 且未跳过校验时推导校验名——与 crypto/tls 语义对齐（ServerName 为空时回退到
// 拨号地址的 host）；pollux-go tlcp 在握手期硬性要求二者至少其一。
func buildClientTLCP(cfg *ClientCredentials, serverAddr string) (*tlcp.Config, error) {
	if cfg == nil {
		return nil, core.NewError(core.ErrCodeCredential, "ntls credentials required")
	}
	tc := tlcp.NewConfig()
	tc.ServerName = cfg.ServerName
	tc.InsecureSkipVerify = cfg.InsecureSkipVerify
	if tc.ServerName == "" && !tc.InsecureSkipVerify {
		if host, _, err := net.SplitHostPort(serverAddr); err == nil && host != "" {
			tc.ServerName = host
		}
	}
	if cfg.InsecureSkipVerify {
		slog.Warn("TLCP certificate verification is DISABLED - do not use in production")
	}
	if cfg.SignCertFile != "" && cfg.EncCertFile != "" {
		dual, err := cert.LoadDualCertificateFiles(cfg.SignCertFile, cfg.SignKeyFile, cfg.EncCertFile, cfg.EncKeyFile)
		if err != nil {
			return nil, core.WrapError(core.ErrCodeTLS, "load dual SM2 cert", err)
		}
		tc.SignCertificate = &dual.Sign
		tc.EncCertificate = &dual.Enc
	}
	if cfg.CAFile != "" {
		if err := tc.LoadRootCAs(cfg.CAFile, cfg.CAFile); err != nil {
			return nil, core.WrapError(core.ErrCodeTLS, "load root CA", err)
		}
	}
	// 与服务端路径对称：构造期校验（版本/凭证形态），错误不拖到握手期才暴露。
	if err := tc.Validate(); err != nil {
		return nil, core.WrapError(core.ErrCodeTLS, "validate tlcp client config", err)
	}
	return tc, nil
}

// --- TLS 1.3 配置（mbta-tls/1，core spec §10 对称补齐）---

// buildServerTLS13 构建 TLS 1.3 server 配置（国际单证书）。
func buildServerTLS13(cfg *ServerConfig) (*tls.Config, error) {
	cert, err := tlshelper.LoadKeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, core.WrapError(core.ErrCodeTLS, "load TLS1.3 cert/key", err)
	}
	tc := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPNProtocolTLS},
	}
	if pool, err := tlshelper.LoadCertPool(cfg.CAFile); err == nil {
		tc.ClientCAs = pool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	} else if !errors.Is(err, tlshelper.ErrNoCAFile) {
		return nil, core.WrapError(core.ErrCodeTLS, "load server CA", err)
	}
	return tc, nil
}

// buildClientTLS13 构建 TLS 1.3 client 配置。
func buildClientTLS13(cfg *ClientCredentials) (*tls.Config, error) {
	if cfg == nil {
		return nil, core.NewError(core.ErrCodeCredential, "TLS1.3 credentials required")
	}
	// 配置构造上提 tlshelper（review P3：与 v1 buildClientTLS 逐行重复 ~30 行）。
	tc, err := tlshelper.BuildClientTLSConfig(tlshelper.ClientTLSOptions{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		NextProtos:         []string{ALPNProtocolTLS},
		CAFile:             cfg.CAFile,
		CertFile:           cfg.CertFile,
		KeyFile:            cfg.KeyFile,
	})
	if err != nil {
		return nil, core.WrapError(core.ErrCodeTLS, "build client TLS config", err)
	}
	return tc, nil
}

// --- Listen / Dial ---

// Listener 包装 TLCP/TLS listener（按 Mode 由 tlcp.Listen 或 tls.Listen 创建）。
type Listener struct {
	inner net.Listener
}

// Accept 等待并返回下一个连接。
func (l *Listener) Accept() (net.Conn, error) { return l.inner.Accept() }

// Close 关闭 listener，停止接受新连接。
func (l *Listener) Close() error { return l.inner.Close() }

// Addr 返回 listener 的监听地址。
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// validateDualSM2Creds 校验 TLCP 客户端双 SM2 凭证的一致性（NewClient 构造期 fail-fast）：
//   - sign 对（SignCertFile/SignKeyFile）与 enc 对（EncCertFile/EncKeyFile）各自同填或同空；
//   - sign 对与 enc 对必须成对出现——只配一对时 buildClientTLCP 的 && 条件不成立会
//     静默不加载任何客户端证书，拖到服务端 mTLS 握手才失败，报错点远离配置错误。
//
// 全空合法（=不带客户端证书，用于非 mTLS 场景）。
func validateDualSM2Creds(c *ClientCredentials) error {
	if (c.SignCertFile != "") != (c.SignKeyFile != "") {
		return core.NewError(core.ErrCodeCredential,
			"SignCertFile and SignKeyFile must both be set or both empty")
	}
	if (c.EncCertFile != "") != (c.EncKeyFile != "") {
		return core.NewError(core.ErrCodeCredential,
			"EncCertFile and EncKeyFile must both be set or both empty")
	}
	if (c.SignCertFile != "") != (c.EncCertFile != "") {
		return core.NewError(core.ErrCodeCredential,
			"TLCP client certificates require both sign and enc pairs (or neither)")
	}
	return nil
}

// validateTLS13Creds 校验 TLS 1.3 客户端单证书的同填一致性（NewClient 构造期
// fail-fast）。部分填充（CertFile 非空但 KeyFile 空）此前要拖到 Dial 的证书加载
// 才报错，与 TLCP 路径的 validateDualSM2Creds 对称。
func validateTLS13Creds(c *ClientCredentials) error {
	if (c.CertFile != "") != (c.KeyFile != "") {
		return core.NewError(core.ErrCodeCredential,
			"CertFile and KeyFile must both be set or both empty")
	}
	return nil
}

// Listen 按 Mode 创建 ntls listener（TLS 1.3 或 TLCP，见 [ServerConfig.Mode]）。
func Listen(cfg *ServerConfig) (*Listener, error) {
	if cfg.Mode.IsTLS13() {
		tc, err := buildServerTLS13(cfg)
		if err != nil {
			return nil, err
		}
		ln, err := tls.Listen("tcp", cfg.Address, tc)
		if err != nil {
			return nil, core.WrapError(core.ErrCodeTransport, "listen tls1.3", err)
		}
		return &Listener{inner: ln}, nil
	}
	tc, err := buildServerTLCP(cfg)
	if err != nil {
		return nil, err
	}
	ln, err := tlcp.Listen("tcp", cfg.Address, tc)
	if err != nil {
		return nil, core.WrapError(core.ErrCodeTransport, "listen tlcp", err)
	}
	return &Listener{inner: ln}, nil
}

// Dial 按 Mode 建立到服务端的 ntls 连接：TLS 1.3 经 tls.Dialer 直接 DialContext；
// TLCP 先建可取消 TCP 连接，再在其上做 TLCP 握手（整体受 tlcpHandshakeTimeout
// 与 ctx deadline 中较早者约束）。ctx 取消时返回 ctx.Err()，已建立的连接由
// 后台 goroutine 异步关闭。
func Dial(ctx context.Context, cfg *ClientConfig) (net.Conn, error) {
	isTLS := cfg.Credentials != nil && cfg.Credentials.Mode.IsTLS13()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		if isTLS {
			tc, err := buildClientTLS13(cfg.Credentials)
			if err != nil {
				ch <- result{nil, err}
				return
			}
			c, err := (&tls.Dialer{Config: tc}).DialContext(ctx, "tcp", cfg.Server)
			ch <- result{c, err}
			return
		}
		tc, err := buildClientTLCP(cfg.Credentials, cfg.Server)
		if err != nil {
			ch <- result{nil, err}
			return
		}
		// 先 DialContext 建立可取消 TCP 连接，再在其上做 TLCP 握手（tlcp.Dial 不接受 context）。
		rawConn, dErr := (&net.Dialer{}).DialContext(ctx, "tcp", cfg.Server)
		if dErr != nil {
			ch <- result{nil, dErr}
			return
		}
		// TLCP 握手 deadline：pollux-go 的 HandshakeContext 仅在入口检查一次 ctx、
		// 中途不可取消（已核实 v0.4.4 engine_conn.go），stalled 对端会使握手 goroutine
		// 永久阻塞（ctx 取消后的清理 goroutine 也随之挂死——goroutine+fd 泄漏）。
		// 对 rawConn 设整体握手 deadline 强制其有界；握手后必须清零，交还协议层
		// 的读超时管理。ctx 带 deadline 时取较早者。
		handshakeTimeout := tlcpHandshakeTimeout
		if dl, ok := ctx.Deadline(); ok {
			if remaining := time.Until(dl); remaining < handshakeTimeout {
				handshakeTimeout = remaining
			}
		}
		if sdErr := rawConn.SetDeadline(time.Now().Add(handshakeTimeout)); sdErr != nil {
			_ = rawConn.Close()
			ch <- result{nil, sdErr}
			return
		}
		c := tlcp.Client(rawConn, tc)
		hErr := c.HandshakeContext(ctx)
		_ = rawConn.SetDeadline(time.Time{})
		if hErr != nil {
			_ = rawConn.Close()
			ch <- result{nil, hErr}
			return
		}
		ch <- result{c, nil}
	}()
	select {
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.c != nil {
				_ = r.c.Close()
			}
		}()
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, core.WrapError(core.ErrCodeTransport, "dial", r.err)
		}
		return r.c, nil
	}
}

// --- Server ---

// Server 是 ntls 服务器。
// 内嵌 binding.Server（与 v1 同构的外壳），自身仅保留 Start/Addr/Close 入口。
type Server struct {
	*binding.Server[*Listener, net.Conn]
	config ServerConfig
}

// Config 返回服务端配置（facade 测试与诊断用；返回副本）。
func (s *Server) Config() ServerConfig { return s.config }

// NewServer 创建 ntls 服务器（仅构造不启动；启动用 [Server.Start]）。
// 构造期 fail-fast 校验：监听地址、Mode 合法性与证书形态（TLCP 双 SM2 或
// TLS 1.3 单证书）；Policy 零值回填 core.DefaultServerPolicy(PROFILE_GM)。
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := core.ValidateListenAddr(cfg.Address); err != nil {
		return nil, core.WrapError(core.ErrCodeConfig, "Address", err)
	}
	// ntls 特有校验：模式合法性 + TLCP 双 SM2 证书或 TLS1.3 证书。
	if err := cfg.Mode.validate(); err != nil {
		return nil, err
	}
	if cfg.Mode.IsTLS13() {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, core.NewError(core.ErrCodeConfig, "TLS1.3 cert/key required for mbta-tls/1")
		}
	} else {
		if cfg.SignCertFile == "" || cfg.SignKeyFile == "" || cfg.EncCertFile == "" || cfg.EncKeyFile == "" {
			return nil, core.NewError(core.ErrCodeConfig, "dual SM2 certificates (sign + enc, cert + key) required for mbta-ntls/1")
		}
	}
	// 零值策略回退默认（gm）：便捷面不强制调用方手写 policy；binding 只校验不回填。
	if cfg.Policy.IsZero() {
		cfg.Policy = core.DefaultServerPolicy(corepb.Profile_PROFILE_GM)
	}
	hcfg := binding.HandlerConfig{
		Auth: cfg.Auth, Policy: cfg.Policy, Metrics: cfg.Metrics,
		ServerID: cfg.ServerID, RedirectChecker: cfg.RedirectChecker,
		OnSession: cfg.OnSession,
		SinkOpts:  cfg.SinkOpts, SinkHandler: cfg.SinkHandler, SinkDeadline: cfg.SinkDeadline,
		SinkQueueSize: cfg.SinkQueueSize, SinkQueueMaxBytes: cfg.SinkQueueMaxBytes,
		Commands: cfg.Commands,
		// epoch 必须服务端级共享分配（r2 审查裁决）：票据丢失的 agent 也要拿到
		// 单调递增的 epoch，否则被围栏死锁。每个 Server 一份，跨连接复用。
		Epochs: binding.EpochAlloc(cfg.Epochs),
	}
	if err := binding.ResolveHandlerConfig(&hcfg); err != nil {
		return nil, err
	}
	return &Server{
		Server: binding.NewServer[*Listener, net.Conn](cfg.MaxConcurrentConns, hcfg),
		config: cfg,
	}, nil
}

// Addr 返回服务器监听地址（Start 完成监听后有效；启动前返回空串）。
func (s *Server) Addr() string {
	return s.Server.Addr(func(l *Listener) net.Addr { return l.Addr() })
}

// Start 监听 TCP 连接并运行 accept 循环，阻塞直至 ctx 取消。
// 每个被接受的连接经 CoreHandler.Handle 在独立 goroutine 中处理。
func (s *Server) Start(ctx context.Context) error {
	return s.Run(ctx, binding.RunSpec[*Listener, net.Conn]{
		Listen: func(ctx context.Context) (*Listener, error) { return Listen(&s.config) },
		Accept: func(ctx context.Context, l *Listener) (net.Conn, error) { return l.Accept() },
		NewTransport: func(ctx context.Context, c net.Conn) (protocol.Transport, error) {
			return newTCPTransport(c, s.config.Policy.MaxFrameBytes), nil
		},
		CloseConn:     func(c net.Conn) { _ = c.Close() },
		AddrOf:        func(l *Listener) net.Addr { return l.Addr() },
		CloseListener: func(l *Listener) error { return l.Close() },
	})
}

// Close 关闭服务器并释放监听资源。
func (s *Server) Close() error {
	return s.Server.Close(func(l *Listener) error { return l.Close() })
}

// --- Client（完整类型定义与方法在 client.go）---
