package v1

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/tlshelper"
	"github.com/quic-go/quic-go"
)

// ALPNProtocol 是 v1 binding（QUIC + TLS 1.3）的 ALPN 标识。
const ALPNProtocol = "mbta/1"

// 默认传输参数：配置未显式指定时使用。(H-3)
const (
	defaultIdleTimeout        = 60 * time.Second // 未配置时的连接最大空闲时长
	defaultMaxIncomingStreams = 256              // 单连接并发 QUIC 流上限
)

// QUIC 流控接收窗口，按 maxBatchBytes 调优（默认窗口偏小会触发额外 BLOCKED 帧往返）。
const (
	initialStreamWnd     = 8 * 1024 * 1024   // 8 MiB，匹配单 batch 上限
	initialConnectionWnd = 64 * 1024 * 1024  // 64 MiB
	maxStreamWnd         = 16 * 1024 * 1024  // 16 MiB
	maxConnectionWnd     = 128 * 1024 * 1024 // 128 MiB
)

// ServerCredentials 是服务端 TLS 凭证（PEM 文件路径）。
type ServerCredentials struct {
	CertFile   string // 服务端证书 PEM
	KeyFile    string // 服务端私钥 PEM
	CAFile     string // 校验客户端证书的 CA 根证书 PEM（可选，启用 mTLS）
	ClientAuth string // 客户端证书模式："none"、"request"、"require-and-verify"
}

// QUICServerConfig 是服务端 QUIC 配置。
type QUICServerConfig struct {
	Address            string             // 监听地址（如 "0.0.0.0:7400"）
	Credentials        *ServerCredentials // TLS 凭证（nil 报错，见 buildServerTLS）
	MaxIncomingStreams int64              // 单连接并发 QUIC 流上限
	IdleTimeout        time.Duration      // 连接空闲超时
}

// ClientCredentials 是客户端 TLS 凭证（PEM 文件路径）。
type ClientCredentials struct {
	CAFile             string // 校验服务端证书的 CA 根证书 PEM
	CertFile           string // 客户端证书 PEM（可选，mTLS 用）
	KeyFile            string // 客户端私钥 PEM（可选，mTLS 用）
	ServerName         string // SNI/证书校验用的服务端主机名
	InsecureSkipVerify bool   // 跳过 TLS 证书校验（仅开发用，生产禁用）
}

// QUICClientConfig 是客户端 QUIC 配置。
type QUICClientConfig struct {
	Server      string             // 服务端地址（如 "localhost:7400"）
	Credentials *ClientCredentials // TLS 凭证（nil 报错，见 buildClientTLS）
	IdleTimeout time.Duration      // 连接空闲超时
}

// buildServerTLS 从凭证构造服务端 tls.Config（强制 TLS 1.3 + ALPN mbta/1；
// cfg 为 nil 或 ClientAuth 值非法时报错）。
func buildServerTLS(cfg *ServerCredentials) (*tls.Config, error) {
	if cfg == nil {
		return nil, core.NewError(core.ErrCodeCredential, "server credentials required")
	}

	cert, err := tlshelper.LoadKeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, core.WrapError(core.ErrCodeTLS, "load server cert/key", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPNProtocol},
	}

	if pool, err := tlshelper.LoadCertPool(cfg.CAFile); err == nil {
		tlsCfg.ClientCAs = pool
	} else if !errors.Is(err, tlshelper.ErrNoCAFile) {
		return nil, core.WrapError(core.ErrCodeTLS, "load server CA", err)
	}

	switch cfg.ClientAuth {
	case "", "none":
		tlsCfg.ClientAuth = tls.NoClientCert
	case "request":
		tlsCfg.ClientAuth = tls.RequestClientCert
	case "require-and-verify":
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	default:
		// fail-closed：未识别的 ClientAuth 值报错，而非静默降级到 NoClientCert（禁用 mTLS）。
		return nil, core.WrapError(core.ErrCodeConfig, fmt.Sprintf("invalid ClientAuth value: %q", cfg.ClientAuth), nil)
	}

	return tlsCfg, nil
}

// buildClientTLS 从凭证构造客户端 tls.Config（cfg 为 nil 时报错，
// 不提供默认配置）。
func buildClientTLS(cfg *ClientCredentials) (*tls.Config, error) {
	if cfg == nil {
		return nil, core.NewError(core.ErrCodeCredential, "client TLS credentials required: provide ClientCredentials or explicitly set InsecureSkipVerify for development")
	}
	// 配置构造上提 tlshelper（review P3：与 ntls buildClientTLS13 逐行重复 ~30 行）。
	tlsCfg, err := tlshelper.BuildClientTLSConfig(tlshelper.ClientTLSOptions{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		NextProtos:         []string{ALPNProtocol},
		CAFile:             cfg.CAFile,
		CertFile:           cfg.CertFile,
		KeyFile:            cfg.KeyFile,
	})
	if err != nil {
		return nil, core.WrapError(core.ErrCodeTLS, "build client TLS config", err)
	}
	return tlsCfg, nil
}

// Listener 包装 QUIC listener，接受 MBTA QUIC 连接（持有底层 UDP socket，
// Close 时一并释放）。
type Listener struct {
	listener *quic.Listener
	conn     *net.UDPConn // 底层 UDP socket；quic.Listener.Close 不会关闭它
	config   QUICServerConfig
}

// Listen 创建 QUIC listener（应用默认传输参数与流控窗口，见本文件常量注释）。
func Listen(ctx context.Context, cfg QUICServerConfig) (*Listener, error) {
	tlsCfg, err := buildServerTLS(cfg.Credentials)
	if err != nil {
		return nil, err
	}

	// 应用默认值并正确映射到 MaxIdleTimeout (H-3)。
	idleTimeout := cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleTimeout
	}
	maxStreams := cfg.MaxIncomingStreams
	if maxStreams <= 0 {
		maxStreams = defaultMaxIncomingStreams
	}
	quicCfg := &quic.Config{
		MaxIncomingStreams:             maxStreams,
		MaxIdleTimeout:                 idleTimeout,
		KeepAlivePeriod:                idleTimeout / 3,
		InitialStreamReceiveWindow:     initialStreamWnd,
		InitialConnectionReceiveWindow: initialConnectionWnd,
		MaxStreamReceiveWindow:         maxStreamWnd,
		MaxConnectionReceiveWindow:     maxConnectionWnd,
		// Allow0RTT=false（审查 P2 裁决）：quic-go 服务端开启后，持会话票据的
		// 任何客户端（含非本库实现）的 0-RTT 早数据会在握手完成前作为应用层
		// stream 数据投递，且天然可重放——直接进入认证前资源面。本库客户端
		// 从不使用 0-RTT，此开关只为外部客户端放行风险，默认关闭。
		Allow0RTT:       false,
		EnableDatagrams: true, // SupportsDatagram()=true 的前置条件（RFC 9221，§11.4）
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Address)
	if err != nil {
		return nil, core.WrapError(core.ErrCodeTransport, "resolve address", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, core.WrapError(core.ErrCodeTransport, "listen UDP", err)
	}

	ql, err := quic.Listen(udpConn, tlsCfg, quicCfg)
	if err != nil {
		_ = udpConn.Close() // #nosec G104 -- best-effort cleanup on error path; close error is subordinate to listen error
		return nil, core.WrapError(core.ErrCodeTransport, "listen QUIC", err)
	}

	return &Listener{listener: ql, conn: udpConn, config: cfg}, nil
}

// Conn 包装 QUIC 连接并跟踪 MBTA 流角色（首个流为 control，其余为 data）。
type Conn struct {
	QC             *quic.Conn // 底层 QUIC 连接
	RemoteAddr     net.Addr   // 对端地址
	controlClaimed bool
	controlMu      sync.Mutex
	authed         atomic.Bool
	// udpConn 是客户端 Dial 自建的本地 socket（服务端侧为 nil，由 Listener 持有）。
	// quic-go single-use Transport（createdConn=false）不负责关闭调用方 PacketConn——
	// 不持有引用会在每次 dial 泄漏 1 个 socket + 接收 goroutine（高频重连累积）。
	udpConn *net.UDPConn
}

// Close 关闭连接：QUIC 层优雅关闭后补关本地 UDP socket（幂等）。
// error code 1（非 0）："conn closed" 语义——0 = "no error" 会让同库对端把
// 正常关闭误判为无错误，影响重连分类（与本文件 Conn.CloseWithError 规约一致）。
func (c *Conn) Close() error {
	err := c.QC.CloseWithError(1, "conn closed")
	if c.udpConn != nil {
		_ = c.udpConn.Close() // #nosec G104 -- QUIC 关闭错误为主，socket 关闭尽力而为
	}
	return err
}

// Accept 等待并返回下一个 QUIC 连接（包装为 [Conn]，记录对端地址）。
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	qc, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &Conn{
		QC:         qc,
		RemoteAddr: qc.RemoteAddr(),
	}, nil
}

// Close 关闭 listener 并释放底层 UDP socket（quic.Listener.Close 不关
// PacketConn，端口释放依赖此处显式关闭）。
func (l *Listener) Close() error {
	// quic.Listener.Close 不会关闭底层 PacketConn，需显式关闭 UDP socket 以释放端口。
	_ = l.listener.Close()
	return l.conn.Close()
}

// Addr 返回 listener 的监听地址。
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// OpenControlStream 打开 control stream（每个连接仅一次；必须先于
// OpenDataStream 调用）。
//
// 持锁检查 controlClaimed 并在解锁前置位，再 OpenStreamSync：消除检查与置位之间的 TOCTOU 窗口（控制流仅开一次，锁内调用无热路径竞争）。
func (c *Conn) OpenControlStream(ctx context.Context) (*quic.Stream, error) {
	c.controlMu.Lock()
	if c.controlClaimed {
		c.controlMu.Unlock()
		return nil, core.NewError(core.ErrCodeStream, "control stream already opened")
	}
	c.controlClaimed = true
	c.controlMu.Unlock()

	s, err := c.QC.OpenStreamSync(ctx)
	if err != nil {
		// OpenStreamSync 失败：回退 controlClaimed，允许重试。
		c.controlMu.Lock()
		c.controlClaimed = false
		c.controlMu.Unlock()
		return nil, core.WrapError(core.ErrCodeStream, "open control stream", err)
	}
	return s, nil
}

// AcceptStream 接受对端打开的下一个流并按到达顺序赋予角色：首个流为
// control，其余为 data（与 OpenControlStream 共享 controlClaimed 判定）。
func (c *Conn) AcceptStream(ctx context.Context) (*quic.Stream, string, error) {
	s, err := c.QC.AcceptStream(ctx)
	if err != nil {
		return nil, "", err
	}

	c.controlMu.Lock()
	defer c.controlMu.Unlock()

	if !c.controlClaimed {
		c.controlClaimed = true
		return s, core.StreamRoleControl, nil
	}
	return s, core.StreamRoleData, nil
}

// OpenDataStream 打开一条新的 data stream（认证未完成时拒绝；
// 门禁由 SetAuthed 控制）。
func (c *Conn) OpenDataStream(ctx context.Context) (*quic.Stream, error) {
	if !c.authed.Load() {
		return nil, core.NewError(core.ErrCodeStream, "cannot open data stream before auth")
	}
	return c.QC.OpenStreamSync(ctx)
}

// SetAuthed 标记连接是否已通过认证（OpenDataStream 的门禁依据）。
func (c *Conn) SetAuthed(authed bool) {
	c.authed.Store(authed)
}

// CloseWithError 以应用层 error code 关闭 QUIC 连接（code 0 表示 "no error"，
// 会误导对端；主动拆除建议用非零 code，参见 [Conn.Close]）。
func (c *Conn) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	return c.QC.CloseWithError(code, reason)
}

// Dial 建立到 MBTA 服务端的 QUIC 连接（客户端自建本地 UDP socket，
// 由返回的 [Conn] 持有并在 Close 时释放）。
func Dial(ctx context.Context, cfg QUICClientConfig) (*Conn, error) {
	tlsCfg, err := buildClientTLS(cfg.Credentials)
	if err != nil {
		return nil, err
	}

	// 客户端同样应用 MaxIdleTimeout 默认值 (H-3)，避免恶意/异常服务端让连接长期挂起。
	idleTimeout := cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleTimeout
	}
	quicCfg := &quic.Config{
		MaxIdleTimeout:                 idleTimeout,
		KeepAlivePeriod:                idleTimeout / 3,
		InitialStreamReceiveWindow:     initialStreamWnd,
		InitialConnectionReceiveWindow: initialConnectionWnd,
		MaxStreamReceiveWindow:         maxStreamWnd,
		MaxConnectionReceiveWindow:     maxConnectionWnd,
		EnableDatagrams:                true, // SupportsDatagram()=true 的前置条件（RFC 9221，§11.4）
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Server)
	if err != nil {
		return nil, core.WrapError(core.ErrCodeTransport, "resolve address", err)
	}
	// 本地 socket 绑定 wildcard（nil addr → 双栈 socket）：固定 IPv4zero 会在对端为
	// IPv6（v6-only 域名 / [::1] 字面量）时于 Linux 上 WriteToUDP 报 EINVAL
	// （macOS 内核宽容纯属平台巧合）。双栈 socket 对 v4/v6 对端均可写。
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, core.WrapError(core.ErrCodeTransport, "listen UDP", err)
	}

	qc, err := quic.Dial(ctx, udpConn, udpAddr, tlsCfg, quicCfg)
	if err != nil {
		_ = udpConn.Close() // #nosec G104 -- best-effort cleanup on error path; close error is subordinate to dial error
		return nil, core.WrapError(core.ErrCodeTransport, "dial QUIC", err)
	}

	return &Conn{
		QC:         qc,
		RemoteAddr: qc.RemoteAddr(),
		udpConn:    udpConn, // Close 时补关（防泄漏，见 Conn 注释）
	}, nil
}
