package v1

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/tlshelper"
	"github.com/quic-go/quic-go"
)

// ALPNProtocol is the Application-Layer Protocol Negotiation identifier for MBTA v1 over QUIC.
const ALPNProtocol = "mbta/1"

// 默认传输参数：配置未显式指定时使用。(H-3)
// 之前 IdleTimeout 只被映射到 KeepAlivePeriod，从未设为 quic.Config.MaxIdleTimeout，
// 导致未显式配置 IdleTimeout 的连接在空闲时永不超时，可被慢速攻击长期占用。
const (
	defaultIdleTimeout        = 60 * time.Second // 未配置时的连接最大空闲时长
	defaultMaxIncomingStreams = 256              // 单连接并发 QUIC 流上限
)

// QUIC 流控接收窗口。默认窗口偏小（~512KB-1MB），小于 maxBatchBytes(8MiB)，
// 大 batch 会触发额外的 BLOCKED 帧往返。这里按 batch 上限调优，跨地域高 BDP 链路
// 下避免每帧多一个 RTT。
const (
	initialStreamWnd     = 8 * 1024 * 1024   // 8 MiB，匹配单 batch 上限
	initialConnectionWnd = 64 * 1024 * 1024  // 64 MiB
	maxStreamWnd         = 16 * 1024 * 1024  // 16 MiB
	maxConnectionWnd     = 128 * 1024 * 1024 // 128 MiB
)

// ServerCredentials holds server-side TLS credentials.
// Follows Go naming convention (similar to tls.Certificate).
type ServerCredentials struct {
	CertFile   string // PEM-encoded server certificate
	KeyFile    string // PEM-encoded server private key
	CAFile     string // PEM-encoded CA certificate for client verification (optional)
	ClientAuth string // Client certificate mode: "none", "request", "require-and-verify"
}

// QUICServerConfig holds server QUIC configuration.
type QUICServerConfig struct {
	Address            string             // listen address (e.g. "0.0.0.0:7400")
	Credentials        *ServerCredentials // TLS credentials (nil uses default config)
	MaxIncomingStreams int64              // maximum concurrent QUIC streams
	IdleTimeout        time.Duration      // connection idle timeout
}

// ClientCredentials holds client-side TLS credentials.
type ClientCredentials struct {
	CAFile             string // PEM-encoded CA certificate for server verification
	CertFile           string // PEM-encoded client certificate (optional, for mTLS)
	KeyFile            string // PEM-encoded client private key (optional, for mTLS)
	ServerName         string // expected server hostname for SNI
	InsecureSkipVerify bool   // skip TLS verification (dev only, never use in production)
}

// QUICClientConfig holds client QUIC configuration.
type QUICClientConfig struct {
	Server      string             // server address (e.g. "localhost:7400")
	Credentials *ClientCredentials // TLS credentials (nil skips client cert)
	IdleTimeout time.Duration      // connection idle timeout
}

// buildServerTLS creates a tls.Config for the server.
func buildServerTLS(cfg *ServerCredentials) (*tls.Config, error) {
	if cfg == nil {
		return nil, core.NewError(core.NumCredential, core.CodeCredential, "server credentials required")
	}

	cert, err := tlshelper.LoadKeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, core.WrapError(core.NumTLS, core.CodeTLS, "load server cert/key", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPNProtocol},
	}

	if pool, err := tlshelper.LoadCertPool(cfg.CAFile); err == nil {
		tlsCfg.ClientCAs = pool
	} else if !errors.Is(err, tlshelper.ErrNoCAFile) {
		return nil, core.WrapError(core.NumTLS, core.CodeTLS, "load server CA", err)
	}

	switch cfg.ClientAuth {
	case "request":
		tlsCfg.ClientAuth = tls.RequestClientCert
	case "require-and-verify":
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	default:
		tlsCfg.ClientAuth = tls.NoClientCert
	}

	return tlsCfg, nil
}

// buildClientTLS creates a tls.Config for the client.
func buildClientTLS(cfg *ClientCredentials) (*tls.Config, error) {
	if cfg == nil {
		return nil, core.NewError(core.NumCredential, core.CodeCredential, "client TLS credentials required: provide ClientCredentials or explicitly set InsecureSkipVerify for development")
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPNProtocol},
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,          // #nosec G402 -- intentional for dev, warning logged below
		ClientSessionCache: tls.NewLRUClientSessionCache(8), // 0-RTT resumption ticket cache
	}

	if cfg.InsecureSkipVerify {
		slog.Warn("TLS certificate verification is DISABLED - do not use in production")
	}

	if pool, err := tlshelper.LoadCertPool(cfg.CAFile); err == nil {
		tlsCfg.RootCAs = pool
	} else if !errors.Is(err, tlshelper.ErrNoCAFile) {
		return nil, core.WrapError(core.NumTLS, core.CodeTLS, "load client CA", err)
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tlshelper.LoadKeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, core.WrapError(core.NumTLS, core.CodeTLS, "load client cert/key", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// Listener accepts MBTA QUIC connections.
type Listener struct {
	listener *quic.Listener
	config   QUICServerConfig
}

// Listen creates a QUIC listener.
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
		Allow0RTT:                      true,       // 接受 0-RTT resumption（core spec §11.6）
		EnableDatagrams:                true,       // SupportsDatagram()=true 的前置条件（RFC 9221，§11.4）
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Address)
	if err != nil {
		return nil, core.WrapError(core.NumTransport, core.CodeTransport, "resolve address", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, core.WrapError(core.NumTransport, core.CodeTransport, "listen UDP", err)
	}

	ql, err := quic.Listen(udpConn, tlsCfg, quicCfg)
	if err != nil {
		_ = udpConn.Close() // #nosec G104 -- best-effort cleanup on error path; close error is subordinate to listen error
		return nil, core.WrapError(core.NumTransport, core.CodeTransport, "listen QUIC", err)
	}

	return &Listener{listener: ql, config: cfg}, nil
}

// Conn wraps a QUIC connection with MBTA stream role tracking.
type Conn struct {
	QC             *quic.Conn
	RemoteAddr     net.Addr
	TLSState       tls.ConnectionState
	controlClaimed bool
	controlMu      sync.Mutex
	authed         atomic.Bool
}

// Accept waits for and returns the next QUIC connection.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	qc, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	cs := qc.ConnectionState().TLS
	return &Conn{
		QC:         qc,
		RemoteAddr: qc.RemoteAddr(),
		TLSState:   cs,
	}, nil
}

// Close shuts down the listener.
func (l *Listener) Close() error {
	return l.listener.Close()
}

// Addr returns the listener address.
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// OpenControlStream opens the control stream. Must be called before OpenDataStream.
func (c *Conn) OpenControlStream(ctx context.Context) (*quic.Stream, error) {
	s, err := c.QC.OpenStreamSync(ctx)
	if err != nil {
		return nil, core.WrapError(core.NumStream, core.CodeStream, "open control stream", err)
	}
	c.controlMu.Lock()
	c.controlClaimed = true
	c.controlMu.Unlock()
	return s, nil
}

// AcceptStream accepts a stream from the remote peer and assigns its role.
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

// OpenDataStream opens a new data stream. Requires auth to be completed.
func (c *Conn) OpenDataStream(ctx context.Context) (*quic.Stream, error) {
	if !c.authed.Load() {
		return nil, core.NewError(core.NumStream, core.CodeStream, "cannot open data stream before auth")
	}
	return c.QC.OpenStreamSync(ctx)
}

// SetAuthed marks the connection as authenticated.
func (c *Conn) SetAuthed(authed bool) {
	c.authed.Store(authed)
}

// CloseWithError closes the QUIC connection with an error code.
func (c *Conn) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	return c.QC.CloseWithError(code, reason)
}

// Dial establishes a QUIC connection to an MBTA server.
func Dial(ctx context.Context, cfg QUICClientConfig) (*Conn, error) {
	return dial(ctx, cfg, false)
}

// DialEarly establishes a 0-RTT QUIC connection for session resumption (core spec §11.6).
// Requires ClientSessionCache populated from a previous Dial (TLS session ticket).
func DialEarly(ctx context.Context, cfg QUICClientConfig) (*Conn, error) {
	return dial(ctx, cfg, true)
}

// dial 建立到 MBTA server 的 QUIC 连接；early=true 走 0-RTT 恢复路径（core spec §11.6）。
func dial(ctx context.Context, cfg QUICClientConfig, early bool) (*Conn, error) {
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
		return nil, core.WrapError(core.NumTransport, core.CodeTransport, "resolve address", err)
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, core.WrapError(core.NumTransport, core.CodeTransport, "listen UDP", err)
	}

	var (
		qc  *quic.Conn
		msg string
	)
	if early {
		qc, err = quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, quicCfg)
		msg = "dial early (0-RTT)"
	} else {
		qc, err = quic.Dial(ctx, udpConn, udpAddr, tlsCfg, quicCfg)
		msg = "dial QUIC"
	}
	if err != nil {
		_ = udpConn.Close() // #nosec G104 -- best-effort cleanup on error path; close error is subordinate to dial error
		return nil, core.WrapError(core.NumTransport, core.CodeTransport, msg, err)
	}

	cs := qc.ConnectionState().TLS
	return &Conn{
		QC:         qc,
		RemoteAddr: qc.RemoteAddr(),
		TLSState:   cs,
	}, nil
}
