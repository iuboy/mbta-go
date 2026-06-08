package v1

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/quic-go/quic-go"
)

// ALPNProtocol is the Application-Layer Protocol Negotiation identifier for MBTA v1 over QUIC.
const ALPNProtocol = "mbta/1"

// ServerCredentials holds server-side TLS credentials.
// Follows Go naming convention (similar to tls.Certificate).
type ServerCredentials struct {
	CertFile   string
	KeyFile    string
	CAFile     string
	ClientAuth string // none, request, require-and-verify
}

// QUICServerConfig holds server QUIC configuration.
type QUICServerConfig struct {
	Address            string
	Credentials        *ServerCredentials // nil 表示使用默认配置
	MaxIncomingStreams int64
	IdleTimeout        time.Duration
}

// ClientCredentials holds client-side TLS credentials.
type ClientCredentials struct {
	CAFile             string
	CertFile           string
	KeyFile            string
	ServerName         string
	InsecureSkipVerify bool
}

// QUICClientConfig holds client QUIC configuration.
type QUICClientConfig struct {
	Server      string
	Credentials *ClientCredentials // nil 表示不提供客户端证书（单向 TLS）
	IdleTimeout time.Duration
}

// buildServerTLS creates a tls.Config for the server.
func buildServerTLS(cfg *ServerCredentials) (*tls.Config, error) {
	if cfg == nil {
		return nil, fmt.Errorf("server credentials required")
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPNProtocol},
	}

	if cfg.CAFile != "" {
		pool := x509.NewCertPool()
		caData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to append CA certificates")
		}
		tlsCfg.ClientCAs = pool
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
		return nil, fmt.Errorf("client TLS credentials required: provide ClientCredentials or explicitly set InsecureSkipVerify for development")
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPNProtocol},
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify, // #nosec G402 -- intentional for dev, warning logged below
	}

	if cfg.InsecureSkipVerify {
		slog.Warn("TLS certificate verification is DISABLED - do not use in production")
	}

	if cfg.CAFile != "" {
		pool := x509.NewCertPool()
		caData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to append CA certificates")
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
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

	quicCfg := &quic.Config{
		MaxIncomingStreams: cfg.MaxIncomingStreams,
		KeepAlivePeriod:    cfg.IdleTimeout / 3,
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("resolve address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	ql, err := quic.Listen(udpConn, tlsCfg, quicCfg)
	if err != nil {
		_ = udpConn.Close() // #nosec G104 -- best-effort cleanup on error path
		return nil, fmt.Errorf("listen QUIC: %w", err)
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
	authed         bool
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
		return nil, fmt.Errorf("open control stream: %w", err)
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
	if !c.authed {
		return nil, fmt.Errorf("cannot open data stream before auth")
	}
	return c.QC.OpenStreamSync(ctx)
}

// SetAuthed marks the connection as authenticated.
func (c *Conn) SetAuthed(authed bool) {
	c.authed = authed
}

// CloseWithError closes the QUIC connection with an error code.
func (c *Conn) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	return c.QC.CloseWithError(code, reason)
}

// Dial establishes a QUIC connection to an MBTA server.
func Dial(ctx context.Context, cfg QUICClientConfig) (*Conn, error) {
	tlsCfg, err := buildClientTLS(cfg.Credentials)
	if err != nil {
		return nil, err
	}

	quicCfg := &quic.Config{
		KeepAlivePeriod: cfg.IdleTimeout / 3,
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("resolve address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	qc, err := quic.Dial(ctx, udpConn, udpAddr, tlsCfg, quicCfg)
	if err != nil {
		_ = udpConn.Close() // #nosec G104 -- best-effort cleanup on error path
		return nil, fmt.Errorf("dial QUIC: %w", err)
	}

	cs := qc.ConnectionState().TLS
	return &Conn{
		QC:         qc,
		RemoteAddr: qc.RemoteAddr(),
		TLSState:   cs,
	}, nil
}
