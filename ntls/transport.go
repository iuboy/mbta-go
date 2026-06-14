// Package ntls implements MBTA-NTLS (mbta-ntls/1) over TCP with NTLS/TLCP.
//
// 所有协议语义（消息类型、流控、envelope、auth 等）共享 core 包。
// ntls 与 v1 的核心区别：单 TCP 连接帧多路复用（control/data 帧在同连接交替），
// 而非 QUIC 多流分离。TLCP 要求双 SM2 证书（签名+加密）。
package ntls

import (
	"context"
	"log/slog"
	"net"
	"sync"

	"github.com/google/uuid"
	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/pollux-go/cert"
	"github.com/iuboy/pollux-go/tlcp"
)

// ALPNProtocol is the ALPN identifier for MBTA-NTLS.
const ALPNProtocol = "mbta-ntls/1"

// FrameVersion is the frame version for MBTA-NTLS (same as v1).
const FrameVersion = 0x01

const defaultMaxConcurrentConns = 10000

// ServerConfig holds full server configuration for NTLS.
type ServerConfig struct {
	Address      string
	SignCertFile string // SM2 签名证书 PEM
	SignKeyFile  string // SM2 签名私钥 PEM
	EncCertFile  string // SM2 加密证书 PEM
	EncKeyFile   string // SM2 加密私钥 PEM
	CAFile       string // 可选 CA 根证书
	Auth         core.TokenValidator
	Policy       core.Policy
	Sink         core.EventSink
	Metrics      *core.MBTAMetrics
}

// ClientCredentials holds NTLS client credentials（双 SM2 证书）。
type ClientCredentials struct {
	SignCertFile       string
	SignKeyFile        string
	EncCertFile        string
	EncKeyFile         string
	CAFile             string
	ServerName         string
	InsecureSkipVerify bool
}

// ClientConfig holds full client configuration for NTLS.
type ClientConfig struct {
	Server       string
	Credentials  *ClientCredentials
	AgentID      string
	Hostname     string
	Token        string
	Capabilities []string // 客户端能力（HELLO 携带，与服务端协商）
}

// --- TLCP 配置构建 ---

func buildServerTLCP(cfg *ServerConfig) (*tlcp.Config, error) {
	tc := tlcp.NewConfig()
	// 用 pollux-go/cert 加载 SM2 双证书（标准 tls.LoadX509KeyPair 不识别 SM2 曲线）
	dual, err := cert.LoadDualCertificateFiles(cfg.SignCertFile, cfg.SignKeyFile, cfg.EncCertFile, cfg.EncKeyFile)
	if err != nil {
		return nil, core.WrapError(core.NumTLS, core.CodeTLS, "load dual SM2 cert", err)
	}
	tc.SignCertificate = &dual.Sign
	tc.EncCertificate = &dual.Enc
	if cfg.CAFile != "" {
		if err := tc.LoadRootCAs(cfg.CAFile, cfg.CAFile); err != nil {
			return nil, core.WrapError(core.NumTLS, core.CodeTLS, "load root CA", err)
		}
	}
	if err := tc.Validate(); err != nil {
		return nil, core.WrapError(core.NumTLS, core.CodeTLS, "validate tlcp config", err)
	}
	return tc, nil
}

func buildClientTLCP(cfg *ClientCredentials) (*tlcp.Config, error) {
	if cfg == nil {
		return nil, core.NewError(core.NumCredential, core.CodeCredential, "ntls credentials required")
	}
	tc := tlcp.NewConfig()
	tc.ServerName = cfg.ServerName
	tc.InsecureSkipVerify = cfg.InsecureSkipVerify
	if cfg.InsecureSkipVerify {
		slog.Warn("TLCP certificate verification is DISABLED - do not use in production")
	}
	if cfg.SignCertFile != "" && cfg.EncCertFile != "" {
		dual, err := cert.LoadDualCertificateFiles(cfg.SignCertFile, cfg.SignKeyFile, cfg.EncCertFile, cfg.EncKeyFile)
		if err != nil {
			return nil, core.WrapError(core.NumTLS, core.CodeTLS, "load dual SM2 cert", err)
		}
		tc.SignCertificate = &dual.Sign
		tc.EncCertificate = &dual.Enc
	}
	if cfg.CAFile != "" {
		if err := tc.LoadRootCAs(cfg.CAFile, cfg.CAFile); err != nil {
			return nil, core.WrapError(core.NumTLS, core.CodeTLS, "load root CA", err)
		}
	}
	return tc, nil
}

// --- Listen / Dial ---

type Listener struct {
	inner net.Listener
}

func (l *Listener) Accept() (net.Conn, error) { return l.inner.Accept() }
func (l *Listener) Close() error              { return l.inner.Close() }
func (l *Listener) Addr() net.Addr            { return l.inner.Addr() }

func Listen(cfg *ServerConfig) (*Listener, error) {
	tc, err := buildServerTLCP(cfg)
	if err != nil {
		return nil, err
	}
	ln, err := tlcp.Listen("tcp", cfg.Address, tc)
	if err != nil {
		return nil, core.WrapError(core.NumTransport, core.CodeTransport, "listen tlcp", err)
	}
	return &Listener{inner: ln}, nil
}

func Dial(ctx context.Context, cfg *ClientConfig) (*tlcp.Conn, error) {
	tc, err := buildClientTLCP(cfg.Credentials)
	if err != nil {
		return nil, err
	}
	type result struct {
		c   *tlcp.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := tlcp.Dial("tcp", cfg.Server, tc)
		ch <- result{c, err}
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
			return nil, core.WrapError(core.NumTransport, core.CodeTransport, "dial tlcp", r.err)
		}
		return r.c, nil
	}
}

// --- Server ---

type Server struct {
	config   ServerConfig
	mu       sync.Mutex
	listener *Listener
	connSem  chan struct{}
}

func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Address == "" {
		return nil, core.NewError(core.NumConfig, core.CodeConfig, "address required")
	}
	if cfg.SignCertFile == "" || cfg.EncCertFile == "" {
		return nil, core.NewError(core.NumConfig, core.CodeConfig, "dual SM2 certificates required")
	}
	return &Server{config: cfg, connSem: make(chan struct{}, defaultMaxConcurrentConns)}, nil
}

func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *Server) Start(ctx context.Context) error {
	l, err := Listen(&s.config)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()
	slog.Info("MBTA-NTLS server listening", "addr", l.Addr().String())
	for {
		select {
		case s.connSem <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		conn, err := l.Accept()
		if err != nil {
			<-s.connSem
			if ctx.Err() != nil {
				return nil //nolint:nilerr // ctx 取消属优雅关闭，accept 错误不应上抛
			}
			slog.Warn("accept error", "error", err)
			continue
		}
		go func() {
			defer func() { <-s.connSem }()
			h := NewConnectionHandler(ConnectionHandlerConfig{
				Conn:    conn,
				Auth:    s.config.Auth,
				Policy:  s.config.Policy,
				Sink:    s.config.Sink,
				Metrics: s.config.Metrics,
			})
			if err := h.HandleConnection(ctx); err != nil {
				slog.Error("handler error", "error", err)
			}
		}()
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// --- Client（完整类型定义与方法在 client.go）---

// ServerID generates a UUID for server identification.
func ServerID() string { return uuid.Must(uuid.NewV7()).String() }
