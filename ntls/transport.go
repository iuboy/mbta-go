// Package ntls implements MBTA-NTLS (mbta-ntls/1) over TCP with NTLS/TLCP.
//
// 所有协议语义（消息类型、流控、envelope、auth 等）共享 core 包。
// ntls 与 v1 的核心区别：单 TCP 连接帧多路复用（control/data 帧在同连接交替），
// 而非 QUIC 多流分离。TLCP 要求双 SM2 证书（签名+加密）。
package ntls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/binding"
	"github.com/iuboy/mbta-go/internal/protocol"
	"github.com/iuboy/pollux-go/cert"
	"github.com/iuboy/pollux-go/tlcp"
)

// ALPNProtocol is the ALPN identifier for MBTA-NTLS (TLCP).
const ALPNProtocol = "mbta-ntls/1"

// ALPNProtocolTLS is the ALPN identifier for mbta-tls/1 (TCP + TLS 1.3)。
const ALPNProtocolTLS = "mbta-tls/1"

// FrameVersion is the frame version for MBTA-NTLS (same as v1).
const FrameVersion = 0x01

// ServerConfig holds full server configuration for NTLS.
//
// TLSMode 切换两个 ALPN（core spec §10 对称两维）：
//   - TLSMode=false（默认）：mbta-ntls/1，TCP + TLCP 国密（双 SM2 证书）；
//   - TLSMode=true：mbta-tls/1，TCP + TLS 1.3 国际（单证书 CertFile/KeyFile）。
type ServerConfig struct {
	Address            string
	TLSMode            bool   // true=mbta-tls/1（TLS1.3），false=mbta-ntls/1（TLCP，默认）
	CertFile           string // TLS1.3 证书 PEM（TLSMode=true；单证书）
	KeyFile            string // TLS1.3 私钥 PEM（TLSMode=true）
	SignCertFile       string // SM2 签名证书 PEM（TLSMode=false）
	SignKeyFile        string // SM2 签名私钥 PEM（TLSMode=false）
	EncCertFile        string // SM2 加密证书 PEM（TLSMode=false）
	EncKeyFile         string // SM2 加密私钥 PEM（TLSMode=false）
	CAFile             string // 可选 CA 根证书（两种模式共用）
	Auth               core.TokenValidator
	Policy             core.Policy
	Sink               core.EventSink
	Metrics            *core.MBTAMetrics
	ServerID           string // 服务端标识，回填 HELLO_ACK；空则 NewServer 自动生成 UUID v7
	MaxConcurrentConns int    // 并发连接上限，0 = 使用 binding.DefaultMaxConcurrentConns (H-3)
}

// ClientCredentials holds NTLS client credentials（双 SM2 证书，或 TLS1.3 单证书）。
type ClientCredentials struct {
	TLSMode            bool // true=TLS1.3 单证书，false=TLCP 双 SM2
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

// ClientConfig holds full client configuration for NTLS.
type ClientConfig struct {
	Server       string
	Credentials  *ClientCredentials
	AgentID      string
	Hostname     string
	Token        string
	Capabilities []string     // 客户端能力（HELLO 携带，与服务端协商）
	Metrics      core.Metrics // 可选：客户端可观测性指标（nil=NoOp）
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

// --- TLS 1.3 配置（mbta-tls/1，core spec §10 对称补齐）---

// buildServerTLS13 构建 TLS 1.3 server 配置（国际单证书）。
func buildServerTLS13(cfg *ServerConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, core.WrapError(core.NumTLS, core.CodeTLS, "load TLS1.3 cert/key", err)
	}
	tc := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPNProtocolTLS},
	}
	if cfg.CAFile != "" {
		pool := x509.NewCertPool()
		caData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, core.WrapError(core.NumTLS, core.CodeTLS, "read CA file", err)
		}
		if !pool.AppendCertsFromPEM(caData) {
			return nil, core.NewError(core.NumTLS, core.CodeTLS, "failed to append CA")
		}
		tc.ClientCAs = pool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tc, nil
}

// buildClientTLS13 构建 TLS 1.3 client 配置。
func buildClientTLS13(cfg *ClientCredentials) (*tls.Config, error) {
	if cfg == nil {
		return nil, core.NewError(core.NumCredential, core.CodeCredential, "TLS1.3 credentials required")
	}
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPNProtocolTLS},
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		ClientSessionCache: tls.NewLRUClientSessionCache(8), // TLS 1.3 session resumption（降低 resumption 握手开销）
	}
	if cfg.CAFile != "" {
		pool := x509.NewCertPool()
		caData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, core.WrapError(core.NumTLS, core.CodeTLS, "read CA file", err)
		}
		if !pool.AppendCertsFromPEM(caData) {
			return nil, core.NewError(core.NumTLS, core.CodeTLS, "failed to append CA")
		}
		tc.RootCAs = pool
	}
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, core.WrapError(core.NumTLS, core.CodeTLS, "load client cert/key", err)
		}
		tc.Certificates = []tls.Certificate{cert}
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
	if cfg.TLSMode {
		tc, err := buildServerTLS13(cfg)
		if err != nil {
			return nil, err
		}
		ln, err := tls.Listen("tcp", cfg.Address, tc)
		if err != nil {
			return nil, core.WrapError(core.NumTransport, core.CodeTransport, "listen tls1.3", err)
		}
		return &Listener{inner: ln}, nil
	}
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

func Dial(ctx context.Context, cfg *ClientConfig) (net.Conn, error) {
	isTLS := cfg.Credentials != nil && cfg.Credentials.TLSMode
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
			c, err := tls.Dial("tcp", cfg.Server, tc)
			ch <- result{c, err}
			return
		}
		tc, err := buildClientTLCP(cfg.Credentials)
		if err != nil {
			ch <- result{nil, err}
			return
		}
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
			return nil, core.WrapError(core.NumTransport, core.CodeTransport, "dial", r.err)
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
	if cfg.TLSMode {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, core.NewError(core.NumConfig, core.CodeConfig, "TLS1.3 cert/key required for mbta-tls/1")
		}
	} else {
		if cfg.SignCertFile == "" || cfg.EncCertFile == "" {
			return nil, core.NewError(core.NumConfig, core.CodeConfig, "dual SM2 certificates required for mbta-ntls/1")
		}
	}
	if cfg.ServerID == "" {
		cfg.ServerID = core.NewChunkID().String()
	}
	maxConns := cfg.MaxConcurrentConns
	if maxConns <= 0 {
		maxConns = binding.DefaultMaxConcurrentConns
	}
	return &Server{config: cfg, connSem: make(chan struct{}, maxConns)}, nil
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

	// ctx 取消时关闭 listener：被 l.Accept() 阻塞的循环因此解除并退出。
	// 监听器 Close 幂等，与 Server.Close 并发调用安全。
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	return binding.AcceptLoop(ctx, s.connSem,
		func(ctx context.Context) (net.Conn, error) { return l.Accept() },
		func(ctx context.Context, conn net.Conn) (protocol.Transport, error) {
			return newTCPTransport(conn), nil
		},
		func(conn net.Conn) { _ = conn.Close() },
		binding.HandlerConfig{
			Auth:     s.config.Auth,
			Policy:   s.config.Policy,
			Sink:     s.config.Sink,
			Metrics:  s.config.Metrics,
			ServerID: s.config.ServerID,
		},
	)
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
