// Package ntls implements MBTA-NTLS (mbta-ntls/1) over TCP with NTLS/TLCP.
//
// 所有协议语义（消息类型、流控、envelope、auth 等）共享 core 包。
// ntls 与 v1 的核心区别：单 TCP 连接帧多路复用（control/data 帧在同连接交替），
// 而非 QUIC 多流分离。TLCP 要求双 SM2 证书（签名+加密）。
package ntls

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/binding"
	"github.com/iuboy/mbta-go/internal/protocol"
	"github.com/iuboy/mbta-go/internal/tlshelper"
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
	RedirectChecker    core.RedirectChecker // HA：AUTH_OK 后检查角色，非 leader 发 TypeRedirect（可选）
	OnSession          core.OnSession       // 会话生命周期回调（可选，nil=禁用）
	SessionStore       *core.SessionStore   // 0-RTT 会话票据存储（nil=禁用 0-RTT）
	ServerID           string               // 服务端标识，回填 HELLO_ACK；空则 NewServer 自动生成 ULID（Crockford base32，26 字符）
	MaxConcurrentConns int                  // 并发连接上限，0 = 使用 binding.DefaultMaxConcurrentConns (H-3)
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
	Capabilities []string // 客户端能力（HELLO 携带，与服务端协商）
	// OS / AgentVersion 写入 HELLO（空则不发/回退默认）。
	OS           string
	AgentVersion string
	Metrics      core.Metrics // 可选：客户端可观测性指标（nil=NoOp）
	// DrainTimeout 限制 Close 时等待未 ACK batch 的最长时间。0=用默认(30s)。
	// 缩短可减小"发完即 Close"的等待窗口；未确认的 batch 会丢（调用方负责重发）。
	DrainTimeout time.Duration
}

// --- TLCP 配置构建 ---

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
	}
	if err := tc.Validate(); err != nil {
		return nil, core.WrapError(core.ErrCodeTLS, "validate tlcp config", err)
	}
	return tc, nil
}

func buildClientTLCP(cfg *ClientCredentials) (*tlcp.Config, error) {
	if cfg == nil {
		return nil, core.NewError(core.ErrCodeCredential, "ntls credentials required")
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
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPNProtocolTLS},
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		ClientSessionCache: tls.NewLRUClientSessionCache(8), // TLS 1.3 session resumption（降低 resumption 握手开销）
	}
	if cfg.InsecureSkipVerify {
		slog.Warn("TLS 1.3 certificate verification is DISABLED - do not use in production")
	}
	if pool, err := tlshelper.LoadCertPool(cfg.CAFile); err == nil {
		tc.RootCAs = pool
	} else if !errors.Is(err, tlshelper.ErrNoCAFile) {
		return nil, core.WrapError(core.ErrCodeTLS, "load client CA", err)
	}
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tlshelper.LoadKeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, core.WrapError(core.ErrCodeTLS, "load client cert/key", err)
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

// validateDualSM2Creds 校验 TLCP 客户端双 SM2 凭证的一致性：sign 对与 enc 对
// 各自的 cert 和 key 必须同填或同空。部分填充（如 SignCert 非空但 SignKey 空）
// 此前要拖到 Dial 的 LoadDualCertificateFiles 才报错，NewClient 构造期 fail-fast。
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
	return nil
}

func Listen(cfg *ServerConfig) (*Listener, error) {
	if cfg.TLSMode {
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
			c, err := (&tls.Dialer{Config: tc}).DialContext(ctx, "tcp", cfg.Server)
			ch <- result{c, err}
			return
		}
		tc, err := buildClientTLCP(cfg.Credentials)
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
		c := tlcp.Client(rawConn, tc)
		if hErr := c.HandshakeContext(ctx); hErr != nil {
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

type Server struct {
	*binding.Server[*Listener, net.Conn]
	config ServerConfig
}

func NewServer(cfg ServerConfig) (*Server, error) {
	if err := core.ValidateListenAddr(cfg.Address); err != nil {
		return nil, core.WrapError(core.ErrCodeConfig, "Address", err)
	}
	// 用户未配置 Policy 时应用默认（cipher 跟随 ntls = GM）；已配置则保持不动。
	if cfg.Policy.IsZeroPolicy() {
		cfg.Policy = core.DefaultPolicy(corepb.CipherSuite_CIPHER_SUITE_GM)
	}
	// fail-fast：Auth/Sink/Policy 缺失属严重误配。
	if cfg.Auth == nil {
		return nil, core.NewError(core.ErrCodeConfig, "Auth (TokenValidator) is required")
	}
	if cfg.Sink == nil {
		return nil, core.NewError(core.ErrCodeConfig, "Sink (EventSink) is required")
	}
	if err := cfg.Policy.Validate(); err != nil {
		return nil, core.WrapError(core.ErrCodeConfig, "Policy", err)
	}
	if cfg.TLSMode {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, core.NewError(core.ErrCodeConfig, "TLS1.3 cert/key required for mbta-tls/1")
		}
	} else {
		if cfg.SignCertFile == "" || cfg.SignKeyFile == "" || cfg.EncCertFile == "" || cfg.EncKeyFile == "" {
			return nil, core.NewError(core.ErrCodeConfig, "dual SM2 certificates (sign + enc, cert + key) required for mbta-ntls/1")
		}
	}
	if cfg.ServerID == "" {
		cfg.ServerID = core.NewChunkID().String()
	}
	hcfg := binding.HandlerConfig{
		Auth:            cfg.Auth,
		Policy:          cfg.Policy,
		Sink:            cfg.Sink,
		Metrics:         cfg.Metrics,
		ServerID:        cfg.ServerID,
		RedirectChecker: cfg.RedirectChecker,
		OnSession:       cfg.OnSession,
		SessionStore:    cfg.SessionStore,
	}
	return &Server{
		Server: binding.NewServer[*Listener, net.Conn](cfg.MaxConcurrentConns, hcfg),
		config: cfg,
	}, nil
}

func (s *Server) Addr() string {
	return s.Server.Addr(func(l *Listener) net.Addr { return l.Addr() })
}

func (s *Server) Start(ctx context.Context) error {
	return s.Run(ctx, binding.RunSpec[*Listener, net.Conn]{
		Listen:        func(ctx context.Context) (*Listener, error) { return Listen(&s.config) },
		Accept:        func(ctx context.Context, l *Listener) (net.Conn, error) { return l.Accept() },
		NewTransport:  func(ctx context.Context, c net.Conn) (protocol.Transport, error) { return newTCPTransport(c), nil },
		CloseConn:     func(c net.Conn) { _ = c.Close() },
		AddrOf:        func(l *Listener) net.Addr { return l.Addr() },
		CloseListener: func(l *Listener) error { return l.Close() },
	})
}

func (s *Server) Close() error {
	return s.Server.Close(func(l *Listener) error { return l.Close() })
}

// --- Client（完整类型定义与方法在 client.go）---
