package mbta

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/iuboy/mbta-go/core"
	ntls "github.com/iuboy/mbta-go/ntls"
	v1 "github.com/iuboy/mbta-go/v1"
)

// ClientOption configures a Client.
type ClientOption func(*ClientConfig) error

// Client is a single-version MBTA client that connects to an MBTA server.
// Each version (v1, ntls) is a completely separate protocol — no automatic
// fallback between versions. Create separate Client instances for different versions.
type Client struct {
	cfg    ClientConfig
	client versionedClient
	mu     sync.RWMutex
}

// ACKHandler is called when the server acknowledges a batch.
type ACKHandler func(chunkID, ackMode string)

// RedirectHandler is called when the server sends a TypeRedirect frame
// (S→C cluster redirect to the HA leader). The payload is application-defined
// (e.g. JSON {leaderAddr, leaderId}).
//
// ctx 带超时（redirectHandlerTimeout），handler 应在内部 IO/锁操作中检查 ctx.Done()
// 并及时退出，否则超时后 goroutine 泄漏（Go runtime 无法杀死阻塞的 goroutine）。
type RedirectHandler func(ctx context.Context, payload []byte)

// versionedClient wraps version-specific clients with a common interface.
type versionedClient interface {
	Connect(ctx context.Context) error
	SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string, opts ...core.SendOption) (string, error)
	Close() error
	State() string
	SetACKHandler(handler ACKHandler)
	SetRedirectHandler(handler RedirectHandler)
}

// ClientConfig holds the client configuration.
type ClientConfig struct {
	// Protocol version — one of Version1, VersionNTLS. Required.
	// 类型化为 ProtocolVersion，调用方传常量减少拼写错误（initClient 仍运行时分派）。
	Version ProtocolVersion

	// Connection settings
	Server   string
	AgentID  string
	Hostname string
	Token    string

	// Agent 元数据（写入 HELLO，供服务端 OnSession 回调读取；空则不发/回退默认）。
	OS           string // agent 操作系统（runtime.GOOS）
	AgentVersion string // agent 构建版本（空则回退 mbta-go 内置默认）

	// Version-specific configurations
	V1Creds   *v1.ClientCredentials
	NTLSCreds *ntls.ClientCredentials

	// Metrics 可选的可观测性接口（nil=NoOp）。客户端侧指标（BatchesSent/BatchLatency）。
	Metrics core.Metrics
}

// NewClient creates a single-version MBTA client.
// The client will connect using exactly the version specified in the config.
func NewClient(opts ...ClientOption) (*Client, error) {
	cfg := &ClientConfig{
		Version: Version1, // Default to v1
	}

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, core.WrapError(core.ErrCodeConfig, "client option", err)
		}
	}

	// Validate version：ProtocolVersion 类型已在编译期约束为合法常量之一，
	// 这里只兜底零值（用户未设置 Version）。
	if cfg.Version == "" {
		return nil, core.NewError(core.ErrCodeConfig, "version is required")
	}

	if cfg.AgentID == "" {
		return nil, core.NewError(core.ErrCodeConfig, "AgentID is required")
	}
	if cfg.Server == "" {
		return nil, core.NewError(core.ErrCodeConfig, "Server address is required")
	}

	c := &Client{cfg: *cfg}

	// Initialize the version-specific client
	client, err := c.initClient()
	if err != nil {
		return nil, err
	}
	c.client = client

	return c, nil
}

// Dial creates a Client, connects it, and returns the ready-to-use client.
// This is a convenience function that combines NewClient + Connect in one call.
//
// For simple use cases:
//
//	client, err := mbta.Dial(ctx, "localhost:7400", "my-agent", "secret-token",
//	    "v1",
//	    mbta.WithV1Credentials(v1.ClientCredentials{CAFile: "ca.pem"}),
//	)
//	if err != nil { ... }
//	defer client.Close()
//
//	// client is already connected, ready to SendBatch
func Dial(ctx context.Context, server, agentID, token string, version ProtocolVersion, opts ...ClientOption) (*Client, error) {
	allOpts := append([]ClientOption{
		WithServer(server),
		WithAgent(agentID, "", token),
		WithVersion(version),
	}, opts...)

	client, err := NewClient(allOpts...)
	if err != nil {
		return nil, core.WrapError(core.ErrCodeTransport, "dial create", err)
	}

	if err := client.Connect(ctx); err != nil {
		if closeErr := client.Close(); closeErr != nil {
			slog.Debug("cleanup close after failed connect", "error", closeErr)
		}
		return nil, core.WrapError(core.ErrCodeTransport, "dial connect", err)
	}

	return client, nil
}

// initClient initializes the version-specific client.
func (c *Client) initClient() (versionedClient, error) {
	switch c.cfg.Version {
	case Version1:
		return c.initV1Client()
	case VersionNTLS:
		return c.initNTLSClient()
	default:
		return nil, core.NewError(core.ErrCodeVersion, fmt.Sprintf("unsupported version: %s", c.cfg.Version))
	}
}

// Connect establishes a connection using the configured version.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client == nil {
		return core.NewError(core.ErrCodeSession, "client has been closed (cannot reconnect after Close)")
	}

	slog.Info("connecting", "version", c.cfg.Version, "server", c.cfg.Server)

	if err := c.client.Connect(ctx); err != nil {
		slog.Error("connection failed", "version", c.cfg.Version, "error", err)
		return err
	}

	slog.Info("connected", "version", c.cfg.Version)
	return nil
}

// SendBatch 通过活动连接发送 batch；opts 携带 per-call 选项（如 WithTraceContext），不传则与旧行为一致。
// RLock 保护防止与 Close 竞态（Close 的 Lock 等待 RLock 释放，保证串行化）。
func (c *Client) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string, opts ...core.SendOption) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return "", core.NewError(core.ErrCodeSession, "not connected (call Connect first)")
	}

	return c.client.SendBatch(ctx, batch, tag, source, opts...)
}

// Close closes the client and releases all resources.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cfg.Token = ""
	c.cfg.V1Creds = nil
	c.cfg.NTLSCreds = nil

	if c.client != nil {
		err := c.client.Close()
		// 置 nil 防止 use-after-close。
		c.client = nil
		return err
	}
	return nil
}

// State returns the current connection state.
func (c *Client) State() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return core.StateDisconnected.String()
	}
	return c.client.State()
}

// SetACKHandler registers a callback for ACK notifications from the server.
// The handler will be called with (chunkID, ackMode) when the server acknowledges a batch.
//
// 用 Lock（非 RLock）：SetACKHandler 修改 handler 状态，需防并发 Set（RLock 仅防与 Close 的并发）。
func (c *Client) SetACKHandler(handler ACKHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client != nil {
		c.client.SetACKHandler(handler)
	}
}

// SetRedirectHandler registers a callback for TypeRedirect notifications
// (S→C cluster redirect to the HA leader). The handler receives the raw frame
// payload for the application to decode.语义同 SetACKHandler，用 Lock 保护。
func (c *Client) SetRedirectHandler(handler RedirectHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client != nil {
		c.client.SetRedirectHandler(handler)
	}
}

// ActiveVersion returns the configured protocol version.
func (c *Client) ActiveVersion() ProtocolVersion {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.Version
}

// initV1Client initializes the V1 client wrapper.
func (c *Client) initV1Client() (versionedClient, error) {
	if c.cfg.V1Creds == nil {
		return nil, core.NewError(core.ErrCodeCredential, "v1 credentials not provided")
	}

	cfg := v1.ClientConfig{
		Transport: v1.QUICClientConfig{
			Server:      c.cfg.Server,
			Credentials: c.cfg.V1Creds,
		},
		AgentID:      c.cfg.AgentID,
		Hostname:     c.cfg.Hostname,
		Token:        c.cfg.Token,
		OS:           c.cfg.OS,
		AgentVersion: c.cfg.AgentVersion,
		Metrics:      c.cfg.Metrics,
	}

	client, err := v1.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	return &v1ClientWrapper{client: client}, nil
}

// initNTLSClient 初始化 NTLS（TCP + TLCP）客户端。
func (c *Client) initNTLSClient() (versionedClient, error) {
	// fail-fast：NewClient 时校验凭证非空。
	if c.cfg.NTLSCreds == nil {
		return nil, core.NewError(core.ErrCodeCredential, "ntls credentials not provided")
	}
	cfg := ntls.ClientConfig{
		Server:       c.cfg.Server,
		Credentials:  c.cfg.NTLSCreds,
		AgentID:      c.cfg.AgentID,
		Hostname:     c.cfg.Hostname,
		Token:        c.cfg.Token,
		OS:           c.cfg.OS,
		AgentVersion: c.cfg.AgentVersion,
		Metrics:      c.cfg.Metrics,
	}
	client, err := ntls.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &ntlsClientWrapper{client: client}, nil
}

// Client wrappers for versionedClient interface

type v1ClientWrapper struct {
	client *v1.Client
}

func (w *v1ClientWrapper) Connect(ctx context.Context) error { return w.client.Connect(ctx) }
func (w *v1ClientWrapper) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string, opts ...core.SendOption) (string, error) {
	return w.client.SendBatch(ctx, batch, tag, source, opts...)
}
func (w *v1ClientWrapper) Close() error                     { return w.client.Close() }
func (w *v1ClientWrapper) State() string                    { return w.client.State().String() }
func (w *v1ClientWrapper) SetACKHandler(handler ACKHandler) { w.client.SetACKHandler(handler) }
func (w *v1ClientWrapper) SetRedirectHandler(handler RedirectHandler) {
	w.client.SetRedirectHandler(handler)
}

type ntlsClientWrapper struct {
	client *ntls.Client
}

func (w *ntlsClientWrapper) Connect(ctx context.Context) error { return w.client.Connect(ctx) }
func (w *ntlsClientWrapper) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string, opts ...core.SendOption) (string, error) {
	return w.client.SendBatch(ctx, batch, tag, source, opts...)
}
func (w *ntlsClientWrapper) Close() error                     { return w.client.Close() }
func (w *ntlsClientWrapper) State() string                    { return w.client.State().String() }
func (w *ntlsClientWrapper) SetACKHandler(handler ACKHandler) { w.client.SetACKHandler(handler) }
func (w *ntlsClientWrapper) SetRedirectHandler(handler RedirectHandler) {
	w.client.SetRedirectHandler(handler)
}

// Client Options (functional options pattern)

// WithVersion sets the protocol version. version 是 ProtocolVersion 类型（typed string），
// 调用方须传 Version1/VersionNTLS 常量之一。从 string 构造时用 [ParseVersion] 转换。
func WithVersion(version ProtocolVersion) ClientOption {
	return func(cc *ClientConfig) error {
		cc.Version = version
		return nil
	}
}

// WithServer sets the server address.
func WithServer(server string) ClientOption {
	return func(cc *ClientConfig) error {
		cc.Server = server
		return nil
	}
}

// WithAgent sets the agent identification.
func WithAgent(agentID, hostname, token string) ClientOption {
	return func(cc *ClientConfig) error {
		cc.AgentID = agentID
		cc.Hostname = hostname
		cc.Token = token
		return nil
	}
}

// WithAgentMeta sets optional agent metadata (os, version) sent in HELLO. Empty
// values are ignored (os omitted, version falls back to mbta-go default).
func WithAgentMeta(os, agentVersion string) ClientOption {
	return func(cc *ClientConfig) error {
		cc.OS = os
		cc.AgentVersion = agentVersion
		return nil
	}
}

// WithV1Credentials configures standard TLS credentials for V1.
func WithV1Credentials(creds v1.ClientCredentials) ClientOption {
	return func(cc *ClientConfig) error {
		cc.V1Creds = &creds
		return nil
	}
}

// WithNTLSCredentials configures NTLS credentials for the NTLS client version.
func WithNTLSCredentials(cfg ntls.ClientCredentials) ClientOption {
	return func(cc *ClientConfig) error {
		cc.NTLSCreds = &cfg
		return nil
	}
}

// WithClientMetrics configures the metrics collector for client-side observability
// (BatchesSent/BatchLatency). Optional; nil uses a no-op collector.
// 注：客户端 option 保留 Client 前缀以与服务端 WithMetrics 区分（同包同名冲突）。
func WithClientMetrics(metrics core.Metrics) ClientOption {
	return func(cc *ClientConfig) error {
		cc.Metrics = metrics
		return nil
	}
}
