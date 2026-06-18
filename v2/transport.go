// Package v2 implements MBTA v2 (mbta/2) over QUIC with RFC 8998 GM TLS 1.3.
//
// ALPN: "mbta/2"
// Frame version: 0x02
//
// This package provides the transport layer for MBTA v2. All protocol semantics
// (message types, flow control, delivery, etc.) are shared with v1 via the core package.
package v2

import (
	"context"

	"github.com/iuboy/mbta-go/core"
)

// ALPNProtocol is the Application-Layer Protocol Negotiation identifier for MBTA v2 over QUIC.
const ALPNProtocol = "mbta/2"

// FrameVersion is the frame version for MBTA v2.
const FrameVersion = 0x02

// Transport implements QUIC + RFC 8998 GM TLS 1.3 transport.
type Transport struct{}

// QUICServerConfig holds server QUIC configuration for v2.
type QUICServerConfig struct {
	Address            string
	CertFile           string // SM2 certificate
	KeyFile            string // SM2 private key
	CAFile             string
	MaxIncomingStreams int64
	IdleTimeout        int64
}

// QUICClientConfig holds client QUIC configuration for v2.
type QUICClientConfig struct {
	Server      string
	Credentials *ClientCredentials
}

// ClientCredentials holds GM TLS client credentials for v2.
type ClientCredentials struct {
	CertFile   string // SM2 client certificate
	KeyFile    string // SM2 client private key
	CAFile     string
	ServerName string
}

// ServerConfig holds full server configuration.
type ServerConfig struct {
	Transport QUICServerConfig
	Auth      core.TokenValidator
	Policy    core.Policy
	Sink      core.EventSink
	Metrics   *core.MBTAMetrics
}

// Server implements V2 MBTA server.
type Server struct {
	config ServerConfig //nolint:unused // v2 落地后使用
}

// NewServer creates a V2 MBTA server.
//
// EXPERIMENTAL: v2（QUIC + RFC 8998 GM TLS）尚未实现。当前直接返回错误，
// 而非返回一个在 Start 时才失败的实例——避免「构造成功、运行失败」的误导。
// v2 落地需要集成 GM TLS（SM2/SM3/SM4 over QUIC）库，届时此函数将返回真实 Server。
func NewServer(cfg ServerConfig) (*Server, error) {
	_ = cfg // 配置字段保留以稳定 API，但当前无法消费
	return nil, core.NewError(core.NumConfig, core.CodeConfig,
		"v2 server not yet implemented (requires GM TLS library)")
}

// Start begins listening for QUIC connections with GM TLS.
func (s *Server) Start(ctx context.Context) error {
	return core.NewError(core.NumConfig, core.CodeConfig, "v2 server not yet implemented (requires GM TLS library)")
}

// Close shuts down the server.
func (s *Server) Close() error { return nil }

// ClientConfig holds full client configuration.
type ClientConfig struct {
	Transport QUICClientConfig
	AgentID   string
	Hostname  string
	Token     string
}

// Client implements V2 MBTA client.
type Client struct {
	config ClientConfig //nolint:unused // v2 落地后使用
}

// NewClient creates a V2 MBTA client.
//
// EXPERIMENTAL: 同 NewServer，v2 客户端尚未实现，构造即返回错误。
func NewClient(cfg ClientConfig) (*Client, error) {
	_ = cfg
	return nil, core.NewError(core.NumConfig, core.CodeConfig,
		"v2 client not yet implemented (requires GM TLS library)")
}

// Connect establishes V2 connection with GM TLS.
func (c *Client) Connect(ctx context.Context) error {
	return core.NewError(core.NumConfig, core.CodeConfig, "v2 client not yet implemented (requires GM TLS library)")
}

// SendBatch sends a signal batch.
func (c *Client) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string) (string, error) {
	return "", core.NewError(core.NumConfig, core.CodeConfig, "v2 send not yet implemented")
}

// Close closes the connection.
func (c *Client) Close() error { return nil }

// State returns connection state.
func (c *Client) State() core.State { return core.StateDisconnected }
