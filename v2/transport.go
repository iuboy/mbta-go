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
	config ServerConfig
}

// NewServer creates a V2 MBTA server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Transport.Address == "" {
		return nil, core.NewError(core.NumConfig, core.CodeConfig, "address required")
	}
	return &Server{config: cfg}, nil
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
	config ClientConfig
}

// NewClient creates a V2 MBTA client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Transport.Server == "" {
		return nil, core.NewError(core.NumCredential, core.CodeCredential, "server address required")
	}
	return &Client{config: cfg}, nil
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
