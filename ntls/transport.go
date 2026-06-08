// Package ntls implements MBTA-NTLS (mbta-ntls/1) over TCP with NTLS/TLCP.
//
// ALPN: "mbta-ntls/1"
// Frame version: 0x01
//
// This package provides the transport layer for MBTA with NTLS/TLCP. All protocol
// semantics (message types, flow control, delivery, etc.) are shared with v1 via
// the core package.
package ntls

import (
	"context"
	"fmt"

	"github.com/iuboy/mbta-go/core"
)

// ALPNProtocol is the ALPN identifier for MBTA-NTLS.
const ALPNProtocol = "mbta-ntls/1"

// FrameVersion is the frame version for MBTA-NTLS (same as v1).
const FrameVersion = 0x01

// Transport implements TCP + NTLS/TLCP transport.
type Transport struct{}

// ServerConfig holds full server configuration for NTLS.
type ServerConfig struct {
	Address  string
	CertFile string // SM2 certificate
	KeyFile  string // SM2 private key
	CAFile   string
	Auth     core.TokenValidator
	Policy   core.Policy
	Sink     core.EventSink
	Metrics  *core.MBTAMetrics
}

// ServerCredentials holds server NTLS credentials.
type ServerCredentials struct {
	CertFile string // SM2 certificate
	KeyFile  string // SM2 private key
	CAFile   string
}

// Server implements NTLS MBTA server.
type Server struct {
	config ServerConfig
}

// NewServer creates an NTLS MBTA server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("address required")
	}
	return &Server{config: cfg}, nil
}

// Start begins listening for TCP connections with NTLS/TLCP.
func (s *Server) Start(ctx context.Context) error {
	return fmt.Errorf("ntls server not yet implemented (requires NTLS/TLCP library)")
}

// Close shuts down the server.
func (s *Server) Close() error { return nil }

// ClientConfig holds full client configuration for NTLS.
type ClientConfig struct {
	Server     string
	CertFile   string // SM2 client certificate
	KeyFile    string // SM2 client private key
	CAFile     string
	ServerName string
	AgentID    string
	Token      string
}

// ClientCredentials holds client NTLS credentials.
type ClientCredentials struct {
	CertFile   string // SM2 client certificate
	KeyFile    string // SM2 client private key
	CAFile     string
	ServerName string
}

// Client implements NTLS MBTA client.
type Client struct {
	config ClientConfig
}

// NewClient creates an NTLS MBTA client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("server address required")
	}
	return &Client{config: cfg}, nil
}

// Connect establishes NTLS connection.
func (c *Client) Connect(ctx context.Context) error {
	return fmt.Errorf("ntls client not yet implemented (requires NTLS/TLCP library)")
}

// SendBatch sends a signal batch.
func (c *Client) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string) (string, error) {
	return "", fmt.Errorf("ntls send not yet implemented")
}

// Close closes the connection.
func (c *Client) Close() error { return nil }

// State returns connection state.
func (c *Client) State() core.State { return core.StateDisconnected }
