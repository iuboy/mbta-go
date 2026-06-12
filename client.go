package mbta

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/iuboy/mbta-go/core"
	ntls "github.com/iuboy/mbta-go/ntls"
	v1 "github.com/iuboy/mbta-go/v1"
	v2 "github.com/iuboy/mbta-go/v2"
)

const stateDisconnected = "disconnected"

// ClientOption configures a Client.
type ClientOption func(*ClientConfig) error

// Client is a single-version MBTA client that connects to an MBTA server.
// Each version (v1, v2, ntls) is a completely separate protocol — no automatic
// fallback between versions. Create separate Client instances for different versions.
type Client struct {
	cfg    ClientConfig
	client versionedClient
	mu     sync.RWMutex
}

// ACKHandler is called when the server acknowledges a batch.
type ACKHandler func(chunkID, ackMode string)

// versionedClient wraps version-specific clients with a common interface.
type versionedClient interface {
	Connect(ctx context.Context) error
	SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string) (string, error)
	Close() error
	State() string
	SetACKHandler(handler ACKHandler)
}

// ClientConfig holds the client configuration.
type ClientConfig struct {
	// Protocol version — one of "v1", "v2", "ntls". Required.
	Version string

	// Connection settings
	Server   string
	AgentID  string
	Hostname string
	Token    string

	// Version-specific configurations
	V1Creds   *v1.ClientCredentials
	V2Creds   *v2.ClientCredentials
	NTLSCreds *ntls.ClientCredentials
}

// NewClient creates a single-version MBTA client.
// The client will connect using exactly the version specified in the config.
func NewClient(opts ...ClientOption) (*Client, error) {
	cfg := &ClientConfig{
		Version: Version1, // Default to v1
	}

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, core.WrapError(core.NumConfig, core.ErrConfig, "client option", err)
		}
	}

	// Validate version
	if cfg.Version == "" {
		return nil, core.NewError(core.NumConfig, core.ErrConfig, "version is required")
	}
	switch cfg.Version {
	case Version1, Version2, VersionNTLS:
		// valid
	default:
		return nil, core.NewError(core.NumVersion, core.ErrVersion, fmt.Sprintf("unsupported version: %s", cfg.Version))
	}

	if cfg.AgentID == "" {
		return nil, core.NewError(core.NumConfig, core.ErrConfig, "AgentID is required")
	}
	if cfg.Server == "" {
		return nil, core.NewError(core.NumConfig, core.ErrConfig, "Server address is required")
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
func Dial(ctx context.Context, server, agentID, token, version string, opts ...ClientOption) (*Client, error) {
	allOpts := append([]ClientOption{
		WithServer(server),
		WithAgent(agentID, "", token),
		WithVersion(version),
	}, opts...)

	client, err := NewClient(allOpts...)
	if err != nil {
		return nil, core.WrapError(core.NumTransport, core.ErrTransport, "dial create", err)
	}

	if err := client.Connect(ctx); err != nil {
		if closeErr := client.Close(); closeErr != nil {
			slog.Debug("cleanup close after failed connect", "error", closeErr)
		}
		return nil, core.WrapError(core.NumTransport, core.ErrTransport, "dial connect", err)
	}

	return client, nil
}

// initClient initializes the version-specific client.
func (c *Client) initClient() (versionedClient, error) {
	switch c.cfg.Version {
	case Version1:
		return c.initV1Client()
	case Version2:
		return c.initV2Client()
	case VersionNTLS:
		return c.initNTLSClient()
	default:
		return nil, core.NewError(core.NumVersion, core.ErrVersion, fmt.Sprintf("unsupported version: %s", c.cfg.Version))
	}
}

// Connect establishes a connection using the configured version.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	slog.Info("connecting", "version", c.cfg.Version, "server", c.cfg.Server)

	if err := c.client.Connect(ctx); err != nil {
		slog.Error("connection failed", "version", c.cfg.Version, "error", err)
		return err
	}

	slog.Info("connected", "version", c.cfg.Version)
	return nil
}

// SendBatch sends a batch using the active connection.
func (c *Client) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string) (string, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return "", core.NewError(core.NumSession, core.ErrSession, "not connected (call Connect first)")
	}

	return client.SendBatch(ctx, batch, tag, source)
}

// Close closes the client and releases all resources.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cfg.Token = ""
	c.cfg.V1Creds = nil
	c.cfg.V2Creds = nil
	c.cfg.NTLSCreds = nil

	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// State returns the current connection state.
func (c *Client) State() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return stateDisconnected
	}
	return c.client.State()
}

// SetACKHandler registers a callback for ACK notifications from the server.
// The handler will be called with (chunkID, ackMode) when the server acknowledges a batch.
func (c *Client) SetACKHandler(handler ACKHandler) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client != nil {
		c.client.SetACKHandler(handler)
	}
}

// ActiveVersion returns the configured protocol version.
func (c *Client) ActiveVersion() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.Version
}

// initV1Client initializes the V1 client wrapper.
func (c *Client) initV1Client() (versionedClient, error) {
	if c.cfg.V1Creds == nil {
		return nil, core.NewError(core.NumCredential, core.ErrCredential, "v1 credentials not provided")
	}

	cfg := v1.ClientConfig{
		Transport: v1.QUICClientConfig{
			Server:      c.cfg.Server,
			Credentials: c.cfg.V1Creds,
		},
		AgentID:  c.cfg.AgentID,
		Hostname: c.cfg.Hostname,
		Token:    c.cfg.Token,
	}

	client, err := v1.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	return &v1ClientWrapper{client: client}, nil
}

// initV2Client initializes the V2 client wrapper.
func (c *Client) initV2Client() (versionedClient, error) {
	slog.Warn("v2 protocol is not yet implemented — all operations will return errors")

	if c.cfg.V2Creds == nil {
		return nil, core.NewError(core.NumCredential, core.ErrCredential, "v2 GM credentials not provided")
	}

	cfg := v2.ClientConfig{
		Transport: v2.QUICClientConfig{
			Server:      c.cfg.Server,
			Credentials: c.cfg.V2Creds,
		},
		AgentID:  c.cfg.AgentID,
		Hostname: c.cfg.Hostname,
		Token:    c.cfg.Token,
	}

	client, err := v2.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	return &v2ClientWrapper{client: client}, nil
}

// initNTLSClient initializes the NTLS client wrapper.
func (c *Client) initNTLSClient() (versionedClient, error) {
	slog.Warn("ntls protocol is not yet implemented — all operations will return errors")

	if c.cfg.NTLSCreds == nil {
		return nil, core.NewError(core.NumCredential, core.ErrCredential, "ntls credentials not provided")
	}

	cfg := ntls.ClientConfig{
		Server:     c.cfg.Server,
		CertFile:   c.cfg.NTLSCreds.CertFile,
		KeyFile:    c.cfg.NTLSCreds.KeyFile,
		CAFile:     c.cfg.NTLSCreds.CAFile,
		ServerName: c.cfg.NTLSCreds.ServerName,
		AgentID:    c.cfg.AgentID,
		Token:      c.cfg.Token,
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

func (w *v1ClientWrapper) Connect(ctx context.Context) error      { return w.client.Connect(ctx) }
func (w *v1ClientWrapper) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string) (string, error) {
	return w.client.SendBatch(ctx, batch, tag, source)
}
func (w *v1ClientWrapper) Close() error                           { return w.client.Close() }
func (w *v1ClientWrapper) State() string                          { return w.client.State().String() }
func (w *v1ClientWrapper) SetACKHandler(handler ACKHandler)       { w.client.SetACKHandler(handler) }

type v2ClientWrapper struct {
	client *v2.Client
}

func (w *v2ClientWrapper) Connect(ctx context.Context) error { return w.client.Connect(ctx) }
func (w *v2ClientWrapper) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string) (string, error) {
	return w.client.SendBatch(ctx, batch, tag, source)
}
func (w *v2ClientWrapper) Close() error    { return w.client.Close() }
func (w *v2ClientWrapper) State() string   { return w.client.State().String() }
func (w *v2ClientWrapper) SetACKHandler(ACKHandler) {
	slog.Warn("SetACKHandler ignored: v2 ACK handling not yet implemented")
}

type ntlsClientWrapper struct {
	client *ntls.Client
}

func (w *ntlsClientWrapper) Connect(ctx context.Context) error { return w.client.Connect(ctx) }
func (w *ntlsClientWrapper) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string) (string, error) {
	return w.client.SendBatch(ctx, batch, tag, source)
}
func (w *ntlsClientWrapper) Close() error    { return w.client.Close() }
func (w *ntlsClientWrapper) State() string   { return w.client.State().String() }
func (w *ntlsClientWrapper) SetACKHandler(ACKHandler) {
	slog.Warn("SetACKHandler ignored: ntls ACK handling not yet implemented")
}

// Client Options (functional options pattern)

// WithVersion sets the protocol version. Must be one of "v1", "v2", "ntls".
func WithVersion(version string) ClientOption {
	return func(cc *ClientConfig) error {
		switch version {
		case Version1, Version2, VersionNTLS:
			cc.Version = version
			return nil
		default:
			return core.NewError(core.NumVersion, core.ErrVersion, fmt.Sprintf("invalid version: %s", version))
		}
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

// WithV1Credentials configures standard TLS credentials for V1.
func WithV1Credentials(creds v1.ClientCredentials) ClientOption {
	return func(cc *ClientConfig) error {
		cc.V1Creds = &creds
		return nil
	}
}

// WithV2Credentials configures GM TLS credentials for V2.
func WithV2Credentials(gmCreds v2.ClientCredentials) ClientOption {
	return func(cc *ClientConfig) error {
		cc.V2Creds = &gmCreds
		return nil
	}
}

// WithClientNTLS configures NTLS credentials for the NTLS client version.
func WithClientNTLS(cfg ntls.ClientCredentials) ClientOption {
	return func(cc *ClientConfig) error {
		cc.NTLSCreds = &cfg
		return nil
	}
}
