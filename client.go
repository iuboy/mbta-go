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

// ClientOption configures a Client.
type ClientOption func(*ClientConfig) error

// Client supports automatic version negotiation and fallback.
// Implements the strategy pattern for version selection.
type Client struct {
	cfg     ClientConfig
	clients map[string]versionedClient // version -> client wrapper
	mu      sync.RWMutex
	current string // actively connected version
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
	// Version priority (attempted in order)
	Versions []string // e.g., ["v2", "v1", "ntls"]

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

// NewClient creates a multi-version MBTA client.
// The client will attempt to connect using versions in the priority order
// specified in the config, falling back to the next version on failure.
func NewClient(opts ...ClientOption) (*Client, error) {
	cfg := &ClientConfig{
		// Default: try v2 first (if available), then v1
		Versions: []string{Version1}, // Default to v1 only
	}

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("client option error: %w", err)
		}
	}

	// Validate at least one version is specified
	if len(cfg.Versions) == 0 {
		return nil, fmt.Errorf("at least one version must be specified")
	}

	c := &Client{
		cfg:     *cfg,
		clients: make(map[string]versionedClient),
	}

	// Initialize version-specific clients
	if err := c.initClients(); err != nil {
		return nil, err
	}

	return c, nil
}

// Dial creates a Client, connects it, and returns the ready-to-use client.
// This is a convenience function that combines NewClient + Connect in one call.
//
// For simple use cases:
//
//	client, err := mbta.Dial(ctx, "localhost:7400", "my-agent", "secret-token",
//	    mbta.WithV1Credentials(v1.ClientCredentials{}),
//	)
//	if err != nil { ... }
//	defer client.Close()
//
//	// client is already connected, ready to SendBatch
func Dial(ctx context.Context, server, agentID, token string, opts ...ClientOption) (*Client, error) {
	allOpts := append([]ClientOption{
		WithServer(server),
		WithAgent(agentID, "", token),
	}, opts...)

	client, err := NewClient(allOpts...)
	if err != nil {
		return nil, fmt.Errorf("mbta dial: create client: %w", err)
	}

	if err := client.Connect(ctx); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("mbta dial: connect: %w", err)
	}

	return client, nil
}

// initClients initializes clients for each configured version.
func (c *Client) initClients() error {
	for _, version := range c.cfg.Versions {
		var client versionedClient
		var err error

		switch version {
		case Version1:
			if c.cfg.V1Creds == nil {
				continue
			}
			client, err = c.initV1Client()
		case Version2:
			if c.cfg.V2Creds == nil {
				continue
			}
			client, err = c.initV2Client()
		case VersionNTLS:
			if c.cfg.NTLSCreds == nil {
				continue
			}
			client, err = c.initNTLSClient()
		default:
			slog.Warn("unknown MBTA version", "version", version)
			continue
		}

		if err != nil {
			slog.Error("failed to init client", "version", version, "error", err)
			continue
		}

		c.clients[version] = client
		slog.Info("initialized client", "version", version)
	}

	// Ensure at least one client was initialized
	if len(c.clients) == 0 {
		return fmt.Errorf("no clients initialized (check version-specific configs)")
	}

	return nil
}

// Connect attempts to connect using versions in priority order.
// The first version to successfully connect becomes the active version.
// Implements the fallback strategy pattern.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var lastErr error

	// Try versions in priority order
	for _, version := range c.cfg.Versions {
		client, ok := c.clients[version]
		if !ok {
			slog.Warn("client not initialized, skipping", "version", version)
			continue
		}

		slog.Info("attempting connection", "version", version, "server", c.cfg.Server)

		if err := client.Connect(ctx); err != nil {
			slog.Error("connection failed", "version", version, "error", err)
			lastErr = err
			continue
		}

		// Connection successful
		c.current = version
		slog.Info("connected", "version", version)
		return nil
	}

	// All versions failed
	return fmt.Errorf("all versions failed to connect (last error: %w)", lastErr)
}

// SendBatch sends a batch using the active connection.
func (c *Client) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string) (string, error) {
	c.mu.RLock()
	client, ok := c.clients[c.current]
	c.mu.RUnlock()

	if !ok || c.current == "" {
		return "", fmt.Errorf("not connected (call Connect first)")
	}

	return client.SendBatch(ctx, batch, tag, source)
}

// Close closes all clients.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error

	for version, client := range c.clients {
		if err := client.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", version, err))
		}
	}

	c.current = ""

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}

// State returns the current connection state.
func (c *Client) State() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.current == "" {
		return "disconnected"
	}

	if client, ok := c.clients[c.current]; ok {
		return client.State()
	}

	return "disconnected"
}

// SetACKHandler registers a callback for ACK notifications from the server.
// The handler will be called with (chunkID, ackMode) when the server acknowledges a batch.
func (c *Client) SetACKHandler(handler ACKHandler) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for version, client := range c.clients {
		if version == Version1 {
			// Only v1 supports ACK handlers
			client.SetACKHandler(handler)
			slog.Info("ACK handler registered", "version", version)
		}
	}
}

// ActiveVersion returns the currently active version.
func (c *Client) ActiveVersion() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current
}

// initV1Client initializes the V1 client wrapper.
func (c *Client) initV1Client() (versionedClient, error) {
	if c.cfg.V1Creds == nil {
		return nil, fmt.Errorf("v1 credentials not provided")
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
	if c.cfg.V2Creds == nil {
		return nil, fmt.Errorf("v2 GM credentials not provided")
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
	if c.cfg.NTLSCreds == nil {
		return nil, fmt.Errorf("ntls credentials not provided")
	}

	// Convert ClientCredentials to ClientConfig
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

func (w *v1ClientWrapper) Connect(ctx context.Context) error {
	return w.client.Connect(ctx)
}

func (w *v1ClientWrapper) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string) (string, error) {
	return w.client.SendBatch(ctx, batch, tag, source)
}

func (w *v1ClientWrapper) Close() error {
	return w.client.Close()
}

func (w *v1ClientWrapper) State() string {
	return w.client.State().String()
}

func (w *v1ClientWrapper) SetACKHandler(handler ACKHandler) {
	w.client.SetACKHandler(handler)
}

type v2ClientWrapper struct {
	client *v2.Client
}

func (w *v2ClientWrapper) Connect(ctx context.Context) error {
	return w.client.Connect(ctx)
}

func (w *v2ClientWrapper) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string) (string, error) {
	return w.client.SendBatch(ctx, batch, tag, source)
}

func (w *v2ClientWrapper) Close() error {
	return w.client.Close()
}

func (w *v2ClientWrapper) State() string {
	return w.client.State().String()
}

func (w *v2ClientWrapper) SetACKHandler(handler ACKHandler) {
	// V2 doesn't support ACK handlers yet
	// This is a no-op to satisfy the interface
}

type ntlsClientWrapper struct {
	client *ntls.Client
}

func (w *ntlsClientWrapper) Connect(ctx context.Context) error {
	return w.client.Connect(ctx)
}

func (w *ntlsClientWrapper) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string) (string, error) {
	return w.client.SendBatch(ctx, batch, tag, source)
}

func (w *ntlsClientWrapper) Close() error {
	return w.client.Close()
}

func (w *ntlsClientWrapper) State() string {
	return w.client.State().String()
}

func (w *ntlsClientWrapper) SetACKHandler(handler ACKHandler) {
	// NTLS doesn't support ACK handlers yet
	// This is a no-op to satisfy the interface
}

// Client Options (functional options pattern)

// WithVersionPriority sets the version priority list.
func WithVersionPriority(versions []string) ClientOption {
	return func(cc *ClientConfig) error {
		// Validate versions
		for _, v := range versions {
			switch v {
			case Version1, Version2, VersionNTLS:
				// Valid
			default:
				return fmt.Errorf("invalid version: %s", v)
			}
		}
		cc.Versions = versions
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
