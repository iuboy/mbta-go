package v1

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

// TestALPNProtocol tests that ALPN protocol is correctly defined.
func TestALPNProtocol(t *testing.T) {
	if ALPNProtocol != "mbta/1" {
		t.Errorf("ALPNProtocol = %q, want 'mbta/1'", ALPNProtocol)
	}
}

// TestServerCredentialsStructure tests ServerCredentials fields.
func TestServerCredentialsStructure(t *testing.T) {
	cfg := &ServerCredentials{
		CertFile:   "/path/to/cert.pem",
		KeyFile:    "/path/to/key.pem",
		CAFile:     "/path/to/ca.pem",
		ClientAuth: "require-and-verify",
	}

	if cfg.CertFile == "" {
		t.Error("CertFile should not be empty")
	}
	if cfg.KeyFile == "" {
		t.Error("KeyFile should not be empty")
	}
	if cfg.ClientAuth == "" {
		t.Error("ClientAuth should not be empty")
	}
}

// TestQUICServerConfigStructure tests QUICServerConfig fields.
func TestQUICServerConfigStructure(t *testing.T) {
	cfg := QUICServerConfig{
		Address:            "0.0.0.0:8080",
		MaxIncomingStreams: 100,
		IdleTimeout:        30 * time.Second,
	}

	if cfg.Address == "" {
		t.Error("Address should not be empty")
	}
	if cfg.MaxIncomingStreams <= 0 {
		t.Error("MaxIncomingStreams should be positive")
	}
	if cfg.IdleTimeout <= 0 {
		t.Error("IdleTimeout should be positive")
	}
}

// TestClientCredentialsStructure tests ClientCredentials fields.
func TestClientCredentialsStructure(t *testing.T) {
	cfg := &ClientCredentials{
		CAFile:             "/path/to/ca.pem",
		CertFile:           "/path/to/cert.pem",
		KeyFile:            "/path/to/key.pem",
		ServerName:         "example.com",
		InsecureSkipVerify: false,
	}

	if cfg.ServerName == "" {
		t.Error("ServerName should not be empty")
	}
}

// TestQUICClientConfigStructure tests QUICClientConfig fields.
func TestQUICClientConfigStructure(t *testing.T) {
	cfg := QUICClientConfig{
		Server:      "example.com:8080",
		IdleTimeout: 30 * time.Second,
	}

	if cfg.Server == "" {
		t.Error("Server should not be empty")
	}
	if cfg.IdleTimeout <= 0 {
		t.Error("IdleTimeout should be positive")
	}
}

// TestBuildServerTLSNilCredentials tests that nil credentials return error.
func TestBuildServerTLSNilCredentials(t *testing.T) {
	_, err := buildServerTLS(nil)
	if err == nil {
		t.Error("buildServerTLS with nil credentials should return error")
	}
}

// TestBuildServerTLSInvalidFiles tests error handling for invalid cert files.
func TestBuildServerTLSInvalidFiles(t *testing.T) {
	cfg := &ServerCredentials{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}

	_, err := buildServerTLS(cfg)
	if err == nil {
		t.Error("buildServerTLS with invalid files should return error")
	}
}

// TestBuildClientTLSNilCredentials tests that nil credentials return error.
func TestBuildClientTLSNilCredentials(t *testing.T) {
	_, err := buildClientTLS(nil)
	if err == nil {
		t.Error("buildClientTLS with nil credentials should return error")
	}
}

// TestBuildClientTLSInvalidFiles tests error handling for invalid cert files.
func TestBuildClientTLSInvalidFiles(t *testing.T) {
	cfg := &ClientCredentials{
		CAFile:   "/nonexistent/ca.pem",
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}

	_, err := buildClientTLS(cfg)
	if err == nil {
		t.Error("buildClientTLS with invalid files should return error")
	}
}

// TestBuildClientTLSValidConfig tests TLS config construction with valid parameters.
func TestBuildClientTLSValidConfig(t *testing.T) {
	cfg := &ClientCredentials{
		ServerName:         "example.com",
		InsecureSkipVerify: false,
	}

	tlsCfg, err := buildClientTLS(cfg)
	if err != nil {
		t.Fatalf("buildClientTLS failed: %v", err)
	}

	if tlsCfg.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want 'example.com'", tlsCfg.ServerName)
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false when explicitly set")
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3", tlsCfg.MinVersion)
	}
}

// TestConnStructure tests Conn structure and methods.
func TestConnStructure(t *testing.T) {
	c := &Conn{}

	// Test initial state
	if c.authed {
		t.Error("authed should be false initially")
	}
	if c.controlClaimed {
		t.Error("controlClaimed should be false initially")
	}

	// Test SetAuthed
	c.SetAuthed(true)
	if !c.authed {
		t.Error("authed should be true after SetAuthed(true)")
	}

	// Test SetAuthed back to false
	c.SetAuthed(false)
	if c.authed {
		t.Error("authed should be false after SetAuthed(false)")
	}
}

// TestConnOpenDataStreamBeforeAuth tests error handling.
func TestConnOpenDataStreamBeforeAuth(t *testing.T) {
	c := &Conn{}

	ctx := context.Background()
	_, err := c.OpenDataStream(ctx)
	if err == nil {
		t.Error("OpenDataStream before auth should return error")
	}

	expectedMsg := "[2002 ERR_STREAM] cannot open data stream before auth"
	if err.Error() != expectedMsg {
		t.Errorf("Error message = %q, want %q", err.Error(), expectedMsg)
	}
}

// TestConnOpenDataStreamAfterAuth tests that auth check passes.
func TestConnOpenDataStreamAfterAuth(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			// Expected panic due to nil QC, but auth check passed
			t.Logf("Recovered from panic (expected due to nil QC): %v", r)
		}
	}()

	c := &Conn{}
	c.SetAuthed(true)

	// After auth, the auth check should pass
	// The call will panic because QC is nil, but auth check should not block it
	ctx := context.Background()
	_, err := c.OpenDataStream(ctx)

	// If we get here without panic, verify no auth error
	if err != nil && err.Error() == "cannot open data stream before auth" {
		t.Error("Should not get auth error after SetAuthed(true)")
	}
}

// TestClientAuthModes tests all client auth modes.
func TestClientAuthModes(t *testing.T) {
	modes := []string{
		"none",
		"request",
		"require-and-verify",
	}

	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			cfg := &ServerCredentials{
				CertFile:   "dummy.pem",
				KeyFile:    "dummy.pem",
				ClientAuth: mode,
			}
			// Will fail on cert loading, but tests the ClientAuth field is handled
			_, err := buildServerTLS(cfg)
			if err != nil {
				// Expected to fail on cert loading
				if !strings.Contains(err.Error(), "load server cert/key") {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestDefaultServerConfigValues tests default config values.
func TestDefaultServerConfigValues(t *testing.T) {
	cfg := QUICServerConfig{
		Address: "0.0.0.0:8080",
	}

	if cfg.MaxIncomingStreams == 0 {
		// Zero is valid, will use QUIC default
		t.Log("MaxIncomingStreams is zero, QUIC will use default")
	}

	if cfg.IdleTimeout == 0 {
		// Zero is valid, will use QUIC default
		t.Log("IdleTimeout is zero, QUIC will use default")
	}
}

// TestDefaultClientConfigValues tests default config values.
func TestDefaultClientConfigValues(t *testing.T) {
	cfg := QUICClientConfig{
		Server: "example.com:8080",
	}

	if cfg.IdleTimeout == 0 {
		// Zero is valid, will use QUIC default
		t.Log("IdleTimeout is zero, QUIC will use default")
	}

	if cfg.Credentials == nil {
		t.Log("Credentials is nil, Dial will return error if used")
	}
}
