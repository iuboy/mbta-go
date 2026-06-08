package v1

import (
	"context"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// TestNewServer tests creating a new Server.
func TestNewServer(t *testing.T) {
	cfg := ServerConfig{
		ServerID: "test-server",
	}

	server := NewServer(cfg)
	if server == nil {
		t.Fatal("NewServer should not return nil")
	}

	if server.config.ServerID != "test-server" {
		t.Errorf("ServerID = %s, want 'test-server'", server.config.ServerID)
	}
}

// TestNewServerWithEmptyID tests that empty ServerID generates a new UUID.
func TestNewServerWithEmptyID(t *testing.T) {
	cfg := ServerConfig{
		ServerID: "",
	}

	server := NewServer(cfg)
	if server == nil {
		t.Fatal("NewServer should not return nil")
	}

	if server.config.ServerID == "" {
		t.Error("ServerID should be auto-generated when empty")
	}

	// Verify it's a valid UUID (basic check)
	id := server.config.ServerID
	if len(id) < 36 {
		t.Errorf("ServerID looks invalid: %s", id)
	}
}

// TestNewServerGeneratesUniqueIDs tests that each server gets a unique ID.
func TestNewServerGeneratesUniqueIDs(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 10; i++ {
		server := NewServer(ServerConfig{})
		id := server.config.ServerID
		if ids[id] {
			t.Errorf("Duplicate ServerID generated: %s", id)
		}
		ids[id] = true
	}
}

// TestServerConfigStructure tests ServerConfig fields.
func TestServerConfigStructure(t *testing.T) {
	cfg := ServerConfig{
		Transport: QUICServerConfig{
			Address:     "0.0.0.0:8080",
			IdleTimeout: 30 * time.Second,
		},
		ServerID: "test-server",
	}

	if cfg.Transport.Address == "" {
		t.Error("Transport.Address should not be empty")
	}
	if cfg.ServerID == "" {
		t.Error("ServerID should not be empty")
	}
}

// TestServerCloseWithoutStart tests Close before Start.
func TestServerCloseWithoutStart(t *testing.T) {
	server := NewServer(ServerConfig{})

	err := server.Close()
	if err != nil {
		t.Errorf("Close before Start should not error, got %v", err)
	}
}

// TestServerCloseAfterStart tests Close after Start (with invalid config).
func TestServerCloseAfterStart(t *testing.T) {
	cfg := ServerConfig{
		Transport: QUICServerConfig{
			Address: "invalid-address", // Will cause Start to fail
		},
	}
	server := NewServer(cfg)

	ctx := context.Background()
	err := server.Start(ctx)
	// Start will fail due to invalid address, but listener should be nil
	if err != nil {
		t.Logf("Start failed as expected: %v", err)
	}

	closeErr := server.Close()
	if closeErr != nil {
		t.Errorf("Close should not error, got %v", closeErr)
	}
}

// TestServerAcceptBeforeStart tests Accept before Start.
func TestServerAcceptBeforeStart(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Recovered from panic (expected): %v", r)
		}
	}()

	server := NewServer(ServerConfig{})

	ctx := context.Background()
	_, err := server.Accept(ctx)
	// Will panic because listener is nil
	if err == nil {
		t.Error("Accept before Start should error or panic")
	}
}

// TestServerConfigWithAllFields tests complete ServerConfig.
func TestServerConfigWithAllFields(t *testing.T) {
	auth := &mockTokenValidator{}
	sink := &mockEventSink{}
	metrics := core.New(nil)
	policy := core.Policy{}

	cfg := ServerConfig{
		Transport: QUICServerConfig{
			Address:            "0.0.0.0:8080",
			MaxIncomingStreams: 100,
			IdleTimeout:        30 * time.Second,
			Credentials: &ServerCredentials{
				CertFile:   "cert.pem",
				KeyFile:    "key.pem",
				CAFile:     "ca.pem",
				ClientAuth: "require-and-verify",
			},
		},
		Auth:     auth,
		Policy:   policy,
		SpoolDir: "/tmp/spool",
		ServerID: "test-server",
		Metrics:  metrics,
		Sink:     sink,
	}

	server := NewServer(cfg)
	if server == nil {
		t.Fatal("NewServer should not return nil")
	}

	if server.config.Transport.Address != "0.0.0.0:8080" {
		t.Errorf("Transport.Address = %s, want '0.0.0.0:8080'", server.config.Transport.Address)
	}
	if server.config.SpoolDir != "/tmp/spool" {
		t.Errorf("SpoolDir = %s, want '/tmp/spool'", server.config.SpoolDir)
	}
	if server.config.Auth == nil {
		t.Error("Auth should not be nil")
	}
	if server.config.Sink == nil {
		t.Error("Sink should not be nil")
	}
	if server.config.Metrics == nil {
		t.Error("Metrics should not be nil")
	}
}

// TestServerIDPersistence tests that ServerID persists after operations.
func TestServerIDPersistence(t *testing.T) {
	expectedID := "persistent-server-id"
	server := NewServer(ServerConfig{ServerID: expectedID})

	// ServerID should persist
	if server.config.ServerID != expectedID {
		t.Errorf("ServerID changed to %s, want %s", server.config.ServerID, expectedID)
	}
}

// TestServerStructure tests Server structure and methods.
func TestServerStructure(t *testing.T) {
	server := &Server{}

	// Test initial state
	if server.listener != nil {
		t.Error("listener should be nil initially")
	}

	// Test that methods exist (compile-time check)
	_ = func(ctx context.Context) error {
		return server.Start(ctx)
	}
	_ = func(ctx context.Context) (*ConnectionHandler, error) {
		return server.Accept(ctx)
	}
	_ = func() error {
		return server.Close()
	}
}

// mockTokenValidator is a mock implementation of core.TokenValidator.
type mockTokenValidator struct{}

func (m *mockTokenValidator) Validate(token string) (*core.AgentIdentity, error) {
	return &core.AgentIdentity{AgentID: "test-agent"}, nil
}

// TestServerWithMockValidator tests server with mock validator.
func TestServerWithMockValidator(t *testing.T) {
	auth := &mockTokenValidator{}
	cfg := ServerConfig{
		Auth:     auth,
		ServerID: "test-server",
	}

	server := NewServer(cfg)
	if server == nil {
		t.Fatal("NewServer should not return nil")
	}

	if server.config.Auth == nil {
		t.Error("Auth should not be nil")
	}
}
