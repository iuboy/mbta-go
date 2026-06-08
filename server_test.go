package mbta

import (
	"context"
	"testing"

	"github.com/iuboy/mbta-go/core"
	v1 "github.com/iuboy/mbta-go/v1"
	v2 "github.com/iuboy/mbta-go/v2"
)

// TestNewServer tests creating a new server with default options.
func TestNewServer(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if server == nil {
		t.Fatal("NewServer() should not return nil")
	}

	if !server.cfg.EnableV1 {
		t.Error("V1 should be enabled by default")
	}
}

// TestNewServerNoVersions tests error handling when no versions enabled.
func TestNewServerNoVersions(t *testing.T) {
	// Create server with all versions disabled via custom option
	disableAllOption := func(cfg *ServerConfig) error {
		cfg.EnableV1 = false
		cfg.EnableV2 = false
		cfg.EnableNTLS = false
		return nil
	}

	_, err := NewServer(disableAllOption)
	// Should fail because no versions are enabled
	if err == nil {
		t.Error("NewServer with no versions enabled should return error")
	}
}

// TestNewServerWithV1 tests creating server with V1 enabled.
func TestNewServerWithV1(t *testing.T) {
	creds := &v1.ServerCredentials{
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	}

	server, err := NewServer(
		WithV1(v1.QUICServerConfig{
			Address:     "0.0.0.0:8080",
			Credentials: creds,
		}),
	)

	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if !server.cfg.EnableV1 {
		t.Error("V1 should be enabled")
	}

	if server.cfg.V1QUIC.Address != "0.0.0.0:8080" {
		t.Errorf("V1 address = %s, want '0.0.0.0:8080'", server.cfg.V1QUIC.Address)
	}
}

// TestServerCloseBeforeStart tests Close before Start.
func TestServerCloseBeforeStart(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	err = server.Close()
	if err != nil {
		t.Errorf("Close before Start should not error, got %v", err)
	}
}

// TestServerStartTwice tests starting server twice.
func TestServerStartTwice(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx := context.Background()

	// First start will fail due to invalid config, but that's OK for this test
	_ = server.Start(ctx)

	// Second start should fail with "already started" error
	err = server.Start(ctx)
	if err == nil {
		t.Error("Second Start should return error")
	}
}

// TestWithV1 tests WithV1 option.
func TestWithV1(t *testing.T) {
	creds := &v1.ServerCredentials{
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	}

	opt := WithV1(v1.QUICServerConfig{
		Address:     "0.0.0.0:8080",
		Credentials: creds,
	})

	cfg := &ServerConfig{}
	err := opt(cfg)
	if err != nil {
		t.Fatalf("WithV1() error = %v", err)
	}

	if !cfg.EnableV1 {
		t.Error("EnableV1 should be true")
	}
	if cfg.V1QUIC.Address != "0.0.0.0:8080" {
		t.Errorf("V1 address = %s, want '0.0.0.0:8080'", cfg.V1QUIC.Address)
	}
}

// TestWithAuth tests WithAuth option.
func TestWithAuth(t *testing.T) {
	auth := &mockTokenValidator{}

	opt := WithAuth(auth)

	cfg := &ServerConfig{}
	err := opt(cfg)
	if err != nil {
		t.Fatalf("WithAuth() error = %v", err)
	}

	if cfg.Auth == nil {
		t.Error("Auth should not be nil")
	}
}

// TestWithPolicy tests WithPolicy option.
func TestWithPolicy(t *testing.T) {
	policy := core.Policy{}

	opt := WithPolicy(policy)

	cfg := &ServerConfig{}
	err := opt(cfg)
	if err != nil {
		t.Fatalf("WithPolicy() error = %v", err)
	}
}

// TestWithEventSink tests WithEventSink option.
func TestWithEventSink(t *testing.T) {
	sink := &mockEventSink{}

	opt := WithEventSink(sink)

	cfg := &ServerConfig{}
	err := opt(cfg)
	if err != nil {
		t.Fatalf("WithEventSink() error = %v", err)
	}

	if cfg.Sink == nil {
		t.Error("Sink should not be nil")
	}
}

// TestWithMetrics tests WithMetrics option.
func TestWithMetrics(t *testing.T) {
	// Skip creating actual metrics to avoid duplicate registration
	// Test the option function directly
	opt := WithMetrics(nil)

	cfg := &ServerConfig{}
	err := opt(cfg)
	if err != nil {
		t.Fatalf("WithMetrics() error = %v", err)
	}

	if cfg.Metrics != nil {
		t.Error("Metrics should be nil as passed")
	}
}

// TestServerConfigStructure tests ServerConfig structure.
func TestServerConfigStructure(t *testing.T) {
	// Avoid creating metrics to prevent duplicate registration issues
	cfg := ServerConfig{
		EnableV1:   true,
		EnableV2:   false,
		EnableNTLS: false,
		Auth:       &mockTokenValidator{},
		Policy:     core.Policy{},
		Sink:       &mockEventSink{},
		Metrics:    nil, // Set to nil to avoid registration issues
	}

	if !cfg.EnableV1 {
		t.Error("EnableV1 should be true")
	}
	if cfg.Auth == nil {
		t.Error("Auth should not be nil")
	}
	if cfg.Sink == nil {
		t.Error("Sink should not be nil")
	}
}

// TestServerOptionsChain tests chaining multiple options.
func TestServerOptionsChain(t *testing.T) {
	creds := &v1.ServerCredentials{
		CertFile: "cert.pem",
		KeyFile:  "key.pem",
	}

	auth := &mockTokenValidator{}
	sink := &mockEventSink{}
	metrics := core.New(nil)

	server, err := NewServer(
		WithV1(v1.QUICServerConfig{
			Address:     "0.0.0.0:8080",
			Credentials: creds,
		}),
		WithAuth(auth),
		WithEventSink(sink),
		WithMetrics(metrics),
	)

	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if !server.cfg.EnableV1 {
		t.Error("EnableV1 should be true")
	}
	if server.cfg.Auth == nil {
		t.Error("Auth should not be nil")
	}
	if server.cfg.Sink == nil {
		t.Error("Sink should not be nil")
	}
	if server.cfg.Metrics == nil {
		t.Error("Metrics should not be nil")
	}
}

// TestServerConcurrency tests concurrent access to server methods.
func TestServerConcurrency(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	// Test concurrent Close calls (safe but should only process once)
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_ = server.Close()
			done <- true
		}()
	}

	// Wait for all to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// mockTokenValidator is a mock implementation for testing.
type mockTokenValidator struct{}

func (m *mockTokenValidator) Validate(token string) (*core.AgentIdentity, error) {
	return &core.AgentIdentity{AgentID: "test-agent"}, nil
}

// mockEventSink is a mock implementation for testing.
type mockEventSink struct{}

func (m *mockEventSink) OnSignalBatch(ctx context.Context, agentID string, batch *core.SignalBatch) error {
	return nil
}

func (m *mockEventSink) OnPressure(agentID string) core.PressureState {
	return core.PressureNormal
}

func (m *mockEventSink) OnSignalBatchWithResult(ctx context.Context, agentID string, batch *core.SignalBatch) (*core.RouteResult, error) {
	return &core.RouteResult{Status: core.ACKStatusDurable}, nil
}

// TestServerOptionsReturnType tests that options return correct type.
func TestServerOptionsReturnType(t *testing.T) {
	var _ ServerOption = WithV1(v1.QUICServerConfig{})
	var _ ServerOption = WithV2(v2.QUICServerConfig{})
	var _ ServerOption = WithAuth(nil)
	var _ ServerOption = WithPolicy(core.Policy{})
	var _ ServerOption = WithEventSink(nil)
	var _ ServerOption = WithMetrics(nil)
}

// TestNewServerWithInvalidOption tests error handling for invalid options.
func TestNewServerWithInvalidOption(t *testing.T) {
	// Create an option that returns an error
	badOption := func(*ServerConfig) error {
		return &testError{}
	}

	_, err := NewServer(badOption)
	if err == nil {
		t.Error("Expected error from bad option, got nil")
	}
}
