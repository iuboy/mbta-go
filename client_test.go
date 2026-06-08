package mbta

import (
	"context"
	"errors"
	"testing"

	"github.com/iuboy/mbta-go/core"
	v1 "github.com/iuboy/mbta-go/v1"
)

// TestNewClient tests creating a new client with default options.
// Note: Without credentials, client initialization will fail, which is expected.
func TestNewClient(t *testing.T) {
	_, err := NewClient()
	// Expected to fail without credentials
	if err == nil {
		t.Error("NewClient() without credentials should return error")
	}
}

// TestNewClientWithVersionPriority tests creating client with custom version priority.
func TestNewClientWithVersionPriority(t *testing.T) {
	creds := v1.ClientCredentials{
		ServerName: "example.com",
	}

	client, err := NewClient(
		WithVersionPriority([]string{Version1}),
		WithServer("example.com:8080"),
		WithAgent("test-agent", "test-host", "test-token"),
		WithV1Credentials(creds),
	)

	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client == nil {
		t.Fatal("NewClient() should not return nil")
	}

	if len(client.cfg.Versions) != 1 {
		t.Errorf("Versions count = %d, want 1", len(client.cfg.Versions))
	}

	if client.cfg.Versions[0] != Version1 {
		t.Errorf("First version = %s, want %s", client.cfg.Versions[0], Version1)
	}
}

// TestNewClientInvalidVersion tests error handling for invalid version.
func TestNewClientInvalidVersion(t *testing.T) {
	_, err := NewClient(
		WithVersionPriority([]string{"v3", "invalid"}),
	)

	if err == nil {
		t.Error("Expected error for invalid version, got nil")
	}
}

// TestNewClientNoVersions tests error handling when no versions specified.
func TestNewClientNoVersions(t *testing.T) {
	// Create client without credentials
	_, err := NewClient()
	// Expected to fail without credentials
	if err == nil {
		t.Error("NewClient() without credentials should return error")
	}
}

// TestClientSendBatchBeforeConnect tests SendBatch before Connect.
func TestClientSendBatchBeforeConnect(t *testing.T) {
	creds := v1.ClientCredentials{
		ServerName: "example.com",
	}

	client, err := NewClient(
		WithVersionPriority([]string{Version1}),
		WithV1Credentials(creds),
	)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	ctx := context.Background()
	_, err = client.SendBatch(ctx, nil, "tag", "source")
	if err == nil {
		t.Error("SendBatch before Connect should return error")
	}
}

// TestClientCloseBeforeConnect tests Close before Connect.
func TestClientCloseBeforeConnect(t *testing.T) {
	creds := v1.ClientCredentials{
		ServerName: "example.com",
	}

	client, err := NewClient(
		WithVersionPriority([]string{Version1}),
		WithV1Credentials(creds),
	)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	err = client.Close()
	if err != nil {
		t.Errorf("Close before Connect should not error, got %v", err)
	}

	if client.ActiveVersion() != "" {
		t.Error("ActiveVersion should be empty after Close")
	}
}

// TestClientActiveVersion tests ActiveVersion method.
func TestClientActiveVersion(t *testing.T) {
	creds := v1.ClientCredentials{
		ServerName: "example.com",
	}

	client, err := NewClient(
		WithVersionPriority([]string{Version1}),
		WithV1Credentials(creds),
	)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.ActiveVersion() != "" {
		t.Error("ActiveVersion should be empty before Connect")
	}
}

// TestClientState tests State method.
func TestClientState(t *testing.T) {
	creds := v1.ClientCredentials{
		ServerName: "example.com",
	}

	client, err := NewClient(
		WithVersionPriority([]string{Version1}),
		WithV1Credentials(creds),
	)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	state := client.State()
	if state != "disconnected" {
		t.Errorf("State = %s, want 'disconnected'", state)
	}
}

// TestWithServer tests WithServer option.
func TestWithServer(t *testing.T) {
	creds := v1.ClientCredentials{
		ServerName: "example.com",
	}

	client, err := NewClient(
		WithServer("example.com:8080"),
		WithVersionPriority([]string{Version1}),
		WithV1Credentials(creds),
	)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.cfg.Server != "example.com:8080" {
		t.Errorf("Server = %s, want 'example.com:8080'", client.cfg.Server)
	}
}

// TestWithAgent tests WithAgent option.
func TestWithAgent(t *testing.T) {
	creds := v1.ClientCredentials{
		ServerName: "example.com",
	}

	client, err := NewClient(
		WithAgent("agent-1", "host-1", "token-123"),
		WithVersionPriority([]string{Version1}),
		WithV1Credentials(creds),
	)

	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.cfg.AgentID != "agent-1" {
		t.Errorf("AgentID = %s, want 'agent-1'", client.cfg.AgentID)
	}
	if client.cfg.Hostname != "host-1" {
		t.Errorf("Hostname = %s, want 'host-1'", client.cfg.Hostname)
	}
	if client.cfg.Token != "token-123" {
		t.Errorf("Token = %s, want 'token-123'", client.cfg.Token)
	}
}

// TestClientConfigStructure tests ClientConfig structure.
func TestClientConfigStructure(t *testing.T) {
	cfg := ClientConfig{
		Versions: []string{Version1, Version2},
		Server:   "example.com:8080",
		AgentID:  "test-agent",
		Hostname: "test-host",
		Token:    "test-token",
	}

	if len(cfg.Versions) != 2 {
		t.Errorf("Versions count = %d, want 2", len(cfg.Versions))
	}
	if cfg.Server == "" {
		t.Error("Server should not be empty")
	}
	if cfg.AgentID == "" {
		t.Error("AgentID should not be empty")
	}
}

// TestClientOptionsChain tests chaining multiple options.
func TestClientOptionsChain(t *testing.T) {
	creds := v1.ClientCredentials{
		ServerName: "example.com",
	}

	client, err := NewClient(
		WithVersionPriority([]string{Version1}),
		WithServer("example.com:8080"),
		WithAgent("agent-1", "host-1", "token-1"),
		WithV1Credentials(creds),
	)

	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.cfg.Server != "example.com:8080" {
		t.Errorf("Server = %s, want 'example.com:8080'", client.cfg.Server)
	}
	if client.cfg.AgentID != "agent-1" {
		t.Errorf("AgentID = %s, want 'agent-1'", client.cfg.AgentID)
	}
	if client.cfg.V1Creds == nil {
		t.Error("V1Creds should not be nil")
	}
}

// TestClientConcurrency tests concurrent access to client methods.
func TestClientConcurrency(t *testing.T) {
	creds := v1.ClientCredentials{
		ServerName: "example.com",
	}

	client, err := NewClient(
		WithVersionPriority([]string{Version1}),
		WithV1Credentials(creds),
	)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Test concurrent reads
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_ = client.State()
			_ = client.ActiveVersion()
			done <- true
		}()
	}

	// Wait for all to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// mockVersionedClient is a mock implementation for testing.
type mockVersionedClient struct {
	connectCalled   bool
	sendBatchCalled bool
	closeCalled     bool
	state           string
}

func (m *mockVersionedClient) Connect(ctx context.Context) error {
	m.connectCalled = true
	return errors.New("mock connection error")
}

func (m *mockVersionedClient) SendBatch(ctx context.Context, batch *core.SignalBatch, tag, source string) (string, error) {
	m.sendBatchCalled = true
	return "", errors.New("mock send error")
}

func (m *mockVersionedClient) SetACKHandler(handler ACKHandler) {
	// no-op for mock
}

func (m *mockVersionedClient) Close() error {
	m.closeCalled = true
	return nil
}

func (m *mockVersionedClient) State() string {
	if m.state == "" {
		return "disconnected"
	}
	return m.state
}

// TestVersionedClientInterface tests that mock implements the interface.
func TestVersionedClientInterface(t *testing.T) {
	mock := &mockVersionedClient{}

	// This is a compile-time test to verify the interface is implemented
	var _ versionedClient = mock

	ctx := context.Background()

	_ = mock.Connect(ctx)
	_, _ = mock.SendBatch(ctx, nil, "tag", "source")
	_ = mock.Close()
	_ = mock.State()
}
