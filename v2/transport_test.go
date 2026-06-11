package v2

import (
	"context"
	"testing"

	"github.com/iuboy/mbta-go/core"
)

// TestNewServer_EmptyAddress verifies that NewServer rejects empty address.
func TestNewServer_EmptyAddress(t *testing.T) {
	_, err := NewServer(ServerConfig{
		Transport: QUICServerConfig{Address: ""},
	})
	if err == nil {
		t.Error("expected error for empty address")
	}
	if core.GetErrorCode(err) != core.NumConfig {
		t.Errorf("error code = %d, want %d", core.GetErrorCode(err), core.NumConfig)
	}
}

// TestNewServer_ValidAddress verifies that NewServer succeeds with valid config.
func TestNewServer_ValidAddress(t *testing.T) {
	s, err := NewServer(ServerConfig{
		Transport: QUICServerConfig{Address: "localhost:7400"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Error("server should not be nil")
	}
}

// TestServer_Start_NotImplemented verifies that Start returns not-implemented error.
func TestServer_Start_NotImplemented(t *testing.T) {
	s, _ := NewServer(ServerConfig{
		Transport: QUICServerConfig{Address: "localhost:7400"},
	})
	err := s.Start(context.Background())
	if err == nil {
		t.Error("expected not-implemented error")
	}
	if core.GetErrorCode(err) != core.NumConfig {
		t.Errorf("error code = %d, want %d", core.GetErrorCode(err), core.NumConfig)
	}
}

// TestNewClient_EmptyServer verifies that NewClient rejects empty server.
func TestNewClient_EmptyServer(t *testing.T) {
	_, err := NewClient(ClientConfig{
		Transport: QUICClientConfig{Server: ""},
	})
	if err == nil {
		t.Error("expected error for empty server")
	}
	if core.GetErrorCode(err) != core.NumCredential {
		t.Errorf("error code = %d, want %d", core.GetErrorCode(err), core.NumCredential)
	}
}

// TestNewClient_ValidServer verifies that NewClient succeeds with valid config.
func TestNewClient_ValidServer(t *testing.T) {
	c, err := NewClient(ClientConfig{
		Transport: QUICClientConfig{Server: "localhost:7400"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Error("client should not be nil")
	}
}

// TestClient_Connect_NotImplemented verifies that Connect returns not-implemented error.
func TestClient_Connect_NotImplemented(t *testing.T) {
	c, _ := NewClient(ClientConfig{
		Transport: QUICClientConfig{Server: "localhost:7400"},
	})
	err := c.Connect(context.Background())
	if err == nil {
		t.Error("expected not-implemented error")
	}
}

// TestClient_SendBatch_NotImplemented verifies that SendBatch returns not-implemented error.
func TestClient_SendBatch_NotImplemented(t *testing.T) {
	c, _ := NewClient(ClientConfig{
		Transport: QUICClientConfig{Server: "localhost:7400"},
	})
	_, err := c.SendBatch(context.Background(), &core.SignalBatch{}, "", "")
	if err == nil {
		t.Error("expected not-implemented error")
	}
}

// TestClient_State returns disconnected.
func TestClient_State(t *testing.T) {
	c, _ := NewClient(ClientConfig{
		Transport: QUICClientConfig{Server: "localhost:7400"},
	})
	if c.State() != core.StateDisconnected {
		t.Errorf("State() = %v, want StateDisconnected", c.State())
	}
}

// TestClient_Close returns nil.
func TestClient_Close(t *testing.T) {
	c, _ := NewClient(ClientConfig{
		Transport: QUICClientConfig{Server: "localhost:7400"},
	})
	if err := c.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

// TestServer_Close returns nil.
func TestServer_Close(t *testing.T) {
	s, _ := NewServer(ServerConfig{
		Transport: QUICServerConfig{Address: "localhost:7400"},
	})
	if err := s.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}
