package ntls

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// SM2 双证书路径（testdata 相对 ntls 包目录）。
const (
	certDir      = "../testdata/ntls"
	signCertFile = certDir + "/sm2_sign_cert.pem"
	signKeyFile  = certDir + "/sm2_sign_key.pem"
	encCertFile  = certDir + "/sm2_enc_cert.pem"
	encKeyFile   = certDir + "/sm2_enc_key.pem"
)

// --- Config 校验 ---

func TestNewServer_EmptyAddress(t *testing.T) {
	_, err := NewServer(ServerConfig{Address: ""})
	if err == nil {
		t.Error("expected error for empty address")
	}
}

func TestNewServer_MissingDualCert(t *testing.T) {
	_, err := NewServer(ServerConfig{Address: "127.0.0.1:0"})
	if err == nil {
		t.Error("expected error for missing dual certificates")
	}
}

func TestNewServer_Valid(t *testing.T) {
	s, err := NewServer(ServerConfig{
		Address:      "127.0.0.1:0",
		SignCertFile: signCertFile,
		SignKeyFile:  signKeyFile,
		EncCertFile:  encCertFile,
		EncKeyFile:   encKeyFile,
		Auth:         core.NewStaticTokenValidator(map[string]string{"tok": "agent-1"}),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil {
		t.Error("server should not be nil")
	}
}

func TestNewClient_EmptyServer(t *testing.T) {
	_, err := NewClient(ClientConfig{Server: ""})
	if err == nil {
		t.Error("expected error for empty server")
	}
}

func TestNewClient_Valid(t *testing.T) {
	c, err := NewClient(ClientConfig{Server: "127.0.0.1:7400"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Error("client should not be nil")
	}
}

func TestClient_State(t *testing.T) {
	c, _ := NewClient(ClientConfig{Server: "127.0.0.1:7400"})
	if c.State() != core.StateDisconnected {
		t.Errorf("State() = %v, want StateDisconnected", c.State())
	}
}

func TestClient_Close(t *testing.T) {
	c, _ := NewClient(ClientConfig{Server: "127.0.0.1:7400"})
	if err := c.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestServer_Close(t *testing.T) {
	s, _ := NewServer(ServerConfig{
		Address:      "127.0.0.1:0",
		SignCertFile: signCertFile,
		SignKeyFile:  signKeyFile,
		EncCertFile:  encCertFile,
		EncKeyFile:   encKeyFile,
	})
	_ = s.Close()
}

// --- E2E smoke：TLCP server + client 完整握手 + SendBatch ---

func TestE2E_NTLS_SendBatch(t *testing.T) {
	sink := &countSink{}
	server, _ := NewServer(ServerConfig{
		Address:      "127.0.0.1:0",
		SignCertFile: signCertFile,
		SignKeyFile:  signKeyFile,
		EncCertFile:  encCertFile,
		EncKeyFile:   encKeyFile,
		Auth:         core.NewStaticTokenValidator(map[string]string{"tok": "agent-1"}),
		Policy: core.Policy{
			EnableHMACSHA256: true,
			EnableWindow:     true,
		},
		Sink: sink,
	})

	srvCtx, srvCancel := context.WithCancel(context.Background())
	defer srvCancel()

	startErr := make(chan error, 1)
	go func() { startErr <- server.Start(srvCtx) }()

	// 等监听就绪
	var addr string
	for i := 0; i < 200; i++ {
		addr = server.Addr()
		if addr != "" {
			break
		}
		select {
		case err := <-startErr:
			t.Fatalf("server start failed: %v", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("server did not start")
	}

	client, err := NewClient(ClientConfig{
		Server: addr,
		Credentials: &ClientCredentials{
			SignCertFile:       signCertFile,
			SignKeyFile:        signKeyFile,
			EncCertFile:        encCertFile,
			EncKeyFile:         encKeyFile,
			InsecureSkipVerify: true,
		},
		AgentID: "agent-1",
		Token:   "tok",
		Capabilities: []string{
			core.CapCodecJSON,
			core.CapHMACSHA256,
			core.CapWindowFlowCtrl,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	connCtx, connCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer connCancel()
	if err := client.Connect(connCtx); err != nil {
		t.Fatalf("connect: %v", err)
	}

	batch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log", Body: "ntls test", TimeUnixMs: 1},
		},
	}
	_, err = client.SendBatch(context.Background(), batch, "tag", "src")
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	// 等 ACK 到达
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if client.pendingCount.Load() == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := sink.events.Load(); got != 1 {
		t.Errorf("sink events = %d, want 1", got)
	}

	_ = client.Close()
}

type countSink struct {
	events atomic.Int64
}

func (s *countSink) OnSignalBatch(_ context.Context, _ string, batch *core.SignalBatch) error {
	s.events.Add(int64(len(batch.Signals)))
	return nil
}
func (s *countSink) OnPressure(_ string) core.PressureState { return core.PressureNormal }
