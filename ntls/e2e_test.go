//go:build integration

package ntls

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// e2eSink 收集投递的 batch（EventSink 最小实现）。
type e2eSink struct {
	count atomic.Int64
}

func (s *e2eSink) OnSignalBatch(_ context.Context, _ string, _ *core.SignalBatch) error {
	s.count.Add(1)
	return nil
}
func (s *e2eSink) OnPressure(_ string) core.PressureState { return core.PressureNormal }

func waitAddr(t *testing.T, srv *Server) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a := srv.Addr(); a != "" {
			return a
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not start listening")
	return ""
}

// TestE2E_NTLS_SendBatch 端到端：ntls TCP+TLCP server + client，握手 → SendBatch → sink 收到。
// 验证 TLCP binding 完整 r2 链路（TLCP SM2 双证书握手 + HELLO/AUTH + envelope + BATCH + route + ACK）。
func TestE2E_NTLS_SendBatch(t *testing.T) {
	sink := &e2eSink{}
	server, err := NewServer(ServerConfig{
		Address:      "127.0.0.1:0",
		SignCertFile: "../testdata/ntls/sm2_sign_cert.pem",
		SignKeyFile:  "../testdata/ntls/sm2_sign_key.pem",
		EncCertFile:  "../testdata/ntls/sm2_enc_cert.pem",
		EncKeyFile:   "../testdata/ntls/sm2_enc_key.pem",
		CAFile:       "../testdata/ntls/sm2_ca.pem",
		Auth:         core.NewStaticTokenValidator(map[string]string{"test-token": "agent-1"}),
		Policy: core.Policy{
			SupportedCapabilities: []string{"codec_proto", "cs_gm"},
			DefaultCodec:          corepb.Codec_CODEC_PROTO,
			DefaultCompression:    corepb.Compression_COMPRESSION_NONE,
			CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_GM,
		},
		Sink: sink,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Start(ctx) }()

	addr := waitAddr(t, server)

	client, err := NewClient(ClientConfig{
		Server: addr,
		Credentials: &ClientCredentials{
			SignCertFile: "../testdata/ntls/sm2_sign_cert.pem",
			SignKeyFile:  "../testdata/ntls/sm2_sign_key.pem",
			EncCertFile:  "../testdata/ntls/sm2_enc_cert.pem",
			EncKeyFile:   "../testdata/ntls/sm2_enc_key.pem",
			CAFile:       "../testdata/ntls/sm2_ca.pem",
		},
		AgentID:      "agent-1",
		Token:        "test-token",
		Capabilities: []string{"codec_proto", "cs_gm"},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	sb := &core.SignalBatch{Signals: []*core.SignalRecord{{SignalType: "log", Body: "hello ntls e2e"}}}

	chunkID, err := client.SendBatch(ctx, sb, "tag", "source")
	if err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	if chunkID == "" {
		t.Error("chunkID empty")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && sink.count.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := sink.count.Load(); got != 1 {
		t.Errorf("sink count = %d, want 1", got)
	}
}

// TestE2E_MBTATLS_SendBatch 端到端：mbta-tls/1（TCP + TLS 1.3）server + client。
// 验证第三 binding（§10 对称补齐）完整 r2 链路（TLS1.3 握手 + HELLO/AUTH + envelope + BATCH + route + ACK）。
func TestE2E_MBTATLS_SendBatch(t *testing.T) {
	sink := &e2eSink{}
	server, err := NewServer(ServerConfig{
		Address:  "127.0.0.1:0",
		TLSMode:  true,
		CertFile: "../testdata/certificates/server.crt",
		KeyFile:  "../testdata/certificates/server.key",
		Auth:     core.NewStaticTokenValidator(map[string]string{"test-token": "agent-1"}),
		Policy: core.Policy{
			SupportedCapabilities: []string{"codec_proto", "cs_intl"},
			DefaultCodec:          corepb.Codec_CODEC_PROTO,
			DefaultCompression:    corepb.Compression_COMPRESSION_NONE,
			CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
		},
		Sink: sink,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Start(ctx) }()

	addr := waitAddr(t, server)

	client, err := NewClient(ClientConfig{
		Server: addr,
		Credentials: &ClientCredentials{
			TLSMode:            true,
			InsecureSkipVerify: true,
		},
		AgentID:      "agent-1",
		Token:        "test-token",
		Capabilities: []string{"codec_proto", "cs_intl"},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	sb := &core.SignalBatch{Signals: []*core.SignalRecord{{SignalType: "log", Body: "hello mbta-tls e2e"}}}

	chunkID, err := client.SendBatch(ctx, sb, "tag", "source")
	if err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	if chunkID == "" {
		t.Error("chunkID empty")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && sink.count.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := sink.count.Load(); got != 1 {
		t.Errorf("sink count = %d, want 1", got)
	}
}
