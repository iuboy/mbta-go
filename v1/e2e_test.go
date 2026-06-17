//go:build integration

package v1

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

// waitAddr 轮询直到 server 完成监听（Addr 非 ""），或超时。
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

// TestE2E_Quic_SendBatch 端到端：v1 QUIC server + client，握手 → SendBatch → sink 收到。
// 验证 QUIC binding 的完整 r2 链路（QUIC 握手 + HELLO/AUTH + envelope + BATCH + route + ACK）。
func TestE2E_Quic_SendBatch(t *testing.T) {
	sink := &e2eSink{}
	server, err := NewServer(ServerConfig{
		Transport: QUICServerConfig{
			Address: "127.0.0.1:0",
			Credentials: &ServerCredentials{
				CertFile: "../testdata/certificates/server.crt",
				KeyFile:  "../testdata/certificates/server.key",
			},
		},
		Auth: core.NewStaticTokenValidator(map[string]string{"test-token": "agent-1"}),
		Policy: core.Policy{
			SupportedCapabilities: []string{"codec_json", "cs_intl"},
			DefaultCodec:          corepb.Codec_CODEC_JSON,
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
		Transport: QUICClientConfig{
			Server: addr,
			Credentials: &ClientCredentials{
				InsecureSkipVerify: true, // 测试环境跳过 server 证书验证
			},
		},
		AgentID:      "agent-1",
		Hostname:     "test-host",
		Token:        "test-token",
		Capabilities: []string{"codec_json", "cs_intl"},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	sb := &core.SignalBatch{Signals: []*core.SignalRecord{{SignalType: "log", Body: "hello e2e"}}}

	chunkID, err := client.SendBatch(ctx, sb, "tag", "source")
	if err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	if chunkID == "" {
		t.Error("chunkID empty")
	}

	// 验证 sink 收到（server route → OnSignalBatch）。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && sink.count.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := sink.count.Load(); got != 1 {
		t.Errorf("sink count = %d, want 1", got)
	}
}
