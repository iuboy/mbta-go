package v1

import (
	"context"
	"strings"
	"testing"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// TestNewServer_Validation 覆盖 v1.NewServer 构造期校验。
// 重点验证 Address 校验（此前完全无校验，靠 Listen 的 ResolveUDPAddr 运行时报错）。
func TestNewServer_Validation(t *testing.T) {
	// validBase 是最小合法配置基线。
	validBase := ServerConfig{
		Transport: QUICServerConfig{Address: "127.0.0.1:0"},
		Auth:      core.NewStaticTokenValidator(map[string]string{"tok": "agent"}),
		Policy: core.Policy{
			SupportedCapabilities: []string{core.CapCodecProto, core.CapCSIntl},
			DefaultCodec:          corepb.Codec_CODEC_PROTO,
			DefaultCompression:    corepb.Compression_COMPRESSION_NONE,
			CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
		},
		Sink: &noopServerSink{},
	}

	tests := []struct {
		name    string
		mutate  func(ServerConfig) ServerConfig
		wantErr string
	}{
		{
			name:   "valid",
			mutate: func(c ServerConfig) ServerConfig { return c },
		},
		{
			name: "address empty",
			mutate: func(c ServerConfig) ServerConfig {
				c.Transport.Address = ""
				return c
			},
			wantErr: "Transport.Address",
		},
		{
			name: "address missing port",
			mutate: func(c ServerConfig) ServerConfig {
				c.Transport.Address = "localhost"
				return c
			},
			wantErr: "Transport.Address",
		},
		{
			name: "address port out of range",
			mutate: func(c ServerConfig) ServerConfig {
				c.Transport.Address = "127.0.0.1:99999"
				return c
			},
			wantErr: "Transport.Address",
		},
		{
			name: "address omit host allowed",
			mutate: func(c ServerConfig) ServerConfig {
				// ":7400" 全网卡监听合法。
				c.Transport.Address = ":0"
				return c
			},
		},
		{
			name: "auth nil",
			mutate: func(c ServerConfig) ServerConfig {
				c.Auth = nil
				return c
			},
			wantErr: "Auth",
		},
		{
			name: "sink nil",
			mutate: func(c ServerConfig) ServerConfig {
				c.Sink = nil
				return c
			},
			wantErr: "Sink",
		},
		{
			name: "default policy applied when unset",
			mutate: func(c ServerConfig) ServerConfig {
				// 完全不配 Policy：NewServer 应注入默认（INTL cipher），不报错。
				c.Policy = core.Policy{}
				return c
			},
		},
		{
			name: "explicit invalid policy rejected",
			mutate: func(c ServerConfig) ServerConfig {
				// 部分 Policy（非零值→IsZeroPolicy=false，不注入默认）但
				// SupportedCapabilities 含未知项→Policy.Validate 报错。
				c.Policy = core.Policy{
					SupportedCapabilities: []string{core.CapCodecProto, "bogus_cap"},
					DefaultCodec:          corepb.Codec_CODEC_PROTO,
					DefaultCompression:    corepb.Compression_COMPRESSION_ZSTD,
					CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
				}
				return c
			},
			wantErr: "Policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewServer(tt.mutate(validBase))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// noopServerSink 是测试用的空 EventSink。
type noopServerSink struct{}

func (n *noopServerSink) OnSignalBatch(_ context.Context, _ string, _ *core.SignalBatch) error {
	return nil
}
func (n *noopServerSink) OnPressure(_ string) core.PressureState {
	return core.PressureNormal
}
