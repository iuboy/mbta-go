package ntls

import (
	"context"
	"strings"
	"testing"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// TestNewServer_Validation 覆盖 ntls.NewServer 构造期校验。
// 重点验证 Address 校验（此前仅 == ""，无格式校验，靠 Listen 运行时报错）。
func TestNewServer_Validation(t *testing.T) {
	// validBase 是最小合法配置基线（TLCP 模式，证书路径填非空字符串即可通过 NewServer，
	// 文件存在性在 Listen 时才校验，符合「构造期校验结构、运行时校验资源」分层）。
	validBase := ServerConfig{
		Address:      "127.0.0.1:0",
		SignCertFile: "sign.pem",
		SignKeyFile:  "sign.key",
		EncCertFile:  "enc.pem",
		EncKeyFile:   "enc.key",
		Auth:         core.NewStaticTokenValidator(map[string]string{"tok": "agent"}),
		Policy: core.Policy{
			SupportedCapabilities: []string{core.CapCodecProto, core.CapCSGM},
			DefaultCodec:          corepb.Codec_CODEC_PROTO,
			DefaultCompression:    corepb.Compression_COMPRESSION_NONE,
			CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_GM,
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
				c.Address = ""
				return c
			},
			wantErr: "Address",
		},
		{
			name: "address missing port",
			mutate: func(c ServerConfig) ServerConfig {
				c.Address = "localhost"
				return c
			},
			wantErr: "Address",
		},
		{
			name: "address port out of range",
			mutate: func(c ServerConfig) ServerConfig {
				c.Address = "127.0.0.1:99999"
				return c
			},
			wantErr: "Address",
		},
		{
			name: "address omit host allowed",
			mutate: func(c ServerConfig) ServerConfig {
				// ":7400" 全网卡监听合法。
				c.Address = ":0"
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
				// 完全不配 Policy：NewServer 应注入默认（GM cipher），不报错。
				c.Policy = core.Policy{}
				return c
			},
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
