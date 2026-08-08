package ntls

import (
	"strings"
	"testing"

	"github.com/iuboy/mbta-go/core"
)

// TestNewClient_Validation 覆盖 ntls.NewClient 构造期的配置校验。
// 校验下沉到 ntls.NewClient（真正消费配置的地方），fail-fast 暴露缺字段/非法地址/未知 capability。
func TestNewClient_Validation(t *testing.T) {
	// validBase 是合法配置基线，各子测试在此基础上构造非法变体。
	validBase := ClientConfig{
		Server:  "localhost:7400",
		AgentID: "agent-1",
		Token:   "secret-token",
	}

	tests := []struct {
		name    string
		mutate  func(ClientConfig) ClientConfig
		wantErr string
	}{
		{
			name:   "valid",
			mutate: func(c ClientConfig) ClientConfig { return c },
		},
		{
			name: "missing agent id",
			mutate: func(c ClientConfig) ClientConfig {
				c.AgentID = ""
				return c
			},
			wantErr: "AgentID required",
		},
		{
			name: "missing token",
			mutate: func(c ClientConfig) ClientConfig {
				c.Token = ""
				return c
			},
			wantErr: "Token required",
		},
		{
			name: "server missing port",
			mutate: func(c ClientConfig) ClientConfig {
				c.Server = "localhost"
				return c
			},
			wantErr: "Server",
		},
		{
			name: "server port out of range",
			mutate: func(c ClientConfig) ClientConfig {
				c.Server = "localhost:99999"
				return c
			},
			wantErr: "Server",
		},
		{
			name: "unknown stable capability",
			mutate: func(c ClientConfig) ClientConfig {
				c.Capabilities = []string{core.CapCodecProto, "bogus_cap"}
				return c
			},
			wantErr: "unknown stable capabilities",
		},
		{
			name: "experimental capability allowed",
			mutate: func(c ClientConfig) ClientConfig {
				c.Capabilities = []string{core.CapCodecProto, "x-experimental"}
				return c
			},
		},
		{
			name: "tlcp sign cert/key inconsistent",
			mutate: func(c ClientConfig) ClientConfig {
				c.Credentials = &ClientCredentials{
					SignCertFile: "sign.pem", // SignKeyFile 漏填
				}
				return c
			},
			wantErr: "SignCertFile and SignKeyFile",
		},
		{
			name: "tlcp enc cert/key inconsistent",
			mutate: func(c ClientConfig) ClientConfig {
				c.Credentials = &ClientCredentials{
					EncKeyFile: "enc.key", // EncCertFile 漏填
				}
				return c
			},
			wantErr: "EncCertFile and EncKeyFile",
		},
		{
			name: "tlcp dual sm2 all empty allowed",
			mutate: func(c ClientConfig) ClientConfig {
				// 全空 = 不带客户端证书，合法（非 mTLS）。
				c.Credentials = &ClientCredentials{}
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(tt.mutate(validBase))
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
