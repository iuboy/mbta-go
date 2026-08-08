package v1

import (
	"strings"
	"testing"

	"github.com/iuboy/mbta-go/core"
)

// TestNewClient_Validation 覆盖 v1.NewClient 构造期的配置校验。
// 校验下沉到 v1.NewClient（真正消费配置的地方），fail-fast 暴露缺字段/非法地址/未知 capability。
func TestNewClient_Validation(t *testing.T) {
	// validBase 是合法配置基线，各子测试在此基础上构造非法变体。
	validBase := ClientConfig{
		Transport: QUICClientConfig{Server: "localhost:7400"},
		AgentID:   "agent-1",
		Token:     "secret-token",
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
			name: "missing server",
			mutate: func(c ClientConfig) ClientConfig {
				c.Transport.Server = ""
				return c
			},
			wantErr: "Transport.Server",
		},
		{
			name: "server missing port",
			mutate: func(c ClientConfig) ClientConfig {
				c.Transport.Server = "localhost"
				return c
			},
			wantErr: "Transport.Server",
		},
		{
			name: "server port out of range",
			mutate: func(c ClientConfig) ClientConfig {
				c.Transport.Server = "localhost:99999"
				return c
			},
			wantErr: "Transport.Server",
		},
		{
			name: "unknown stable capability",
			mutate: func(c ClientConfig) ClientConfig {
				c.Capabilities = []string{"codec_proto", "bogus_cap"}
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
			name: "invalid pick strategy",
			mutate: func(c ClientConfig) ClientConfig {
				c.PickStrategy = "roundrobin"
				return c
			},
			wantErr: "invalid PickStrategy",
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
