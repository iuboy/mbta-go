package ntls

import (
	"strings"
	"testing"
)

// Mode 枚举校验回归（review 裁决：TLSMode bool 枚举化、无兼容别名）：
// 未注册模式在 NewServer/NewClient 构造期 fail-fast；零值缺省 TLCP。
func TestServerConfig_ModeValidation(t *testing.T) {
	// 模式检查先于证书校验——无证书配置即可触发模式错误。
	_, err := NewServer(ServerConfig{Address: "127.0.0.1:0", Mode: "bogus"})
	if err == nil || !strings.Contains(err.Error(), "unknown ntls mode") {
		t.Fatalf("err = %v, want unknown ntls mode", err)
	}
	// 零值缺省 TLCP：模式检查通过（后续因缺证书失败，但错误不是 mode）。
	_, err = NewServer(ServerConfig{Address: "127.0.0.1:0"})
	if err != nil && strings.Contains(err.Error(), "unknown ntls mode") {
		t.Fatalf("empty mode must default to TLCP, got: %v", err)
	}
}

func TestClientCredentials_ModeValidation(t *testing.T) {
	_, err := NewClient(ClientConfig{
		Server:      "127.0.0.1:7400",
		AgentID:     "a1",
		Token:       "tok",
		Credentials: &ClientCredentials{Mode: "bogus"},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown ntls mode") {
		t.Fatalf("err = %v, want unknown ntls mode", err)
	}
}
