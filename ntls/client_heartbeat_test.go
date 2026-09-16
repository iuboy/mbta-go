package ntls

import "testing"

// TestNewClientInjectsHeartbeat 断言 TCP/TLCP binding 注入应用层心跳
// （与 v1 对称的防回归断言，背景见 v1/client_heartbeat_test.go：读侧空闲
// 超时依赖 PING/PONG 维持活性）。
func TestNewClientInjectsHeartbeat(t *testing.T) {
	c, err := NewClient(ClientConfig{
		Server:  "127.0.0.1:1",
		AgentID: "heartbeat-injection-test",
		Token:   "tok-heartbeat-test",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if !c.core.HeartbeatEnabled() {
		t.Fatal("ntls NewClient 未注入 HeartbeatLoop：TCP 无空闲超时机制，读侧活性失去维持")
	}
}
