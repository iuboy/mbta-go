package v1

import "testing"

// TestNewClientInjectsHeartbeat 断言 QUIC binding 注入应用层心跳。
//
// 回归背景（2026-09 生产实测）：QUIC 传输层 keepalive 是 QUIC PING 帧，
// 不会在 MBTA control stream 上产生应用层数据；两侧 control 读循环按帧
// 计 DefaultReadTimeout(5min)，纯发送型 agent（BATCH 走 data stream）的
// control stream 因此每 5 分钟被读超时断连、epoch 单调递增。黑盒集成
// 测试无法在 CI 时长预算内复现 5 分钟窗口，注入存在性在此白盒断言；
// 端到端验收看部署侧 journal（不再出现周期性 disconnect→handshake）。
func TestNewClientInjectsHeartbeat(t *testing.T) {
	c, err := NewClient(ClientConfig{
		Transport: QUICClientConfig{Server: "127.0.0.1:1"},
		AgentID:   "heartbeat-injection-test",
		Token:     "tok-heartbeat-test",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if !c.core.HeartbeatEnabled() {
		t.Fatal("v1 NewClient 未注入 HeartbeatLoop：空闲 control stream 将被 5min 读超时周期性断连")
	}
}
