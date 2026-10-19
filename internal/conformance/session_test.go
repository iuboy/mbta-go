package conformance

// session_test.go：OnSession 会话生命周期回调契约。
//
//   - nil 回调（契约「可选，nil=禁用」）：断开路径必须容忍——Handle 收尾
//     defer 对 DISCONNECTED 的回调补 nil 守卫（59d79a7），未注入回调的连接
//     断开曾直接 panic 崩溃整个测试进程；
//   - 注入回调：CONNECTED 在握手完成后投递一次、DISCONNECTED 在连接结束
//     后投递一次，携带 AgentID/SessionID——此前 conformance 从未注入过
//     OnSession，该回调的两个调用点均无断言。

import (
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// TestSession_NilCallbackDisconnectNoPanic 回归 59d79a7：OnSession 未注入
// 的连接断开，Handle 收尾 defer 不得 panic。守卫缺失时本测试连同整个测试
// 进程一起崩溃（goroutine panic 不可恢复），即天然的失败信号。
func TestSession_NilCallbackDisconnectNoPanic(t *testing.T) {
	env := startEnv(t, envConfig{}) // startEnv 默认不注入 OnSession（nil）

	// 已认证连接的异常断开（transport 关闭 → controlLoop 退出 → 收尾 defer
	// 触发 DISCONNECTED 回调路径——正是曾经的 panic 点）。
	if err := env.tr.Close(); err != nil {
		t.Fatalf("close transport: %v", err)
	}
	// Handle 收尾含最多 ~5s 的 sink 排空等待（drainTimeout），等待上限须
	// 与其解耦，避免贴边闪烁。
	select {
	case <-env.handleErr:
		// Handle 正常返回即守卫生效；进程存活由测试继续执行隐式证明。
	case <-time.After(12 * time.Second):
		t.Fatal("Handle did not return after transport close")
	}
}

// TestSession_LifecycleEventsDelivered 注入回调后 CONNECTED/DISCONNECTED
// 各投递一次：AgentID/SessionID 正确、次序符合生命周期。
func TestSession_LifecycleEventsDelivered(t *testing.T) {
	events := make(chan core.SessionEvent, 4)
	env := startEnv(t, envConfig{onSession: func(ev core.SessionEvent) {
		events <- ev
	}})

	// CONNECTED：握手完成即投递（startEnv 返回时握手已毕，仍用超时等待
	// 规避投递时序假设）。
	var connected core.SessionEvent
	select {
	case connected = <-events:
	case <-time.After(5 * time.Second):
		t.Fatal("CONNECTED event not delivered after handshake")
	}
	if connected.Type != core.SessionConnected {
		t.Fatalf("first event type = %v, want SessionConnected", connected.Type)
	}
	if connected.AgentID != env.cfg.agentID {
		t.Errorf("CONNECTED AgentID = %q, want %q", connected.AgentID, env.cfg.agentID)
	}
	if connected.SessionID == "" {
		t.Error("CONNECTED SessionID is empty")
	}

	// 无中间事件混入后断开。
	if err := env.tr.Close(); err != nil {
		t.Fatalf("close transport: %v", err)
	}
	select {
	case <-env.handleErr:
	case <-time.After(12 * time.Second):
		t.Fatal("Handle did not return after transport close")
	}

	var disconnected core.SessionEvent
	select {
	case disconnected = <-events:
	case <-time.After(5 * time.Second):
		t.Fatal("DISCONNECTED event not delivered after connection end")
	}
	if disconnected.Type != core.SessionDisconnected {
		t.Fatalf("post-close event type = %v, want SessionDisconnected", disconnected.Type)
	}
	if disconnected.AgentID != env.cfg.agentID {
		t.Errorf("DISCONNECTED AgentID = %q, want %q", disconnected.AgentID, env.cfg.agentID)
	}
	if disconnected.SessionID != connected.SessionID {
		t.Errorf("DISCONNECTED SessionID = %q, want same as CONNECTED %q",
			disconnected.SessionID, connected.SessionID)
	}

	// 恰好两事件——多余投递（重复 DISCONNECTED 等）即违约。
	if n := len(events); n != 0 {
		t.Errorf("extra session events after disconnect: %d", n)
	}
}
