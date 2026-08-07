package core

import "net"

// SessionEventType 标识会话生命周期事件的类型。
type SessionEventType int

const (
	// SessionConnected 表示一个 agent 完成认证（AUTH_OK 后、进入 READY）。
	SessionConnected SessionEventType = iota
	// SessionDisconnected 表示一个已认证 agent 的连接结束（正常关闭或异常断开）。
	// 仅对认证成功过的连接触发；未通过 HELLO/AUTH 的连接不会产生 DISCONNECTED 事件。
	SessionDisconnected
)

// SessionEvent 在 agent 连接生命周期关键节点（认证成功、连接断开）投递给 OnSession 回调。
//
// 与 RedirectChecker（仅返回 leader 地址）不同，SessionEvent 携带完整的连接身份：
// agentID/sessionID 来自握手状态机；Hostname/InstanceID/AgentVersion/OS 来自 HELLO 帧；
// RemoteAddr 来自传输层。这让上层（如 forwarder 的 agentregistry）能在 connect 时刻
// 完整登记一个 agent，而不必等到首条 BATCH 才 lazy 注册。
type SessionEvent struct {
	Type         SessionEventType
	AgentID      string
	SessionID    string
	Hostname     string // 来自 HELLO.hostname
	InstanceID   string // 来自 HELLO.instance_id（一次连接一个）
	AgentVersion string // 来自 HELLO.agent_version
	OS           string // 来自 HELLO.os（如 "linux"/"darwin"/"windows"）
	RemoteAddr   net.Addr
}

// OnSession 是可选的会话生命周期回调。nil 表示不观测连接生命周期。
//
// 调用时序约定：
//   - CONNECTED：在 AUTH_OK 发送、状态机进入 READY 之后触发（早于 RedirectChecker 判定，
//     也早于任何 BATCH 处理）。被重定向（follower→leader）的连接也会先触发 CONNECTED 再
//     触发 DISCONNECTED，保证 CONNECTED/DISCONNECTED 严格成对。
//   - DISCONNECTED：在连接结束（正常 CLOSE、传输错误、ctx 取消）时触发，仅当该连接此前
//     已认证成功（agentID 非空）。
//
// 实现必须是线程安全的、非阻塞的：回调在连接处理 goroutine 内同步调用，阻塞会拖死该连接。
// 重型持久化/网络操作应异步派发。
type OnSession func(ev SessionEvent)
