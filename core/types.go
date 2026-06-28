package core

// Message types (wire values, uint8, core spec §4).
// 值发布后不可改（§1.4）。1–16 已分配，17–255 保留。
const (
	TypeHello    uint8 = 1 // C→S handshake
	TypeHelloAck uint8 = 2 // S→C handshake response
	TypeAuth     uint8 = 3 // C→S authentication
	TypeAuthOK   uint8 = 4 // S→C authentication success
	TypeAuthFail uint8 = 5 // S→C authentication failure

	TypeBatch      uint8 = 6  // C→S reliable batch
	TypeDatagram   uint8 = 7  // C→S unreliable datagram (capability unreliable_datagram, §11.4)
	TypeAck        uint8 = 8  // S→C batch acknowledged
	TypeNack       uint8 = 9  // S→C batch rejected
	TypePartialAck uint8 = 10 // S→C partial success

	TypeWindow   uint8 = 11 // S→C flow-control window
	TypeThrottle uint8 = 12 // S→C explicit backoff

	TypePing  uint8 = 13 // bidirectional health check
	TypePong  uint8 = 14 // bidirectional health check response
	TypeClose    uint8 = 15 // bidirectional graceful close
	TypeError    uint8 = 16 // bidirectional protocol error
	TypeRedirect uint8 = 17 // S→C cluster redirect: guide client to the leader (§4.17)
)

// 帧头 ChannelID 约定（core spec §10.1 / §3）。
const (
	ChannelControl uint8 = 0 // control channel：HELLO/AUTH/WINDOW/THROTTLE/PING/PONG/CLOSE/ERROR
	ChannelData    uint8 = 1 // data channel：BATCH/DATAGRAM/ACK/NACK/PARTIAL_ACK
)

// Frame flags (core spec §3)。bit6–7 = FlowClass。
const (
	FlagEnvelope    byte = 0x01 // payload 是 SecureEnvelope
	FlagControl     byte = 0x02 // 控制面消息
	FlagData        byte = 0x04 // 数据面消息
	FlagMoreFollows byte = 0x08 // 逻辑多片消息的一片（§3）
	FlagReserved4   byte = 0x10 // reserved（MUST NOT set，v2 预留）
	FlagCoalesced   byte = 0x20 // 多条同类型小消息合并打包（§3.2）

	FlagControlDataMask byte = 0x06 // Control 与 Data 互斥校验
	FlagFlowClassMask   byte = 0xC0
	FlagFlowClassShift       = 6

	// FlowClass 取值（占 bit6–7）。值 3（reserved）MUST 拒绝。
	FlowClassNormal     byte = 0x00 << FlagFlowClassShift
	FlowClassBestEffort byte = 0x01 << FlagFlowClassShift
	FlowClassCritical   byte = 0x02 << FlagFlowClassShift
)

// FlowClassOf 从 flags 提取 FlowClass（返回 0/1/2；3 为 reserved，由 ValidateFlags 拒绝）。
func FlowClassOf(flags byte) byte { return (flags & FlagFlowClassMask) >> FlagFlowClassShift }

// Stream roles.
// r2 capability 标识与算法枚举由 corepb（proto enum）与 core/capability.go（registry）承载，
const (
	StreamRoleControl = "control"
	StreamRoleData    = "data"
)
