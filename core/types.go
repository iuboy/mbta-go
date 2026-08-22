package core

// 帧类型注册表（r3）。type 高位为通道域：0x00-0x7F control / 0x80-0xFF data。
// append-only：新类型只能追加；data 方向帧必须落在 data 域（conformance 断言）。
const (
	TypeHello    uint8 = 0x01 // C→S 握手（1-RTT：profile/token_proof/eph/caps）
	TypeHelloAck uint8 = 0x02 // S→C 握手应答（epoch/ack_mode/limits/credits/finished）
	TypeHelloNak uint8 = 0x03 // S→C 握手拒绝（code/retryable/retry_hint）
	TypeResult   uint8 = 0x20 // S→C 唯一反馈帧（accepted/durable/rejected/released）
	TypeCredit   uint8 = 0x21 // S→C 唯一流控发放帧
	TypeDict     uint8 = 0x22 // S→C zstd 字典下发（zstd_dict 能力协商后，HELLO_ACK 之后立即发送）
	TypePing     uint8 = 0x30 // 双向保活（仅 TCP binding）
	TypePong     uint8 = 0x31
	TypeClose    uint8 = 0x40 // 双向优雅关闭（drain 超时提示）
	TypeRedirect uint8 = 0x41 // S→C HA 重定向
	TypeAbort    uint8 = 0x50 // 双向立即拆除（写失败/协议违规/账本漂移）
	TypeDgram    uint8 = 0x90 // C→S 不可靠批次（Envelope；豁免 credit，硬限速）
	TypeBatch    uint8 = 0x91 // C→S 可靠批次（Envelope；消耗 credit）
)

// IsControlType 报告 type 是否落在 control 域（type 高位 = 0）。
// TCP binding 依赖此位做单连接逻辑流 demux；QUIC binding 以 stream 角色放置。
func IsControlType(t uint8) bool { return t&0x80 == 0 }

// IsDataType 报告 type 是否落在 data 域（type 高位 = 1）。
func IsDataType(t uint8) bool { return t&0x80 != 0 }

// Frame flags：v1(r3) 全部位为保留位——压缩标识移入 Envelope（载荷属性，
// 须在 AEAD 覆盖内）。接收端对任何非零 flags MUST ABORT（frame.go Read/Write 校验）。

// Stream roles（QUIC binding 的 stream 放置语义）。
const (
	StreamRoleControl = "control"
	StreamRoleData    = "data"
)
