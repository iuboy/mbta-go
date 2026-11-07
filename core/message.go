package core

// message.go：控制面消息类型别名 + 校验（r3）。
// 数据模型（SignalBatch/TraceContext）沿用 signal.proto。

import (
	"fmt"

	corepb "github.com/iuboy/mbta-go/corepb"
	"google.golang.org/protobuf/proto"
)

// 控制面消息与枚举的类型别名：数据模型 = proto/control.proto（schema 权威），
// 包内直接使用 corepb 消息，不再包一层 wrapper。
type (
	Hello    = corepb.Hello
	HelloAck = corepb.HelloAck
	Limits   = corepb.Limits
	HelloNak = corepb.HelloNak
	Credits  = corepb.Credits
	Envelope = corepb.Envelope
	Batch    = corepb.Batch
	Result   = corepb.Result
	Credit   = corepb.Credit
	CloseMsg = corepb.Close
	AbortMsg = corepb.Abort
	Redirect = corepb.Redirect
	PingMsg  = corepb.Ping
	PongMsg  = corepb.Pong
	ZstdDict = corepb.ZstdDict

	Profile     = corepb.Profile
	AckMode     = corepb.AckMode
	ResultLevel = corepb.ResultLevel
	Compression = corepb.Compression
)

// Encode 将 proto 消息序列化为字节。m 为 nil 时返回协议错误。
func Encode(m proto.Message) ([]byte, error) {
	if m == nil {
		return nil, NewError(ErrCodeProtocol, "encode: nil message")
	}
	return proto.Marshal(m)
}

// Decode 把字节反序列化到 proto 消息 m。m 为 nil 或解码失败时返回协议错误。
func Decode(data []byte, m proto.Message) error {
	if m == nil {
		return NewError(ErrCodeProtocol, "decode: nil target message")
	}
	if err := proto.Unmarshal(data, m); err != nil {
		return WrapError(ErrCodeProtocol, "decode", err)
	}
	return nil
}

// EphemeralPubLen 返回 profile 临时公钥的 wire 长度（intl = X25519 32B；
// gm = SM2 非压缩点 65B）。未知 profile 返回 -1。
func EphemeralPubLen(p corepb.Profile) int {
	switch p {
	case corepb.Profile_PROFILE_INTL:
		return 32 // X25519
	case corepb.Profile_PROFILE_GM:
		return 65 // SM2 非压缩 0x04‖X‖Y
	default:
		return -1
	}
}

// MaxHelloCaps 是 HELLO.capabilities 的条目数上限（已注册能力集 ≤8，上限留足
// 演进空间）；MaxHelloCapLen 是单条 capability 的字节上限。capabilities 在认证前
// 进入 Negotiate 与失败诊断日志——不校验时超长/控制字符字符串构成认证前的
// 日志注入与放大面（与 meta 字段同强度，审查 F8/P2-4 裁决）。
const (
	MaxHelloCaps   = 32
	MaxHelloCapLen = 64
	// MaxHelloMetaEntries 是 HELLO.meta 的条目数上限。逐条长度校验不约束条数：
	// proto 解码先于校验执行，16MB 帧可先解出百万级 map entries 再被逐条拒绝
	// （认证前内存放大，与 capabilities 条数上限对称的防线）。
	MaxHelloMetaEntries = 32
)

// MaxHandshakeFrameBytes 是握手帧（HELLO/HELLO_ACK/NAK）的帧层尺寸上限。
// 握手消息有天然小上界（agent_id 256B + meta 32×256B + caps 32×64B + eph 65B +
// proof ≪ 64KB）；先于 Decode 的尺寸先验拒把认证前/恶意服务端的解码放大窗口
// 压到常数级（16MB 全额帧 otherwise 全量进 proto.Unmarshal 的 map/repeated 分配）。
const MaxHandshakeFrameBytes = 64 << 10

// ValidateHello 校验 HELLO。agent_id 必填且过长度/控制字符校验；
// meta 各字段可选但一旦提供须过同强度校验（继承 v1 加固）；
// capabilities 逐条过长度/控制字符校验并限条数；
// eph 长度按 profile 严格校验；profile 必须已知。
func ValidateHello(m *corepb.Hello) error {
	if m == nil || m.GetAgentId() == "" {
		return NewError(ErrCodeBadHandshake, "agent_id is required")
	}
	if err := validateAgentID(m.GetAgentId()); err != nil {
		return err
	}
	if len(m.GetCapabilities()) > MaxHelloCaps {
		return NewError(ErrCodeBadHandshake, fmt.Sprintf("capabilities exceeds maximum %d entries", MaxHelloCaps))
	}
	for _, c := range m.GetCapabilities() {
		if len(c) > MaxHelloCapLen {
			return NewError(ErrCodeBadHandshake, fmt.Sprintf("capability exceeds maximum length %d", MaxHelloCapLen))
		}
		if hasStrictControlChars(c) {
			return NewError(ErrCodeBadHandshake, "capability contains control characters")
		}
	}
	if len(m.GetMeta()) > MaxHelloMetaEntries {
		return NewError(ErrCodeBadHandshake, fmt.Sprintf("meta exceeds maximum %d entries", MaxHelloMetaEntries))
	}
	for k, v := range m.GetMeta() {
		if err := validateHelloMetaField("meta."+k, k); err != nil {
			return err
		}
		if err := validateHelloMetaField("meta."+k, v); err != nil {
			return err
		}
	}
	if EphemeralPubLen(m.GetProfile()) < 0 {
		return NewError(ErrCodeUnsupportedProfile, fmt.Sprintf("unsupported profile %v", m.GetProfile()))
	}
	if n := EphemeralPubLen(m.GetProfile()); len(m.GetClientEph()) != n {
		return NewError(ErrCodeHelloEphInvalid, fmt.Sprintf("client_eph must be %d bytes, got %d", n, len(m.GetClientEph())))
	}
	if len(m.GetTokenProof()) == 0 {
		return NewError(ErrCodeBadHandshake, "token_proof is required")
	}
	return nil
}

// ValidateHelloAck 校验 HELLO_ACK（客户端侧）。
// 初始 credit 非正值 = 协议错误；ack_mode 零值拒绝；limits 非正值拒绝。
func ValidateHelloAck(a *corepb.HelloAck) error {
	if a == nil {
		return NewError(ErrCodeBadHandshake, "nil hello_ack")
	}
	if a.GetAckMode() != corepb.AckMode_ACK_MODE_ACCEPTED_ONLY && a.GetAckMode() != corepb.AckMode_ACK_MODE_DURABLE {
		return NewError(ErrCodeAckModeBad, fmt.Sprintf("invalid ack_mode %v", a.GetAckMode()))
	}
	// 恶意/受损服务端防线：selected_capabilities 条数与单条长度钳制（服务端注册
	// 能力集 ≤8）。CodecFor 对超长列表仅做前缀匹配，但 Decode 分配先于校验——
	// 与 HELLO.capabilities 同一裁决。
	if len(a.GetSelectedCapabilities()) > MaxHelloCaps {
		return NewError(ErrCodeBadHandshake, fmt.Sprintf("selected_capabilities exceeds maximum %d entries", MaxHelloCaps))
	}
	for _, c := range a.GetSelectedCapabilities() {
		if len(c) > MaxHelloCapLen {
			return NewError(ErrCodeBadHandshake, fmt.Sprintf("selected_capability exceeds maximum length %d", MaxHelloCapLen))
		}
	}
	if a.GetCredits().GetBatches() == 0 || a.GetCredits().GetBytes() == 0 {
		return NewError(ErrCodeCreditInvalid, "initial credits must be positive")
	}
	if a.GetLimits().GetMaxFrameBytes() == 0 || a.GetLimits().GetMaxBatchBytes() == 0 {
		return NewError(ErrCodeBadHandshake, "limits must be positive")
	}
	if len(a.GetFinished()) == 0 {
		return NewError(ErrCodeBadHandshake, "finished mac is required")
	}
	if a.GetExpiryUnix() <= 0 {
		return NewError(ErrCodeBadHandshake, "expiry_unix must be > 0")
	}
	return nil
}

// validateHelloMetaField 校验 HELLO meta 的键/值（长度 + 严格控制字符）。
func validateHelloMetaField(name, val string) error {
	if val == "" {
		return nil
	}
	if len(val) > MaxAgentIDLen {
		return NewError(ErrCodeBadHandshake, fmt.Sprintf("%s exceeds maximum length %d", name, MaxAgentIDLen))
	}
	if hasStrictControlChars(val) {
		return NewError(ErrCodeBadHandshake, name+" contains control characters")
	}
	return nil
}

// ValidateResultLevel 校验 RESULT level 合法（非零枚举值）。
func ValidateResultLevel(l corepb.ResultLevel) error {
	switch l {
	case corepb.ResultLevel_RESULT_LEVEL_ACCEPTED,
		corepb.ResultLevel_RESULT_LEVEL_DURABLE,
		corepb.ResultLevel_RESULT_LEVEL_REJECTED,
		corepb.ResultLevel_RESULT_LEVEL_RELEASED:
		return nil
	default:
		return NewError(ErrCodeResultLevelBad, fmt.Sprintf("invalid result level %v", l))
	}
}

// MarshalSignalBatchCodec / UnmarshalSignalBatchCodec 保留在 codec*.go。
