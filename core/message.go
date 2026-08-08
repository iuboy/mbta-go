package core

import (
	"fmt"

	corepb "github.com/iuboy/mbta-go/corepb"
	"google.golang.org/protobuf/proto"
)

// 控制面/数据面消息类型 = corepb 生成类型（core spec §4 / §9.5）。
//
// 与旧 JSON struct 的差异：session_id / chunk_id / nonce / 密钥为原生 bytes（去 base64）；
// chunk_id 为 ULID 16B。字段号发布后不可改（§1.4）。
type (
	HelloMessage      = corepb.HelloMessage
	HelloAckMessage   = corepb.HelloAckMessage
	AuthMessage       = corepb.AuthMessage
	AuthOKMessage     = corepb.AuthOKMessage
	AuthFailMessage   = corepb.AuthFailMessage
	BatchMessage      = corepb.BatchMessage
	DatagramMessage   = corepb.DatagramMessage
	AckMessage        = corepb.AckMessage
	NackMessage       = corepb.NackMessage
	PartialAckMessage = corepb.PartialAckMessage
	RejectedEvent     = corepb.RejectedEvent
	WindowMessage     = corepb.WindowMessage
	ThrottleMessage   = corepb.ThrottleMessage
	PingMessage       = corepb.PingMessage
	PongMessage       = corepb.PongMessage
	CloseMessage      = corepb.CloseMessage
	ErrorMessage      = corepb.ErrorMessage

	// AckMode 重导出，便于 core 包调用方引用。
	AckMode = corepb.AckMode
)

// knownFrameVersions 是当前已知的帧版本集合（用于 HELLO.frame_version 校验）。
// 新增版本时在此登记，防止服务端接受未声明的版本（降级攻击面）。
var knownFrameVersions = map[uint32]bool{1: true}

// ValidateHello 校验 HELLO。agent_id 必填且须通过长度/控制字符校验；
// frame_version 必须是已支持的版本。
func ValidateHello(m *HelloMessage) error {
	if m == nil || m.GetAgentId() == "" {
		return NewError(ErrCodeValidation, "agent_id is required")
	}
	if err := validateAgentID(m.GetAgentId()); err != nil {
		return err
	}
	// 校验 frame_version：0 或未知版本一律拒绝，避免降级攻击或后续编解码异常。
	if !knownFrameVersions[m.GetFrameVersion()] {
		return NewError(ErrCodeValidation, fmt.Sprintf("unsupported frame_version: %d", m.GetFrameVersion()))
	}
	return nil
}

// ValidateAuth 校验 AUTH。agent_id / session_id / auth_nonce 必填。
// token 在非 tokenless 模式下必填——但 tokenless 模式（TokenResolver）允许客户端
// 省略 token，由服务端通过 agent_id 反查。token 必填校验由调用方（handleAuth）
// 在确认不支持 tokenless 后执行，而非在此处无条件拒绝。
// agent_id 须通过长度/控制字符校验（日志注入防护）。
func ValidateAuth(m *AuthMessage) error {
	if m == nil {
		return NewError(ErrCodeValidation, "nil auth message")
	}
	if m.GetAgentId() == "" {
		return NewError(ErrCodeValidation, "agent_id is required")
	}
	if err := validateAgentID(m.GetAgentId()); err != nil {
		return err
	}
	if len(m.GetSessionId()) == 0 {
		return NewError(ErrCodeValidation, "session_id is required")
	}
	if len(m.GetAuthNonce()) == 0 {
		return NewError(ErrCodeValidation, "auth_nonce is required")
	}
	// 注意：token 必填校验已移至 handleAuth，以支持 tokenless AUTH（TokenResolver）。
	// handleAuth 在 resolveAuthToken 之后、若 token 仍为空则 failAuth。
	return nil
}

// ValidateBatch 校验 BATCH。seq>=1，chunk_id（ULID 16B）必填，batch 非空。
func ValidateBatch(m *BatchMessage) error {
	if m == nil {
		return NewError(ErrCodeValidation, "nil batch message")
	}
	if m.GetSeq() == 0 {
		return NewError(ErrCodeValidation, "seq must be >= 1")
	}
	if len(m.GetChunkId()) != 16 {
		return NewError(ErrCodeValidation, fmt.Sprintf("chunk_id must be exactly 16 bytes (ULID), got %d", len(m.GetChunkId())))
	}
	if len(m.GetBatch()) == 0 {
		return NewError(ErrCodeValidation, "batch must not be empty")
	}
	return nil
}

// Encode proto 序列化消息。
func Encode(m proto.Message) ([]byte, error) {
	if m == nil {
		return nil, NewError(ErrCodeProtocol, "encode: nil message")
	}
	return proto.Marshal(m)
}

// Decode proto 反序列化到 m。
func Decode(data []byte, m proto.Message) error {
	if m == nil {
		return NewError(ErrCodeProtocol, "decode: nil target message")
	}
	if err := proto.Unmarshal(data, m); err != nil {
		return WrapError(ErrCodeProtocol, "decode", err)
	}
	return nil
}
