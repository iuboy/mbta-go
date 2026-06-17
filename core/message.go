package core

import (
	"fmt"

	corepb "github.com/iuboy/mbta-go/corepb"
	"google.golang.org/protobuf/proto"
)

// r2 控制面/数据面消息类型 = corepb 生成类型（core spec §4 / §9.5）。
//
// 与旧 JSON struct 的差异：session_id / chunk_id / nonce / 密钥为原生 bytes（去 base64）；
// chunk_id 为 ULID 16B。字段号即 wire 稳定性契约（§1.4 只追加纪律）。
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

// ValidateHello 校验 HELLO。agent_id 必填。
func ValidateHello(m *HelloMessage) error {
	if m == nil || m.GetAgentId() == "" {
		return NewError(NumValidation, CodeValidation, "agent_id is required")
	}
	return nil
}

// ValidateHelloAck 校验 HELLO_ACK。session_id 必填。
func ValidateHelloAck(m *HelloAckMessage) error {
	if m == nil || len(m.GetSessionId()) == 0 {
		return NewError(NumValidation, CodeValidation, "session_id is required")
	}
	return nil
}

// ValidateAuth 校验 AUTH。agent_id / session_id / auth_nonce 必填。
func ValidateAuth(m *AuthMessage) error {
	if m == nil {
		return NewError(NumValidation, CodeValidation, "nil auth message")
	}
	if m.GetAgentId() == "" {
		return NewError(NumValidation, CodeValidation, "agent_id is required")
	}
	if len(m.GetSessionId()) == 0 {
		return NewError(NumValidation, CodeValidation, "session_id is required")
	}
	if len(m.GetAuthNonce()) == 0 {
		return NewError(NumValidation, CodeValidation, "auth_nonce is required")
	}
	return nil
}

// ValidateBatch 校验 BATCH。seq>=1，chunk_id（ULID 16B）必填，batch 非空。
func ValidateBatch(m *BatchMessage) error {
	if m == nil {
		return NewError(NumValidation, CodeValidation, "nil batch message")
	}
	if m.GetSeq() == 0 {
		return NewError(NumValidation, CodeValidation, "seq must be >= 1")
	}
	if len(m.GetChunkId()) == 0 {
		return NewError(NumValidation, CodeValidation, "chunk_id is required")
	}
	if len(m.GetChunkId()) > 16 {
		return NewError(NumValidation, CodeValidation, fmt.Sprintf("chunk_id exceeds 16 bytes (ULID), got %d", len(m.GetChunkId())))
	}
	if len(m.GetBatch()) == 0 {
		return NewError(NumValidation, CodeValidation, "batch must not be empty")
	}
	return nil
}

// Encode proto 序列化消息。
func Encode(m proto.Message) ([]byte, error) {
	return proto.Marshal(m)
}

// Decode proto 反序列化到 m。
func Decode(data []byte, m proto.Message) error {
	return proto.Unmarshal(data, m)
}
