package core

import (
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// 数字错误码 — 用于程序快速匹配（switch / map 查找）
// ---------------------------------------------------------------------------

const (
	// 配置/初始化 (1000-1099)
	NumConfig     = 1000 // 配置无效
	NumCredential = 1001 // 凭据缺失或无效

	// 连接/传输 (2000-2099)
	NumTransport = 2000 // 传输层错误（QUIC/TCP 连接失败）
	NumTLS       = 2001 // TLS 配置或握手失败
	NumStream    = 2002 // 流操作失败

	// 协议/会话 (3000-3099)
	NumHandshake = 3000 // 握手失败
	NumAuth      = 3001 // 认证失败
	NumSession   = 3002 // 会话状态错误
	NumProtocol  = 3003 // 协议违规（非法帧类型、非法状态转换）

	// 数据/业务 (4000-4099)
	NumBatch      = 4000 // 批次处理失败
	NumEnvelope   = 4001 // 信封编解码失败
	NumValidation = 4002 // 数据校验失败
	NumHMAC       = 4003 // HMAC 验证失败

	// 流控 (5000-5099)
	NumWindowFull = 5000 // 流控窗口已满
	NumThrottle   = 5001 // 被限流

	// 存储 (6000-6099)
	NumSpool = 6000 // Spool 存储错误

	// 版本 (7000-7099)
	NumVersion = 7000 // 版本不支持
)

// ---------------------------------------------------------------------------
// 字符串错误码 — 用于日志和线缆传输
// ---------------------------------------------------------------------------

const (
	// 配置/初始化
	ErrConfig     = "ERR_CONFIG"
	ErrCredential = "ERR_CREDENTIAL" //#nosec G101 -- false positive: error code constant, not a credential

	// 连接/传输
	ErrTransport = "ERR_TRANSPORT"
	ErrTLS       = "ERR_TLS"
	ErrStream    = "ERR_STREAM"

	// 协议/会话
	ErrHandshake = "ERR_HANDSHAKE"
	ErrAuth      = "ERR_AUTH"
	ErrSession   = "ERR_SESSION"
	ErrProtocol  = "ERR_PROTOCOL"

	// 数据/业务
	ErrBatch      = "ERR_BATCH"
	ErrEnvelope   = "ERR_ENVELOPE"
	ErrValidation = "ERR_VALIDATION"
	ErrHMAC       = "ERR_HMAC"

	// 流控
	ErrWindowFull = "ERR_WINDOW_FULL"
	ErrThrottle   = "ERR_THROTTLE"

	// 存储
	ErrSpool = "ERR_SPOOL"

	// 版本
	ErrVersion = "ERR_VERSION"
)

// ---------------------------------------------------------------------------
// 协议层线缆错误码（用于 ErrorMessage 帧的 Code 字段）
// ---------------------------------------------------------------------------

const (
	CodeUnsupportedVersion    = "ERR_UNSUPPORTED_VERSION"
	CodeUnsupportedCapability = "ERR_UNSUPPORTED_CAPABILITY"
	CodeUnsupportedMessage    = "ERR_UNSUPPORTED_MESSAGE"
	CodeUnsupportedFlag       = "ERR_UNSUPPORTED_FLAG"
	CodeInvalidMagic          = "ERR_INVALID_MAGIC"
	CodeInvalidFrame          = "ERR_INVALID_FRAME"
	CodeFrameTooLarge         = "ERR_FRAME_TOO_LARGE"
	CodeCRCMismatch           = "ERR_CRC_MISMATCH"
	CodeDecodeFailed          = "ERR_DECODE_FAILED"
	CodeAuthRequired          = "ERR_AUTH_REQUIRED"
	CodeAuthFailed            = "ERR_AUTH_FAILED"
	CodeSessionExpired        = "ERR_SESSION_EXPIRED"
	CodeHMACFailed            = "ERR_HMAC_FAILED"
	CodeDecryptFailed         = "ERR_DECRYPT_FAILED"
	CodeDecompressFailed      = "ERR_DECOMPRESS_FAILED"
	CodeBatchTooLarge         = "ERR_BATCH_TOO_LARGE"
	CodeEventTooLarge         = "ERR_EVENT_TOO_LARGE"
	CodeRateLimited           = "ERR_RATE_LIMITED"
	CodeServerOverloaded      = "ERR_SERVER_OVERLOADED"
	CodeDuplicateChunk        = "ERR_DUPLICATE_CHUNK"
	CodeDuplicateInflight     = "ERR_DUPLICATE_INFLIGHT"
	CodeEnvelopeMismatch      = "ERR_ENVELOPE_MISMATCH"
	CodeForbiddenTag          = "ERR_FORBIDDEN_TAG"
	CodeForbiddenSource       = "ERR_FORBIDDEN_SOURCE"
	CodeForbiddenEvent        = "ERR_FORBIDDEN_EVENT"
)

// ---------------------------------------------------------------------------
// Error 类型 — MBTA 库的标准错误
// ---------------------------------------------------------------------------

// Error 是 MBTA 库的标准错误类型，携带数字错误码和字符串错误码。
type Error struct {
	NumCode int    // 数字错误码，用于程序快速匹配（switch、map）
	Code    string // 字符串错误码，用于日志和线缆传输
	Message string // 人类可读描述
	Err     error  // 可选的被包装错误
}

// Error 实现 error 接口。
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%d %s] %s: %v", e.NumCode, e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%d %s] %s", e.NumCode, e.Code, e.Message)
}

// Unwrap 返回被包装的错误，支持 errors.As/Is 链式查找。
func (e *Error) Unwrap() error { return e.Err }

// Is 支持 errors.Is 匹配：当 target 也是 *Error 时比较 NumCode。
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.NumCode == t.NumCode && t.NumCode != 0
}

// ---------------------------------------------------------------------------
// 构造函数
// ---------------------------------------------------------------------------

// NewError 创建一个不包装其他错误的标准错误。
func NewError(numCode int, code, msg string) *Error {
	return &Error{NumCode: numCode, Code: code, Message: msg}
}

// WrapError 创建一个包装其他错误的标准错误。
func WrapError(numCode int, code, msg string, err error) *Error {
	return &Error{NumCode: numCode, Code: code, Message: msg, Err: err}
}

// ---------------------------------------------------------------------------
// 提取函数
// ---------------------------------------------------------------------------

// GetErrorCode 从 error 链中提取数字错误码。
// 返回 0 如果链中没有 *Error。
func GetErrorCode(err error) int {
	e, ok := errors.AsType[*Error](err)
	if ok {
		return e.NumCode
	}
	return 0
}

// GetErrorCodeString 从 error 链中提取字符串错误码。
// 返回空字符串如果链中没有 *Error。
func GetErrorCodeString(err error) string {
	e, ok := errors.AsType[*Error](err)
	if ok {
		return e.Code
	}
	return ""
}
