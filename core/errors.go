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
	// NumAuth 认证失败。语义属"安全"类，但状态机上紧随握手（HELLO→AUTH），故归协议段；
	// spec §13 的安全段 (8000-8099) 预留给传输层安全（TLS/TLCP 握手失败等）。
	NumAuth     = 3001 // 认证失败
	NumSession  = 3002 // 会话状态错误
	NumProtocol = 3003 // 协议违规（非法帧类型、非法状态转换）

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
	CodeConfig     = "ERR_CONFIG"
	CodeCredential = "ERR_CREDENTIAL" //#nosec G101 -- false positive: error code constant, not a credential

	// 连接/传输
	CodeTransport = "ERR_TRANSPORT"
	CodeTLS       = "ERR_TLS"
	CodeStream    = "ERR_STREAM"

	// 协议/会话
	CodeHandshake = "ERR_HANDSHAKE"
	CodeAuth      = "ERR_AUTH"
	CodeSession   = "ERR_SESSION"
	CodeProtocol  = "ERR_PROTOCOL"

	// 数据/业务
	CodeBatch      = "ERR_BATCH"
	CodeEnvelope   = "ERR_ENVELOPE"
	CodeValidation = "ERR_VALIDATION"
	CodeHMAC       = "ERR_HMAC"

	// 流控
	CodeWindowFull = "ERR_WINDOW_FULL"
	CodeThrottle   = "ERR_THROTTLE"

	// 存储
	CodeSpool = "ERR_SPOOL"

	// 版本
	CodeVersion = "ERR_VERSION"
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
	NumCode int    // 数字错误码，用于程序快速匹配
	Code    string // 字符串错误码，用于日志和线缆传输
	Message string // 描述
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
// Sentinel errors — 支持 errors.Is 按错误类别匹配
// ---------------------------------------------------------------------------
//
// 这些 sentinel 仅携带 NumCode。Error.Is 按 NumCode 比较，因此对任何由
// NewError/WrapError 创建的、NumCode 相同的错误，errors.Is 均返回 true。
//
// 用法：
//
//	if errors.Is(err, core.ErrSession) { ... }   // 推荐
//	// 等价于旧的数字比较：
//	// if core.GetErrorCode(err) == core.NumSession { ... }
//
// sentinel 本身不应直接返回给调用方（它是类别标记，不是具体错误）；
// 返回具体错误时仍用 NewError/WrapError 携带 Code 与 Message。
var (
	ErrConfig     = &Error{NumCode: NumConfig}
	ErrCredential = &Error{NumCode: NumCredential}

	ErrTransport = &Error{NumCode: NumTransport}
	ErrTLS       = &Error{NumCode: NumTLS}
	ErrStream    = &Error{NumCode: NumStream}

	ErrHandshake = &Error{NumCode: NumHandshake}
	ErrAuth      = &Error{NumCode: NumAuth}
	ErrSession   = &Error{NumCode: NumSession}
	ErrProtocol  = &Error{NumCode: NumProtocol}

	ErrBatch      = &Error{NumCode: NumBatch}
	ErrEnvelope   = &Error{NumCode: NumEnvelope}
	ErrValidation = &Error{NumCode: NumValidation}
	ErrHMAC       = &Error{NumCode: NumHMAC}

	ErrWindowFull = &Error{NumCode: NumWindowFull}
	ErrThrottle   = &Error{NumCode: NumThrottle}

	ErrSpool = &Error{NumCode: NumSpool}

	ErrVersion = &Error{NumCode: NumVersion}
)

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
