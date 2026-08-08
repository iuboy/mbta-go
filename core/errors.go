package core

import (
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
	NumProtocol  = 3003 // 非法协议（非法帧类型、非法状态转换）

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
// ErrorCode — 错误码类型 + register()
// ---------------------------------------------------------------------------

// ErrorCode 绑定数字码 Num 与字符串码 Code 为单一值。
// 所有错误码（大类 + 具体原因）通过 register() 注册到 registry，加码只需一行 var。
type ErrorCode struct {
	Num  int
	Code string
}

// registry 是所有已注册错误码的查找表，由 register() 在包初始化时填充。
// MatchWireCode 据此把对端 wire 字符串反查回 ErrorCode。
var registry = map[string]ErrorCode{}

// register 把 ErrorCode 注册到 registry 并原样返回，支持 var X = register(ErrorCode{...})。
// 包初始化期 fail-fast：空 Code 或重复码 panic。
func register(c ErrorCode) ErrorCode {
	if c.Code == "" {
		panic("errors: register empty Code")
	}
	if _, dup := registry[c.Code]; dup {
		panic("errors: duplicate Code " + c.Code)
	}
	registry[c.Code] = c
	return c
}

// 错误码 wire 字符串常量（snake_case，实际写入线缆 Code 字段的值）。
// 大类码以 _error / _unavailable 后缀明确标识"这是一个错误"，而非无定语名词。
// 具体码描述具体原因（如 hmac_mismatch、invalid_token），自解释。
// 导出供需要直接比对 wire 字符串的场景使用（如收帧匹配、测试断言）。
const (
	// 通用
	CodeConfig     = "invalid_config"
	CodeCredential = "missing_credentials"
	CodeTransport  = "transport_error"
	CodeTLS        = "tls_error"
	CodeStream     = "stream_error"
	CodeHandshake  = "handshake_error"
	CodeAuth       = "auth_error"
	CodeSession    = "session_error"
	CodeProtocol   = "protocol_error"
	CodeBatch      = "batch_error"
	CodeEnvelope   = "envelope_error"
	CodeValidation = "validation_error"
	CodeHMAC       = "hmac_error"
	CodeWindowFull = "window_full"
	CodeThrottle   = "throttled"
	CodeSpool      = "spool_error"
	CodeVersion    = "unsupported_version"

	// Auth（握手期 AUTH_FAIL）
	CodeInvalidAuth       = "invalid_auth"
	CodeInvalidToken      = "invalid_token"
	CodeTooManyAttempts   = "too_many_attempts"
	CodeChallengeMismatch = "challenge_mismatch"
	CodeAgentNotFound     = "agent_not_found"

	// Session（连接级）
	CodeSessionExpired = "session_expired"
	CodeRedirected     = "redirected"

	// Stream
	CodeNoStreams = "no_streams"

	// Envelope / HMAC（BATCH 处理期 NACK）
	CodeHMACMismatch         = "hmac_mismatch"
	CodeEnvelopeOpenError    = "envelope_open_error"
	CodeEnvelopeAlgoMismatch = "envelope_algo_mismatch"

	// Batch（BATCH 处理期 NACK）
	CodeBatchTooLarge = "batch_too_large"
	CodeInvalidBatch  = "invalid_batch"
	CodeTooManyEvents = "too_many_events"

	// Validation（BATCH 内容校验 NACK）
	CodeBatchValidation    = "batch_validation"
	CodeBatchTraceContext  = "batch_trace_context"
	CodeInvalidSignalBatch = "invalid_signal_batch"
	CodeSignalValidation   = "signal_validation"

	// Flow control（THROTTLE）
	CodeWindowExceeded = "window_exceeded"
	CodeTooManyBatches = "too_many_batches"
	CodeQueuePressure  = "queue_pressure"

	// Protocol（ERROR 帧）
	CodeDecodeFailed       = "decode_failed"
	CodeUnsupportedMessage = "unsupported_message"
	CodeInternalError      = "internal_error"
)

// 全部错误码（大类 + 具体 wire 码）。每个码定义即注册，加码只加一行。
var (
	// 大类
	ErrCodeConfig     = register(ErrorCode{NumConfig, CodeConfig})
	ErrCodeCredential = register(ErrorCode{NumCredential, CodeCredential})
	ErrCodeTransport  = register(ErrorCode{NumTransport, CodeTransport})
	ErrCodeTLS        = register(ErrorCode{NumTLS, CodeTLS})
	ErrCodeStream     = register(ErrorCode{NumStream, CodeStream})
	ErrCodeHandshake  = register(ErrorCode{NumHandshake, CodeHandshake})
	ErrCodeAuth       = register(ErrorCode{NumAuth, CodeAuth})
	ErrCodeSession    = register(ErrorCode{NumSession, CodeSession})
	ErrCodeProtocol   = register(ErrorCode{NumProtocol, CodeProtocol})
	ErrCodeBatch      = register(ErrorCode{NumBatch, CodeBatch})
	ErrCodeEnvelope   = register(ErrorCode{NumEnvelope, CodeEnvelope})
	ErrCodeValidation = register(ErrorCode{NumValidation, CodeValidation})
	ErrCodeHMAC       = register(ErrorCode{NumHMAC, CodeHMAC})
	ErrCodeWindowFull = register(ErrorCode{NumWindowFull, CodeWindowFull})
	ErrCodeThrottle   = register(ErrorCode{NumThrottle, CodeThrottle})
	ErrCodeSpool      = register(ErrorCode{NumSpool, CodeSpool})
	ErrCodeVersion    = register(ErrorCode{NumVersion, CodeVersion})

	// Auth（握手期 AUTH_FAIL）
	ErrCodeInvalidAuth       = register(ErrorCode{NumAuth, CodeInvalidAuth})
	ErrCodeInvalidToken      = register(ErrorCode{NumAuth, CodeInvalidToken})
	ErrCodeTooManyAttempts   = register(ErrorCode{NumAuth, CodeTooManyAttempts})
	ErrCodeChallengeMismatch = register(ErrorCode{NumAuth, CodeChallengeMismatch})
	ErrCodeAgentNotFound     = register(ErrorCode{NumAuth, CodeAgentNotFound})

	// Session（连接级）
	ErrCodeSessionExpired = register(ErrorCode{NumSession, CodeSessionExpired})
	ErrCodeRedirected     = register(ErrorCode{NumSession, CodeRedirected})

	// Stream
	ErrCodeNoStreams = register(ErrorCode{NumStream, CodeNoStreams})

	// Envelope / HMAC（BATCH 处理期 NACK）
	ErrCodeHMACMismatch         = register(ErrorCode{NumHMAC, CodeHMACMismatch})
	ErrCodeEnvelopeOpenError    = register(ErrorCode{NumEnvelope, CodeEnvelopeOpenError})
	ErrCodeEnvelopeAlgoMismatch = register(ErrorCode{NumEnvelope, CodeEnvelopeAlgoMismatch})

	// Batch（BATCH 处理期 NACK）
	ErrCodeBatchTooLarge = register(ErrorCode{NumBatch, CodeBatchTooLarge})
	ErrCodeInvalidBatch  = register(ErrorCode{NumBatch, CodeInvalidBatch})
	ErrCodeTooManyEvents = register(ErrorCode{NumBatch, CodeTooManyEvents})

	// Validation（BATCH 内容校验 NACK）
	ErrCodeBatchValidation    = register(ErrorCode{NumValidation, CodeBatchValidation})
	ErrCodeBatchTraceContext  = register(ErrorCode{NumValidation, CodeBatchTraceContext})
	ErrCodeInvalidSignalBatch = register(ErrorCode{NumValidation, CodeInvalidSignalBatch})
	ErrCodeSignalValidation   = register(ErrorCode{NumValidation, CodeSignalValidation})

	// Flow control（THROTTLE）
	ErrCodeWindowExceeded = register(ErrorCode{NumWindowFull, CodeWindowExceeded})
	ErrCodeTooManyBatches = register(ErrorCode{NumWindowFull, CodeTooManyBatches})
	ErrCodeQueuePressure  = register(ErrorCode{NumThrottle, CodeQueuePressure})

	// Protocol（ERROR 帧）
	ErrCodeDecodeFailed       = register(ErrorCode{NumProtocol, CodeDecodeFailed})
	ErrCodeUnsupportedMessage = register(ErrorCode{NumProtocol, CodeUnsupportedMessage})
	ErrCodeInternalError      = register(ErrorCode{NumProtocol, CodeInternalError})

	// ErrCodeUnknown 标识未注册的 wire 码（MatchWireCode 的 fallback），不注册。
	ErrCodeUnknown = ErrorCode{}
)

// MatchWireCode 把对端发来的 wire Code 字符串匹配到注册的 ErrorCode。
// 未注册返回 ErrCodeUnknown（Num=0），调用方可据此判断是否为未知码。
func MatchWireCode(code string) ErrorCode {
	if c, ok := registry[code]; ok {
		return c
	}
	return ErrCodeUnknown
}

// ---------------------------------------------------------------------------
// Error 类型 — MBTA 库的标准错误
// ---------------------------------------------------------------------------

// Error 是 MBTA 库的标准错误类型。内嵌 ErrorCode，Num/Code 经字段提升可直接访问（e.Num / e.Code）。
type Error struct {
	ErrorCode        // 嵌入：Num（程序匹配）、Code（日志/线缆）
	Message   string // 人类可读描述
	Detail    any    // 可选结构化详情（字段名/值、frame header 等），nil 不输出
	Err       error  // 可选的被包装错误
}

// Error 实现 error 接口。
func (e *Error) Error() string {
	out := fmt.Sprintf("[%d %s] %s", e.Num, e.Code, e.Message)
	if e.Detail != nil {
		out += fmt.Sprintf(":{%+v}", e.Detail)
	}
	if e.Err != nil {
		out += fmt.Sprintf(": %v", e.Err)
	}
	return out
}

// Unwrap 返回被包装的错误，支持 errors.As 链式查找。
func (e *Error) Unwrap() error { return e.Err }

// ---------------------------------------------------------------------------
// 构造函数（均基于 ErrorCode，避免手动配对 Num/Code）
// ---------------------------------------------------------------------------

// NewError 创建一个不包装其他错误的标准错误。
func NewError(c ErrorCode, msg string) *Error {
	return &Error{ErrorCode: c, Message: msg}
}

// WrapError 创建一个包装其他错误的标准错误。
func WrapError(c ErrorCode, msg string, err error) *Error {
	return &Error{ErrorCode: c, Message: msg, Err: err}
}

// ---------------------------------------------------------------------------
// 提取函数
// ---------------------------------------------------------------------------

// CodeOf 从 error 链中提取 *Error 的 Code 字符串；非 *Error 返回空串。
// 用于按 ErrorCode 匹配错误：if core.CodeOf(err) == core.ErrCodeHMACMismatch.Code { ... }
func CodeOf(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}
