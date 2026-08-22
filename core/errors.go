package core

import (
	"errors"
	"fmt"
)

// 错误码注册表（r3）：wire 上只传数字（Result.code / HelloNak.code / Abort.code），
// append-only：只增不改不复用。分组段位：1x 握手 / 2x 数据 / 3x 会话 / 4x 服务端。
const (
	CodeOK uint32 = 0

	CodeAuthFailed            uint32 = 10 // 未认证维度唯一码（防 agent/token 枚举 oracle）
	CodeUnsupportedProfile    uint32 = 12
	CodeUnsupportedCapability uint32 = 13
	CodeBadHandshakeMessage   uint32 = 14

	CodeBatchTooLarge     uint32 = 20 // 解压后 payload 超 limits.max_batch_bytes
	CodeBatchInvalid      uint32 = 21 // 含 Envelope.seq ≠ Batch.seq
	CodeDecompressLimit   uint32 = 22
	CodeEnvelopeOpenFail  uint32 = 23
	CodeWindowExceeded    uint32 = 24 // 协议违规，配合 ABORT
	CodeStaleEpoch        uint32 = 25 // 预留（票据演进项）
	CodeLedgerDivergence  uint32 = 26 // 预留（连接级致命）
	CodeResultLevelBad    uint32 = 27 // RESULT level 非法
	CodeAckModeBad        uint32 = 28 // HelloAck.ack_mode 非法
	CodeCreditInvalid     uint32 = 29 // CREDIT 帧非法
	CodeHelloEphInvalid   uint32 = 30 // 临时公钥格式/长度非法
	CodeHelloProofInvalid uint32 = 31 // token_proof 验证失败（对外与 10 同面，仅日志区分）

	CodeServerDraining uint32 = 32
	CodeInternal       uint32 = 40 // 服务端 reaper 合成 released 时使用
	CodeUnavailable    uint32 = 41
	CodeProtocolError  uint32 = 42 // 通用协议违规（未知 flags/类型错域等）
)

// ErrCode 是标准错误的错误码（Num=注册表数字；Name 仅供日志，不上 wire）。
type ErrCode struct {
	Num  uint32
	Name string
}

var (
	ErrCodeOK                 = ErrCode{CodeOK, "ok"}
	ErrCodeAuthFailed         = ErrCode{CodeAuthFailed, "auth_failed"}
	ErrCodeUnsupportedProfile = ErrCode{CodeUnsupportedProfile, "unsupported_profile"}
	ErrCodeUnsupportedCap     = ErrCode{CodeUnsupportedCapability, "unsupported_capability"}
	ErrCodeBadHandshake       = ErrCode{CodeBadHandshakeMessage, "bad_handshake_message"}
	ErrCodeBatchTooLarge      = ErrCode{CodeBatchTooLarge, "batch_too_large"}
	ErrCodeBatchInvalid       = ErrCode{CodeBatchInvalid, "batch_invalid"}
	ErrCodeDecompressLimit    = ErrCode{CodeDecompressLimit, "decompress_limit"}
	ErrCodeEnvelopeOpenFail   = ErrCode{CodeEnvelopeOpenFail, "envelope_open_failed"}
	ErrCodeWindowExceeded     = ErrCode{CodeWindowExceeded, "window_exceeded"}
	ErrCodeStaleEpoch         = ErrCode{CodeStaleEpoch, "stale_epoch"}
	ErrCodeLedgerDivergence   = ErrCode{CodeLedgerDivergence, "ledger_divergence"}
	ErrCodeResultLevelBad     = ErrCode{CodeResultLevelBad, "result_level_bad"}
	ErrCodeAckModeBad         = ErrCode{CodeAckModeBad, "ack_mode_bad"}
	ErrCodeCreditInvalid      = ErrCode{CodeCreditInvalid, "credit_invalid"}
	ErrCodeHelloEphInvalid    = ErrCode{CodeHelloEphInvalid, "hello_eph_invalid"}
	ErrCodeHelloProofInvalid  = ErrCode{CodeHelloProofInvalid, "hello_proof_invalid"}
	ErrCodeServerDraining     = ErrCode{CodeServerDraining, "server_draining"}
	ErrCodeInternal           = ErrCode{CodeInternal, "internal"}
	ErrCodeUnavailable        = ErrCode{CodeUnavailable, "unavailable"}
	ErrCodeProtocolError      = ErrCode{CodeProtocolError, "protocol_error"}
	ErrCodeUnknown            = ErrCode{^uint32(0), "unknown"}
)

// CodeName 反查错误码名称（日志用；未注册返回 "unknown"）。
func CodeName(c uint32) string {
	if e, ok := codeRegistry[c]; ok {
		return e.Name
	}
	return ErrCodeUnknown.Name
}

var codeRegistry = map[uint32]ErrCode{}

func init() {
	for _, e := range []ErrCode{
		ErrCodeOK, ErrCodeAuthFailed, ErrCodeUnsupportedProfile, ErrCodeUnsupportedCap,
		ErrCodeBadHandshake, ErrCodeBatchTooLarge, ErrCodeBatchInvalid, ErrCodeDecompressLimit,
		ErrCodeEnvelopeOpenFail, ErrCodeWindowExceeded, ErrCodeStaleEpoch, ErrCodeLedgerDivergence,
		ErrCodeResultLevelBad, ErrCodeAckModeBad, ErrCodeCreditInvalid, ErrCodeHelloEphInvalid,
		ErrCodeHelloProofInvalid, ErrCodeServerDraining, ErrCodeInternal, ErrCodeUnavailable,
		ErrCodeProtocolError,
	} {
		codeRegistry[e.Num] = e
	}
}

// Error 是 MBTA 库的标准错误类型。
type Error struct {
	Code    ErrCode
	Message string
	Detail  any
	Err     error
}

func (e *Error) Error() string {
	out := fmt.Sprintf("[%d %s] %s", e.Code.Num, e.Code.Name, e.Message)
	if e.Detail != nil {
		out += fmt.Sprintf(":{%+v}", e.Detail)
	}
	if e.Err != nil {
		out += fmt.Sprintf(": %v", e.Err)
	}
	return out
}

func (e *Error) Unwrap() error { return e.Err }

// NewError / WrapError 构造标准错误。
func NewError(c ErrCode, msg string) *Error { return &Error{Code: c, Message: msg} }
func WrapError(c ErrCode, msg string, err error) *Error {
	return &Error{Code: c, Message: msg, Err: err}
}

// CodeNumOf 从 error 链提取数字错误码；非 *Error 返回 unknown 哨兵。
func CodeNumOf(err error) uint32 {
	var e *Error
	if errors.As(err, &e) {
		return e.Code.Num
	}
	return ErrCodeUnknown.Num
}

// CodeOf 保留名称提取（内部用途）。非 *Error 返回空串。
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code.Name
	}
	return ""
}

// 本地错误码（不上 wire 的库内错误分类面；哨兵 Num 值域与 wire 注册表隔离）。
// 这些不是 wire 错误码的别名，是独立的本地分类——调用方按库错误来源分派处理。
var (
	// LocalConfig: 配置无效（NewServer/NewClient 构造期 fail-fast）。
	LocalConfig = ErrCode{^uint32(0) - 1, "invalid_config"}
	// LocalSession/LocalBatch/LocalHandshake/LocalStream: 库内错误大类。
	LocalSession   = ErrCode{^uint32(0) - 2, "session_error"}
	LocalBatch     = ErrCode{^uint32(0) - 3, "batch_error"}
	LocalHandshake = ErrCode{^uint32(0) - 4, "handshake_error"}
	LocalTransport = ErrCode{^uint32(0) - 5, "transport_error"}
	LocalTLS       = ErrCode{^uint32(0) - 6, "tls_error"}
	LocalStream    = ErrCode{^uint32(0) - 7, "stream_error"}
	// LocalCredential: 凭证加载/校验失败（binding 层 TLS 配置常用）。
	LocalCredential = ErrCode{^uint32(0) - 8, "invalid_credential"}
)

// 旧名 → 新名迁移（破坏性重构收尾：别名最终删除，调用方全部改用 Local*）。
var (
	ErrCodeProtocol   = ErrCodeProtocolError
	ErrCodeStream     = LocalStream
	ErrCodeConfig     = LocalConfig
	ErrCodeSession    = LocalSession
	ErrCodeBatch      = LocalBatch
	ErrCodeHandshake  = LocalHandshake
	ErrCodeTransport  = LocalTransport
	ErrCodeTLS        = LocalTLS
	ErrCodeCredential = LocalCredential
)
