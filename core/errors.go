package core

// Protocol error codes used in MBTA frame-level error reporting.
// These are string codes carried on the wire, not Go error values.
// Use the Code prefix to distinguish from error-typed variables (ErrXxx).
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
