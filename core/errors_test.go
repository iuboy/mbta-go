package core

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestErrorCodeConstants tests that all error code constants are correctly defined.
func TestErrorCodeConstants(t *testing.T) {
	codes := []string{
		CodeUnsupportedVersion,
		CodeUnsupportedCapability,
		CodeUnsupportedMessage,
		CodeUnsupportedFlag,
		CodeInvalidMagic,
		CodeInvalidFrame,
		CodeFrameTooLarge,
		CodeCRCMismatch,
		CodeDecodeFailed,
		CodeAuthRequired,
		CodeAuthFailed,
		CodeSessionExpired,
		CodeHMACFailed,
		CodeDecryptFailed,
		CodeDecompressFailed,
		CodeBatchTooLarge,
		CodeEventTooLarge,
		CodeRateLimited,
		CodeServerOverloaded,
		CodeDuplicateChunk,
		CodeDuplicateInflight,
		CodeEnvelopeMismatch,
		CodeForbiddenTag,
		CodeForbiddenSource,
		CodeForbiddenEvent,
	}

	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			if code == "" {
				t.Errorf("Error code constant should not be empty")
			}
			// All error codes should start with ERR_
			if !strings.HasPrefix(code, "ERR_") {
				t.Errorf("Error code should start with 'ERR_', got %q", code)
			}
		})
	}
}

// TestErrorCodesByCategory tests error codes grouped by category.
func TestErrorCodesByCategory(t *testing.T) {
	// Version/capability errors
	versionErrors := []string{
		CodeUnsupportedVersion,
		CodeUnsupportedCapability,
		CodeUnsupportedMessage,
		CodeUnsupportedFlag,
	}
	t.Run("version and capability errors", func(t *testing.T) {
		for _, code := range versionErrors {
			if !strings.Contains(code, "UNSUPPORTED") {
				t.Errorf("Version/capability error should contain 'UNSUPPORTED', got %q", code)
			}
		}
	})

	// Frame errors
	frameErrors := []string{
		CodeInvalidMagic,
		CodeInvalidFrame,
		CodeFrameTooLarge,
		CodeCRCMismatch,
		CodeDecodeFailed,
	}
	t.Run("frame errors", func(t *testing.T) {
		for _, code := range frameErrors {
			if !strings.Contains(code, "MAGIC") && !strings.Contains(code, "FRAME") &&
				!strings.Contains(code, "LARGE") && !strings.Contains(code, "CRC") &&
				!strings.Contains(code, "DECODE") {
				t.Errorf("Frame error should contain relevant keyword, got %q", code)
			}
		}
	})

	// Authentication errors
	authErrors := []string{
		CodeAuthRequired,
		CodeAuthFailed,
		CodeSessionExpired,
	}
	t.Run("authentication errors", func(t *testing.T) {
		for _, code := range authErrors {
			if !strings.Contains(code, "AUTH") && code != CodeSessionExpired {
				t.Errorf("Auth error should contain 'AUTH', got %q", code)
			}
		}
	})

	// Cryptography errors
	cryptoErrors := []string{
		CodeHMACFailed,
		CodeDecryptFailed,
		CodeDecompressFailed,
	}
	t.Run("cryptography errors", func(t *testing.T) {
		for _, code := range cryptoErrors {
			if !strings.Contains(code, "HMAC") && !strings.Contains(code, "DECRYPT") &&
				!strings.Contains(code, "DECOMPRESS") {
				t.Errorf("Crypto error should contain relevant keyword, got %q", code)
			}
		}
	})

	// Size errors
	sizeErrors := []string{
		CodeBatchTooLarge,
		CodeEventTooLarge,
	}
	t.Run("size errors", func(t *testing.T) {
		for _, code := range sizeErrors {
			if !strings.Contains(code, "TOO_LARGE") {
				t.Errorf("Size error should contain 'TOO_LARGE', got %q", code)
			}
		}
	})

	// Rate limiting errors
	rateErrors := []string{
		CodeRateLimited,
		CodeServerOverloaded,
	}
	t.Run("rate limiting errors", func(t *testing.T) {
		for _, code := range rateErrors {
			if !strings.Contains(code, "LIMITED") && !strings.Contains(code, "OVERLOADED") {
				t.Errorf("Rate error should contain 'LIMITED' or 'OVERLOADED', got %q", code)
			}
		}
	})

	// Deduplication errors
	dedupErrors := []string{
		CodeDuplicateChunk,
		CodeDuplicateInflight,
	}
	t.Run("deduplication errors", func(t *testing.T) {
		for _, code := range dedupErrors {
			if !strings.Contains(code, "DUPLICATE") {
				t.Errorf("Dedup error should contain 'DUPLICATE', got %q", code)
			}
		}
	})

	// Validation errors
	validationErrors := []string{
		CodeEnvelopeMismatch,
		CodeForbiddenTag,
		CodeForbiddenSource,
		CodeForbiddenEvent,
	}
	t.Run("validation errors", func(t *testing.T) {
		for _, code := range validationErrors {
			if !strings.Contains(code, "MISMATCH") && !strings.Contains(code, "FORBIDDEN") {
				t.Errorf("Validation error should contain 'MISMATCH' or 'FORBIDDEN', got %q", code)
			}
		}
	})
}

// TestErrorCodeUniqueness tests that all error codes are unique.
func TestErrorCodeUniqueness(t *testing.T) {
	codes := map[string]bool{
		CodeUnsupportedVersion:    true,
		CodeUnsupportedCapability: true,
		CodeUnsupportedMessage:    true,
		CodeUnsupportedFlag:       true,
		CodeInvalidMagic:          true,
		CodeInvalidFrame:          true,
		CodeFrameTooLarge:         true,
		CodeCRCMismatch:           true,
		CodeDecodeFailed:          true,
		CodeAuthRequired:          true,
		CodeAuthFailed:            true,
		CodeSessionExpired:        true,
		CodeHMACFailed:            true,
		CodeDecryptFailed:         true,
		CodeDecompressFailed:      true,
		CodeBatchTooLarge:         true,
		CodeEventTooLarge:         true,
		CodeRateLimited:           true,
		CodeServerOverloaded:      true,
		CodeDuplicateChunk:        true,
		CodeDuplicateInflight:     true,
		CodeEnvelopeMismatch:      true,
		CodeForbiddenTag:          true,
		CodeForbiddenSource:       true,
		CodeForbiddenEvent:        true,
	}

	expectedCount := 25
	if len(codes) != expectedCount {
		t.Errorf("Expected %d unique error codes, got %d", expectedCount, len(codes))
	}
}

// TestErrorCodeFormats tests that error codes follow expected format.
func TestErrorCodeFormats(t *testing.T) {
	codes := []string{
		CodeUnsupportedVersion,
		CodeUnsupportedCapability,
		CodeInvalidMagic,
		CodeFrameTooLarge,
		CodeCRCMismatch,
		CodeAuthFailed,
		CodeRateLimited,
		CodeDuplicateChunk,
	}

	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			// Should be uppercase with underscores
			if code != strings.ToUpper(code) {
				t.Errorf("Error code should be uppercase, got %q", code)
			}
			// Should start with ERR_
			if !strings.HasPrefix(code, "ERR_") {
				t.Errorf("Error code should start with 'ERR_', got %q", code)
			}
			// Should not contain spaces
			if strings.ContainsAny(code, " ") {
				t.Errorf("Error code should not contain spaces, got %q", code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Error 类型测试
// ---------------------------------------------------------------------------

func TestMBTAError_Error(t *testing.T) {
	e := NewError(NumConfig, CodeConfig, "invalid config")
	want := "[1000 ERR_CONFIG] invalid config"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestMBTAError_ErrorWrapped(t *testing.T) {
	inner := fmt.Errorf("listen failed")
	e := WrapError(NumTransport, CodeTransport, "dial QUIC", inner)
	want := "[2000 ERR_TRANSPORT] dial QUIC: listen failed"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestMBTAError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("base error")
	e := WrapError(NumTLS, CodeTLS, "tls failed", inner)
	if !errors.Is(e, inner) {
		t.Error("Unwrap should return inner error")
	}
}

func TestMBTAError_Is(t *testing.T) {
	e1 := NewError(NumAuth, CodeAuth, "auth failed")
	e2 := NewError(NumAuth, CodeAuth, "different message")
	e3 := NewError(NumTransport, CodeTransport, "transport")

	if !errors.Is(e1, e2) {
		t.Error("same NumCode should match via errors.Is")
	}
	if errors.Is(e1, e3) {
		t.Error("different NumCode should not match")
	}
}

func TestMBTAError_IsWrapped(t *testing.T) {
	inner := fmt.Errorf("connection refused")
	e := WrapError(NumTransport, CodeTransport, "dial", inner)

	if !errors.Is(e, NewError(NumTransport, CodeTransport, "")) {
		t.Error("wrapped error should match by NumCode")
	}
	if !errors.Is(e, inner) {
		t.Error("wrapped error should match inner via errors.Is")
	}
}

// TestSentinelErrors verifies the package-level sentinel errors enable
// idiomatic errors.Is matching by category, including through wrapping.
func TestSentinelErrors(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		target  error
		matches bool
	}{
		{"session matches sentinel", NewError(NumSession, CodeSession, "bad state"), ErrSession, true},
		{"transport matches sentinel", WrapError(NumTransport, CodeTransport, "dial", fmt.Errorf("refused")), ErrTransport, true},
		{"auth matches through wrap", WrapError(NumAuth, CodeAuth, "token", fmt.Errorf("expired")), ErrAuth, true},
		{"config matches sentinel", NewError(NumConfig, CodeConfig, "missing"), ErrConfig, true},
		{"validation matches sentinel", NewError(NumValidation, CodeValidation, "too long"), ErrValidation, true},
		// Different category must NOT match.
		{"transport does not match session", NewError(NumTransport, CodeTransport, "dial"), ErrSession, false},
		{"auth does not match config", WrapError(NumAuth, CodeAuth, "tok", nil), ErrConfig, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := errors.Is(tc.err, tc.target); got != tc.matches {
				t.Errorf("errors.Is(%v, %v) = %v, want %v", tc.err, tc.target, got, tc.matches)
			}
		})
	}
}

func TestGetErrorCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"standard error", fmt.Errorf("plain error"), 0},
		{"mbta error", NewError(NumSpool, CodeSpool, "spool failed"), NumSpool},
		{"wrapped mbta", WrapError(NumAuth, CodeAuth, "auth", fmt.Errorf("bad token")), NumAuth},
		{"double wrapped", fmt.Errorf("outer: %w", WrapError(NumBatch, CodeBatch, "batch", fmt.Errorf("inner"))), NumBatch},
		{"nil", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetErrorCode(tt.err); got != tt.want {
				t.Errorf("GetErrorCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestGetErrorCodeString(t *testing.T) {
	e := WrapError(NumEnvelope, CodeEnvelope, "gzip failed", fmt.Errorf("compress error"))
	if got := GetErrorCodeString(e); got != CodeEnvelope {
		t.Errorf("GetErrorCodeString() = %q, want %q", got, CodeEnvelope)
	}
	if got := GetErrorCodeString(fmt.Errorf("plain")); got != "" {
		t.Errorf("GetErrorCodeString(plain) = %q, want empty", got)
	}
}

func TestNumCodeRanges(t *testing.T) {
	tests := []struct {
		code int
		min  int
		max  int
		cat  string
	}{
		{NumConfig, 1000, 1099, "config"},
		{NumCredential, 1000, 1099, "config"},
		{NumTransport, 2000, 2099, "transport"},
		{NumTLS, 2000, 2099, "transport"},
		{NumStream, 2000, 2099, "transport"},
		{NumHandshake, 3000, 3099, "protocol"},
		{NumAuth, 3000, 3099, "protocol"},
		{NumSession, 3000, 3099, "protocol"},
		{NumProtocol, 3000, 3099, "protocol"},
		{NumBatch, 4000, 4099, "data"},
		{NumEnvelope, 4000, 4099, "data"},
		{NumValidation, 4000, 4099, "data"},
		{NumHMAC, 4000, 4099, "data"},
		{NumWindowFull, 5000, 5099, "flow"},
		{NumThrottle, 5000, 5099, "flow"},
		{NumSpool, 6000, 6099, "storage"},
		{NumVersion, 7000, 7099, "version"},
	}
	for _, tt := range tests {
		if tt.code < tt.min || tt.code > tt.max {
			t.Errorf("%s (%d) not in range %d-%d (%s)", tt.cat, tt.code, tt.min, tt.max, tt.cat)
		}
	}
}
