package core

import (
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
