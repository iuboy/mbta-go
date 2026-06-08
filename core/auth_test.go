package core

import (
	"strings"
	"testing"
	"time"
)

// TestStaticTokenValidator tests the StaticTokenValidator implementation.
func TestStaticTokenValidator(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		tokens := map[string]string{
			"token-123": "agent-1",
			"token-456": "agent-2",
		}
		validator := NewStaticTokenValidator(tokens)

		identity, err := validator.Validate("token-123")
		if err != nil {
			t.Errorf("Validate() unexpected error: %v", err)
		}
		if identity.AgentID != "agent-1" {
			t.Errorf("AgentID = %q, want 'agent-1'", identity.AgentID)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		tokens := map[string]string{
			"token-123": "agent-1",
		}
		validator := NewStaticTokenValidator(tokens)

		identity, err := validator.Validate("invalid-token")
		if err != ErrInvalidToken {
			t.Errorf("Error = %v, want ErrInvalidToken", err)
		}
		if identity != nil {
			t.Error("Identity should be nil for invalid token")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		tokens := map[string]string{
			"token-123": "agent-1",
		}
		validator := NewStaticTokenValidator(tokens)

		identity, err := validator.Validate("")
		if err != ErrInvalidToken {
			t.Errorf("Error = %v, want ErrInvalidToken", err)
		}
		if identity != nil {
			t.Error("Identity should be nil for empty token")
		}
	})

	t.Run("empty token map", func(t *testing.T) {
		validator := NewStaticTokenValidator(map[string]string{})

		identity, err := validator.Validate("any-token")
		if err != ErrInvalidToken {
			t.Errorf("Error = %v, want ErrInvalidToken", err)
		}
		if identity != nil {
			t.Error("Identity should be nil for empty token map")
		}
	})
}

// TestAgentIdentity tests the AgentIdentity structure.
func TestAgentIdentity(t *testing.T) {
	t.Run("identity with permissions", func(t *testing.T) {
		identity := &AgentIdentity{
			AgentID: "agent-123",
			Permissions: []string{
				"read:events",
				"write:events",
			},
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		if identity.AgentID != "agent-123" {
			t.Errorf("AgentID = %q, want 'agent-123'", identity.AgentID)
		}
		if len(identity.Permissions) != 2 {
			t.Errorf("Permissions count = %d, want 2", len(identity.Permissions))
		}
		if identity.ExpiresAt.Before(time.Now()) {
			t.Error("ExpiresAt should be in the future")
		}
	})

	t.Run("identity with empty permissions", func(t *testing.T) {
		identity := &AgentIdentity{
			AgentID:     "agent-123",
			Permissions: []string{},
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		}

		if len(identity.Permissions) != 0 {
			t.Errorf("Permissions should be empty, got %d items", len(identity.Permissions))
		}
	})
}

// TestGenerateSessionKeys tests the GenerateSessionKeys function.
func TestGenerateSessionKeys(t *testing.T) {
	t.Run("generate session keys successfully", func(t *testing.T) {
		keys, err := GenerateSessionKeys()
		if err != nil {
			t.Errorf("GenerateSessionKeys() unexpected error: %v", err)
		}

		// Check KeyID is not empty
		if keys.KeyID == "" {
			t.Error("KeyID should not be empty")
		}

		// Check HMACKey length (32 bytes)
		if len(keys.HMACKey) != 32 {
			t.Errorf("HMACKey length = %d, want 32", len(keys.HMACKey))
		}

		// Check HMACAlgo
		if keys.HMACAlgo != "sha256" {
			t.Errorf("HMACAlgo = %q, want 'sha256'", keys.HMACAlgo)
		}
	})

	t.Run("generated keys are unique", func(t *testing.T) {
		keys1, err1 := GenerateSessionKeys()
		keys2, err2 := GenerateSessionKeys()

		if err1 != nil || err2 != nil {
			t.Errorf("GenerateSessionKeys() errors: %v, %v", err1, err2)
		}

		// KeyIDs should be different
		if keys1.KeyID == keys2.KeyID {
			t.Error("Generated KeyIDs should be unique")
		}

		// HMAC keys should be different
		if string(keys1.HMACKey) == string(keys2.HMACKey) {
			t.Error("Generated HMAC keys should be unique")
		}
	})
}

// TestSessionKeysHMACKeyBase64 tests the HMACKeyBase64 method.
func TestSessionKeysHMACKeyBase64(t *testing.T) {
	keys := &SessionKeys{
		KeyID:    "key-123",
		HMACKey:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		HMACAlgo: "sha256",
	}

	b64 := keys.HMACKeyBase64()
	if b64 == "" {
		t.Error("HMACKeyBase64 should not be empty")
	}

	// Base64 encoding of 8 bytes should be longer than 8
	if len(b64) <= 8 {
		t.Errorf("HMACKeyBase64 length = %d, should be > 8", len(b64))
	}

	// Should be valid base64 (only alphanumeric, +, /, = characters)
	for _, c := range b64 {
		if !isBase64Char(c) {
			t.Errorf("HMACKeyBase64 contains invalid character: %c", c)
		}
	}
}

// TestSessionKeys tests SessionKeys structure.
func TestSessionKeys(t *testing.T) {
	t.Run("session keys with all fields", func(t *testing.T) {
		keys := &SessionKeys{
			KeyID:    "key-123",
			HMACKey:  make([]byte, 32),
			HMACAlgo: "sha256",
		}

		if keys.KeyID != "key-123" {
			t.Errorf("KeyID = %q, want 'key-123'", keys.KeyID)
		}
		if len(keys.HMACKey) != 32 {
			t.Errorf("HMACKey length = %d, want 32", len(keys.HMACKey))
		}
		if keys.HMACAlgo != "sha256" {
			t.Errorf("HMACAlgo = %q, want 'sha256'", keys.HMACAlgo)
		}
	})
}

// TestStaticTokenValidatorWithPermissions tests token validator with permissions.
func TestStaticTokenValidatorWithPermissions(t *testing.T) {
	// StaticTokenValidator doesn't support permissions in the basic implementation,
	// but we can verify the interface works correctly
	t.Run("validator returns identity with default permissions", func(t *testing.T) {
		tokens := map[string]string{
			"token-123": "agent-1",
		}
		validator := NewStaticTokenValidator(tokens)

		identity, err := validator.Validate("token-123")
		if err != nil {
			t.Errorf("Validate() unexpected error: %v", err)
		}

		// StaticTokenValidator always sets Permissions to nil
		if identity.Permissions != nil {
			t.Errorf("Permissions should be nil for StaticTokenValidator, got %v", identity.Permissions)
		}
	})
}

// TestErrInvalidToken tests the ErrInvalidToken variable.
func TestErrInvalidToken(t *testing.T) {
	if ErrInvalidToken == nil {
		t.Error("ErrInvalidToken should not be nil")
	}

	// Test error message
	msg := ErrInvalidToken.Error()
	if !strings.Contains(msg, "invalid") || !strings.Contains(msg, "token") {
		t.Errorf("ErrInvalidToken message = %q, should contain 'invalid' and 'token'", msg)
	}
}

// TestTokenValidatorInterface tests that StaticTokenValidator implements TokenValidator.
func TestTokenValidatorInterface(t *testing.T) {
	var _ TokenValidator = NewStaticTokenValidator(map[string]string{})

	tokens := map[string]string{"token": "agent"}
	validator := NewStaticTokenValidator(tokens)

	// Verify it implements the interface
	identity, err := validator.Validate("token")
	if err != nil {
		t.Errorf("TokenValidator.Validate() error: %v", err)
	}
	if identity == nil {
		t.Error("TokenValidator.Validate() should return identity")
	}
}

// isBase64Char checks if a character is valid in base64 encoding.
func isBase64Char(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '='
}

// TestGenerateSessionKeysRandomness tests that generated keys have randomness.
func TestGenerateSessionKeysRandomness(t *testing.T) {
	t.Run("generated keys are random", func(t *testing.T) {
		const iterations = 100
		seenKeys := make(map[string]bool)

		for i := 0; i < iterations; i++ {
			keys, err := GenerateSessionKeys()
			if err != nil {
				t.Errorf("GenerateSessionKeys() iteration %d error: %v", i, err)
			}

			keyStr := string(keys.HMACKey)
			if seenKeys[keyStr] {
				t.Errorf("Duplicate HMAC key generated at iteration %d", i)
			}
			seenKeys[keyStr] = true
		}

		if len(seenKeys) != iterations {
			t.Errorf("Generated %d unique keys out of %d iterations", len(seenKeys), iterations)
		}
	})
}
