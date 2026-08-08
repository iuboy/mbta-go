package core

import (
	"testing"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/testutil"
)

// testAgentID 为 core 测试包共享的固定 agent_id，flow_test.go 引用。
// 其余任意 fixture 由 testutil 随机生成。
const testAgentID = "agent-123"

// TestStaticTokenValidator tests the StaticTokenValidator implementation.
func TestStaticTokenValidator(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		tok1, agent1 := testutil.RandToken(), testutil.RandAgentID()
		tok2, agent2 := testutil.RandToken(), testutil.RandAgentID()
		tokens := map[string]string{
			tok1: agent1,
			tok2: agent2,
		}
		validator := NewStaticTokenValidator(tokens)

		identity, err := validator.Validate(tok1)
		if err != nil {
			t.Errorf("Validate() unexpected error: %v", err)
		}
		if identity.AgentID != agent1 {
			t.Errorf("AgentID = %q, want %q", identity.AgentID, agent1)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		tok, agent := testutil.RandToken(), testutil.RandAgentID()
		tokens := map[string]string{
			tok: agent,
		}
		validator := NewStaticTokenValidator(tokens)

		identity, err := validator.Validate("invalid-token-" + testutil.RandString(4))
		if CodeOf(err) != ErrCodeInvalidToken.Code {
			t.Errorf("Error = %v, want ErrInvalidToken", err)
		}
		if identity != nil {
			t.Error("Identity should be nil for invalid token")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		tok, agent := testutil.RandToken(), testutil.RandAgentID()
		tokens := map[string]string{
			tok: agent,
		}
		validator := NewStaticTokenValidator(tokens)

		identity, err := validator.Validate("")
		if CodeOf(err) != ErrCodeInvalidToken.Code {
			t.Errorf("Error = %v, want ErrInvalidToken", err)
		}
		if identity != nil {
			t.Error("Identity should be nil for empty token")
		}
	})

	t.Run("empty token map", func(t *testing.T) {
		validator := NewStaticTokenValidator(map[string]string{})

		identity, err := validator.Validate(testutil.RandToken())
		if CodeOf(err) != ErrCodeInvalidToken.Code {
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
			AgentID: testAgentID,
			Permissions: []string{
				"read:events",
				"write:events",
			},
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		if identity.AgentID != testAgentID {
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
			AgentID:     testAgentID,
			Permissions: []string{},
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		}

		if len(identity.Permissions) != 0 {
			t.Errorf("Permissions should be empty, got %d items", len(identity.Permissions))
		}
	})
}

// TestGenerateSessionKeys tests the GenerateSessionKeys function (r2 按 CipherSuite)。
func TestGenerateSessionKeys(t *testing.T) {
	t.Run("intl suite", func(t *testing.T) {
		keys, err := GenerateSessionKeys(corepb.CipherSuite_CIPHER_SUITE_INTL)
		if err != nil {
			t.Fatalf("GenerateSessionKeys(INTL): %v", err)
		}
		if keys.KeyID == "" {
			t.Error("KeyID empty")
		}
		if keys.CipherSuite != corepb.CipherSuite_CIPHER_SUITE_INTL {
			t.Errorf("CipherSuite = %v, want INTL", keys.CipherSuite)
		}
		if len(keys.HMACKey()) != HMACKeyLenIntl {
			t.Errorf("HMACKey len = %d, want %d", len(keys.HMACKey()), HMACKeyLenIntl)
		}
		if len(keys.AEADKey()) != AEADKeyLenIntl {
			t.Errorf("AEADKey len = %d, want %d", len(keys.AEADKey()), AEADKeyLenIntl)
		}
	})

	t.Run("gm suite", func(t *testing.T) {
		keys, err := GenerateSessionKeys(corepb.CipherSuite_CIPHER_SUITE_GM)
		if err != nil {
			t.Fatalf("GenerateSessionKeys(GM): %v", err)
		}
		if len(keys.HMACKey()) != HMACKeyLenGM {
			t.Errorf("HMACKey len = %d, want %d", len(keys.HMACKey()), HMACKeyLenGM)
		}
		if len(keys.AEADKey()) != AEADKeyLenGM {
			t.Errorf("AEADKey len = %d, want %d", len(keys.AEADKey()), AEADKeyLenGM)
		}
	})

	t.Run("generated keys are unique", func(t *testing.T) {
		k1, _ := GenerateSessionKeys(corepb.CipherSuite_CIPHER_SUITE_INTL)
		k2, _ := GenerateSessionKeys(corepb.CipherSuite_CIPHER_SUITE_INTL)
		if k1.KeyID == k2.KeyID || string(k1.HMACKey()) == string(k2.HMACKey()) {
			t.Error("generated keys should be unique")
		}
	})
}

// TestSessionKeys tests SessionKeys structure (r2)。
func TestSessionKeys(t *testing.T) {
	keyID := "key-" + testutil.RandString(6)
	keys := &SessionKeys{
		KeyID:       keyID,
		CipherSuite: corepb.CipherSuite_CIPHER_SUITE_INTL,
		hmacKey:     make([]byte, HMACKeyLenIntl),
		aeadKey:     make([]byte, AEADKeyLenIntl),
	}
	if keys.KeyID != keyID {
		t.Errorf("KeyID = %q", keys.KeyID)
	}
	if len(keys.HMACKey()) != HMACKeyLenIntl || len(keys.AEADKey()) != AEADKeyLenIntl {
		t.Errorf("key lengths: hmac=%d aead=%d", len(keys.HMACKey()), len(keys.AEADKey()))
	}
}

// TestComputeChallengeResponse r2：按 CipherSuite 的挑战响应。
func TestComputeChallengeResponse(t *testing.T) {
	token, nonce := testutil.RandToken(), testutil.RandString(16)
	intl := ComputeChallengeResponse(token, nonce, corepb.CipherSuite_CIPHER_SUITE_INTL)
	gm := ComputeChallengeResponse(token, nonce, corepb.CipherSuite_CIPHER_SUITE_GM)
	if len(intl) != 32 {
		t.Errorf("intl challenge response len = %d, want 32 (SHA-256)", len(intl))
	}
	if len(gm) != 32 {
		t.Errorf("gm challenge response len = %d, want 32 (SM3)", len(gm))
	}
	// 不同 token 不同响应
	other := ComputeChallengeResponse(testutil.RandToken(), nonce, corepb.CipherSuite_CIPHER_SUITE_INTL)
	if string(intl) == string(other) {
		t.Error("different tokens should yield different responses")
	}
}

// TestStaticTokenValidatorWithPermissions tests token validator with permissions.
func TestStaticTokenValidatorWithPermissions(t *testing.T) {
	// StaticTokenValidator doesn't support permissions in the basic implementation,
	// but we can verify the interface works correctly
	t.Run("validator returns identity with default permissions", func(t *testing.T) {
		tok, agent := testutil.RandToken(), testutil.RandAgentID()
		tokens := map[string]string{
			tok: agent,
		}
		validator := NewStaticTokenValidator(tokens)

		identity, err := validator.Validate(tok)
		if err != nil {
			t.Errorf("Validate() unexpected error: %v", err)
		}

		// StaticTokenValidator always sets Permissions to nil
		if identity.Permissions != nil {
			t.Errorf("Permissions should be nil for StaticTokenValidator, got %v", identity.Permissions)
		}
	})
}

// TestTokenValidatorInterface tests that StaticTokenValidator implements TokenValidator.
func TestTokenValidatorInterface(t *testing.T) {
	var _ TokenValidator = NewStaticTokenValidator(map[string]string{})

	tok, agent := testutil.RandToken(), testutil.RandAgentID()
	tokens := map[string]string{tok: agent}
	validator := NewStaticTokenValidator(tokens)

	// Verify it implements the interface
	identity, err := validator.Validate(tok)
	if err != nil {
		t.Errorf("TokenValidator.Validate() error: %v", err)
	}
	if identity == nil {
		t.Error("TokenValidator.Validate() should return identity")
	}
}

// TestGenerateSessionKeysRandomness tests that generated keys have randomness.
func TestGenerateSessionKeysRandomness(t *testing.T) {
	t.Run("generated keys are random", func(t *testing.T) {
		const iterations = 100
		seenKeys := make(map[string]bool)

		for i := 0; i < iterations; i++ {
			keys, err := GenerateSessionKeys(corepb.CipherSuite_CIPHER_SUITE_INTL)
			if err != nil {
				t.Errorf("GenerateSessionKeys() iteration %d error: %v", i, err)
			}

			keyStr := string(keys.HMACKey())
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
