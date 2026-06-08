package core

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// TokenValidator verifies an agent token and returns its identity.
type TokenValidator interface {
	Validate(token string) (*AgentIdentity, error)
}

// AgentIdentity is returned on successful token authentication.
type AgentIdentity struct {
	AgentID     string
	Permissions []string
	ExpiresAt   time.Time
}

// ErrInvalidToken is returned when token validation fails.
var ErrInvalidToken = fmt.Errorf("invalid token")

// StaticTokenValidator validates tokens against a static map (dev/test use).
type StaticTokenValidator struct {
	tokens map[string]string // token -> agentID
}

// NewStaticTokenValidator creates a validator from a token->agentID mapping.
func NewStaticTokenValidator(tokens map[string]string) *StaticTokenValidator {
	return &StaticTokenValidator{tokens: tokens}
}

// Validate looks up the token and returns the associated agent identity.
func (v *StaticTokenValidator) Validate(token string) (*AgentIdentity, error) {
	agentID, ok := v.tokens[token]
	if !ok {
		return nil, ErrInvalidToken
	}
	return &AgentIdentity{
		AgentID:   agentID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, nil
}

// SessionKeys holds the cryptographic material for an authenticated session.
type SessionKeys struct {
	KeyID    string
	HMACKey  []byte // 32 bytes
	HMACAlgo string // sha256 (or sm3 for future)
}

// GenerateSessionKeys creates fresh session keys for an authenticated agent.
func GenerateSessionKeys() (*SessionKeys, error) {
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("generate HMAC key: %w", err)
	}

	return &SessionKeys{
		KeyID:    uuid.Must(uuid.NewV7()).String(),
		HMACKey:  hmacKey,
		HMACAlgo: "sha256",
	}, nil
}

// HMACKeyBase64 returns the HMAC key as a base64 string for AUTH_OK messages.
func (sk *SessionKeys) HMACKeyBase64() string {
	return base64.StdEncoding.EncodeToString(sk.HMACKey)
}
