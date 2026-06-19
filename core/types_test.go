package core

import (
	"testing"
)

// TestMessageTypeConstants tests that all message type constants are correctly defined (r2 uint8).
func TestMessageTypeConstants(t *testing.T) {
	tests := []struct {
		name  string
		value uint8
	}{
		{"TypeHello", TypeHello},
		{"TypeHelloAck", TypeHelloAck},
		{"TypeAuth", TypeAuth},
		{"TypeAuthOK", TypeAuthOK},
		{"TypeAuthFail", TypeAuthFail},
		{"TypeBatch", TypeBatch},
		{"TypeDatagram", TypeDatagram},
		{"TypeAck", TypeAck},
		{"TypeNack", TypeNack},
		{"TypePartialAck", TypePartialAck},
		{"TypeWindow", TypeWindow},
		{"TypeThrottle", TypeThrottle},
		{"TypePing", TypePing},
		{"TypePong", TypePong},
		{"TypeClose", TypeClose},
		{"TypeError", TypeError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value == 0 {
				t.Errorf("%s should not be zero", tt.name)
			}
		})
	}
}

// TestMessageTypeValues tests specific message type values (r2 编号，core spec §4)。
func TestMessageTypeValues(t *testing.T) {
	tests := []struct {
		constant    uint8
		expectValue uint8
	}{
		{TypeHello, 1},
		{TypeHelloAck, 2},
		{TypeAuth, 3},
		{TypeAuthOK, 4},
		{TypeAuthFail, 5},
		{TypeBatch, 6},
		{TypeDatagram, 7},
		{TypeAck, 8},
		{TypeNack, 9},
		{TypePartialAck, 10},
		{TypeWindow, 11},
		{TypeThrottle, 12},
		{TypePing, 13},
		{TypePong, 14},
		{TypeClose, 15},
		{TypeError, 16},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if tt.constant != tt.expectValue {
				t.Errorf("Expected %d, got %d", tt.expectValue, tt.constant)
			}
		})
	}
}

// TestCodecConstants tests codec algorithm constants.
func TestConstantsUniqueness(t *testing.T) {
	// Test message type constants are unique
	messageTypeValues := map[uint8]bool{
		TypeHello:      true,
		TypeHelloAck:   true,
		TypeAuth:       true,
		TypeAuthOK:     true,
		TypeAuthFail:   true,
		TypeBatch:      true,
		TypeDatagram:   true,
		TypeAck:        true,
		TypeNack:       true,
		TypePartialAck: true,
		TypeWindow:     true,
		TypeThrottle:   true,
		TypePing:       true,
		TypePong:       true,
		TypeClose:      true,
		TypeError:      true,
	}

	if len(messageTypeValues) != 16 {
		t.Errorf("Expected 16 unique message types, got %d", len(messageTypeValues))
	}
}
