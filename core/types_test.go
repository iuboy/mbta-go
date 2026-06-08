package core

import (
	"testing"
)

// TestMessageTypeConstants tests that all message type constants are correctly defined.
func TestMessageTypeConstants(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
	}{
		{"TypeHello", TypeHello},
		{"TypeHelloAck", TypeHelloAck},
		{"TypeAuth", TypeAuth},
		{"TypeAuthOK", TypeAuthOK},
		{"TypeAuthFail", TypeAuthFail},
		{"TypeBatch", TypeBatch},
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

// TestMessageTypeValues tests specific message type values.
func TestMessageTypeValues(t *testing.T) {
	tests := []struct {
		constant    uint16
		expectValue uint16
	}{
		{TypeHello, 0x0001},
		{TypeHelloAck, 0x0002},
		{TypeAuth, 0x0003},
		{TypeAuthOK, 0x0004},
		{TypeAuthFail, 0x0005},
		{TypeBatch, 0x0010},
		{TypeAck, 0x0011},
		{TypeNack, 0x0012},
		{TypePartialAck, 0x0013},
		{TypeWindow, 0x0020},
		{TypeThrottle, 0x0021},
		{TypePing, 0x0030},
		{TypePong, 0x0031},
		{TypeClose, 0x0040},
		{TypeError, 0x0050},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if tt.constant != tt.expectValue {
				t.Errorf("Expected 0x%04x, got 0x%04x", tt.expectValue, tt.constant)
			}
		})
	}
}

// TestCodecConstants tests codec algorithm constants.
func TestCodecConstants(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"CodecJSON", CodecJSON},
		{"CodecMsgpack", CodecMsgpack},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value == "" {
				t.Errorf("%s should not be empty", tt.name)
			}
		})
	}
}

// TestCompressionConstants tests compression algorithm constants.
func TestCompressionConstants(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"CompressionNone", CompressionNone},
		{"CompressionGzip", CompressionGzip},
		{"CompressionZstd", CompressionZstd},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value == "" {
				t.Errorf("%s should not be empty", tt.name)
			}
		})
	}
}

// TestEncryptionConstants tests encryption algorithm constants.
func TestEncryptionConstants(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"EncryptionNone", EncryptionNone},
		{"EncryptionSM4", EncryptionSM4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value == "" {
				t.Errorf("%s should not be empty", tt.name)
			}
		})
	}
}

// TestHMACAlgoConstants tests HMAC algorithm constants.
func TestHMACAlgoConstants(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"HMACAlgoNone", HMACAlgoNone},
		{"HMACAlgoSHA256", HMACAlgoSHA256},
		{"HMACAlgoSM3", HMACAlgoSM3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value == "" {
				t.Errorf("%s should not be empty", tt.name)
			}
		})
	}
}

// TestAckModeConstants tests ACK mode constants.
func TestAckModeConstants(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"AckModeAccepted", AckModeAccepted},
		{"AckModeDurable", AckModeDurable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value == "" {
				t.Errorf("%s should not be empty", tt.name)
			}
		})
	}
}

// TestConstantsUniqueness tests that constants have unique values where appropriate.
func TestConstantsUniqueness(t *testing.T) {
	// Test message type constants are unique
	messageTypeValues := map[uint16]bool{
		TypeHello:      true,
		TypeHelloAck:   true,
		TypeAuth:       true,
		TypeAuthOK:     true,
		TypeAuthFail:   true,
		TypeBatch:      true,
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

	if len(messageTypeValues) != 15 {
		t.Errorf("Expected 15 unique message types, got %d", len(messageTypeValues))
	}
}
