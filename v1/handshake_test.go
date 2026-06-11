package v1

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestDecodeBase64KeyValid tests successful key decoding.
func TestDecodeBase64KeyValid(t *testing.T) {
	// Create a 32-byte key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(key)

	decoded, err := decodeBase64Key(b64, 32)
	if err != nil {
		t.Fatalf("decodeBase64Key failed: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("Decoded key length = %d, want 32", len(decoded))
	}

	// Verify content matches
	for i := range key {
		if decoded[i] != key[i] {
			t.Errorf("Byte %d mismatch: got %d, want %d", i, decoded[i], key[i])
		}
	}
}

// TestDecodeBase64KeyWrongLength tests error handling for wrong key length.
func TestDecodeBase64KeyWrongLength(t *testing.T) {
	// Create a 32-byte key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(key)

	// Try to decode expecting 16 bytes
	_, err := decodeBase64Key(b64, 16)
	if err == nil {
		t.Error("Expected error for wrong key length, got nil")
	}

	expectedMsg := "[3001 ERR_AUTH] key length 32, expected 16"
	if err.Error() != expectedMsg {
		t.Errorf("Error message = %q, want %q", err.Error(), expectedMsg)
	}
}

// TestDecodeBase64KeyInvalidBase64 tests error handling for invalid base64.
func TestDecodeBase64KeyInvalidBase64(t *testing.T) {
	_, err := decodeBase64Key("not-valid-base64!!!", 32)
	if err == nil {
		t.Error("Expected error for invalid base64, got nil")
	}

	// Check that error contains "base64 decode"
	expectedMsg := "base64 decode"
	if err == nil {
		t.Error("Expected error, got nil")
	} else if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("Error message should contain %q, got %q", expectedMsg, err.Error())
	}
}

// TestDecodeBase64KeyEmptyString tests empty string input.
func TestDecodeBase64KeyEmptyString(t *testing.T) {
	_, err := decodeBase64Key("", 32)
	if err == nil {
		t.Error("Expected error for empty string, got nil")
	}
}

// TestDecodeBase64Key16Byte tests 16-byte key decoding.
func TestDecodeBase64Key16Byte(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(key)

	decoded, err := decodeBase64Key(b64, 16)
	if err != nil {
		t.Fatalf("decodeBase64Key failed: %v", err)
	}

	if len(decoded) != 16 {
		t.Errorf("Decoded key length = %d, want 16", len(decoded))
	}
}

// TestDecodeBase64Key64Byte tests 64-byte key decoding.
func TestDecodeBase64Key64Byte(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i % 256)
	}
	b64 := base64.StdEncoding.EncodeToString(key)

	decoded, err := decodeBase64Key(b64, 64)
	if err != nil {
		t.Fatalf("decodeBase64Key failed: %v", err)
	}

	if len(decoded) != 64 {
		t.Errorf("Decoded key length = %d, want 64", len(decoded))
	}
}

// TestDecodeBase64KeyWithPadding tests base64 string with padding.
func TestDecodeBase64KeyWithPadding(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(key)

	// Verify the encoded string has padding
	if b64[len(b64)-1] != '=' {
		t.Log("Base64 encoding may not have padding for this key")
	}

	decoded, err := decodeBase64Key(b64, 32)
	if err != nil {
		t.Fatalf("decodeBase64Key with padding failed: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("Decoded key length = %d, want 32", len(decoded))
	}
}

// TestDecodeBase64KeyInvalidCharacters tests error handling for invalid characters.
func TestDecodeBase64KeyInvalidCharacters(t *testing.T) {
	// Use characters that are not valid in base64
	_, err := decodeBase64Key("invalid@#$%^&*()", 32)
	if err == nil {
		t.Error("Expected error for invalid characters, got nil")
	}

	expectedMsg := "base64 decode"
	if err == nil {
		t.Error("Expected error, got nil")
	} else if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("Error message should contain %q, got %q", expectedMsg, err.Error())
	}
}
