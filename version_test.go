package mbta

import (
	"testing"
)

// TestVersionConstants tests that all version constants are correctly defined.
func TestVersionConstants(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"Version1", Version1},
		{"Version2", Version2},
		{"VersionNTLS", VersionNTLS},
		{"ALPNV1", ALPNV1},
		{"ALPNV2", ALPNV2},
		{"ALPNNTLS", ALPNNTLS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value == "" {
				t.Errorf("%s should not be empty", tt.name)
			}
		})
	}
}

// TestFrameVersionConstants tests frame version constants.
func TestFrameVersionConstants(t *testing.T) {
	if FrameV1 != 0x01 {
		t.Errorf("FrameV1 = 0x%02x, want 0x01", FrameV1)
	}
	if FrameV2 != 0x02 {
		t.Errorf("FrameV2 = 0x%02x, want 0x02", FrameV2)
	}
}

// TestParseVersionValid tests parsing valid version strings.
func TestParseVersionValid(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"v1", "v1"},
		{"v2", "v2"},
		{"ntls", "ntls"},
		{"mbta/1", "v1"},
		{"mbta/2", "v2"},
		{"mbta-ntls/1", "ntls"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseVersion(tt.input)
			if err != nil {
				t.Errorf("ParseVersion(%q) error = %v", tt.input, err)
			}
			if result != tt.expected {
				t.Errorf("ParseVersion(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestParseVersionInvalid tests parsing invalid version strings.
func TestParseVersionInvalid(t *testing.T) {
	invalidVersions := []string{
		"v3",
		"mbta/3",
		"invalid",
		"",
		"V1", // case sensitive
		"V2",
		"NTLS",
	}

	for _, input := range invalidVersions {
		t.Run(input, func(t *testing.T) {
			result, err := ParseVersion(input)
			if err == nil {
				t.Errorf("ParseVersion(%q) should return error, got %q", input, result)
			}
			if !IsUnsupportedVersion(err) {
				t.Errorf("ParseVersion(%q) error should be UnsupportedVersionError", input)
			}
		})
	}
}

// TestParseALPNValid tests parsing valid ALPN strings.
func TestParseALPNValid(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"mbta/1", "v1"},
		{"mbta/2", "v2"},
		{"mbta-ntls/1", "ntls"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseALPN(tt.input)
			if err != nil {
				t.Errorf("ParseALPN(%q) error = %v", tt.input, err)
			}
			if result != tt.expected {
				t.Errorf("ParseALPN(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestParseALPNInvalid tests parsing invalid ALPN strings.
func TestParseALPNInvalid(t *testing.T) {
	invalidALPNs := []string{
		"mbta/3",
		"http/1.1",
		"h2",
		"",
		"v1",
		"v2",
	}

	for _, input := range invalidALPNs {
		t.Run(input, func(t *testing.T) {
			result, err := ParseALPN(input)
			if err == nil {
				t.Errorf("ParseALPN(%q) should return error, got %q", input, result)
			}
			if !IsUnsupportedVersion(err) {
				t.Errorf("ParseALPN(%q) error should be UnsupportedVersionError", input)
			}
		})
	}
}

// TestUnsupportedVersionError tests UnsupportedVersionError structure.
func TestUnsupportedVersionError(t *testing.T) {
	err := &UnsupportedVersionError{Version: "v3"}

	if err.Error() != "[7000 ERR_VERSION] unsupported mbta version: v3" {
		t.Errorf("Error() = %q, want '[7000 ERR_VERSION] unsupported mbta version: v3'", err.Error())
	}

	if !IsUnsupportedVersion(err) {
		t.Error("IsUnsupportedVersion should return true for UnsupportedVersionError")
	}
}

// TestIsUnsupportedVersion tests the error checker function.
func TestIsUnsupportedVersion(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "UnsupportedVersionError",
			err:  &UnsupportedVersionError{Version: "v3"},
			want: true,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "generic error",
			err:  &testError{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUnsupportedVersion(tt.err); got != tt.want {
				t.Errorf("IsUnsupportedVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

// testError is a custom error type for testing.
type testError struct{}

func (e *testError) Error() string {
	return "test error"
}

// TestVersionMapping tests that version names map correctly to ALPN and frame versions.
func TestVersionMapping(t *testing.T) {
	tests := []struct {
		version       string
		expectedALPN  string
		expectedFrame uint8
	}{
		{Version1, ALPNV1, FrameV1},
		{Version2, ALPNV2, FrameV2},
		{VersionNTLS, ALPNNTLS, FrameV1}, // NTLS uses frame v1
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			// Parse version name
			parsed, err := ParseVersion(tt.version)
			if err != nil {
				t.Fatalf("ParseVersion(%q) failed: %v", tt.version, err)
			}

			// Verify it matches expected
			if parsed != tt.version {
				t.Errorf("Parsed version = %s, want %s", parsed, tt.version)
			}

			// Verify ALPN mapping
			alpnParsed, err := ParseALPN(tt.expectedALPN)
			if err != nil {
				t.Fatalf("ParseALPN(%q) failed: %v", tt.expectedALPN, err)
			}
			if alpnParsed != tt.version {
				t.Errorf("ALPN %q maps to %s, want %s", tt.expectedALPN, alpnParsed, tt.version)
			}
		})
	}
}
