package core

import (
	"strings"
	"testing"

	mbtatest "github.com/iuboy/mbta-go/testing"
)

// TestStateString tests the State.String() method.
func TestStateString(t *testing.T) {
	tests := []struct {
		state    State
		expected string
	}{
		{StateDisconnected, "DISCONNECTED"},
		{StateConnecting, "CONNECTING"},
		{StateControlStreamOpen, "CONTROL_STREAM_OPEN"},
		{StateHelloSent, "HELLO_SENT"},
		{StateHelloAcked, "HELLO_ACKED"},
		{StateAuthSent, "AUTH_SENT"},
		{StateReady, "READY"},
		{StateDraining, "DRAINING"},
		{StateClosed, "CLOSED"},
		{State(999), "UNKNOWN(999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestServerStateString tests the ServerState.String() method.
func TestServerStateString(t *testing.T) {
	tests := []struct {
		state    ServerState
		expected string
	}{
		{ServerStateAccepted, "ACCEPTED"},
		{ServerStateControlWait, "CONTROL_WAIT"},
		{ServerStateHelloReceived, "HELLO_RECEIVED"},
		{ServerStateAuthWait, "AUTH_WAIT"},
		{ServerStateReady, "READY"},
		{ServerStateDraining, "DRAINING"},
		{ServerStateClosed, "CLOSED"},
		{ServerState(999), "UNKNOWN(999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestValidateHello tests the ValidateHello function.
func TestValidateHello(t *testing.T) {
	tests := []struct {
		name      string
		agentID   string
		version   int
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid HELLO",
			agentID: "agent-123",
			version: 1,
			wantErr: false,
		},
		{
			name:      "empty agent_id",
			agentID:   "",
			version:   1,
			wantErr:   true,
			errSubstr: "agent_id is required",
		},
		{
			name:      "unsupported version 0",
			agentID:   "agent-123",
			version:   0,
			wantErr:   true,
			errSubstr: "unsupported version",
		},
		{
			name:      "unsupported version 2",
			agentID:   "agent-123",
			version:   2,
			wantErr:   true,
			errSubstr: "unsupported version",
		},
		{
			name:      "negative version",
			agentID:   "agent-123",
			version:   -1,
			wantErr:   true,
			errSubstr: "unsupported version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHello(tt.agentID, tt.version)
			if tt.wantErr {
				mbtatest.AssertError(t, err, tt.name)
				if err != nil && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("Error = %v, want error containing %q", err, tt.errSubstr)
				}
			} else {
				mbtatest.AssertNoError(t, err, tt.name)
			}
		})
	}
}

// TestNegotiate tests the Negotiate function with various scenarios.
func TestNegotiate(t *testing.T) {
	tests := []struct {
		name       string
		clientCaps []string
		policy     Policy
		wantResult NegotiateResult
	}{
		{
			name:       "minimal client - no optional capabilities",
			clientCaps: []string{CapCodecJSON},
			policy:     Policy{},
			wantResult: NegotiateResult{
				SelectedCapabilities: []string{CapCodecJSON},
				Codec:                CodecJSON,
				Compression:          CompressionNone,
				HMACAlgo:             HMACAlgoNone,
				Encryption:           EncryptionNone,
			},
		},
		{
			name:       "client offers gzip, server enables gzip",
			clientCaps: []string{CapCodecJSON, CapCompressGzip},
			policy:     Policy{EnableGzip: true},
			wantResult: NegotiateResult{
				SelectedCapabilities: []string{CapCodecJSON, CapCompressGzip},
				Codec:                CodecJSON,
				Compression:          CompressionGzip,
				HMACAlgo:             HMACAlgoNone,
				Encryption:           EncryptionNone,
			},
		},
		{
			name:       "client offers gzip, server disables gzip",
			clientCaps: []string{CapCodecJSON, CapCompressGzip},
			policy:     Policy{EnableGzip: false},
			wantResult: NegotiateResult{
				SelectedCapabilities: []string{CapCodecJSON},
				Codec:                CodecJSON,
				Compression:          CompressionNone,
				HMACAlgo:             HMACAlgoNone,
				Encryption:           EncryptionNone,
			},
		},
		{
			name:       "client offers both HMAC, server prefers SM3 over SHA256",
			clientCaps: []string{CapCodecJSON, CapHMACSHA256, CapHMACSM3},
			policy:     Policy{EnableHMACSHA256: true, EnableHMACSM3: true},
			wantResult: NegotiateResult{
				SelectedCapabilities: []string{CapCodecJSON, CapHMACSM3},
				Codec:                CodecJSON,
				Compression:          CompressionNone,
				HMACAlgo:             HMACAlgoSM3,
				Encryption:           EncryptionNone,
			},
		},
		{
			name:       "client offers only SHA256, server enables both",
			clientCaps: []string{CapCodecJSON, CapHMACSHA256},
			policy:     Policy{EnableHMACSHA256: true, EnableHMACSM3: true},
			wantResult: NegotiateResult{
				SelectedCapabilities: []string{CapCodecJSON, CapHMACSHA256},
				Codec:                CodecJSON,
				Compression:          CompressionNone,
				HMACAlgo:             HMACAlgoSHA256,
				Encryption:           EncryptionNone,
			},
		},
		{
			name:       "client offers SM4 encryption",
			clientCaps: []string{CapCodecJSON, CapSM4GCM},
			policy:     Policy{EnableSM4GCM: true},
			wantResult: NegotiateResult{
				SelectedCapabilities: []string{CapCodecJSON, CapSM4GCM},
				Codec:                CodecJSON,
				Compression:          CompressionNone,
				HMACAlgo:             HMACAlgoNone,
				Encryption:           EncryptionSM4,
			},
		},
		{
			name: "client offers multiple optional capabilities",
			clientCaps: []string{
				CapCodecJSON,
				CapCompressGzip,
				CapHMACSM3,
				CapPartialAck,
				CapWindowFlowCtrl,
				CapThrottle,
				CapDurableAck,
			},
			policy: Policy{
				EnableGzip:       true,
				EnableHMACSM3:    true,
				EnablePartialAck: true,
				EnableWindow:     true,
				EnableThrottle:   true,
				EnableDurableAck: true,
			},
			wantResult: NegotiateResult{
				SelectedCapabilities: []string{
					CapCodecJSON,
					CapCompressGzip,
					CapHMACSM3,
					CapPartialAck,
					CapWindowFlowCtrl,
					CapThrottle,
					CapDurableAck,
				},
				Codec:       CodecJSON,
				Compression: CompressionGzip,
				HMACAlgo:    HMACAlgoSM3,
				Encryption:  EncryptionNone,
			},
		},
		{
			name:       "client offers SM2 cert auth",
			clientCaps: []string{CapCodecJSON, CapSM2CertAuth},
			policy:     Policy{EnableSM2CertAuth: true},
			wantResult: NegotiateResult{
				SelectedCapabilities: []string{CapCodecJSON, CapSM2CertAuth},
				Codec:                CodecJSON,
				Compression:          CompressionNone,
				HMACAlgo:             HMACAlgoNone,
				Encryption:           EncryptionNone,
			},
		},
		{
			name:       "empty client capabilities - should still get json codec",
			clientCaps: []string{},
			policy:     Policy{},
			wantResult: NegotiateResult{
				SelectedCapabilities: []string{CapCodecJSON},
				Codec:                CodecJSON,
				Compression:          CompressionNone,
				HMACAlgo:             HMACAlgoNone,
				Encryption:           EncryptionNone,
			},
		},
		{
			name:       "client offers capability not enabled by server policy",
			clientCaps: []string{CapCodecJSON, CapCompressGzip, CapPartialAck},
			policy:     Policy{EnableGzip: true},
			wantResult: NegotiateResult{
				SelectedCapabilities: []string{CapCodecJSON, CapCompressGzip},
				Codec:                CodecJSON,
				Compression:          CompressionGzip,
				HMACAlgo:             HMACAlgoNone,
				Encryption:           EncryptionNone,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Negotiate(tt.clientCaps, tt.policy)

			// Check codec
			if got.Codec != tt.wantResult.Codec {
				t.Errorf("Codec = %q, want %q", got.Codec, tt.wantResult.Codec)
			}

			// Check compression
			if got.Compression != tt.wantResult.Compression {
				t.Errorf("Compression = %q, want %q", got.Compression, tt.wantResult.Compression)
			}

			// Check HMAC
			if got.HMACAlgo != tt.wantResult.HMACAlgo {
				t.Errorf("HMACAlgo = %q, want %q", got.HMACAlgo, tt.wantResult.HMACAlgo)
			}

			// Check encryption
			if got.Encryption != tt.wantResult.Encryption {
				t.Errorf("Encryption = %q, want %q", got.Encryption, tt.wantResult.Encryption)
			}

			// Check selected capabilities
			if !equalStringSlices(got.SelectedCapabilities, tt.wantResult.SelectedCapabilities) {
				t.Errorf("SelectedCapabilities = %v, want %v", got.SelectedCapabilities, tt.wantResult.SelectedCapabilities)
			}
		})
	}
}

// TestNegotiatePreferences tests that server preferences are correctly applied.
func TestNegotiatePreferences(t *testing.T) {
	// Test SM3 preference over SHA256 when both available
	t.Run("SM3 preferred over SHA256", func(t *testing.T) {
		clientCaps := []string{CapCodecJSON, CapHMACSHA256, CapHMACSM3}
		policy := Policy{EnableHMACSHA256: true, EnableHMACSM3: true}
		result := Negotiate(clientCaps, policy)

		if result.HMACAlgo != HMACAlgoSM3 {
			t.Errorf("Expected SM3 to be preferred, got %q", result.HMACAlgo)
		}
	})

	// Test that codec_json is always included
	t.Run("codec_json always included", func(t *testing.T) {
		clientCaps := []string{CapCompressGzip, CapPartialAck}
		policy := Policy{EnableGzip: true, EnablePartialAck: true}
		result := Negotiate(clientCaps, policy)

		found := false
		for _, cap := range result.SelectedCapabilities {
			if cap == CapCodecJSON {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("codec_json should always be included in selected capabilities")
		}
	})
}

// TestPolicyDefaults tests that Policy with zero values has sensible defaults.
func TestPolicyDefaults(t *testing.T) {
	policy := Policy{}

	// All optional features should be disabled
	if policy.EnableGzip {
		t.Error("EnableGzip should be false by default")
	}
	if policy.EnableHMACSHA256 {
		t.Error("EnableHMACSHA256 should be false by default")
	}
	if policy.EnableSM4GCM {
		t.Error("EnableSM4GCM should be false by default")
	}
}

// TestCapabilityConstants tests that capability constants are correctly defined.
func TestCapabilityConstants(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"CapCodecJSON", CapCodecJSON},
		{"CapCompressGzip", CapCompressGzip},
		{"CapHMACSHA256", CapHMACSHA256},
		{"CapHMACSM3", CapHMACSM3},
		{"CapSM4GCM", CapSM4GCM},
		{"CapSM2CertAuth", CapSM2CertAuth},
		{"CapPartialAck", CapPartialAck},
		{"CapWindowFlowCtrl", CapWindowFlowCtrl},
		{"CapThrottle", CapThrottle},
		{"CapDurableAck", CapDurableAck},
		{"CapMultiStream", CapMultiStream},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if tt.value == "" {
				t.Errorf("Capability constant %q is empty", tt.name)
			}
		})
	}
}

// TestAlgorithmConstants tests that algorithm constants are correctly defined.
func TestAlgorithmConstants(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"CodecJSON", CodecJSON},
		{"CompressionNone", CompressionNone},
		{"CompressionGzip", CompressionGzip},
		{"HMACAlgoNone", HMACAlgoNone},
		{"HMACAlgoSHA256", HMACAlgoSHA256},
		{"HMACAlgoSM3", HMACAlgoSM3},
		{"EncryptionNone", EncryptionNone},
		{"EncryptionSM4", EncryptionSM4},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if tt.value == "" {
				t.Errorf("Algorithm constant %q is empty", tt.name)
			}
		})
	}
}
