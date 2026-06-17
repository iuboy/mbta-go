package core

import (
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
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

// equalStringSlices 比较 []string（测试 helper，slices.Equal 的本地等价）。
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestValidateHelloForVersion tests the ValidateHelloForVersion function.
func TestNegotiate(t *testing.T) {
	policy := Policy{
		SupportedCapabilities: []string{"codec_proto", "codec_cbor", "comp_zstd", "comp_lz4", "cs_intl", "cs_gm", "durable_ack", "partial_ack"},
		DefaultCodec:          corepb.Codec_CODEC_PROTO,
		DefaultCompression:    corepb.Compression_COMPRESSION_ZSTD,
		CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
	}

	t.Run("intersect selects shared stable capabilities", func(t *testing.T) {
		client := []string{"codec_proto", "comp_zstd", "cs_intl", "durable_ack", "x-experimental"}
		res, err := Negotiate(client, policy)
		if err != nil {
			t.Fatalf("Negotiate: %v", err)
		}
		want := []string{"codec_proto", "comp_zstd", "cs_intl", "durable_ack"}
		if !equalStringSlices(res.SelectedCapabilities, want) {
			t.Errorf("selected = %v, want %v", res.SelectedCapabilities, want)
		}
		if res.Codec != corepb.Codec_CODEC_PROTO {
			t.Errorf("codec = %v, want PROTO", res.Codec)
		}
		if res.Compression != corepb.Compression_COMPRESSION_ZSTD {
			t.Errorf("compression = %v, want ZSTD", res.Compression)
		}
		if res.CipherSuite != corepb.CipherSuite_CIPHER_SUITE_INTL {
			t.Errorf("cipher = %v, want INTL", res.CipherSuite)
		}
	})

	t.Run("defaults when client offers nothing relevant", func(t *testing.T) {
		res, err := Negotiate([]string{"x-foo"}, policy)
		if err != nil {
			t.Fatalf("Negotiate: %v", err)
		}
		if res.Codec != policy.DefaultCodec || res.Compression != policy.DefaultCompression || res.CipherSuite != policy.CipherSuite {
			t.Errorf("defaults not applied: %+v", res)
		}
		if len(res.SelectedCapabilities) != 0 {
			t.Errorf("expected no selected, got %v", res.SelectedCapabilities)
		}
	})

	t.Run("unknown stable capability rejected", func(t *testing.T) {
		if _, err := Negotiate([]string{"codec_proto", "bogus_stable_cap"}, policy); err == nil {
			t.Error("unknown stable capability should be rejected")
		}
	})

	t.Run("gm cipher preferred over intl when both offered", func(t *testing.T) {
		res, err := Negotiate([]string{"cs_intl", "cs_gm"}, policy)
		if err != nil {
			t.Fatalf("Negotiate: %v", err)
		}
		if res.CipherSuite != corepb.CipherSuite_CIPHER_SUITE_GM {
			t.Errorf("cipher = %v, want GM", res.CipherSuite)
		}
	})
}
