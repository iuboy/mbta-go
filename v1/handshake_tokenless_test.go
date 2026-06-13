package v1

import (
	"testing"

	"github.com/iuboy/mbta-go/core"
)

// TestBuildAuthMessage_LegacyIncludesToken: 未协商 tokenless 时，AUTH 帧必须回传明文 Token。
func TestBuildAuthMessage_LegacyIncludesToken(t *testing.T) {
	c := &Client{
		config:         ClientConfig{AgentID: "agent-1", Token: "tok1"},
		sessionID:      "sess-1",
		challengeNonce: "nonce-1",
		negotiated:     &core.NegotiateResult{HMACAlgo: core.HMACAlgoSHA256}, // 不含 tokenless
	}
	msg := c.buildAuthMessage()

	if msg.Token != "tok1" {
		t.Errorf("Token = %q, want tok1 (legacy must transmit plaintext token)", msg.Token)
	}
	want := core.ComputeChallengeResponse("tok1", "nonce-1", core.HMACAlgoSHA256)
	if msg.AuthNonce != want {
		t.Errorf("AuthNonce = %q, want %q", msg.AuthNonce, want)
	}
}

// TestBuildAuthMessage_TokenlessOmitsToken: 协商选中 tokenless 时省略明文 Token，
// AuthNonce 仍由本地 token 计算（客户端持有自己的 token）。
func TestBuildAuthMessage_TokenlessOmitsToken(t *testing.T) {
	c := &Client{
		config:         ClientConfig{AgentID: "agent-1", Token: "tok1"},
		sessionID:      "sess-1",
		challengeNonce: "nonce-1",
		negotiated: &core.NegotiateResult{
			HMACAlgo:             core.HMACAlgoSHA256,
			SelectedCapabilities: []string{core.CapCodecJSON, core.CapHMACSHA256, core.CapAuthTokenless},
		},
	}
	msg := c.buildAuthMessage()

	if msg.Token != "" {
		t.Errorf("Token = %q, want empty (tokenless omits plaintext token)", msg.Token)
	}
	want := core.ComputeChallengeResponse("tok1", "nonce-1", core.HMACAlgoSHA256)
	if msg.AuthNonce != want {
		t.Errorf("AuthNonce = %q, want %q", msg.AuthNonce, want)
	}
}

// TestBuildAuthMessage_NilNegotiatedIsLegacy: nil negotiated（未完成协商）安全回退 legacy。
func TestBuildAuthMessage_NilNegotiatedIsLegacy(t *testing.T) {
	c := &Client{
		config:         ClientConfig{AgentID: "agent-1", Token: "tok1"},
		sessionID:      "sess-1",
		challengeNonce: "nonce-1",
		negotiated:     nil,
	}
	msg := c.buildAuthMessage()
	if msg.Token != "tok1" {
		t.Errorf("Token = %q, want tok1 (nil negotiated must fall back to legacy)", msg.Token)
	}
}
