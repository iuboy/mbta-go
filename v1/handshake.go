package v1

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/iuboy/mbta-go/core"
)

func (c *Client) sendHello() error {
	hello := core.HelloMessage{
		AgentID:       c.config.AgentID,
		Hostname:      c.config.Hostname,
		Version:       1,
		AgentVersion:  "0.1.0",
		Capabilities:  c.config.Capabilities,
		InstanceID:    uuid.Must(uuid.NewV7()).String(),
		StartedAtUnix: time.Now().Unix(),
	}
	payload, err := json.Marshal(hello)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal hello", err)
	}
	if err := core.Write(c.controlStr, core.TypeHello, core.FlagControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateHelloSent); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to HELLO_SENT", err)
	}
	return nil
}

func (c *Client) recvHelloAck() (*core.HelloAckMessage, error) {
	f, err := core.Read(c.controlStr, core.DefaultLimits())
	if err != nil {
		return nil, err
	}
	if f.Header.Type == core.TypeError {
		var errMsg core.ErrorMessage
		if uerr := json.Unmarshal(f.Payload, &errMsg); uerr != nil {
			slog.Debug("failed to decode error frame", "error", uerr)
		}
		return nil, core.NewError(core.NumHandshake, core.CodeHandshake, fmt.Sprintf("server error: %s", errMsg.Reason))
	}
	if f.Header.Type != core.TypeHelloAck {
		return nil, core.NewError(core.NumProtocol, core.CodeProtocol, fmt.Sprintf("expected HELLO_ACK, got 0x%04x", f.Header.Type))
	}

	var ack core.HelloAckMessage
	if err := json.Unmarshal(f.Payload, &ack); err != nil {
		return nil, err
	}

	// Store negotiated capabilities
	c.negotiated = &core.NegotiateResult{
		SelectedCapabilities: ack.SelectedCapabilities,
		Codec:                ack.Codec,
		Compression:          ack.Compression,
		HMACAlgo:             ack.HMACAlgo,
		Encryption:           ack.Encryption,
	}

	// Store server challenge for auth
	c.challengeNonce = ack.ChallengeNonce

	// 校验 ChallengeNonce：服务端必须在 HELLO_ACK 中提供非空的挑战
	if c.challengeNonce == "" {
		return nil, core.NewError(core.NumHandshake, core.CodeHandshake, "server did not provide challenge_nonce in HELLO_ACK")
	}

	// 校验 HMACAlgo：服务端选择的算法必须是客户端已知的
	if ack.HMACAlgo != "" && ack.HMACAlgo != core.HMACAlgoNone &&
		ack.HMACAlgo != core.HMACAlgoSHA256 && ack.HMACAlgo != core.HMACAlgoSM3 {
		return nil, core.NewError(core.NumHandshake, core.CodeHandshake, fmt.Sprintf("server selected unknown HMAC algorithm: %s", ack.HMACAlgo))
	}

	return &ack, nil
}

func (c *Client) sendAuth() error {
	// Challenge nonce is mandatory — the server must provide it in HELLO_ACK.
	if c.challengeNonce == "" {
		return core.NewError(core.NumAuth, core.CodeAuth, "server did not provide challenge_nonce in HELLO_ACK, cannot authenticate")
	}

	auth := c.buildAuthMessage()
	payload, err := json.Marshal(auth)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal auth", err)
	}
	if err := core.Write(c.controlStr, core.TypeAuth, core.FlagControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateAuthSent); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to AUTH_SENT", err)
	}
	return nil
}

// buildAuthMessage 构造 AUTH 帧。tokenless 模式（协商选中 CapAuthTokenless）下
// 省略明文 Token——服务端按 AgentID 反查 token 后验证挑战响应。IsCapabilitySelected
// 对 nil negotiated 安全（返回 false），故未完成协商的调用方回退到回传 Token 的 legacy 路径。
func (c *Client) buildAuthMessage() core.AuthMessage {
	algo := core.HMACAlgoSHA256
	if c.negotiated != nil && c.negotiated.HMACAlgo != core.HMACAlgoNone {
		algo = c.negotiated.HMACAlgo
	}
	auth := core.AuthMessage{
		AgentID:   c.config.AgentID,
		SessionID: c.sessionID,
		AuthNonce: core.ComputeChallengeResponse(c.config.Token, c.challengeNonce, algo),
		HMACAlgo:  algo,
	}
	if !c.negotiated.IsCapabilitySelected(core.CapAuthTokenless) {
		auth.Token = c.config.Token
	}
	return auth
}

func (c *Client) recvAuthResult() error {
	f, err := core.Read(c.controlStr, core.DefaultLimits())
	if err != nil {
		return err
	}

	switch f.Header.Type {
	case core.TypeAuthOK:
		var okMsg core.AuthOKMessage
		if err := json.Unmarshal(f.Payload, &okMsg); err != nil {
			return err
		}

		// Decode HMAC key
		if okMsg.HMACKey != "" {
			hmacKey, err := decodeBase64Key(okMsg.HMACKey, 32)
			if err != nil {
				return core.WrapError(core.NumAuth, core.CodeAuth, "decode hmac key", err)
			}
			algo := okMsg.HMACAlgo
			if algo == "" {
				algo = core.HMACAlgoSHA256
			}
			c.keys = &core.SessionKeys{
				KeyID:    okMsg.KeyID,
				HMACKey:  hmacKey,
				HMACAlgo: algo,
			}
		}

		// 存储会话过期时间
		if okMsg.ExpiresAtUnix > 0 {
			c.expiresAt = time.Unix(okMsg.ExpiresAtUnix, 0)
		}

		c.conn.SetAuthed(true)
		if err := c.sm.Transition(core.StateReady); err != nil {
			return core.WrapError(core.NumSession, core.CodeSession, "transition to READY", err)
		}
		return nil

	case core.TypeAuthFail:
		var failMsg core.AuthFailMessage
		if uerr := json.Unmarshal(f.Payload, &failMsg); uerr != nil {
			slog.Debug("failed to decode auth_fail frame", "error", uerr)
		}
		return core.NewError(core.NumAuth, core.CodeAuth, fmt.Sprintf("auth failed: %s (%s)", failMsg.Reason, failMsg.Code))

	default:
		return core.NewError(core.NumProtocol, core.CodeProtocol, fmt.Sprintf("expected AUTH_OK/FAIL, got 0x%04x", f.Header.Type))
	}
}

func decodeBase64Key(b64 string, expectedLen int) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, core.WrapError(core.NumAuth, core.CodeAuth, "base64 decode", err)
	}
	if len(key) != expectedLen {
		return nil, core.NewError(core.NumAuth, core.CodeAuth, fmt.Sprintf("key length %d, expected %d", len(key), expectedLen))
	}
	return key, nil
}
