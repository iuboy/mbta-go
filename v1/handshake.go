package v1

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// sendHello 发送 HELLO（core spec §9.5）。
func (c *Client) sendHello() error {
	hello := &corepb.HelloMessage{
		AgentId:       c.config.AgentID,
		Hostname:      c.config.Hostname,
		FrameVersion:  1,
		AgentVersion:  "0.1.0",
		Capabilities:  c.config.Capabilities,
		InstanceId:    uuid.Must(uuid.NewV7()).String(),
		StartedAtUnix: time.Now().Unix(),
	}
	payload, err := core.Encode(hello)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal hello", err)
	}
	if err := core.Write(c.controlStr, core.TypeHello, core.FlagControl, core.ChannelControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateHelloSent); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to HELLO_SENT", err)
	}
	return nil
}

// recvHelloAck 接收 HELLO_ACK，存储协商结果与 challenge nonce。
func (c *Client) recvHelloAck() (*core.HelloAckMessage, error) {
	f, err := core.Read(c.controlStr, core.DefaultLimits())
	if err != nil {
		return nil, err
	}
	if f.Header.Type == core.TypeError {
		var errMsg core.ErrorMessage
		_ = core.Decode(f.Payload, &errMsg)
		return nil, core.NewError(core.NumHandshake, core.CodeHandshake, fmt.Sprintf("server error: %s", errMsg.GetReason()))
	}
	if f.Header.Type != core.TypeHelloAck {
		return nil, core.NewError(core.NumProtocol, core.CodeProtocol, fmt.Sprintf("expected HELLO_ACK, got 0x%02x", f.Header.Type))
	}

	var ack core.HelloAckMessage
	if err := core.Decode(f.Payload, &ack); err != nil {
		return nil, err
	}

	c.negotiated = &core.NegotiateResult{
		SelectedCapabilities: ack.GetSelectedCapabilities(),
		Codec:                ack.GetCodec(),
		Compression:          ack.GetCompression(),
		CipherSuite:          ack.GetCipherSuite(),
	}
	c.challengeNonce = ack.GetChallengeNonce()

	// challenge_nonce 必须非空（core spec §9.5）。
	if len(c.challengeNonce) == 0 {
		return nil, core.NewError(core.NumHandshake, core.CodeHandshake, "server did not provide challenge_nonce in HELLO_ACK")
	}

	return &ack, nil
}

// sendAuth 发送 AUTH（challenge-response）。
func (c *Client) sendAuth() error {
	if len(c.challengeNonce) == 0 {
		return core.NewError(core.NumAuth, core.CodeAuth, "server did not provide challenge_nonce in HELLO_ACK, cannot authenticate")
	}

	auth := c.buildAuthMessage()
	payload, err := core.Encode(auth)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal auth", err)
	}
	if err := core.Write(c.controlStr, core.TypeAuth, core.FlagControl, core.ChannelControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateAuthSent); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to AUTH_SENT", err)
	}
	return nil
}

// buildAuthMessage 构造 AUTH 帧：Token + 基于 challenge 的 HMAC 应答（按协商 CipherSuite）。
// r2 tokenless（TokenResolver 反查）作为后续增强；当前走 legacy 明文 Token 路径。
func (c *Client) buildAuthMessage() *corepb.AuthMessage {
	cs := corepb.CipherSuite_CIPHER_SUITE_INTL
	if c.negotiated != nil {
		cs = c.negotiated.CipherSuite
	}
	return &corepb.AuthMessage{
		Token:     c.config.Token,
		AgentId:   c.config.AgentID,
		SessionId: c.sessionID,
		AuthNonce: core.ComputeChallengeResponse(c.config.Token, string(c.challengeNonce), cs),
	}
}

// recvAuthResult 接收 AUTH_OK / AUTH_FAIL。
func (c *Client) recvAuthResult() error {
	f, err := core.Read(c.controlStr, core.DefaultLimits())
	if err != nil {
		return err
	}

	switch f.Header.Type {
	case core.TypeAuthOK:
		var okMsg core.AuthOKMessage
		if err := core.Decode(f.Payload, &okMsg); err != nil {
			return err
		}

		cs := okMsg.GetCipherSuite()
		c.keys = &core.SessionKeys{
			KeyID:       okMsg.GetKeyId(),
			CipherSuite: cs,
			HMACKey:     okMsg.GetHmacKey(),
		}
		// AEAD 密钥按套件下发字段（intl=AesKey, gm=Sm4Key）。
		if cs == corepb.CipherSuite_CIPHER_SUITE_INTL {
			c.keys.AEADKey = okMsg.GetAesKey()
		} else {
			c.keys.AEADKey = okMsg.GetSm4Key()
		}

		if okMsg.GetExpiresAtUnix() > 0 {
			c.expiresAt = time.Unix(okMsg.GetExpiresAtUnix(), 0)
		}

		c.conn.SetAuthed(true)
		if err := c.sm.Transition(core.StateReady); err != nil {
			return core.WrapError(core.NumSession, core.CodeSession, "transition to READY", err)
		}
		return nil

	case core.TypeAuthFail:
		var failMsg core.AuthFailMessage
		if uerr := core.Decode(f.Payload, &failMsg); uerr != nil {
			slog.Debug("failed to decode auth_fail frame", "error", uerr)
		}
		return core.NewError(core.NumAuth, core.CodeAuth, fmt.Sprintf("auth failed: %s (%s)", failMsg.GetReason(), failMsg.GetCode()))

	default:
		return core.NewError(core.NumProtocol, core.CodeProtocol, fmt.Sprintf("expected AUTH_OK/FAIL, got 0x%02x", f.Header.Type))
	}
}
