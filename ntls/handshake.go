package ntls

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// sendHello 发送 HELLO（ntls 写帧走 c.writeFrame 单连接）。
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
	if err := c.writeFrame(core.TypeHello, core.FlagControl, core.ChannelControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateHelloSent); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to HELLO_SENT", err)
	}
	return nil
}

// recvHelloAck 读取 HELLO_ACK（单 TCP 连接），存储协商结果与 challenge nonce。
func (c *Client) recvHelloAck() (*core.HelloAckMessage, error) {
	f, err := core.Read(c.conn, core.DefaultLimits())
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
	if err := c.writeFrame(core.TypeAuth, core.FlagControl, core.ChannelControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateAuthSent); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to AUTH_SENT", err)
	}
	return nil
}

// buildAuthMessage 构造 AUTH 帧：Token + 基于 challenge 的 HMAC 应答（按协商 CipherSuite）。
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

// recvAuthResult 读取 AUTH_OK / AUTH_FAIL。ntls 单 TCP 连接无 SetAuthed（QUIC 旁路）。
func (c *Client) recvAuthResult() error {
	f, err := core.Read(c.conn, core.DefaultLimits())
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
		if cs == corepb.CipherSuite_CIPHER_SUITE_INTL {
			c.keys.AEADKey = okMsg.GetAesKey()
		} else {
			c.keys.AEADKey = okMsg.GetSm4Key()
		}

		if okMsg.GetExpiresAtUnix() > 0 {
			c.expiresAt = time.Unix(okMsg.GetExpiresAtUnix(), 0)
		}

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
