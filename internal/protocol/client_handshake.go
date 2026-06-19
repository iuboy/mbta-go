package protocol

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// --- 握手（sendHello / recvHelloAck / sendAuth / recvAuthResult）---
// 这些方法原在 v1/handshake.go 与 ntls/handshake.go 中逐字重复，现已下沉。
// 读写均经 c.tr（ClientTransport），消除对 controlStr/conn 的直接依赖。

// SendHello 发送 HELLO（core spec §9.5）。
func (c *CoreClient) SendHello() error {
	hello := &corepb.HelloMessage{
		AgentId:       c.cfg.AgentID,
		Hostname:      c.cfg.Hostname,
		FrameVersion:  1,
		AgentVersion:  "0.1.0",
		Capabilities:  c.cfg.Capabilities,
		InstanceId:    core.NewChunkID().String(),
		StartedAtUnix: time.Now().Unix(),
	}
	payload, err := core.Encode(hello)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal hello", err)
	}
	if err := c.tr.WriteFrame(context.Background(), core.TypeHello, core.FlagControl, core.ChannelControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateHelloSent); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to HELLO_SENT", err)
	}
	return nil
}

// RecvHelloAck 接收 HELLO_ACK，存储协商结果与 challenge nonce。
func (c *CoreClient) RecvHelloAck() (*core.HelloAckMessage, error) {
	f, err := c.tr.ReadFrame()
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

// SendAuth 发送 AUTH（challenge-response）。
func (c *CoreClient) SendAuth() error {
	if len(c.challengeNonce) == 0 {
		return core.NewError(core.NumAuth, core.CodeAuth, "server did not provide challenge_nonce in HELLO_ACK, cannot authenticate")
	}

	auth := c.buildAuthMessage()
	payload, err := core.Encode(auth)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal auth", err)
	}
	if err := c.tr.WriteFrame(context.Background(), core.TypeAuth, core.FlagControl, core.ChannelControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateAuthSent); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to AUTH_SENT", err)
	}
	return nil
}

// buildAuthMessage 构造 AUTH 帧：Token + 基于 challenge 的 HMAC 应答（按协商 CipherSuite）。
// CipherSuite 优先协商结果，否则回退到 binding 注入的 cfg.DefaultCipherSuite
// （spec §8.3：默认套件跟随传输 binding，不应在协议核心硬编码 intl）。
func (c *CoreClient) buildAuthMessage() *corepb.AuthMessage {
	cs := c.cfg.DefaultCipherSuite
	if c.negotiated != nil {
		cs = c.negotiated.CipherSuite
	}
	return &corepb.AuthMessage{
		Token:     c.cfg.Token,
		AgentId:   c.cfg.AgentID,
		SessionId: c.sessionID,
		AuthNonce: core.ComputeChallengeResponse(c.cfg.Token, string(c.challengeNonce), cs),
	}
}

// RecvAuthResult 接收 AUTH_OK / AUTH_FAIL。AUTH_OK 后调用 onAuthed 钩子（v1 binding
// 用于 SetAuthed 开放 data stream 门禁；ntls binding 不设置此钩子）。
func (c *CoreClient) RecvAuthResult() error {
	f, err := c.tr.ReadFrame()
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
		c.keys = core.NewSessionKeys(okMsg.GetKeyId(), cs, okMsg.GetHmacKey())
		// AEAD 密钥按套件下发字段（intl=AesKey, gm=Sm4Key）。
		if cs == corepb.CipherSuite_CIPHER_SUITE_INTL {
			c.keys.SetAEADKey(okMsg.GetAesKey())
		} else {
			c.keys.SetAEADKey(okMsg.GetSm4Key())
		}

		if okMsg.GetExpiresAtUnix() > 0 {
			c.expiresAt = time.Unix(okMsg.GetExpiresAtUnix(), 0)
		}

		if c.onAuthed != nil {
			c.onAuthed(context.Background())
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
