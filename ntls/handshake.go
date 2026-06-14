package ntls

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/iuboy/mbta-go/core"
)

// sendHello 发送 HELLO 帧。
//
// ntls 与 v1 的区别：写帧走 c.writeFrame（writeMu 串行化单连接所有写），
// 而非 core.Write(c.controlStr, ...)。Payload 序列化使用 core.FastMarshal。
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
	payload, err := core.FastMarshal(hello)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal hello", err)
	}
	if err := c.writeFrame(core.TypeHello, core.FlagControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateHelloSent); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to HELLO_SENT", err)
	}
	return nil
}

// recvHelloAck 读取并处理 HELLO_ACK 帧。
//
// ntls 读取走 core.Read(c.conn, ...)（单 TCP 连接），并校验服务端下发的
// ChallengeNonce 与 HMACAlgo。
func (c *Client) recvHelloAck() (*core.HelloAckMessage, error) {
	f, err := core.Read(c.conn, core.DefaultLimits())
	if err != nil {
		return nil, err
	}
	if f.Header.Type == core.TypeError {
		var errMsg core.ErrorMessage
		if uerr := core.FastUnmarshal(f.Payload, &errMsg); uerr != nil {
			slog.Debug("failed to decode error frame", "error", uerr)
		}
		return nil, core.NewError(core.NumHandshake, core.CodeHandshake, fmt.Sprintf("server error: %s", errMsg.Reason))
	}
	if f.Header.Type != core.TypeHelloAck {
		return nil, core.NewError(core.NumProtocol, core.CodeProtocol, fmt.Sprintf("expected HELLO_ACK, got 0x%04x", f.Header.Type))
	}

	var ack core.HelloAckMessage
	if err := core.FastUnmarshal(f.Payload, &ack); err != nil {
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

// sendAuth 发送 AUTH 帧。
//
// ntls 写帧走 c.writeFrame；Payload 序列化用 core.FastMarshal。
func (c *Client) sendAuth() error {
	// Challenge nonce is mandatory — the server must provide it in HELLO_ACK.
	if c.challengeNonce == "" {
		return core.NewError(core.NumAuth, core.CodeAuth, "server did not provide challenge_nonce in HELLO_ACK, cannot authenticate")
	}

	auth := c.buildAuthMessage()
	payload, err := core.FastMarshal(auth)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal auth", err)
	}
	if err := c.writeFrame(core.TypeAuth, core.FlagControl, payload); err != nil {
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

// recvAuthResult 读取 AUTH_OK / AUTH_FAIL 帧。
//
// ntls 读取走 core.Read(c.conn, ...)。AUTH_OK 解析 HMAC/SM4 密钥与会话过期时间。
// 注意：v1 在握手成功后调用 c.conn.SetAuthed(true)（QUIC Conn 自定义方法），
// ntls 单 TCP 连接（net.Conn）无此方法——该标记仅 QUIC 旁路使用，ntls 不需要。
func (c *Client) recvAuthResult() error {
	f, err := core.Read(c.conn, core.DefaultLimits())
	if err != nil {
		return err
	}

	switch f.Header.Type {
	case core.TypeAuthOK:
		var okMsg core.AuthOKMessage
		if err := core.FastUnmarshal(f.Payload, &okMsg); err != nil {
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

		// Decode SM4 key（SM4-GCM 加密密钥，服务端总下发；encryption=none 时不使用）
		if okMsg.SM4Key != "" {
			sm4Key, err := decodeBase64Key(okMsg.SM4Key, 16)
			if err != nil {
				return core.WrapError(core.NumAuth, core.CodeAuth, "decode sm4 key", err)
			}
			if c.keys == nil {
				c.keys = &core.SessionKeys{}
			}
			c.keys.SM4Key = sm4Key
		}

		// 存储会话过期时间
		if okMsg.ExpiresAtUnix > 0 {
			c.expiresAt = time.Unix(okMsg.ExpiresAtUnix, 0)
		}

		if err := c.sm.Transition(core.StateReady); err != nil {
			return core.WrapError(core.NumSession, core.CodeSession, "transition to READY", err)
		}
		return nil

	case core.TypeAuthFail:
		var failMsg core.AuthFailMessage
		if uerr := core.FastUnmarshal(f.Payload, &failMsg); uerr != nil {
			slog.Debug("failed to decode auth_fail frame", "error", uerr)
		}
		return core.NewError(core.NumAuth, core.CodeAuth, fmt.Sprintf("auth failed: %s (%s)", failMsg.Reason, failMsg.Code))

	default:
		return core.NewError(core.NumProtocol, core.CodeProtocol, fmt.Sprintf("expected AUTH_OK/FAIL, got 0x%04x", f.Header.Type))
	}
}

// decodeBase64Key 解码 base64 密钥并校验长度。
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
