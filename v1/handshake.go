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
		return fmt.Errorf("marshal hello: %w", err)
	}
	if err := core.Write(c.controlStr, core.TypeHello, core.FlagControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateHelloSent); err != nil {
		slog.Warn("state transition failed", "to", core.StateHelloSent, "error", err)
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
		return nil, fmt.Errorf("server error: %s", errMsg.Reason)
	}
	if f.Header.Type != core.TypeHelloAck {
		return nil, fmt.Errorf("expected HELLO_ACK, got 0x%04x", f.Header.Type)
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

	return &ack, nil
}

func (c *Client) sendAuth() error {
	auth := core.AuthMessage{
		Token:     c.config.Token,
		AgentID:   c.config.AgentID,
		SessionID: c.sessionID,
		AuthNonce: uuid.Must(uuid.NewV7()).String(),
	}
	payload, err := json.Marshal(auth)
	if err != nil {
		return fmt.Errorf("marshal auth: %w", err)
	}
	if err := core.Write(c.controlStr, core.TypeAuth, core.FlagControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateAuthSent); err != nil {
		slog.Warn("state transition failed", "to", core.StateAuthSent, "error", err)
	}
	return nil
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
				return fmt.Errorf("decode hmac key: %w", err)
			}
			c.keys = &core.SessionKeys{
				KeyID:    okMsg.KeyID,
				HMACKey:  hmacKey,
				HMACAlgo: "sha256",
			}
		}

		c.conn.SetAuthed(true)
		if err := c.sm.Transition(core.StateReady); err != nil {
			slog.Warn("state transition failed", "to", core.StateReady, "error", err)
		}
		return nil

	case core.TypeAuthFail:
		var failMsg core.AuthFailMessage
		if uerr := json.Unmarshal(f.Payload, &failMsg); uerr != nil {
			slog.Debug("failed to decode auth_fail frame", "error", uerr)
		}
		return fmt.Errorf("auth failed: %s (%s)", failMsg.Reason, failMsg.Code)

	default:
		return fmt.Errorf("expected AUTH_OK/FAIL, got 0x%04x", f.Header.Type)
	}
}

func decodeBase64Key(b64 string, expectedLen int) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(key) != expectedLen {
		return nil, fmt.Errorf("key length %d, expected %d", len(key), expectedLen)
	}
	return key, nil
}
