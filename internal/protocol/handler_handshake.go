package protocol

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"log/slog"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// handleHello 处理 HELLO（core spec §9.5）。
func (h *CoreHandler) handleHello(ctx context.Context, payload []byte) error {
	var msg corepb.HelloMessage
	if err := core.Decode(payload, &msg); err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "decode hello", err)
	}
	if err := core.ValidateHello(&msg); err != nil {
		slog.Debug("HELLO validation failed", "error", err)
		h.sendError(ctx, core.CodeDecodeFailed, "invalid hello message", true)
		return err
	}

	h.setAgentID(msg.GetAgentId())
	h.setSessionID(core.NewChunkID().Bytes())
	nonce, err := randBytes(challengeNonceLen)
	if err != nil {
		// 密码学随机源不可用：中断握手，拒绝该连接（不回退弱随机）。
		return core.WrapError(core.NumAuth, core.CodeAuth, "generate challenge nonce", err)
	}
	h.setChallengeNonce(nonce)

	// 0-RTT resumption：从 session ticket 恢复 keys（core spec §11.6）。
	// 恢复后 earlyData=true，dataLoop 可在 AUTH 前启动处理 0-RTT BATCH。
	// 票据单次使用：Get 后立即 Delete，防止捕获的票据被无限重放恢复密钥发 0-RTT。
	if ticket := msg.GetSessionTicket(); len(ticket) > 0 && h.config.SessionStore != nil {
		if state, ok := h.config.SessionStore.Get(ticket); ok {
			h.config.SessionStore.Delete(ticket)
			h.keys.Store(state.Keys)
			// 先写 agentID 再置 earlyData：earlyData 是 dataLoop 启动门控，
			// 用 atomic.Bool 的 Store 提供 happens-before，保证读端看到 agentID。
			h.setAgentID(state.AgentID)
			h.earlyData.Store(true)
			slog.Info("0-RTT resumption: keys restored from ticket", "agent", core.SanitizeForLog(h.getAgentID()))
		}
	}

	// 先 Negotiate 成功再 Transition：避免协商失败时状态机已前移到 HelloReceived
	// 却无法回退（旧实现先 Transition 再 Negotiate，失败后状态残留干扰 cleanup/metrics）。
	result, err := core.Negotiate(msg.GetCapabilities(), h.config.Policy)
	if err != nil {
		slog.Debug("negotiation failed", "error", err)
		h.sendError(ctx, core.CodeUnsupportedMessage, "capability negotiation failed", true)
		return err
	}
	h.negotiated.Store(&result)

	if err := h.sm.Transition(core.ServerStateHelloReceived); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition HELLO_RECEIVED", err)
	}

	ack := &corepb.HelloAckMessage{
		ServerId:             h.config.ServerID,
		SessionId:            h.getSessionID(),
		SelectedCapabilities: result.SelectedCapabilities,
		Codec:                result.Codec,
		Compression:          result.Compression,
		CipherSuite:          result.CipherSuite,
		HeartbeatIntervalSec: heartbeatIntervalSec,
		MaxFramePayloadBytes: maxFramePayloadBytes,
		MaxBatchBytes:        maxBatchBytes,
		MaxEventBytes:        maxEventBytes,
		MaxBatchEvents:       maxBatchEvents,
		InitialWindow: &corepb.WindowMessage{
			MaxInflightBatches: int32(windowMaxBatches),
			MaxInflightEvents:  int32(windowMaxEvents),
			MaxInflightBytes:   windowMaxBytes,
		},
		ChallengeNonce: h.getChallengeNonce(),
	}
	ackPayload, err := core.Encode(ack)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal hello_ack", err)
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeHelloAck, core.FlagControl, ackPayload); err != nil {
		return core.WrapError(core.NumStream, core.CodeStream, "write hello_ack", err)
	}

	if err := h.sm.Transition(core.ServerStateAuthWait); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition AUTH_WAIT", err)
	}
	slog.Info("hello processed", "agent", core.SanitizeForLog(h.getAgentID()), "session", string(h.getSessionID()))
	return nil
}

// handleAuth 处理 AUTH：challenge-response + token 校验 + 会话密钥（core spec §9.5）。
func (h *CoreHandler) handleAuth(ctx context.Context, payload []byte) error {
	h.handshakeMu.Lock()
	if h.authAttempts >= maxAuthAttempts {
		h.handshakeMu.Unlock()
		h.sendAuthFail(ctx, "too_many_attempts", "authentication retry limit exceeded", false)
		return core.NewError(core.NumAuth, core.CodeAuth, "too many auth attempts")
	}
	h.authAttempts++
	h.handshakeMu.Unlock()

	var msg corepb.AuthMessage
	if err := core.Decode(payload, &msg); err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "decode auth", err)
	}
	if err := core.ValidateAuth(&msg); err != nil {
		slog.Warn("auth validation failed", "session", string(h.getSessionID()), "error", err)
		h.failAuth(ctx, "invalid_auth", "authentication failed")
		return err
	}
	if msg.GetAgentId() != h.getAgentID() {
		h.failAuth(ctx, "invalid_auth", "authentication failed")
		return core.NewError(core.NumAuth, core.CodeAuth, "agent_id mismatch")
	}
	if !bytes.Equal(msg.GetSessionId(), h.getSessionID()) {
		h.failAuth(ctx, "invalid_auth", "authentication failed")
		return core.NewError(core.NumAuth, core.CodeAuth, "session_id mismatch")
	}

	token, _, err := h.resolveAuthToken(&msg)
	if err != nil {
		return err
	}

	// Challenge-response：HMAC(token, nonce) 验证客户端持有 token。
	// 安全 fail-closed：challengeNonce/negotiated 缺失属异常状态，必须拒绝认证而非静默跳过。
	negotiated := h.negotiated.Load()
	challengeNonce := h.getChallengeNonce()
	if len(challengeNonce) == 0 || negotiated == nil {
		slog.Warn("challenge nonce or negotiation result missing", "session", string(h.getSessionID()))
		h.failAuth(ctx, "internal_error", "challenge nonce or negotiation result missing")
		return core.NewError(core.NumConfig, core.CodeConfig, "missing challenge nonce or negotiation result")
	}
	expected := core.ComputeChallengeResponse(token, string(challengeNonce), negotiated.CipherSuite)
	if !hmac.Equal(msg.GetAuthNonce(), expected) {
		slog.Warn("auth challenge mismatch", "session", string(h.getSessionID()))
		h.failAuth(ctx, "challenge_mismatch", "auth_nonce HMAC verification failed")
		return core.NewError(core.NumAuth, core.CodeAuth, "challenge nonce mismatch")
	}

	if h.config.Auth != nil {
		if _, err := h.config.Auth.Validate(token); err != nil {
			h.failAuth(ctx, "invalid_token", "token validation failed")
			h.config.Metrics.AuthFailure().Inc()
			return core.WrapError(core.NumAuth, core.CodeAuth, "token validation", err)
		}
	}

	if negotiated == nil {
		h.sendAuthFail(ctx, "internal_error", "no negotiation result", true)
		return core.NewError(core.NumConfig, core.CodeConfig, "missing negotiation result")
	}
	keys, err := core.GenerateSessionKeys(negotiated.CipherSuite)
	if err != nil {
		h.sendAuthFail(ctx, "internal_error", "key generation failed", true)
		return core.WrapError(core.NumConfig, core.CodeConfig, "session key generation", err)
	}
	h.keys.Store(keys)
	h.expiresAt.Store(time.Now().Add(core.DefaultSessionTTL).Unix())

	agentID := h.getAgentID()
	sessionID := h.getSessionID()
	okMsg := &corepb.AuthOKMessage{
		SessionId:     sessionID,
		KeyId:         keys.KeyID,
		HmacKey:       keys.HMACKey(),
		CipherSuite:   keys.CipherSuite,
		ExpiresAtUnix: h.expiresAt.Load(),
	}
	// 按协商套件下发对应 AEAD 密钥（intl=AesKey, gm=Sm4Key）。
	if negotiated.CipherSuite == corepb.CipherSuite_CIPHER_SUITE_INTL {
		okMsg.AesKey = keys.AEADKey()
	} else {
		okMsg.Sm4Key = keys.AEADKey()
	}
	// 0-RTT session ticket：颁发新 ticket（client 保存用于下次 resumption，core spec §11.6）。
	if h.config.SessionStore != nil {
		ticket, err := core.NewTicket()
		if err != nil {
			h.sendAuthFail(ctx, "internal_error", "ticket generation failed", true)
			return core.WrapError(core.NumAuth, core.CodeAuth, "generate session ticket", err)
		}
		if err := h.config.SessionStore.Put(ticket, &core.SessionState{
			Keys:    keys,
			AgentID: agentID,
			Expiry:  time.Unix(h.expiresAt.Load(), 0),
		}); err != nil {
			// session store 已满或已关闭：不阻塞 AUTH_OK，但记录告警便于运维定位。
			slog.Warn("session store put failed", "error", err)
		}
		okMsg.SessionTicket = ticket
	}
	okPayload, err := core.Encode(okMsg)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal auth_ok", err)
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeAuthOK, core.FlagControl, okPayload); err != nil {
		return core.WrapError(core.NumStream, core.CodeStream, "write auth_ok", err)
	}

	if err := h.sm.Transition(core.ServerStateReady); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition READY", err)
	}
	h.config.Metrics.AuthSuccess().Inc()
	slog.Info("auth succeeded", "agent", core.SanitizeForLog(agentID), "session", string(sessionID), "key_id", keys.KeyID)

	// HA cluster redirect (§4.17): if this replica is a follower (not the
	// elected leader), steer the client to the leader before data flows. Done
	// after AUTH_OK so the client has a valid session context to interpret the
	// redirect, and before any BATCH is processed so no data is lost on the
	// doomed connection. A nil RedirectChecker disables this (single-replica).
	if h.config.RedirectChecker != nil {
		info, redirect := h.config.RedirectChecker(ctx)
		if redirect {
			// JSON payload keeps the redirect format application-defined (avoids a
			// proto round-trip); the agent decodes {"leaderAddr","leaderId"}.
			payload, _ := json.Marshal(map[string]string{
				"leaderAddr": info.LeaderAddr,
				"leaderId":   info.LeaderID,
			})
			if err := SendControlFrame(ctx, h.tr, core.TypeRedirect, core.FlagControl, payload); err != nil {
				// redirect 帧发送失败视为致命错误：AUTH_OK 已发但客户端未收到 redirect，
				// 将在 follower 上发数据导致路由错误/数据丢失。返回 error 触发连接清理。
				return core.WrapError(core.NumStream, core.CodeStream, "write redirect frame", err)
			}
			slog.Info("redirected client to leader", "agent", core.SanitizeForLog(agentID), "leader", info.LeaderAddr)
			return core.ErrRedirected
		}
	}
	return nil
}

// resolveAuthToken 决定 token 来源（tokenless 反查 vs legacy 明文）。
func (h *CoreHandler) resolveAuthToken(msg *corepb.AuthMessage) (token string, tokenless bool, err error) {
	if h.config.Auth == nil {
		return msg.GetToken(), false, nil
	}
	// r2 tokenless：保留 legacy 路径（无 TokenResolver 时用明文 token）。
	if resolver, ok := h.config.Auth.(core.TokenResolver); ok && resolver != nil {
		t, rerr := resolver.ResolveToken(msg.GetAgentId())
		if rerr != nil {
			// Resolver 失败必须作为认证错误传播，否则服务端会静默降级到明文 token，形成降级攻击面。
			return "", false, core.WrapError(core.NumAuth, core.CodeAuth, "resolve token", rerr)
		}
		return t, true, nil
	}
	return msg.GetToken(), false, nil
}

func (h *CoreHandler) handlePing(ctx context.Context, payload []byte) {
	var msg corepb.PingMessage
	if err := core.Decode(payload, &msg); err != nil {
		slog.Debug("invalid ping payload", "error", err)
		return
	}
	pong := &corepb.PongMessage{TimeUnixMs: time.Now().UnixMilli(), Nonce: msg.GetNonce(), Status: "ok"}
	p, err := core.Encode(pong)
	if err != nil {
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypePong, core.FlagControl, p); err != nil {
		slog.Warn("write pong failed", "error", err)
	}
}
