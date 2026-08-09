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
		return core.WrapError(core.ErrCodeProtocol, "decode hello", err)
	}
	if err := core.ValidateHello(&msg); err != nil {
		slog.Debug("HELLO validation failed", "error", err)
		h.sendError(ctx, core.ErrCodeDecodeFailed, "invalid hello message", true)
		return err
	}

	h.setAgentID(msg.GetAgentId())
	h.setHelloMeta(msg.GetHostname(), msg.GetInstanceId(), msg.GetAgentVersion(), msg.GetOs())
	h.setSessionID(core.NewChunkID().Bytes())
	nonce, err := randBytes(challengeNonceLen)
	if err != nil {
		// 密码学随机源不可用：中断握手，拒绝该连接（不回退弱随机）。
		return core.WrapError(core.ErrCodeAuth, "generate challenge nonce", err)
	}
	h.setChallengeNonce(nonce)

	// 0-RTT resumption（core spec §11.6）：从 session ticket 恢复 master 密钥。
	// 仅暂存 master 到 resumptionMaster，等 handleAuth 完成 challenge-response 后
	// 用 HKDF 派生独立子钥（前向保密）。票据单次使用：Get 后立即 Delete 防重放。
	if ticket := msg.GetSessionTicket(); len(ticket) > 0 && h.config.SessionStore != nil {
		if state, ok := h.config.SessionStore.Get(ticket); ok {
			h.config.SessionStore.Delete(ticket)
			// 安全校验：0-RTT 恢复的 agentID 必须与 HELLO 中声明的 agentID 一致。
			// 若不一致说明票据可能被窃取（重放到不同 agent），拒绝恢复。
			if state.AgentID != msg.GetAgentId() {
				slog.Warn("0-RTT resumption rejected: agentID mismatch",
					"ticket_agent", core.SanitizeForLog(state.AgentID),
					"hello_agent", core.SanitizeForLog(msg.GetAgentId()))
			} else {
				// 仅暂存 master，不置 keys——子钥在 handleAuth 派生。
				// 这样即便后续 challenge-response 失败，攻击者也无法用 master 解密任何数据。
				h.resumptionMaster.Store(state.Keys)
				slog.Info("0-RTT resumption: master cached, awaiting re-auth for subkey derivation", "agent", core.SanitizeForLog(state.AgentID))
			}
		}
	}

	// 先 Negotiate 成功再 Transition：避免协商失败时状态机已前移到 HelloReceived
	// 却无法回退（先 Transition 再 Negotiate，失败后状态残留干扰 cleanup/metrics）。
	result, err := core.Negotiate(msg.GetCapabilities(), h.config.Policy)
	if err != nil {
		slog.Debug("negotiation failed", "error", err)
		h.sendError(ctx, core.ErrCodeUnsupportedMessage, "capability negotiation failed", true)
		return err
	}
	h.negotiated.Store(&result)

	if err := h.sm.Transition(core.ServerStateHelloReceived); err != nil {
		return core.WrapError(core.ErrCodeSession, "transition HELLO_RECEIVED", err)
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
		return core.WrapError(core.ErrCodeProtocol, "marshal hello_ack", err)
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeHelloAck, core.FlagControl, ackPayload); err != nil {
		return core.WrapError(core.ErrCodeStream, "write hello_ack", err)
	}

	if err := h.sm.Transition(core.ServerStateAuthWait); err != nil {
		return core.WrapError(core.ErrCodeSession, "transition AUTH_WAIT", err)
	}
	slog.Info("hello processed", "agent", core.SanitizeForLog(h.getAgentID()), "session", string(h.getSessionID()))
	return nil
}

// handleAuth 处理 AUTH：challenge-response + token 校验 + 会话密钥（core spec §9.5）。
//
// 返回值语义：
//   - 返回 nil：认证成功，或可重试的认证失败（已发送 AUTH_FAIL 帧，连接保持打开，
//     允许客户端在同连接上重试，maxAuthAttempts 限制生效）。
//   - 返回 error：不可恢复的认证失败（达到最大重试次数、致命解码错误），
//     controlLoop 将终止连接。
func (h *CoreHandler) handleAuth(ctx context.Context, payload []byte) error {
	h.handshakeMu.Lock()
	if h.authAttempts >= maxAuthAttempts {
		h.handshakeMu.Unlock()
		h.sendAuthFail(ctx, core.ErrCodeTooManyAttempts, "authentication retry limit exceeded", false)
		return core.NewError(core.ErrCodeAuth, "too many auth attempts")
	}
	h.authAttempts++
	h.handshakeMu.Unlock()

	var msg corepb.AuthMessage
	if err := core.Decode(payload, &msg); err != nil {
		return core.WrapError(core.ErrCodeProtocol, "decode auth", err)
	}
	if err := core.ValidateAuth(&msg); err != nil {
		slog.Warn("auth validation failed", "session", string(h.getSessionID()), "error", err)
		h.failAuth(ctx, core.ErrCodeInvalidAuth, "authentication failed")
		return nil // 可重试：连接保持打开
	}
	if msg.GetAgentId() != h.getAgentID() {
		h.failAuth(ctx, core.ErrCodeInvalidAuth, "authentication failed")
		return nil
	}
	if !bytes.Equal(msg.GetSessionId(), h.getSessionID()) {
		h.failAuth(ctx, core.ErrCodeInvalidAuth, "authentication failed")
		return nil
	}

	token, _, err := h.resolveAuthToken(&msg)
	if err != nil {
		h.failAuth(ctx, core.ErrCodeInvalidToken, "token resolution failed")
		return nil //nolint:nilerr // 可重试：已发 AUTH_FAIL，连接保持打开
	}
	// token 必填校验：resolveAuthToken 返回空 token 说明既非 tokenless（无 TokenResolver）
	// 也非 legacy 明文 token（客户端未传 token）。空 token 不能进行 challenge-response。
	if token == "" {
		h.failAuth(ctx, core.ErrCodeInvalidToken, "token is required")
		return nil //nolint:nilerr // 可重试
	}

	negotiated, err := h.verifyChallenge(ctx, &msg, token)
	if err != nil {
		return nil //nolint:nilerr // verifyChallenge 内部已发 AUTH_FAIL（retryable），连接保持打开
	}

	if h.config.Auth != nil {
		if _, err := h.config.Auth.Validate(token); err != nil {
			h.failAuth(ctx, core.ErrCodeInvalidToken, "token validation failed")
			h.config.Metrics.AuthFailure().Inc()
			return nil //nolint:nilerr // 可重试
		}
	}

	if negotiated == nil {
		h.sendAuthFail(ctx, core.ErrCodeInternalError, "no negotiation result", true)
		return core.NewError(core.ErrCodeConfig, "missing negotiation result")
	}
	keys, kerr := h.deriveSessionKeys(ctx, negotiated.CipherSuite)
	if kerr != nil {
		return kerr // deriveSessionKeys 已发 AUTH_FAIL
	}
	h.keys.Store(keys)
	h.expiresAt.Store(time.Now().Add(core.DefaultSessionTTL).Unix())

	agentID := h.getAgentID()
	sessionID := h.getSessionID()
	if err := h.buildAndSendAuthOK(ctx, agentID, sessionID, keys); err != nil {
		return err
	}

	if err := h.sm.Transition(core.ServerStateReady); err != nil {
		return core.WrapError(core.ErrCodeSession, "transition READY", err)
	}
	slog.Info("auth succeeded", "agent", core.SanitizeForLog(agentID), "session", string(sessionID), "key_id", keys.KeyID)

	// 会话生命周期回调：在 AUTH_OK 发送、状态机进入 READY 之后触发 CONNECTED。
	// 放在 RedirectChecker 之前：被重定向（follower→leader）的连接也会先 CONNECTED，
	// 随后连接关闭时再触发 DISCONNECTED，保证 CONNECTED/DISCONNECTED 严格成对。
	// 早于任何 BATCH 处理，且此时 dataLoop 尚未启动，回调内不会与数据路径竞争。
	// 标记已认证：DISCONNECTED 仅对认证成功（到达 READY）的连接触发，与 CONNECTED 严格配对。
	h.authed.Store(true)
	// 注意：回调在连接 goroutine 内同步执行，实现必须非阻塞。
	if h.config.OnSession != nil {
		hostname, instanceID, agentVersion, osStr := h.helloMeta()
		h.config.OnSession(core.SessionEvent{
			Type:         core.SessionConnected,
			AgentID:      agentID,
			SessionID:    string(sessionID),
			Hostname:     hostname,
			InstanceID:   instanceID,
			AgentVersion: agentVersion,
			OS:           osStr,
			RemoteAddr:   h.tr.RemoteAddr(),
		})
	}

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
				// redirect 帧发送失败为非致命：AUTH_OK 已发，客户端 session 有效，
				// redirect 仅是 HA 路由指导（best-effort）。记录告警并返回 ErrRedirected
				// 使 binding/server.go 的 errors.Is 判定为正常 HA 流程（Debug 级日志），
				// 而非被当作普通 handler error 误记为 ERROR 级。
				slog.Warn("send redirect frame failed", "error", err, "agent", core.SanitizeForLog(agentID))
				return core.NewError(core.ErrCodeRedirected, "redirect frame send failed")
			}
			slog.Info("redirected client to leader", "agent", core.SanitizeForLog(agentID), "leader", info.LeaderAddr)
			return core.NewError(core.ErrCodeRedirected, "client redirected to leader")
		}
	}
	// AuthSuccess 在 redirect 检查之后递增：redirect 的会话由 leader 处理，不应在
	// follower 上计入成功——否则指标虚高（Inc() 放在 redirect 之前会虚高）。
	h.config.Metrics.AuthSuccess().Inc()
	return nil
}

// verifyChallenge 校验 challenge-response（HMAC(token, nonce)），确认客户端持有 token。
// 安全 fail-closed：challengeNonce/negotiated 缺失属异常状态，必须拒绝认证而非静默跳过。
// 从 handleAuth 抽取以降低认知复杂度。
func (h *CoreHandler) verifyChallenge(ctx context.Context, msg *corepb.AuthMessage, token string) (*core.NegotiateResult, error) {
	negotiated := h.negotiated.Load()
	challengeNonce := h.getChallengeNonce()
	if len(challengeNonce) == 0 || negotiated == nil {
		slog.Warn("challenge nonce or negotiation result missing", "session", string(h.getSessionID()))
		h.failAuth(ctx, core.ErrCodeInternalError, "challenge nonce or negotiation result missing")
		return nil, core.NewError(core.ErrCodeConfig, "missing challenge nonce or negotiation result")
	}
	expected := core.ComputeChallengeResponse(token, h.getAgentID(), string(h.getSessionID()), challengeNonce, negotiated.CipherSuite)
	if !hmac.Equal(msg.GetAuthNonce(), expected) {
		slog.Warn("auth challenge mismatch", "session", string(h.getSessionID()))
		h.failAuth(ctx, core.ErrCodeChallengeMismatch, "auth_nonce HMAC verification failed")
		return nil, core.NewError(core.ErrCodeAuth, "challenge nonce mismatch")
	}
	return negotiated, nil
}

// deriveSessionKeys 生成本次会话密钥。
// 0-RTT resumption 时从 handleHello 暂存的 master 用 HKDF 派生子钥（前向保密）；
// 非恢复路径全新生成。抽取自 handleAuth 以降低其认知复杂度。
func (h *CoreHandler) deriveSessionKeys(ctx context.Context, cs corepb.CipherSuite) (*core.SessionKeys, error) {
	// 0-RTT resumption：master 在 handleHello 暂存。challenge-response 通过后派生子钥。
	if master := h.resumptionMaster.Swap(nil); master != nil {
		serverRandom, randErr := randBytes(32)
		if randErr != nil {
			h.sendAuthFail(ctx, core.ErrCodeInternalError, "resumption random generation failed", true)
			return nil, core.WrapError(core.ErrCodeEnvelope, "generate resumption server random", randErr)
		}
		keys, derr := core.DeriveResumptionKeys(master, serverRandom)
		if derr != nil {
			h.sendAuthFail(ctx, core.ErrCodeInternalError, "resumption key derivation failed", true)
			return nil, core.WrapError(core.ErrCodeEnvelope, "derive resumption keys", derr)
		}
		return keys, nil
	}
	keys, gerr := core.GenerateSessionKeys(cs)
	if gerr != nil {
		h.sendAuthFail(ctx, core.ErrCodeInternalError, "key generation failed", true)
		return nil, core.WrapError(core.ErrCodeConfig, "session key generation", gerr)
	}
	return keys, nil
}

// buildAndSendAuthOK 构造并发送 AUTH_OK 帧（含会话密钥 + 可选 0-RTT ticket）。
// 抽取自 handleAuth 以降低认知复杂度。
func (h *CoreHandler) buildAndSendAuthOK(ctx context.Context, agentID string, sessionID []byte, keys *core.SessionKeys) error {
	okMsg := &corepb.AuthOKMessage{
		SessionId:     sessionID,
		KeyId:         keys.KeyID,
		HmacKey:       keys.HMACKey(),
		CipherSuite:   keys.CipherSuite,
		ExpiresAtUnix: h.expiresAt.Load(),
	}
	// 按协商套件下发对应 AEAD 密钥（intl=AesKey, gm=Sm4Key）。
	if keys.CipherSuite == corepb.CipherSuite_CIPHER_SUITE_INTL {
		okMsg.AesKey = keys.AEADKey()
	} else {
		okMsg.Sm4Key = keys.AEADKey()
	}
	// 0-RTT session ticket：颁发新 ticket（client 保存用于下次 resumption，core spec §11.6）。
	if h.config.SessionStore != nil {
		ticket, err := core.NewTicket()
		if err != nil {
			h.sendAuthFail(ctx, core.ErrCodeInternalError, "ticket generation failed", true)
			return core.WrapError(core.ErrCodeAuth, "generate session ticket", err)
		}
		if err := h.config.SessionStore.Put(ticket, &core.SessionState{
			Keys:    keys,
			AgentID: agentID,
			Expiry:  time.Unix(h.expiresAt.Load(), 0),
		}); err != nil {
			// session store 已满或已关闭：不阻塞 AUTH_OK，但不下发 ticket——
			// 否则客户端保存后用于 0-RTT 恢复时会静默失败（store 找不到该 ticket）。
			slog.Warn("session store put failed, disabling 0-RTT ticket", "error", err)
		} else {
			okMsg.SessionTicket = ticket
		}
	}
	okPayload, err := core.Encode(okMsg)
	if err != nil {
		return core.WrapError(core.ErrCodeProtocol, "marshal auth_ok", err)
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeAuthOK, core.FlagControl, okPayload); err != nil {
		return core.WrapError(core.ErrCodeStream, "write auth_ok", err)
	}
	return nil
}

// resolveAuthToken 决定 token 来源（tokenless 反查 vs legacy 明文）。
func (h *CoreHandler) resolveAuthToken(msg *corepb.AuthMessage) (token string, tokenless bool, err error) {
	if h.config.Auth == nil {
		return msg.GetToken(), false, nil
	}
	// tokenless：有 TokenResolver 时反查 token；无则用 legacy 明文 token。
	if resolver, ok := h.config.Auth.(core.TokenResolver); ok && resolver != nil {
		t, rerr := resolver.ResolveToken(msg.GetAgentId())
		if rerr != nil {
			// Resolver 失败必须作为认证错误传播，否则服务端会静默降级到明文 token，形成降级攻击面。
			return "", false, core.WrapError(core.ErrCodeAuth, "resolve token", rerr)
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
		slog.Warn("failed to marshal pong", "error", err)
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypePong, core.FlagControl, p); err != nil {
		slog.Warn("write pong failed", "error", err)
	}
}
