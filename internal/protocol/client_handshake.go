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

// SendHello 发送 HELLO（core spec §9.5）。ctx 约束写操作超时/取消。
func (c *CoreClient) SendHello(ctx context.Context) error {
	agentVersion := c.cfg.AgentVersion
	if agentVersion == "" {
		agentVersion = "0.1.0" // 未显式配置时回退到 mbta-go 内置默认
	}
	hello := &corepb.HelloMessage{
		AgentId:       c.cfg.AgentID,
		Hostname:      c.cfg.Hostname,
		FrameVersion:  1,
		AgentVersion:  agentVersion,
		Capabilities:  c.cfg.Capabilities,
		InstanceId:    core.NewChunkID().String(),
		StartedAtUnix: time.Now().Unix(),
	}
	if c.cfg.OS != "" {
		hello.Os = &c.cfg.OS // optional 字段：仅在配置时发送
	}
	payload, err := core.Encode(hello)
	if err != nil {
		return core.WrapError(core.ErrCodeProtocol, "marshal hello", err)
	}
	if err := c.tr.WriteFrame(ctx, core.TypeHello, core.FlagControl, core.ChannelControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateHelloSent); err != nil {
		return core.WrapError(core.ErrCodeSession, "transition to HELLO_SENT", err)
	}
	return nil
}

// RecvHelloAck 接收 HELLO_ACK，存储协商结果与 challenge nonce。ctx 约束读超时/取消。
func (c *CoreClient) RecvHelloAck(ctx context.Context) (*core.HelloAckMessage, error) {
	f, err := c.tr.ReadFrame(ctx)
	if err != nil {
		return nil, err
	}
	if f.Header.Type == core.TypeError {
		var errMsg core.ErrorMessage
		if derr := core.Decode(f.Payload, &errMsg); derr != nil {
			// 解码失败不静默丢弃：记录原始错误，携带可用的 raw payload 信息辅助排障。
			slog.Warn("failed to decode TypeError payload, using raw bytes for diagnosis",
				"decode_error", derr,
				"raw_payload_len", len(f.Payload))
			return nil, core.NewError(core.ErrCodeHandshake, fmt.Sprintf("server error (decode failed: %v, raw=%x)", derr, f.Payload))
		}
		// MatchWireCode 解析对端具体 wire 码（如 unsupported_version），
		// 用其 Num 构造 *Error，使上层 errors.Is 可精确匹配；未知码回退 Handshake 大类。
		ec := core.MatchWireCode(errMsg.GetCode())
		if ec == core.ErrCodeUnknown {
			ec = core.ErrCodeHandshake
		}
		return nil, core.NewError(ec, fmt.Sprintf("server error: %s", errMsg.GetReason()))
	}
	if f.Header.Type != core.TypeHelloAck {
		return nil, core.NewError(core.ErrCodeProtocol, fmt.Sprintf("expected HELLO_ACK, got 0x%02x", f.Header.Type))
	}

	var ack core.HelloAckMessage
	if err := core.Decode(f.Payload, &ack); err != nil {
		return nil, err
	}

	// 先校验再 Store：避免校验失败时脏的 NegotiateResult（含 UNSPECIFIED cipher suite）
	// 残留在 atomic 指针中，被并发 reader（buildAndSend/codecForMarshal）看到。
	if ack.GetCipherSuite() == corepb.CipherSuite_CIPHER_SUITE_UNSPECIFIED {
		return nil, core.NewError(core.ErrCodeHandshake, "server selected unspecified cipher suite")
	}
	if len(ack.GetChallengeNonce()) == 0 {
		return nil, core.NewError(core.ErrCodeHandshake, "server did not provide challenge_nonce in HELLO_ACK")
	}
	c.negotiated.Store(&core.NegotiateResult{
		SelectedCapabilities: ack.GetSelectedCapabilities(),
		Codec:                ack.GetCodec(),
		Compression:          ack.GetCompression(),
		CipherSuite:          ack.GetCipherSuite(),
	})
	// 防御性拷贝：GetChallengeNonce 返回 proto 内部 slice 引用，直接 Store 会在
	// proto 消息被复用/pool 化时被静默篡改，影响 HMAC 计算安全性。
	nonce := make([]byte, len(ack.GetChallengeNonce()))
	copy(nonce, ack.GetChallengeNonce())
	c.challengeNonce.Store(nonce)

	return &ack, nil
}

// getChallengeNonce 返回 challengeNonce 字节（atomic.Value 内为 []byte）。
func (c *CoreClient) getChallengeNonce() []byte {
	if v := c.challengeNonce.Load(); v != nil {
		return v.([]byte)
	}
	return nil
}

// SendAuth 发送 AUTH（challenge-response）。ctx 约束写操作超时/取消。
func (c *CoreClient) SendAuth(ctx context.Context) error {
	challengeNonce := c.getChallengeNonce()
	if len(challengeNonce) == 0 {
		return core.NewError(core.ErrCodeAuth, "server did not provide challenge_nonce in HELLO_ACK, cannot authenticate")
	}

	auth := c.buildAuthMessage()
	payload, err := core.Encode(auth)
	if err != nil {
		return core.WrapError(core.ErrCodeProtocol, "marshal auth", err)
	}
	if err := c.tr.WriteFrame(ctx, core.TypeAuth, core.FlagControl, core.ChannelControl, payload); err != nil {
		return err
	}
	if err := c.sm.Transition(core.StateAuthSent); err != nil {
		return core.WrapError(core.ErrCodeSession, "transition to AUTH_SENT", err)
	}
	return nil
}

// buildAuthMessage 构造 AUTH 帧：Token + 基于 challenge 的 HMAC 应答（按协商 CipherSuite）。
// CipherSuite 优先协商结果，否则回退到 binding 注入的 cfg.DefaultCipherSuite
// （spec §8.3：默认套件跟随传输 binding，不应在协议核心硬编码 intl）。
func (c *CoreClient) buildAuthMessage() *corepb.AuthMessage {
	cs := c.cfg.DefaultCipherSuite
	if n := c.negotiated.Load(); n != nil {
		cs = n.CipherSuite
	}
	return &corepb.AuthMessage{
		Token:     c.cfg.Token,
		AgentId:   c.cfg.AgentID,
		SessionId: c.getSessionID(),
		AuthNonce: core.ComputeChallengeResponse(c.cfg.Token, string(c.getChallengeNonce()), cs),
	}
}

// RecvAuthResult 接收 AUTH_OK / AUTH_FAIL。AUTH_OK 后调用 onAuthed 钩子（v1 binding
// 用于 SetAuthed 开放 data stream 门禁；ntls binding 不设置此钩子）。ctx 约束读超时/取消。
func (c *CoreClient) RecvAuthResult(ctx context.Context) error {
	f, err := c.tr.ReadFrame(ctx)
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
		// 安全交叉校验：AUTH_OK 的 cipher suite 必须与 HELLO_ACK 协商结果一致，
		// 防止恶意/有缺陷的服务端在协商后下发不同套件导致密钥派生用错误算法。
		if n := c.negotiated.Load(); n != nil && cs != n.CipherSuite {
			return core.NewError(core.ErrCodeProtocol, fmt.Sprintf("cipher suite mismatch: AUTH_OK=%s vs negotiated=%s", cs, n.CipherSuite))
		}
		keys := core.NewSessionKeys(okMsg.GetKeyId(), cs, okMsg.GetHmacKey())
		// AEAD 密钥按套件下发字段（intl=AesKey, gm=Sm4Key）。
		// 显式 switch 替代 else 兜底，避免 UNSPECIFIED 静默用空 Sm4Key 导致加密失效。
		switch cs {
		case corepb.CipherSuite_CIPHER_SUITE_INTL:
			keys.SetAEADKey(okMsg.GetAesKey())
		case corepb.CipherSuite_CIPHER_SUITE_GM:
			keys.SetAEADKey(okMsg.GetSm4Key())
		default:
			return core.NewError(core.ErrCodeProtocol, fmt.Sprintf("unsupported cipher suite in AUTH_OK: %s", cs))
		}
		c.keys.Store(keys)

		// 服务端必须指定 session TTL（spec §9.5）。expires_at_unix=0 视为协议错误。
		if okMsg.GetExpiresAtUnix() <= 0 {
			return core.NewError(core.ErrCodeProtocol, "AUTH_OK missing session expiry (expires_at_unix must be > 0)")
		}
		c.expiresAt.Store(okMsg.GetExpiresAtUnix())

		// 先 Transition(StateReady) 再触发 onAuthed：binding 回调（v1 SetAuthed）
		// 可能检查 StateReady 开放 data stream 门禁，若状态仍为 StateAuthSent 会行为异常。
		if err := c.sm.Transition(core.StateReady); err != nil {
			return core.WrapError(core.ErrCodeSession, "transition to READY", err)
		}
		if c.onAuthed != nil {
			// 使用调用方 ctx 而非 context.Background()：尊重上游超时/取消约束，
			// 避免 onAuthed 回调在调用方已取消的上下文中无限执行。
			c.onAuthed(ctx)
		}
		return nil

	case core.TypeAuthFail:
		var failMsg core.AuthFailMessage
		if uerr := core.Decode(f.Payload, &failMsg); uerr != nil {
			// AUTH_FAIL 反序列化失败不可静默丢弃（仅 Debug）：retryable 标记与
			// challenge nonce 均丢失，违反 spec §9.5 重放防护。记录 warn 并携带
			// raw payload 信息，便于从日志中还原故障上下文。
			slog.Warn("failed to decode AUTH_FAIL frame, challenge nonce and retry flag lost",
				"decode_error", uerr,
				"raw_payload_len", len(f.Payload))
		}
		// 重放防护（core spec §9.5）：retryable 时服务端回传新的一次性 challenge，
		// 客户端 MUST 用新挑战重算。更新本地 challengeNonce，供上层重试时
		// buildAuthMessage 使用——旧 challenge 一次性，复用会使重放防护形同虚设。
		if failMsg.GetRetryable() && len(failMsg.GetChallengeNonce()) > 0 {
			nonce := make([]byte, len(failMsg.GetChallengeNonce()))
			copy(nonce, failMsg.GetChallengeNonce())
			c.challengeNonce.Store(nonce)
		}
		return core.NewError(core.ErrCodeAuth, fmt.Sprintf("auth failed: %s (%s)", failMsg.GetReason(), failMsg.GetCode()))

	default:
		return core.NewError(core.ErrCodeProtocol, fmt.Sprintf("expected AUTH_OK/FAIL, got 0x%02x", f.Header.Type))
	}
}
