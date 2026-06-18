package protocol

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// 常量（core spec §9.5 limits；与 v1/handler 对齐）。
const (
	maxConcurrentQuicDataFrames       = 64
	maxConcurrentTCPBatches           = 8
	maxAuthAttempts                   = 3
	heartbeatIntervalSec              = 30
	maxFramePayloadBytes              = 16 * 1024 * 1024
	maxBatchBytes                     = 8 * 1024 * 1024
	maxEventBytes                     = 256 * 1024
	maxBatchEvents                    = 10000
	windowMaxBatches                  = 100
	windowMaxEvents                   = 10000
	windowMaxBytes              int64 = 16 * 1024 * 1024
	throttleRetryMs                   = 1000
	challengeNonceLen                 = 16
)

// CodeEnvelopeAlgoMismatch 是 envelope 算法一致性复核失败时回送的 NACK code。
// 客户端 envelope 声明的 Codec/Compression/CipherSuite 与服务端协商结果不符时使用。
const CodeEnvelopeAlgoMismatch = "envelope_algo_mismatch"

// HandlerConfig 是 CoreHandler 的配置（传输无关）。
type HandlerConfig struct {
	Auth         core.TokenValidator
	Policy       core.Policy
	Sink         core.EventSink
	Metrics      *core.MBTAMetrics
	ServerID     string
	SessionStore *core.SessionStore // 0-RTT resumption（可选，nil = 不支持 early_data）
}

// CoreHandler 是 server 端协议状态机核心，仅依赖 Transport 接口，
// 不感知 quic.Stream/net.Conn（core spec §10.2）。
// 吸收 v1/handler.go 与 ntls/handler.go 的全部共享协议逻辑。
type CoreHandler struct {
	tr     Transport
	config HandlerConfig

	sm         *core.ServerMachine
	negotiated *core.NegotiateResult
	keys       *core.SessionKeys
	replay     *core.ReplayCache
	window     *core.Window
	inflight   *core.Inflight

	agentID        string
	sessionID      []byte
	challengeNonce []byte
	authAttempts   int
	expiresAt      atomic.Int64
	closeTimeout   time.Duration // 优雅关闭 drain 超时（从 CloseMessage.close_timeout_ms 协商，默认 5s）
	earlyData      bool          // 0-RTT resumption：HELLO 恢复 keys 后置位，dataLoop early 启动
	lastPressure   atomic.Value

	dataOnce sync.Once
	dataWG   sync.WaitGroup // 跟踪 data frame 处理 goroutine
	batchSem chan struct{}  // data frame 并发上限（QUIC=64 / TCP=8）
}

// NewCoreHandler 创建 handler。batchSem 容量按 Multiplexing 选（保留两套并发模型）。
func NewCoreHandler(tr Transport, cfg HandlerConfig) *CoreHandler {
	sem := maxConcurrentQuicDataFrames
	if tr.Multiplexing() == MultiplexTCPSingleConn {
		sem = maxConcurrentTCPBatches
	}
	h := &CoreHandler{
		tr:       tr,
		config:   cfg,
		sm:       core.NewServerMachine(),
		replay:   core.NewReplayCache(),
		window:   core.NewWindow(windowMaxBatches, windowMaxEvents, windowMaxBytes),
		inflight: &core.Inflight{},
		batchSem: make(chan struct{}, sem),
	}
	h.lastPressure.Store(core.PressureNormal)
	return h
}

// Handle 运行连接生命周期：control loop → READY 后启动 data loop。
func (h *CoreHandler) Handle(ctx context.Context) error {
	defer h.cleanup()
	// 进入 CONTROL_WAIT（server 状态机初始为 Accepted）。
	if err := h.sm.Transition(core.ServerStateControlWait); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to CONTROL_WAIT", err)
	}
	err := h.controlLoop(ctx)
	// 等待所有 data frame 处理 goroutine 退出后再清密钥（避免与 processBatch 读 keys 竞态）。
	// drain 超时：从 CloseMessage.close_timeout_ms 协商，默认 5s（core spec §9.6）。
	drainTimeout := h.closeTimeout
	if drainTimeout == 0 {
		drainTimeout = 5 * time.Second
	}
	done := make(chan struct{})
	go func() { h.dataWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(drainTimeout):
		slog.Warn("data frame goroutines did not exit within drain timeout", "session", string(h.sessionID), "timeout", drainTimeout)
	}
	return err
}

func (h *CoreHandler) cleanup() {
	if h.keys != nil {
		for i := range h.keys.HMACKey {
			h.keys.HMACKey[i] = 0
		}
		for i := range h.keys.AEADKey {
			h.keys.AEADKey[i] = 0
		}
		h.keys = nil
	}
}

// controlLoop 处理控制帧：HELLO/AUTH/PING/CLOSE。
func (h *CoreHandler) controlLoop(ctx context.Context) error {
	for {
		f, err := h.tr.RecvControlFrame(ctx)
		if err != nil {
			return core.WrapError(core.NumProtocol, core.CodeProtocol, "read control frame", err)
		}
		switch f.Header.Type {
		case core.TypeHello:
			if h.sm.State() == core.ServerStateReady {
				h.sendError(ctx, core.CodeUnsupportedMessage, "HELLO not allowed after auth", true)
				continue
			}
			if err := h.handleHello(ctx, f.Payload); err != nil {
				return err
			}
		case core.TypeAuth:
			if h.sm.State() == core.ServerStateReady {
				h.sendError(ctx, core.CodeUnsupportedMessage, "AUTH not allowed after auth", true)
				continue
			}
			if err := h.handleAuth(ctx, f.Payload); err != nil {
				return err
			}
		case core.TypePing:
			if h.sm.State() != core.ServerStateReady {
				h.sendError(ctx, core.CodeUnsupportedMessage, "PING not allowed before auth", true)
				continue
			}
			h.handlePing(ctx, f.Payload)
		case core.TypeClose:
			var closeMsg core.CloseMessage
			_ = core.Decode(f.Payload, &closeMsg)
			if closeMsg.GetCloseTimeoutMs() > 0 {
				h.closeTimeout = time.Duration(closeMsg.GetCloseTimeoutMs()) * time.Millisecond
			}
			slog.Info("close received", "session", string(h.sessionID), "drain_timeout", h.closeTimeout)
			return nil
		default:
			h.sendError(ctx, core.CodeUnsupportedMessage, fmt.Sprintf("unexpected control type 0x%02x", f.Header.Type), true)
			return core.NewError(core.NumProtocol, core.CodeProtocol, fmt.Sprintf("unexpected control type 0x%02x", f.Header.Type))
		}

		// READY 或 0-RTT early_data 后启动 data loop（exactly once）
		if h.sm.State() == core.ServerStateReady || h.earlyData {
			h.dataOnce.Do(func() {
				h.dataWG.Add(1)
				go func() {
					defer h.dataWG.Done()
					h.dataLoop(ctx)
				}()
			})
		}
	}
}

// dataLoop 读 BATCH 帧并发处理（batchSem 限流）。
func (h *CoreHandler) dataLoop(ctx context.Context) {
	for {
		f, err := h.tr.RecvDataFrame(ctx)
		if err != nil {
			slog.Debug("data frame stream ended", "session", string(h.sessionID), "error", err)
			return
		}
		switch f.Header.Type {
		case core.TypeBatch:
			// 并发处理，受 batchSem 限制。
			select {
			case h.batchSem <- struct{}{}:
				h.dataWG.Add(1)
				go func(pf core.Frame) {
					defer func() { <-h.batchSem; h.dataWG.Done() }()
					h.processBatch(ctx, pf.Payload)
				}(f)
			default:
				// 并发满，拒绝并要求退避。
				h.sendThrottle(ctx, throttleRetryMs, "too_many_batches", "max concurrent batches exceeded")
			}
		case core.TypeDatagram:
			// r2 unreliable 通道：at-most-once，无 ACK/spool，HMAC 失败静默丢弃（core spec §11.4）。
			h.processDatagram(ctx, f.Payload)
		default:
			slog.Debug("unexpected frame on data channel", "type", f.Header.Type)
		}
	}
}

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

	h.agentID = msg.GetAgentId()
	h.sessionID = core.NewChunkID().Bytes()
	nonce, err := randBytes(challengeNonceLen)
	if err != nil {
		// 密码学随机源不可用：中断握手，拒绝该连接（不回退弱随机）。
		return core.WrapError(core.NumAuth, core.CodeAuth, "generate challenge nonce", err)
	}
	h.challengeNonce = nonce

	// 0-RTT resumption：从 session ticket 恢复 keys（core spec §11.6）。
	// 恢复后 earlyData=true，dataLoop 可在 AUTH 前启动处理 0-RTT BATCH。
	if ticket := msg.GetSessionTicket(); len(ticket) > 0 && h.config.SessionStore != nil {
		if state, ok := h.config.SessionStore.Get(ticket); ok {
			h.keys = state.Keys
			h.agentID = state.AgentID
			h.earlyData = true
			slog.Info("0-RTT resumption: keys restored from ticket", "agent", core.SanitizeForLog(h.agentID))
		}
	}

	if err := h.sm.Transition(core.ServerStateHelloReceived); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition HELLO_RECEIVED", err)
	}

	result, err := core.Negotiate(msg.GetCapabilities(), h.config.Policy)
	if err != nil {
		slog.Debug("negotiation failed", "error", err)
		h.sendError(ctx, core.CodeUnsupportedMessage, "capability negotiation failed", true)
		return err
	}
	h.negotiated = &result

	ack := &corepb.HelloAckMessage{
		ServerId:             h.config.ServerID,
		SessionId:            h.sessionID,
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
		ChallengeNonce: h.challengeNonce,
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
	slog.Info("hello processed", "agent", core.SanitizeForLog(h.agentID), "session", string(h.sessionID))
	return nil
}

// handleAuth 处理 AUTH：challenge-response + token 校验 + 会话密钥（core spec §9.5）。
func (h *CoreHandler) handleAuth(ctx context.Context, payload []byte) error {
	if h.authAttempts >= maxAuthAttempts {
		h.sendAuthFail(ctx, "too_many_attempts", "authentication retry limit exceeded", false)
		return core.NewError(core.NumAuth, core.CodeAuth, "too many auth attempts")
	}
	h.authAttempts++

	var msg corepb.AuthMessage
	if err := core.Decode(payload, &msg); err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "decode auth", err)
	}
	if err := core.ValidateAuth(&msg); err != nil {
		slog.Warn("auth validation failed", "session", string(h.sessionID), "error", err)
		h.failAuth(ctx, "invalid_auth", "authentication failed")
		return err
	}
	if msg.GetAgentId() != h.agentID {
		h.failAuth(ctx, "invalid_auth", "authentication failed")
		return core.NewError(core.NumAuth, core.CodeAuth, "agent_id mismatch")
	}
	if !bytes.Equal(msg.GetSessionId(), h.sessionID) {
		h.failAuth(ctx, "invalid_auth", "authentication failed")
		return core.NewError(core.NumAuth, core.CodeAuth, "session_id mismatch")
	}

	token, _, err := h.resolveAuthToken(&msg)
	if err != nil {
		return err
	}

	// Challenge-response：HMAC(token, nonce) 验证客户端持有 token。
	if len(h.challengeNonce) > 0 && h.negotiated != nil {
		expected := core.ComputeChallengeResponse(token, string(h.challengeNonce), h.negotiated.CipherSuite)
		if !hmac.Equal(msg.GetAuthNonce(), expected) {
			slog.Warn("auth challenge mismatch", "session", string(h.sessionID))
			h.failAuth(ctx, "challenge_mismatch", "auth_nonce HMAC verification failed")
			return core.NewError(core.NumAuth, core.CodeAuth, "challenge nonce mismatch")
		}
	}

	if h.config.Auth != nil {
		if _, err := h.config.Auth.Validate(token); err != nil {
			h.failAuth(ctx, "invalid_token", "token validation failed")
			if h.config.Metrics != nil {
				h.config.Metrics.AuthFailureTotal.Inc()
			}
			return core.WrapError(core.NumAuth, core.CodeAuth, "token validation", err)
		}
	}

	if h.negotiated == nil {
		h.sendAuthFail(ctx, "internal_error", "no negotiation result", true)
		return core.NewError(core.NumConfig, core.CodeConfig, "missing negotiation result")
	}
	keys, err := core.GenerateSessionKeys(h.negotiated.CipherSuite)
	if err != nil {
		h.sendAuthFail(ctx, "internal_error", "key generation failed", true)
		return core.WrapError(core.NumConfig, core.CodeConfig, "session key generation", err)
	}
	h.keys = keys
	h.expiresAt.Store(time.Now().Add(core.DefaultSessionTTL).Unix())

	okMsg := &corepb.AuthOKMessage{
		SessionId:     h.sessionID,
		KeyId:         keys.KeyID,
		HmacKey:       keys.HMACKey,
		CipherSuite:   keys.CipherSuite,
		ExpiresAtUnix: h.expiresAt.Load(),
	}
	// 按协商套件下发对应 AEAD 密钥（intl=AesKey, gm=Sm4Key）。
	if h.negotiated.CipherSuite == corepb.CipherSuite_CIPHER_SUITE_INTL {
		okMsg.AesKey = keys.AEADKey
	} else {
		okMsg.Sm4Key = keys.AEADKey
	}
	// 0-RTT session ticket：颁发新 ticket（client 保存用于下次 resumption，core spec §11.6）。
	if h.config.SessionStore != nil {
		ticket := core.NewTicket()
		h.config.SessionStore.Put(ticket, &core.SessionState{
			Keys:    keys,
			AgentID: h.agentID,
			Expiry:  time.Unix(h.expiresAt.Load(), 0),
		})
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
	if h.config.Metrics != nil {
		h.config.Metrics.AuthSuccessTotal.Inc()
	}
	slog.Info("auth succeeded", "agent", core.SanitizeForLog(h.agentID), "session", string(h.sessionID), "key_id", keys.KeyID)
	return nil
}

// resolveAuthToken 决定 token 来源（tokenless 反查 vs legacy 明文）。
func (h *CoreHandler) resolveAuthToken(msg *corepb.AuthMessage) (token string, tokenless bool, err error) {
	_ = tokenless
	if h.config.Auth == nil {
		return msg.GetToken(), false, nil
	}
	// r2 tokenless：保留 legacy 路径（无 TokenResolver 时用明文 token）。
	if resolver, ok := h.config.Auth.(core.TokenResolver); ok && resolver != nil {
		t, rerr := resolver.ResolveToken(msg.GetAgentId())
		if rerr == nil {
			return t, true, nil
		}
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

// processBatch 处理 reliable BATCH：envelope → 校验 → 路由 → ACK。
func (h *CoreHandler) processBatch(ctx context.Context, payload []byte) {
	env, err := core.DecodeEnvelope(payload)
	if err != nil {
		slog.Debug("invalid envelope", "error", err)
		h.sendError(ctx, core.CodeDecodeFailed, "invalid_envelope", false)
		return
	}

	if h.expiresAt.Load() > 0 && time.Now().Unix() > h.expiresAt.Load() {
		h.sendNack(ctx, env.GetSeq(), env.GetChunkId(), "session_expired", "session TTL exceeded, please reconnect", false)
		return
	}

	// Verify HMAC（在解密/解码前）。
	if h.keys != nil {
		ok, verr := core.VerifyMAC(h.keys.HMACKey, env)
		if verr != nil || !ok {
			h.sendNack(ctx, env.GetSeq(), env.GetChunkId(), "hmac_mismatch", "HMAC verification failed", false)
			if h.config.Metrics != nil {
				h.config.Metrics.HMACFailuresTotal.Inc()
			}
			return
		}
	}

	// 算法一致性复核（依据权威协商结果）。
	if h.verifyEnvelopeAlgo(env) {
		return
	}

	// Open envelope（解密+解压）。
	var aeadKey []byte
	if h.keys != nil {
		aeadKey = h.keys.AEADKey
	}
	batchPayload, err := core.Open(env, aeadKey)
	if err != nil {
		slog.Debug("envelope open failed", "error", err)
		h.sendNack(ctx, env.GetSeq(), env.GetChunkId(), "envelope_open_error", "envelope could not be opened", true)
		return
	}
	if len(batchPayload) > maxBatchBytes {
		h.sendNack(ctx, env.GetSeq(), env.GetChunkId(), "batch_too_large",
			fmt.Sprintf("batch payload %d bytes exceeds limit %d", len(batchPayload), maxBatchBytes), false)
		return
	}

	var batchMsg corepb.BatchMessage
	if err := core.Decode(batchPayload, &batchMsg); err != nil {
		slog.Debug("batch decode failed", "error", err)
		h.sendNack(ctx, env.GetSeq(), env.GetChunkId(), "invalid_batch", "batch message could not be decoded", false)
		return
	}
	if err := core.ValidateBatch(&batchMsg); err != nil {
		slog.Debug("batch validation failed", "error", err)
		h.sendNack(ctx, batchMsg.GetSeq(), batchMsg.GetChunkId(), "batch_validation", "batch failed validation", false)
		return
	}

	// chunk_id dedup key（ULID 文本）。
	chunkIDText := chunkIDText(batchMsg.GetChunkId())
	batchEvents, signalBatchPtr := h.resolveBatchEvents(&batchMsg)
	if batchEvents < 0 {
		return // 已发 NACK
	}
	batchBytes := int64(len(batchPayload))

	// 服务端流控强制。
	if !h.window.CanSend(h.inflight, batchEvents, batchBytes) {
		h.sendThrottle(ctx, throttleRetryMs, "window_exceeded", "server flow-control window exceeded")
		return
	}
	h.inflight.Add(batchEvents, batchBytes)

	// Replay 去重。
	dedupKey := core.Key(h.agentID, chunkIDText)
	if existing := h.replay.SeenOrAdd(dedupKey); existing != nil {
		h.inflight.Remove(batchEvents, batchBytes)
		ackMode := corepb.AckMode_ACK_MODE_ACCEPTED
		if existing.Status == core.ReplayDurable {
			ackMode = corepb.AckMode_ACK_MODE_DURABLE
		}
		h.sendAck(ctx, batchMsg.GetSeq(), batchMsg.GetChunkId(), batchEvents, ackMode)
		return
	}

	h.replay.Update(dedupKey, core.ReplayAccepted)
	h.routeAndACK(ctx, dedupKey, &batchMsg, signalBatchPtr, batchEvents, batchBytes)
}

// processDatagram 处理 unreliable DATAGRAM：at-most-once，无 ACK/spool（core spec §11.4）。
func (h *CoreHandler) processDatagram(ctx context.Context, payload []byte) {
	env, err := core.DecodeEnvelope(payload)
	if err != nil {
		slog.Debug("datagram decode envelope failed", "error", err)
		return // 静默丢弃
	}
	if h.keys != nil {
		ok, _ := core.VerifyMAC(h.keys.HMACKey, env)
		if !ok {
			slog.Debug("datagram hmac failed")
			return // HMAC 失败静默丢弃
		}
	}
	var aeadKey []byte
	if h.keys != nil {
		aeadKey = h.keys.AEADKey
	}
	batchPayload, err := core.Open(env, aeadKey)
	if err != nil {
		slog.Debug("datagram open failed", "error", err)
		return
	}
	var batchMsg corepb.DatagramMessage
	if err := core.Decode(batchPayload, &batchMsg); err != nil {
		slog.Debug("datagram decode message failed", "error", err)
		return
	}
	// 不可靠投递：尽力路由，无 ACK。
	if h.config.Sink != nil {
		if rawSink, ok := h.config.Sink.(core.RawEventSink); ok {
			slog.Debug("datagram delivering to raw sink", "events", batchMsg.GetEventsCount())
			_, _ = rawSink.OnRawBatch(ctx, h.agentID, int(batchMsg.GetEventsCount()), batchMsg.GetBatch())
		} else {
			slog.Debug("datagram sink is not RawEventSink")
		}
	}
}

// resolveBatchEvents 解析事件数（RawEventSink 快速路径 vs 完整解码）。batchEvents<0 表示已发 NACK。
func (h *CoreHandler) resolveBatchEvents(batchMsg *corepb.BatchMessage) (int, *core.SignalBatch) {
	rawSink, _ := h.config.Sink.(core.RawEventSink)
	if rawSink != nil && batchMsg.GetEventsCount() > 0 {
		ec := int(batchMsg.GetEventsCount())
		if ec > maxBatchEvents {
			h.sendNack(context.Background(), batchMsg.GetSeq(), batchMsg.GetChunkId(), "too_many_events",
				fmt.Sprintf("event count %d exceeds limit %d", ec, maxBatchEvents), false)
			return -1, nil
		}
		return ec, nil
	}
	sb, ok := h.decodeSignalBatch(batchMsg)
	if !ok {
		return -1, nil
	}
	return len(sb.Signals), sb
}

func (h *CoreHandler) decodeSignalBatch(batchMsg *corepb.BatchMessage) (*core.SignalBatch, bool) {
	sb, err := core.UnmarshalSignalBatch(batchMsg.GetBatch())
	if err != nil {
		slog.Debug("signal batch decode failed", "error", err)
		h.sendNack(context.Background(), batchMsg.GetSeq(), batchMsg.GetChunkId(), "invalid_signal_batch", "signal batch could not be decoded", false)
		return nil, false
	}
	if err := sb.Validate(); err != nil {
		slog.Debug("signal validation failed", "error", err)
		h.sendNack(context.Background(), batchMsg.GetSeq(), batchMsg.GetChunkId(), "signal_validation", "signal batch failed validation", false)
		return nil, false
	}
	if len(sb.Signals) > maxBatchEvents {
		h.sendNack(context.Background(), batchMsg.GetSeq(), batchMsg.GetChunkId(), "too_many_events",
			fmt.Sprintf("event count %d exceeds limit %d", len(sb.Signals), maxBatchEvents), false)
		return nil, false
	}
	return sb, true
}

// verifyEnvelopeAlgo 强制 envelope 使用协商算法（Compression + Codec + CipherSuite）。
// 任一不一致即拒绝——防止客户端单方面降级或注入未协商算法（defense-in-depth，
// 即使 HMAC 通过也不允许 wire 字段与权威协商结果不符）。返回 true 表示已发 NACK，调用方中止。
func (h *CoreHandler) verifyEnvelopeAlgo(env *core.SecureEnvelope) bool {
	if h.negotiated == nil {
		return false
	}
	if env.Compression != h.negotiated.Compression {
		h.sendNack(context.Background(), env.GetSeq(), env.GetChunkId(), CodeEnvelopeAlgoMismatch,
			"compression not negotiated", false)
		return true
	}
	if env.Codec != h.negotiated.Codec {
		h.sendNack(context.Background(), env.GetSeq(), env.GetChunkId(), CodeEnvelopeAlgoMismatch,
			"codec not negotiated", false)
		return true
	}
	if env.CipherSuite != h.negotiated.CipherSuite {
		h.sendNack(context.Background(), env.GetSeq(), env.GetChunkId(), CodeEnvelopeAlgoMismatch,
			"cipher suite not negotiated", false)
		return true
	}
	return false
}

// routeAndACK 路由 batch 到 sink 并发送 ACK（core spec §11）。
func (h *CoreHandler) routeAndACK(ctx context.Context, dedupKey string, batchMsg *corepb.BatchMessage, signalBatch *core.SignalBatch, batchEvents int, batchBytes int64) {
	defer h.inflight.Remove(batchEvents, batchBytes)

	ackMode := corepb.AckMode_ACK_MODE_ACCEPTED

	if h.config.Sink != nil {
		if rawSink, ok := h.config.Sink.(core.RawEventSink); ok && signalBatch == nil {
			result, err := rawSink.OnRawBatch(ctx, h.agentID, batchEvents, batchMsg.GetBatch())
			if err != nil {
				slog.Warn("raw routing failed", "error", err)
			} else if h.applyRouteResult(ctx, result, dedupKey, &ackMode) {
				return
			}
		} else if durable, ok := h.config.Sink.(core.DurableEventSink); ok {
			result, err := durable.OnSignalBatchWithResult(ctx, h.agentID, signalBatch)
			if err != nil {
				slog.Warn("durable routing failed", "error", err)
			} else if h.applyRouteResult(ctx, result, dedupKey, &ackMode) {
				return
			}
		} else {
			if err := h.config.Sink.OnSignalBatch(ctx, h.agentID, signalBatch); err != nil {
				slog.Warn("event routing failed", "error", err)
			}
			pressure := h.config.Sink.OnPressure(h.agentID)
			if pressure != "" && pressure != h.loadLastPressure() {
				h.lastPressure.Store(pressure)
				b, e, by := pressureToWindow(pressure)
				h.window.Update(b, e, by)
				h.sendWindowUpdate(ctx, b, e, by, string(pressure))
			}
		}
	}

	h.sendAck(ctx, batchMsg.GetSeq(), batchMsg.GetChunkId(), batchEvents, ackMode)
	if h.config.Metrics != nil {
		h.config.Metrics.BatchesAckedTotal.Inc()
	}
}

func (h *CoreHandler) applyRouteResult(ctx context.Context, result *core.RouteResult, dedupKey string, ackMode *corepb.AckMode) bool {
	if result == nil {
		return false
	}
	switch result.Status {
	case core.ACKStatusDurable:
		*ackMode = corepb.AckMode_ACK_MODE_DURABLE
		h.replay.Update(dedupKey, core.ReplayDurable)
	case core.ACKStatusThrottle:
		h.sendThrottle(ctx, throttleRetryMs, "queue_pressure", "queue pressure critical, retry later")
		return true
	default:
		*ackMode = corepb.AckMode_ACK_MODE_ACCEPTED
	}
	if result.Pressure != "" && result.Pressure != h.loadLastPressure() {
		h.lastPressure.Store(result.Pressure)
		b, e, by := pressureToWindow(result.Pressure)
		h.window.Update(b, e, by)
		h.sendWindowUpdate(ctx, b, e, by, string(result.Pressure))
	}
	return false
}

func (h *CoreHandler) loadLastPressure() core.PressureState {
	if v := h.lastPressure.Load(); v != nil {
		return v.(core.PressureState)
	}
	return core.PressureNormal
}

// ===== 帧发送（均走 control channel）=====

func (h *CoreHandler) sendAck(ctx context.Context, seq uint64, chunkID []byte, count int, ackMode corepb.AckMode) {
	ack := &corepb.AckMessage{Seq: seq, ChunkId: chunkID, Count: int32(count), AckMode: ackMode, ReceivedAtUnixMs: time.Now().UnixMilli()} //nolint:gosec // G115: count bounded by maxBatchEvents
	p, err := core.Encode(ack)
	if err != nil {
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeAck, core.FlagControl, p); err != nil {
		slog.Warn("write ack failed", "error", err)
	}
}

func (h *CoreHandler) sendNack(ctx context.Context, seq uint64, chunkID []byte, code, reason string, retryable bool) {
	nack := &corepb.NackMessage{Seq: seq, ChunkId: chunkID, Code: code, Reason: reason, Retryable: retryable}
	p, err := core.Encode(nack)
	if err != nil {
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeNack, core.FlagControl, p); err != nil {
		slog.Warn("write nack failed", "error", err)
	}
	if h.config.Metrics != nil {
		h.config.Metrics.BatchesNackedTotal.Inc()
	}
}

func (h *CoreHandler) sendThrottle(ctx context.Context, retryDelayMs int, code, reason string) {
	t := &corepb.ThrottleMessage{RetryDelayMs: int32(retryDelayMs), Code: code, Reason: reason}
	p, err := core.Encode(t)
	if err != nil {
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeThrottle, core.FlagControl, p); err != nil {
		slog.Warn("write throttle failed", "error", err)
	}
	if h.config.Metrics != nil {
		h.config.Metrics.ThrottledTotal.Inc()
	}
}

// failAuth 发 AUTH_FAIL 并轮换 challengeNonce（每次在线验证用新挑战）。
func (h *CoreHandler) failAuth(ctx context.Context, code, reason string) {
	// 轮换 nonce；失败时保留旧 nonce（此处已是错误处理路径，最坏情况是下一次
	// 挑战复用旧值，优于丢弃 AUTH_FAIL 不响应）。AUTH_FAIL 帧仍可发送。
	if nonce, err := randBytes(challengeNonceLen); err != nil {
		slog.Warn("rotate challenge nonce failed, keeping previous", "error", err)
	} else {
		h.challengeNonce = nonce
	}
	fail := &corepb.AuthFailMessage{Code: code, Reason: reason, Retryable: true, ChallengeNonce: h.challengeNonce}
	p, err := core.Encode(fail)
	if err != nil {
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeAuthFail, core.FlagControl, p); err != nil {
		slog.Warn("write auth_fail failed", "error", err)
	}
}

func (h *CoreHandler) sendAuthFail(ctx context.Context, code, reason string, retryable bool) {
	fail := &corepb.AuthFailMessage{Code: code, Reason: reason, Retryable: retryable}
	p, err := core.Encode(fail)
	if err != nil {
		return
	}
	_ = SendControlFrame(ctx, h.tr, core.TypeAuthFail, core.FlagControl, p)
}

func (h *CoreHandler) sendError(ctx context.Context, code, reason string, fatal bool) {
	e := &corepb.ErrorMessage{Code: code, Reason: reason, Fatal: fatal, Retryable: !fatal}
	p, err := core.Encode(e)
	if err != nil {
		return
	}
	_ = SendControlFrame(ctx, h.tr, core.TypeError, core.FlagControl, p)
}

func (h *CoreHandler) sendWindowUpdate(ctx context.Context, batches, events int, maxBytes int64, reason string) {
	w := &corepb.WindowMessage{MaxInflightBatches: int32(batches), MaxInflightEvents: int32(events), MaxInflightBytes: maxBytes, Reason: reason}
	p, err := core.Encode(w)
	if err != nil {
		return
	}
	_ = SendControlFrame(ctx, h.tr, core.TypeWindow, core.FlagControl, p)
}

func pressureToWindow(pressure core.PressureState) (batches, events int, maxBytes int64) {
	switch pressure {
	case core.PressureDegraded:
		return windowMaxBatches / 2, windowMaxEvents / 2, windowMaxBytes / 2
	case core.PressureCritical:
		return windowMaxBatches / 10, windowMaxEvents / 10, windowMaxBytes / 10
	default:
		return windowMaxBatches, windowMaxEvents, windowMaxBytes
	}
}

// ===== helpers =====

// randBytes 生成 n 字节密码学随机数。
//
// crypto/rand.Read 在现代系统上极少失败，但失败时绝不应回退到可预测的时间戳
// 派生值——那会产出可猜测的 challenge nonce / session key，破坏 challenge-response
// 与会话机密性。故失败时直接返回 error，让调用方中断该次握手而非使用弱随机。
func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// chunkIDText 把 wire chunk_id（ULID 16B）转为文本作 ReplayCache/spool key。
func chunkIDText(chunkID []byte) string {
	if c, err := core.ChunkIDFromBytes(chunkID); err == nil {
		return c.String()
	}
	return string(chunkID) // fallback（非 16B 时）
}
