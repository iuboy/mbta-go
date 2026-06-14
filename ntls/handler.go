package ntls

import (
	"context"
	"crypto/hmac"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/iuboy/mbta-go/core"
)

// 单连接帧多路复用 handler 常量（与 v1 等价，本地声明避免循环导入 v1）。
const (
	maxAuthAttempts            = 3
	heartbeatIntervalSec       = 30
	maxFramePayloadBytes       = 16 * 1024 * 1024
	maxBatchBytes              = 8 * 1024 * 1024
	maxEventBytes              = 256 * 1024
	maxBatchEvents             = 10000
	windowMaxBatches           = 100
	windowMaxEvents            = 10000
	windowMaxBytes       int64 = 16 * 1024 * 1024
	throttleRetryMs            = 1000
)

// ConnectionHandlerConfig holds configuration for a connection handler.
type ConnectionHandlerConfig struct {
	Conn     net.Conn
	Auth     core.TokenValidator
	Policy   core.Policy
	Sink     core.EventSink
	Metrics  *core.MBTAMetrics
	ServerID string
}

// NewConnectionHandler creates a new connection handler.
func NewConnectionHandler(cfg ConnectionHandlerConfig) *ConnectionHandler {
	return &ConnectionHandler{
		conn:           cfg.Conn,
		config:         cfg,
		sm:             core.NewServerMachine(),
		replay:         core.NewReplayCache(),
		window:         core.NewWindow(windowMaxBatches, windowMaxEvents, windowMaxBytes),
		serverInflight: &core.Inflight{},
		lastPressure:   func() atomic.Value { v := atomic.Value{}; v.Store(core.PressureNormal); return v }(),
		batchSem:       make(chan struct{}, defaultBatchWorkers),
	}
}

// ConnectionHandler manages a single MBTA-NTLS agent connection.
// 与 v1 不同：control/data 帧在同一条 TCP 连接上交替复用，
// 不存在多 quic.Stream，故无 acceptDataStreams / handleDataStream 分支。
type ConnectionHandler struct {
	conn   net.Conn
	config ConnectionHandlerConfig

	sm         *core.ServerMachine
	negotiated *core.NegotiateResult
	keys       *core.SessionKeys
	replay     *core.ReplayCache
	window     *core.Window
	agentID    string
	sessionID  string

	lastPressure   atomic.Value // tracks pressure state for WINDOW updates (core.PressureState)
	challengeNonce string       // server-generated challenge for auth
	authAttempts   int          // tracks authentication retry count
	expiresAt      atomic.Int64 // 会话过期时间(Unix秒)，processBatch 检查

	writeMu        sync.Mutex     // protects concurrent writes to conn
	serverInflight *core.Inflight // server-side flow-control accounting (M-4)

	// windowMu 保护「压力变更决策」：并发 worker 检测到 sink 压力变化时，串行化
	// lastPressure 的读-改，避免多 worker 对同一新压力值各发一次 WINDOW（同值重复）。
	// 锁序 windowMu → writeMu（sendWindowUpdate 取 writeMu）；sendAck/sendNack 只取 writeMu，
	// 不存在反向获取，无死锁。
	windowMu sync.Mutex

	// BATCH worker 池：readLoop 把 BATCH 帧派发给有界并发 worker（解除大 batch 队头阻塞，
	// ACK 可乱序）。batchSem 容量=并发上限，满时 readLoop 阻塞派发=保留背压（client window 填满）。
	// batchWG 跟踪 in-flight worker，readLoop 退出前 Wait，避免 worker 与 HandleConnection
	// defer 的密钥清零/conn 关闭竞争。control 帧（HELLO/AUTH/PING/CLOSE）仍内联保序。
	batchSem chan struct{}
	batchWG  sync.WaitGroup
}

// defaultBatchWorkers 是单连接 BATCH 并发处理上限。readLoop 派发 BATCH 时占一个槽位，
// worker 完成释放。池满时 readLoop 停止读新帧，形成自然背压（客户端发送窗口随之填满）。
const defaultBatchWorkers = 8

// loadLastPressure returns the current pressure state, defaulting to PressureNormal
// if never set (handles zero-value atomic.Value safely).
func (h *ConnectionHandler) loadLastPressure() core.PressureState {
	v := h.lastPressure.Load()
	if v == nil {
		return core.PressureNormal
	}
	return v.(core.PressureState)
}

// HandleConnection orchestrates the full connection lifecycle over a single TCP connection.
// 单读循环模型：在同一连接上交替读 control 帧（HELLO/AUTH/PING/CLOSE）与 data 帧（BATCH）。
// 不再像 v1 那样区分 control stream 与 data stream：单连接上所有帧类型都由本循环处理。
func (h *ConnectionHandler) HandleConnection(ctx context.Context) error {
	defer func() {
		// 1. 关闭 TCP 连接，让读循环解除阻塞。
		if err := h.conn.Close(); err != nil {
			slog.Debug("connection close error", "session", h.sessionID, "error", err)
		}

		// 2. 此时已无并发 goroutine 读 keys，安全清除会话密钥（含 HMAC + SM4）。
		if h.keys != nil {
			for i := range h.keys.HMACKey {
				h.keys.HMACKey[i] = 0
			}
			for i := range h.keys.SM4Key {
				h.keys.SM4Key[i] = 0
			}
			h.keys = nil
		}
	}()

	slog.Debug("handling connection", "remote", h.conn.RemoteAddr())

	if err := h.sm.Transition(core.ServerStateControlWait); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to CONTROL_WAIT", err)
	}

	return h.readLoop(ctx)
}

// readLoop 是单连接帧多路复用的核心循环：读一帧 → 按 type 分发。
// v1 的 handleControlStream 仅处理控制帧，BATCH 由 acceptDataStreams/handleDataStream
// 在单独的 quic.Stream 上处理；ntls 中所有帧类型共用同一条 TCP 连接，故合并为一处。
func (h *ConnectionHandler) readLoop(ctx context.Context) error {
	// 退出前等所有 in-flight BATCH worker 完成，避免 worker 与 HandleConnection defer 的
	// conn 关闭/密钥清零竞争。worker 写 ACK 走 writeMu，conn 关闭时写返回错误（log+继续）。
	defer h.batchWG.Wait()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		f, err := core.Read(h.conn, core.DefaultLimits())
		if err != nil {
			return core.WrapError(core.NumProtocol, core.CodeProtocol, "read frame", err)
		}

		switch f.Header.Type {
		case core.TypeHello:
			if h.sm.State() == core.ServerStateReady {
				h.sendError(core.CodeUnsupportedMessage, "HELLO not allowed after auth", true)
				continue
			}
			if err := h.handleHello(f.Payload); err != nil {
				return err
			}
		case core.TypeAuth:
			if h.sm.State() == core.ServerStateReady {
				h.sendError(core.CodeUnsupportedMessage, "AUTH not allowed after auth", true)
				continue
			}
			if err := h.handleAuth(f.Payload); err != nil {
				return err
			}
		case core.TypeBatch:
			// BATCH 仅在 READY 后允许（v1 中此约束由"必须开 data stream"隐式保证）
			if h.sm.State() != core.ServerStateReady {
				h.sendError(core.CodeUnsupportedMessage, "BATCH not allowed before auth", true)
				continue
			}
			// 派发到有界 worker 池并发处理：单大 batch 不再阻塞后续帧的读取。
			// batchSem 满时阻塞派发=保留背压（client window 填满）；ctx 取消时及时退出。
			// ACK 按完成顺序返回（client 按 chunkID 关联，功能正确）。
			// ReplayCache/Window/Inflight 均 mutex/atomic 保护，processBatch 可安全并发。
			select {
			case h.batchSem <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}
			h.batchWG.Add(1)
			go func(payload []byte) {
				defer h.batchWG.Done()
				defer func() { <-h.batchSem }()
				h.processBatch(ctx, payload)
			}(f.Payload)
		case core.TypePing:
			if h.sm.State() != core.ServerStateReady {
				h.sendError(core.CodeUnsupportedMessage, "PING not allowed before auth", true)
				continue
			}
			h.handlePing(f.Payload)
		case core.TypeClose:
			slog.Info("close received", "session", h.sessionID)
			return nil
		default:
			if h.sm.State() == core.ServerStateReady {
				slog.Debug("unexpected control message after auth", "type", f.Header.Type)
			} else {
				h.sendError(core.CodeUnsupportedMessage, fmt.Sprintf("unexpected message type 0x%04x before auth", f.Header.Type), true)
				return core.NewError(core.NumProtocol, core.CodeProtocol, fmt.Sprintf("unexpected message type 0x%04x", f.Header.Type))
			}
		}
	}
}

func (h *ConnectionHandler) handleHello(payload []byte) error {
	var msg core.HelloMessage
	if err := core.FastUnmarshal(payload, &msg); err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "decode hello", err)
	}

	if err := msg.Validate(); err != nil {
		h.sendError(core.CodeDecodeFailed, err.Error(), true)
		return err
	}

	h.agentID = msg.AgentID
	h.sessionID = uuid.Must(uuid.NewV7()).String()
	h.challengeNonce = uuid.Must(uuid.NewV7()).String()

	if err := h.sm.Transition(core.ServerStateHelloReceived); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to HELLO_RECEIVED", err)
	}

	// Negotiate capabilities
	result := core.Negotiate(msg.Capabilities, h.config.Policy)
	// 二次裁剪 (H-4)：若 Negotiate 乐观选中了 tokenless，但注入的 Auth 不实现
	// TokenResolver，则撤回该能力——服务端无法按 agentID 反查 token，必须回退到
	// 客户端回传明文 Token 的 legacy 路径。
	if result.IsCapabilitySelected(core.CapAuthTokenless) {
		if _, ok := h.config.Auth.(core.TokenResolver); !ok {
			pruned := result.SelectedCapabilities[:0]
			for _, c := range result.SelectedCapabilities {
				if c != core.CapAuthTokenless {
					pruned = append(pruned, c)
				}
			}
			result.SelectedCapabilities = pruned
		}
	}
	h.negotiated = &result

	// Build HELLO_ACK
	helloAck := core.HelloAckMessage{
		ServerVersion:        1,
		ServerID:             h.config.ServerID,
		SessionID:            h.sessionID,
		SelectedCapabilities: result.SelectedCapabilities,
		Codec:                result.Codec,
		Compression:          result.Compression,
		HMACAlgo:             result.HMACAlgo,
		Encryption:           result.Encryption,
		HeartbeatIntervalSec: heartbeatIntervalSec,
		MaxFramePayloadBytes: maxFramePayloadBytes,
		MaxBatchBytes:        maxBatchBytes,
		MaxEventBytes:        maxEventBytes,
		MaxBatchEvents:       maxBatchEvents,
		InitialWindow: core.WindowMessage{
			MaxInflightBatches: windowMaxBatches,
			MaxInflightEvents:  windowMaxEvents,
			MaxInflightBytes:   windowMaxBytes,
		},
		ChallengeNonce: h.challengeNonce,
	}

	ackPayload, err := core.FastMarshal(helloAck)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal hello_ack", err)
	}
	if err := h.writeFrame(core.TypeHelloAck, core.FlagControl, ackPayload); err != nil {
		return core.WrapError(core.NumStream, core.CodeStream, "write hello_ack", err)
	}

	if err := h.sm.Transition(core.ServerStateAuthWait); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to AUTH_WAIT", err)
	}
	slog.Info("hello processed", "agent", h.agentID, "session", h.sessionID)
	return nil
}

func (h *ConnectionHandler) handleAuth(payload []byte) error {
	// Enforce authentication retry limit to prevent brute-force attacks.
	if h.authAttempts >= maxAuthAttempts {
		h.sendAuthFail("too_many_attempts", "authentication retry limit exceeded", false)
		return core.NewError(core.NumAuth, core.CodeAuth, "too many auth attempts")
	}
	h.authAttempts++

	var msg core.AuthMessage
	if err := core.FastUnmarshal(payload, &msg); err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "decode auth", err)
	}

	if err := msg.Validate(); err != nil {
		slog.Warn("auth validation failed", "session", h.sessionID, "error", err)
		h.failAuth("invalid_auth", "authentication failed")
		return err
	}

	if msg.AgentID != h.agentID {
		slog.Warn("auth agent_id mismatch", "session", h.sessionID, "hello_agent", h.agentID, "auth_agent", msg.AgentID)
		h.failAuth("invalid_auth", "authentication failed")
		return core.NewError(core.NumAuth, core.CodeAuth, "agent_id mismatch")
	}

	if msg.SessionID != h.sessionID {
		slog.Warn("auth session_id mismatch", "session", h.sessionID, "auth_session", msg.SessionID)
		h.failAuth("invalid_auth", "authentication failed")
		return core.NewError(core.NumAuth, core.CodeAuth, "session_id mismatch")
	}

	// === H-4：决定用于校验的 token 来源 ===
	// tokenless 模式：客户端省略明文 Token，服务端按 agentID 反查 token。
	// legacy 模式：客户端在 AUTH 帧携带明文 Token，服务端直接使用。
	// 两条路径下游统一过 hmac.Equal 与 Validate 两道关，无捷径旁路。
	token, tokenless, err := h.resolveAuthToken(&msg)
	if err != nil {
		return err
	}

	// Challenge-response validation: 使用 HMAC(token, nonce) 验证客户端持有 token
	if h.challengeNonce != "" {
		algo := core.HMACAlgoSHA256
		if h.negotiated != nil && h.negotiated.HMACAlgo != core.HMACAlgoNone {
			algo = h.negotiated.HMACAlgo
		}
		expected := core.ComputeChallengeResponse(token, h.challengeNonce, algo)
		if !hmac.Equal([]byte(msg.AuthNonce), []byte(expected)) {
			slog.Warn("auth challenge mismatch", "session", h.sessionID, "tokenless", tokenless)
			h.failAuth("challenge_mismatch", "auth_nonce HMAC verification failed")
			return core.NewError(core.NumAuth, core.CodeAuth, "challenge nonce mismatch")
		}
	}

	// Token validation（授权/过期，统一用 token）
	if h.config.Auth != nil {
		_, err = h.config.Auth.Validate(token)
		if err != nil {
			h.failAuth("invalid_token", "token validation failed")
			if h.config.Metrics != nil {
				h.config.Metrics.AuthFailureTotal.Inc()
			}
			return core.WrapError(core.NumAuth, core.CodeAuth, "token validation", err)
		}
	}

	// Generate session keys with the negotiated HMAC algorithm
	if h.negotiated == nil {
		h.sendAuthFail("internal_error", "no negotiation result", true)
		return core.NewError(core.NumConfig, core.CodeConfig, "missing negotiation result")
	}
	keys, err := core.GenerateSessionKeys(h.negotiated.HMACAlgo)
	if err != nil {
		h.sendAuthFail("internal_error", "key generation failed", true)
		return core.WrapError(core.NumConfig, core.CodeConfig, "session key generation", err)
	}
	h.keys = keys
	h.expiresAt.Store(time.Now().Add(core.DefaultSessionTTL).Unix())

	// Send AUTH_OK
	authOK := core.AuthOKMessage{
		SessionID:     h.sessionID,
		KeyID:         keys.KeyID,
		HMACKey:       keys.HMACKeyBase64(),
		HMACAlgo:      keys.HMACAlgo,
		SM4Key:        keys.SM4KeyBase64(),
		ExpiresAtUnix: h.expiresAt.Load(),
	}
	okPayload, err := core.FastMarshal(authOK)
	if err != nil {
		return core.WrapError(core.NumProtocol, core.CodeProtocol, "marshal auth_ok", err)
	}
	if err := h.writeFrame(core.TypeAuthOK, core.FlagControl, okPayload); err != nil {
		return core.WrapError(core.NumStream, core.CodeStream, "write auth_ok", err)
	}

	if err := h.sm.Transition(core.ServerStateReady); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to READY", err)
	}

	if h.config.Metrics != nil {
		h.config.Metrics.AuthSuccessTotal.Inc()
	}

	slog.Info("auth succeeded", "agent", h.agentID, "session", h.sessionID, "key_id", keys.KeyID)
	return nil
}

// resolveAuthToken 决定本次 AUTH 校验所用 token 来源：
// tokenless 模式下由服务端按 agentID 反查，legacy 模式下直接采用客户端明文 Token。
// 两条路径下游统一过 hmac.Equal 与 Validate 两道关，无捷径旁路。
// 失败时已通过 failAuth 向客户端回送 AUTH_FAIL，调用方仅需上抛错误。
func (h *ConnectionHandler) resolveAuthToken(msg *core.AuthMessage) (token string, tokenless bool, err error) {
	tokenless = h.negotiated != nil && h.negotiated.IsCapabilitySelected(core.CapAuthTokenless)
	if !tokenless {
		return msg.Token, tokenless, nil
	}
	resolver, ok := h.config.Auth.(core.TokenResolver)
	if !ok || resolver == nil {
		// handleHello 应已裁剪此能力；防御性处理，避免误置导致旁路。
		slog.Error("tokenless negotiated but Auth is not a TokenResolver", "session", h.sessionID)
		h.failAuth("internal_error", "authentication failed")
		return "", tokenless, core.NewError(core.NumConfig, core.CodeConfig, "tokenless negotiated without TokenResolver")
	}
	t, rerr := resolver.ResolveToken(msg.AgentID)
	if rerr != nil {
		// 不区分"agent 不存在"与"token 无效"，避免 agentID 枚举。
		slog.Warn("resolve token failed", "session", h.sessionID, "agent", msg.AgentID)
		h.failAuth("invalid_auth", "authentication failed")
		return "", tokenless, core.WrapError(core.NumAuth, core.CodeAuth, "resolve token", rerr)
	}
	return t, tokenless, nil
}

func (h *ConnectionHandler) handlePing(payload []byte) {
	var msg core.PingMessage
	if err := core.FastUnmarshal(payload, &msg); err != nil {
		slog.Debug("invalid ping payload", "error", err)
		return
	}

	pong := core.PongMessage{
		TimeUnixMs: time.Now().UnixMilli(),
		Nonce:      msg.Nonce,
		Status:     "ok",
	}
	pongPayload, err := core.FastMarshal(pong)
	if err != nil {
		slog.Warn("marshal pong failed", "error", err)
		return
	}
	if err := h.writeFrame(core.TypePong, core.FlagControl, pongPayload); err != nil {
		slog.Warn("write pong failed", "error", err)
	}
}

func (h *ConnectionHandler) processBatch(ctx context.Context, payload []byte) {
	// Decode envelope
	var env core.SecureEnvelope
	if err := core.FastUnmarshal(payload, &env); err != nil {
		// envelope 无法解码时 seq/chunkID 未知，发送 ERROR 而非 NACK。
		// 零值 NACK 会导致客户端 pendingAcks 无法清理，最终 inflight 死锁。
		slog.Debug("invalid envelope", "session", h.sessionID, "error", err)
		h.sendError(core.CodeDecodeFailed, "invalid_envelope", false)
		return
	}

	// 检查会话是否过期
	if h.expiresAt.Load() > 0 && time.Now().Unix() > h.expiresAt.Load() {
		h.sendNack(env.Seq, env.ChunkID, "session_expired", "session TTL exceeded, please reconnect", false)
		return
	}

	// Verify HMAC if enabled
	if h.negotiated != nil && h.negotiated.HMACAlgo != core.HMACAlgoNone && h.keys != nil {
		if !core.VerifyHMAC(h.keys.HMACKey, &env) {
			h.sendNack(env.Seq, env.ChunkID, "hmac_mismatch", "HMAC verification failed", false)
			if h.config.Metrics != nil {
				h.config.Metrics.HMACFailuresTotal.Inc()
			}
			return
		}
	}

	// Algorithm consistency: an authenticated client may only use the
	// compression/encryption selected during negotiation. A client holding the
	// HMAC key can produce a valid MAC over a non-negotiated algorithm, so the
	// check is enforced here (after HMAC, before Open) against the authoritative
	// negotiated result rather than relying solely on Open's allow-list.
	if h.verifyEnvelopeAlgo(&env) {
		return
	}

	// Open envelope
	batchPayload, err := h.openEnvelope(&env)
	if err != nil {
		h.sendNack(env.Seq, env.ChunkID, "envelope_open_error", err.Error(), true)
		return
	}

	// Enforce batch size limits early — before JSON unmarshal allocates memory.
	if len(batchPayload) > maxBatchBytes {
		h.sendNack(env.Seq, env.ChunkID, "batch_too_large",
			fmt.Sprintf("batch payload %d bytes exceeds limit %d", len(batchPayload), maxBatchBytes), false)
		return
	}

	// Decode batch message (protocol metadata wrapper)
	var batchMsg core.BatchMessage
	if err := core.FastUnmarshal(batchPayload, &batchMsg); err != nil {
		h.sendNack(env.Seq, env.ChunkID, "invalid_batch", err.Error(), false)
		return
	}

	if err := batchMsg.Validate(); err != nil {
		h.sendNack(batchMsg.Seq, batchMsg.ChunkID, "batch_validation", err.Error(), false)
		return
	}

	// RawEventSink fast path：sink 实现该接口且客户端填了 events_count 时，
	// 跳过 signalBatch 逐事件解码（省反射/map 分配，约 13 allocs/event）。
	rawSink, _ := h.config.Sink.(core.RawEventSink)
	var signalBatchPtr *core.SignalBatch
	var batchEvents int
	if rawSink != nil && batchMsg.EventsCount > 0 {
		batchEvents = batchMsg.EventsCount
		if batchEvents > maxBatchEvents {
			h.sendNack(batchMsg.Seq, batchMsg.ChunkID, "too_many_events",
				fmt.Sprintf("event count %d exceeds limit %d", batchEvents, maxBatchEvents), false)
			return
		}
	} else {
		sb, ok := h.decodeSignalBatch(&batchMsg)
		if !ok {
			return
		}
		signalBatchPtr = sb
		batchEvents = len(sb.Signals)
	}
	batchBytes := int64(len(batchPayload))

	// 服务端流控强制 (M-4)：客户端侧 window 检查只对正常客户端有效，已认证的恶意/异常
	// 客户端可无视窗口持续灌入。此处按事件数与字节检查服务端 inflight 窗口，超限发
	// THROTTLE 让客户端退避重试。检查置于 replay check 之前：窗口满时新包被直接拒绝
	// 且不进入 replay 缓存，客户端重试时仍按新包正常处理（不会被误判为已处理）。
	// serverInflight 由 NewConnectionHandler 初始化；enforceWindow 的 nil 分支仅为兼容
	// 直接构造 ConnectionHandler 字面量的既有测试，生产路径恒为 true。
	enforceWindow := h.serverInflight != nil && h.window != nil
	if enforceWindow && !h.window.CanSend(h.serverInflight, batchEvents, batchBytes) {
		h.sendThrottle(throttleRetryMs, "window_exceeded", "server flow-control window exceeded")
		return
	}
	if enforceWindow {
		h.serverInflight.Add(batchEvents, batchBytes)
	}

	// Replay check
	dedupKey := core.Key(h.agentID, batchMsg.ChunkID)
	existing := h.replay.SeenOrAdd(dedupKey)
	if existing != nil {
		// Already processed — 重复包不占用服务端窗口，撤销上方 Add 后返回幂等 ACK。
		if enforceWindow {
			h.serverInflight.Remove(batchEvents, batchBytes)
		}
		ackMode := core.AckModeAccepted
		if existing.Status == core.ReplayDurable {
			ackMode = core.AckModeDurable
		}
		h.sendAck(batchMsg.Seq, batchMsg.ChunkID, batchEvents, ackMode)
		return
	}

	// Process events
	h.replay.Update(dedupKey, core.ReplayAccepted)
	h.routeAndACK(ctx, dedupKey, &batchMsg, signalBatchPtr, batchEvents, batchBytes, rawSink)
}

// openEnvelope 解密+解压 envelope payload。SM4 key 从 h.keys 取（已认证连接非 nil；
// nil 时传 nil key，encryption=none 下 Open 忽略）。
func (h *ConnectionHandler) openEnvelope(env *core.SecureEnvelope) ([]byte, error) {
	var sm4Key []byte
	if h.keys != nil {
		sm4Key = h.keys.SM4Key
	}
	return core.Open(env, sm4Key)
}

// decodeSignalBatch 解码并校验 SignalBatch，失败时已发 NACK。
// 返回 (signalBatch, true) 成功；失败返回 (nil, false)，调用方应直接 return。
func (h *ConnectionHandler) decodeSignalBatch(batchMsg *core.BatchMessage) (*core.SignalBatch, bool) {
	var sb core.SignalBatch
	if err := core.FastUnmarshal(batchMsg.Batch, &sb); err != nil {
		h.sendNack(batchMsg.Seq, batchMsg.ChunkID, "invalid_signal_batch", err.Error(), false)
		return nil, false
	}
	if err := sb.Validate(); err != nil {
		h.sendNack(batchMsg.Seq, batchMsg.ChunkID, "signal_validation", err.Error(), false)
		return nil, false
	}
	if len(sb.Signals) > maxBatchEvents {
		h.sendNack(batchMsg.Seq, batchMsg.ChunkID, "too_many_events",
			fmt.Sprintf("event count %d exceeds limit %d", len(sb.Signals), maxBatchEvents), false)
		return nil, false
	}
	return &sb, true
}

// verifyEnvelopeAlgo 强制 envelope 只能使用协商期内选定的压缩/加密算法。
// 客户端持有 HMAC 密钥即可对未协商算法产出合法 MAC，故在 Open 前依据权威协商结果
// 复核，而非仅依赖 Open 的 allow-list。未协商字段按 "none" 处理。
// 返回 true 表示已发送 NACK 且调用方应中止处理。
func (h *ConnectionHandler) verifyEnvelopeAlgo(env *core.SecureEnvelope) bool {
	if h.negotiated == nil {
		return false
	}
	wantComp := h.negotiated.Compression
	if wantComp == "" {
		wantComp = core.CompressionNone
	}
	wantEnc := h.negotiated.Encryption
	if wantEnc == "" {
		wantEnc = core.EncryptionNone
	}
	if env.Compression != wantComp || env.Encryption != wantEnc {
		h.sendNack(env.Seq, env.ChunkID, "envelope_algo_mismatch",
			"compression/encryption not negotiated", false)
		return true
	}
	return false
}

// routeAndACK routes the batch to the configured sink and sends the appropriate ACK response.
// rawSink 非 nil 时走快速路径（不解码 signalBatch）；signalBatch 在原路径下非 nil。
func (h *ConnectionHandler) routeAndACK(ctx context.Context, dedupKey string, batchMsg *core.BatchMessage, signalBatch *core.SignalBatch, batchEvents int, batchBytes int64, rawSink core.RawEventSink) {
	// 处理完成（含所有 ACK/THROTTLE 退出路径）后释放服务端 inflight 占用。(M-4)
	if h.serverInflight != nil {
		defer h.serverInflight.Remove(batchEvents, batchBytes)
	}

	ackMode := core.AckModeAccepted

	if h.config.Sink != nil {
		// RawEventSink fast path：sink 实现该接口时直接投递原始 batch JSON，
		// 跳过 signalBatch 解码（processBatch 已省去 Unmarshal/Validate）。
		if rawSink != nil {
			result, err := rawSink.OnRawBatch(ctx, h.agentID, batchEvents, batchMsg.Batch)
			if err != nil {
				slog.Warn("raw routing failed", "session", h.sessionID, "error", err)
			} else if h.applyRouteResult(result, dedupKey, &ackMode) {
				return
			}
		} else if durable, ok := h.config.Sink.(core.DurableEventSink); ok {
			result, err := durable.OnSignalBatchWithResult(ctx, h.agentID, signalBatch)
			if err != nil {
				slog.Warn("durable routing failed", "session", h.sessionID, "error", err)
			} else if h.applyRouteResult(result, dedupKey, &ackMode) {
				return
			}
		} else {
			if err := h.config.Sink.OnSignalBatch(ctx, h.agentID, signalBatch); err != nil {
				slog.Warn("event routing failed", "session", h.sessionID, "error", err)
			}
			pressure := h.config.Sink.OnPressure(h.agentID)
			if b, e, by, ok := h.applyPressureChange(pressure); ok {
				h.sendWindowUpdate(b, e, by, string(pressure))
			}
		}
	}

	h.sendAck(batchMsg.Seq, batchMsg.ChunkID, batchEvents, ackMode)

	if h.config.Metrics != nil {
		h.config.Metrics.BatchesAckedTotal.Inc()
	}

	slog.Debug("batch processed", "session", h.sessionID, "seq", batchMsg.Seq, "chunk", batchMsg.ChunkID, "events", batchEvents)
}

// applyRouteResult 处理 sink 返回的 RouteResult：更新 ackMode 与 replay，在压力状态变化时
// 发送 WINDOW 更新。返回 true 表示结果为 throttle（已发 THROTTLE 帧），调用方应中止 routeAndACK。
// 提取为方法以复用于 RawEventSink 与 DurableEventSink 两条路径。
func (h *ConnectionHandler) applyRouteResult(result *core.RouteResult, dedupKey string, ackMode *string) bool {
	switch result.Status {
	case core.ACKStatusDurable:
		*ackMode = core.AckModeDurable
		h.replay.Update(dedupKey, core.ReplayDurable)
	case core.ACKStatusThrottle:
		h.sendThrottle(throttleRetryMs, "queue_pressure", "queue pressure critical, retry later")
		slog.Warn("throttling agent due to queue pressure",
			"session", h.sessionID, "agent", h.agentID, "pressure", result.Pressure)
		return true
	default:
		*ackMode = core.AckModeAccepted
	}
	if b, e, by, ok := h.applyPressureChange(result.Pressure); ok {
		h.sendWindowUpdate(b, e, by, string(result.Pressure))
	}
	return false
}

// applyPressureChange 在 windowMu 保护下原子完成压力状态变更决策：若 pressure 与上次不同，
// 更新 lastPressure + window 维度，返回 (batches, events, maxBytes, true)；否则返回 (..., false)。
// 串行化避免并发 worker 对同一新压力值各发一次 WINDOW（同值重复，client 幂等但多一次网络写）。
// 网络发帧由调用方在锁外执行，避免持 windowMu 做 I/O。
func (h *ConnectionHandler) applyPressureChange(pressure core.PressureState) (batches, events int, maxBytes int64, send bool) {
	if pressure == "" {
		return 0, 0, 0, false
	}
	h.windowMu.Lock()
	defer h.windowMu.Unlock()
	// 持锁后复查：等锁期间可能已被其他 worker 更新到相同值，此时无需再发。
	if pressure == h.loadLastPressure() {
		return 0, 0, 0, false
	}
	h.lastPressure.Store(pressure)
	batches, events, maxBytes = pressureToWindow(pressure)
	h.window.Update(batches, events, maxBytes)
	return batches, events, maxBytes, true
}

// writeFrame writes a frame to the underlying TCP connection with mutex protection.
// 单连接模型下，所有出站帧（控制帧、ACK、NACK、THROTTLE、WINDOW、ERROR）都经此串行化，
// 避免与 processBatch 等潜在并发写者交错产生半帧。
func (h *ConnectionHandler) writeFrame(typ uint16, flags byte, payload []byte) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	return core.Write(h.conn, typ, flags, payload)
}

func (h *ConnectionHandler) sendAck(seq uint64, chunkID string, count int, ackMode string) {
	ack := core.AckMessage{
		Seq:        seq,
		ChunkID:    chunkID,
		Count:      count,
		AckMode:    ackMode,
		ReceivedAt: time.Now().UnixMilli(),
	}
	payload, err := core.FastMarshal(ack)
	if err != nil {
		slog.Warn("marshal ack failed", "error", err)
		return
	}
	if err := h.writeFrame(core.TypeAck, core.FlagControl, payload); err != nil {
		slog.Warn("write ack failed", "session", h.sessionID, "error", err)
	}
}

func (h *ConnectionHandler) sendNack(seq uint64, chunkID, code, reason string, retryable bool) {
	nack := core.NackMessage{
		Seq:       seq,
		ChunkID:   chunkID,
		Code:      code,
		Reason:    reason,
		Retryable: retryable,
	}
	payload, err := core.FastMarshal(nack)
	if err != nil {
		slog.Warn("marshal nack failed", "error", err)
		return
	}
	if err := h.writeFrame(core.TypeNack, core.FlagControl, payload); err != nil {
		slog.Warn("write nack failed", "session", h.sessionID, "error", err)
	}

	if h.config.Metrics != nil {
		h.config.Metrics.BatchesNackedTotal.Inc()
	}
}

func (h *ConnectionHandler) sendThrottle(retryDelayMs int, code, reason string) {
	throttle := core.ThrottleMessage{
		RetryDelayMs: retryDelayMs,
		Code:         code,
		Reason:       reason,
	}
	payload, err := core.FastMarshal(throttle)
	if err != nil {
		slog.Warn("marshal throttle failed", "error", err)
		return
	}
	if err := h.writeFrame(core.TypeThrottle, core.FlagControl, payload); err != nil {
		slog.Warn("write throttle failed", "session", h.sessionID, "error", err)
	}

	if h.config.Metrics != nil {
		h.config.Metrics.ThrottledTotal.Inc()
	}
}

// failAuth 发送 AUTH_FAIL 帧并在每次调用时轮换 challengeNonce、将新 nonce 随帧下发。
// 这样保证每个 challenge 仅用于一次在线验证，限制在线穷举窗口（离线穷举由 token 熵兜底）。
// retryable 始终为 true：凭证类错误本就允许客户端重试；实现重试的客户端必须用返回的
// 新 nonce 重新计算 AuthNonce，不识别该字段的旧客户端照常报错，向后兼容。(M-1)
// 不可重试的终态失败（too_many_attempts、internal_error）仍用 sendAuthFail，不轮换 nonce。
func (h *ConnectionHandler) failAuth(code, reason string) {
	h.challengeNonce = uuid.Must(uuid.NewV7()).String()
	fail := core.AuthFailMessage{
		Code:           code,
		Reason:         reason,
		Retryable:      true,
		ChallengeNonce: h.challengeNonce,
	}
	payload, err := core.FastMarshal(fail)
	if err != nil {
		slog.Warn("marshal auth_fail failed", "error", err)
		return
	}
	if err := h.writeFrame(core.TypeAuthFail, core.FlagControl, payload); err != nil {
		slog.Warn("write auth_fail failed", "session", h.sessionID, "error", err)
	}
}

func (h *ConnectionHandler) sendAuthFail(code, reason string, retryable bool) {
	fail := core.AuthFailMessage{
		Code:      code,
		Reason:    reason,
		Retryable: retryable,
	}
	payload, err := core.FastMarshal(fail)
	if err != nil {
		slog.Warn("marshal auth_fail failed", "error", err)
		return
	}
	if err := h.writeFrame(core.TypeAuthFail, core.FlagControl, payload); err != nil {
		slog.Warn("write auth_fail failed", "session", h.sessionID, "error", err)
	}
}

func (h *ConnectionHandler) sendError(code, reason string, fatal bool) {
	errMsg := core.ErrorMessage{
		Code:      code,
		Reason:    reason,
		Fatal:     fatal,
		Retryable: !fatal,
	}
	payload, err := core.FastMarshal(errMsg)
	if err != nil {
		slog.Warn("marshal error frame failed", "error", err)
		return
	}
	if err := h.writeFrame(core.TypeError, core.FlagControl, payload); err != nil {
		slog.Warn("write error frame failed", "session", h.sessionID, "error", err)
	}
}

// sendWindowUpdate sends a WINDOW frame to the client with updated flow-control limits.
func (h *ConnectionHandler) sendWindowUpdate(batches, events int, maxBytes int64, reason string) {
	win := core.WindowMessage{
		MaxInflightBatches: batches,
		MaxInflightEvents:  events,
		MaxInflightBytes:   maxBytes,
		Reason:             reason,
	}
	payload, err := core.FastMarshal(win)
	if err != nil {
		slog.Warn("marshal window failed", "error", err)
		return
	}
	if err := h.writeFrame(core.TypeWindow, core.FlagControl, payload); err != nil {
		slog.Warn("write window failed", "session", h.sessionID, "error", err)
	}
	slog.Debug("window update sent",
		"session", h.sessionID,
		"batches", batches,
		"events", events,
		"bytes", maxBytes,
		"reason", reason)
}

// pressureToWindow maps a PressureState to window dimensions.
func pressureToWindow(pressure core.PressureState) (batches int, events int, maxBytes int64) {
	switch pressure {
	case core.PressureDegraded:
		return windowMaxBatches / 2, windowMaxEvents / 2, windowMaxBytes / 2
	case core.PressureCritical:
		return windowMaxBatches / 10, windowMaxEvents / 10, windowMaxBytes / 10
	default: // PressureNormal
		return windowMaxBatches, windowMaxEvents, windowMaxBytes
	}
}
