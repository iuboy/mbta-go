package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/iuboy/mbta-go/core"
	"github.com/quic-go/quic-go"
)

// ConnectionHandlerConfig holds configuration for a connection handler.
type ConnectionHandlerConfig struct {
	Conn     *Conn
	Auth     core.TokenValidator
	Policy   core.Policy
	SpoolDir string
	Sink     core.EventSink
	Metrics  *core.MBTAMetrics
	ServerID string
}

// NewConnectionHandler creates a new connection handler.
func NewConnectionHandler(cfg ConnectionHandlerConfig) *ConnectionHandler {
	return &ConnectionHandler{
		conn:   cfg.Conn,
		config: cfg,
		sm:     core.NewServerMachine(),
		replay: core.NewReplayCache(),
		window: core.NewWindow(100, 10000, 16*1024*1024),
	}
}

// ConnectionHandler manages a single MBTA agent connection.
type ConnectionHandler struct {
	conn   *Conn
	config ConnectionHandlerConfig

	sm         *core.ServerMachine
	negotiated *core.NegotiateResult
	keys       *core.SessionKeys
	replay     *core.ReplayCache
	window     *core.Window
	agentID    string
	sessionID  string
	controlStr *quic.Stream
	controlMu  sync.Mutex // protects concurrent writes to controlStr
}

// HandleConnection orchestrates the full connection lifecycle.
func (h *ConnectionHandler) HandleConnection(ctx context.Context) error {
	defer func() { _ = h.conn.CloseWithError(0, "done") }()

	slog.Debug("handling connection", "remote", h.conn.RemoteAddr)

	// Accept the control stream
	s, role, err := h.conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept control stream: %w", err)
	}
	if role != core.StreamRoleControl {
		return fmt.Errorf("first stream must be control, got %s", role)
	}
	h.controlStr = s
	defer h.controlStr.Close()

	_ = h.sm.Transition(core.ServerStateControlWait)

	// Handle control stream messages
	if err := h.handleControlStream(ctx); err != nil {
		slog.Warn("control stream ended", "session", h.sessionID, "error", err)
	}

	return nil
}

func (h *ConnectionHandler) handleControlStream(ctx context.Context) error {
	for {
		f, err := core.Read(h.controlStr, core.DefaultLimits())
		if err != nil {
			return fmt.Errorf("read frame: %w", err)
		}

		switch f.Header.Type {
		case core.TypeHello:
			if err := h.handleHello(f.Payload); err != nil {
				return err
			}
		case core.TypeAuth:
			if err := h.handleAuth(f.Payload); err != nil {
				return err
			}
		case core.TypePing:
			h.handlePing(f.Payload)
		case core.TypeClose:
			slog.Info("close received", "session", h.sessionID)
			return nil
		default:
			if h.sm.State() == core.ServerStateReady {
				slog.Debug("unexpected control message after auth", "type", f.Header.Type)
			} else {
				h.sendError(fmt.Sprintf("unexpected message type 0x%04x before auth", f.Header.Type), true)
				return fmt.Errorf("unexpected message type 0x%04x", f.Header.Type)
			}
		}

		// After AUTH_OK, also accept data streams
		if h.sm.State() == core.ServerStateReady {
			go h.acceptDataStreams(ctx)
		}
	}
}

func (h *ConnectionHandler) handleHello(payload []byte) error {
	var msg core.HelloMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return fmt.Errorf("decode hello: %w", err)
	}

	if err := msg.Validate(); err != nil {
		h.sendError(err.Error(), true)
		return err
	}

	h.agentID = msg.AgentID
	h.sessionID = uuid.Must(uuid.NewV7()).String()

	_ = h.sm.Transition(core.ServerStateHelloReceived)

	// Negotiate capabilities
	result := core.Negotiate(msg.Capabilities, h.config.Policy)
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
		HeartbeatIntervalSec: 30,
		MaxFramePayloadBytes: 16 * 1024 * 1024,
		MaxBatchBytes:        8 * 1024 * 1024,
		MaxEventBytes:        256 * 1024,
		MaxBatchEvents:       10000,
		InitialWindow: core.WindowMessage{
			MaxInflightBatches: 100,
			MaxInflightEvents:  10000,
			MaxInflightBytes:   16 * 1024 * 1024,
		},
	}

	ackPayload, _ := json.Marshal(helloAck)
	if err := h.writeControl(core.TypeHelloAck, core.FlagControl, ackPayload); err != nil {
		return fmt.Errorf("write hello_ack: %w", err)
	}

	_ = h.sm.Transition(core.ServerStateAuthWait)
	slog.Info("hello processed", "agent", h.agentID, "session", h.sessionID)
	return nil
}

func (h *ConnectionHandler) handleAuth(payload []byte) error {
	var msg core.AuthMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return fmt.Errorf("decode auth: %w", err)
	}

	if err := msg.Validate(); err != nil {
		h.sendAuthFail("invalid_auth", err.Error(), false)
		return err
	}

	if msg.AgentID != h.agentID {
		h.sendAuthFail("agent_mismatch", "auth agent_id does not match hello", false)
		return fmt.Errorf("agent_id mismatch")
	}

	// Token validation
	if h.config.Auth != nil {
		_, err := h.config.Auth.Validate(msg.Token)
		if err != nil {
			h.sendAuthFail("invalid_token", "token validation failed", false)
			if h.config.Metrics != nil {
				h.config.Metrics.AuthFailureTotal.Inc()
			}
			return err
		}
	}

	// Generate session keys
	keys, err := core.GenerateSessionKeys()
	if err != nil {
		h.sendAuthFail("internal_error", "key generation failed", true)
		return err
	}
	h.keys = keys

	// Send AUTH_OK
	authOK := core.AuthOKMessage{
		SessionID:     h.sessionID,
		KeyID:         keys.KeyID,
		HMACKey:       keys.HMACKeyBase64(),
		ExpiresAtUnix: time.Now().Add(24 * time.Hour).Unix(),
	}
	okPayload, _ := json.Marshal(authOK)
	if err := h.writeControl(core.TypeAuthOK, core.FlagControl, okPayload); err != nil {
		return fmt.Errorf("write auth_ok: %w", err)
	}

	_ = h.sm.Transition(core.ServerStateReady)
	h.conn.SetAuthed(true)

	if h.config.Metrics != nil {
		h.config.Metrics.AuthSuccessTotal.Inc()
	}

	slog.Info("auth succeeded", "agent", h.agentID, "session", h.sessionID, "key_id", keys.KeyID)
	return nil
}

func (h *ConnectionHandler) handlePing(payload []byte) {
	var msg core.PingMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return
	}

	pong := core.PongMessage{
		TimeUnixMs: time.Now().UnixMilli(),
		Nonce:      msg.Nonce,
		Status:     "ok",
	}
	pongPayload, _ := json.Marshal(pong)
	_ = h.writeControl(core.TypePong, core.FlagControl, pongPayload)
}

func (h *ConnectionHandler) acceptDataStreams(ctx context.Context) {
	for {
		s, role, err := h.conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		if role == core.StreamRoleData {
			go h.handleDataStream(ctx, s)
		}
	}
}

func (h *ConnectionHandler) handleDataStream(ctx context.Context, s *quic.Stream) {
	defer s.Close()

	for {
		f, err := core.Read(s, core.DefaultLimits())
		if err != nil {
			return
		}

		if f.Header.Type != core.TypeBatch {
			continue
		}

		h.processBatch(ctx, s, f.Payload)
	}
}

func (h *ConnectionHandler) processBatch(ctx context.Context, w *quic.Stream, payload []byte) {
	// Decode envelope
	var env core.SecureEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		h.sendNack(0, "invalid_envelope", err.Error(), false)
		return
	}

	// Verify HMAC if enabled
	if h.negotiated.HMACAlgo == "sha256" && h.keys != nil {
		if !core.VerifyHMACSHA256(h.keys.HMACKey, &env) {
			h.sendNack(env.Seq, "hmac_mismatch", "HMAC verification failed", false)
			if h.config.Metrics != nil {
				h.config.Metrics.HMACFailuresTotal.Inc()
			}
			return
		}
	}

	// Open envelope
	batchPayload, err := core.Open(&env)
	if err != nil {
		h.sendNack(env.Seq, "envelope_open_error", err.Error(), true)
		return
	}

	// Decode batch message (protocol metadata wrapper)
	var batchMsg core.BatchMessage
	if err := json.Unmarshal(batchPayload, &batchMsg); err != nil {
		h.sendNack(env.Seq, "invalid_batch", err.Error(), false)
		return
	}

	if err := batchMsg.Validate(); err != nil {
		h.sendNack(batchMsg.Seq, "batch_validation", err.Error(), false)
		return
	}

	// Decode SignalBatch from the batch payload
	var signalBatch core.SignalBatch
	if err := json.Unmarshal(batchMsg.Batch, &signalBatch); err != nil {
		h.sendNack(batchMsg.Seq, "invalid_signal_batch", err.Error(), false)
		return
	}

	if err := signalBatch.Validate(); err != nil {
		h.sendNack(batchMsg.Seq, "signal_validation", err.Error(), false)
		return
	}

	// Replay check
	dedupKey := core.Key(h.agentID, batchMsg.ChunkID)
	existing := h.replay.SeenOrAdd(dedupKey)
	if existing != nil {
		// Already processed, resend ACK
		h.sendAck(batchMsg.Seq, batchMsg.ChunkID, len(signalBatch.Signals), core.AckModeAccepted)
		return
	}

	// Process events
	h.replay.Update(dedupKey, core.ReplayAccepted)

	// Route SignalBatch into the processing pipeline and determine ACK mode
	ackMode := core.AckModeAccepted // default: accepted

	if h.config.Sink != nil {
		if durable, ok := h.config.Sink.(core.DurableEventSink); ok {
			// Use result-aware routing for correct ACK mode selection
			result, err := durable.OnSignalBatchWithResult(ctx, h.agentID, &signalBatch)
			if err != nil {
				slog.Warn("durable routing failed", "session", h.sessionID, "error", err)
			} else {
				switch result.Status {
				case core.ACKStatusDurable:
					ackMode = core.AckModeDurable
					h.replay.Update(dedupKey, core.ReplayDurable)
				case core.ACKStatusThrottle:
					// Queue pressure critical - send THROTTLE frame instead of ACK
					h.sendThrottle(1000, "queue_pressure", "queue pressure critical, retry later")
					slog.Warn("throttling agent due to queue pressure",
						"session", h.sessionID,
						"agent", h.agentID,
						"pressure", result.Pressure)
					return
				default:
					ackMode = core.AckModeAccepted
				}
			}
		} else {
			// Fallback: basic sink without result feedback
			if err := h.config.Sink.OnSignalBatch(ctx, h.agentID, &signalBatch); err != nil {
				slog.Warn("event routing failed", "session", h.sessionID, "error", err)
			}
		}
	}

	// Send ACK with the appropriate mode
	h.sendAck(batchMsg.Seq, batchMsg.ChunkID, len(signalBatch.Signals), ackMode)

	if h.config.Metrics != nil {
		h.config.Metrics.BatchesAckedTotal.Inc()
	}

	slog.Debug("batch processed", "session", h.sessionID, "seq", batchMsg.Seq, "chunk", batchMsg.ChunkID, "signals", len(signalBatch.Signals))
}

// writeControl writes a frame to the control stream with mutex protection.
// Must be used for all control stream writes because data-stream goroutines
// (sendAck/sendNack/sendThrottle) can write concurrently with the control loop.
func (h *ConnectionHandler) writeControl(typ uint16, flags byte, payload []byte) error {
	h.controlMu.Lock()
	defer h.controlMu.Unlock()
	return core.Write(h.controlStr, typ, flags, payload)
}

func (h *ConnectionHandler) sendAck(seq uint64, chunkID string, count int, ackMode string) {
	ack := core.AckMessage{
		Seq:        seq,
		ChunkID:    chunkID,
		Count:      count,
		AckMode:    ackMode,
		ReceivedAt: time.Now().UnixMilli(),
	}
	payload, _ := json.Marshal(ack)
	_ = h.writeControl(core.TypeAck, core.FlagData, payload)
}

func (h *ConnectionHandler) sendNack(seq uint64, code, reason string, retryable bool) {
	nack := core.NackMessage{
		Seq:       seq,
		Code:      code,
		Reason:    reason,
		Retryable: retryable,
	}
	payload, _ := json.Marshal(nack)
	_ = h.writeControl(core.TypeNack, core.FlagData, payload)

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
	payload, _ := json.Marshal(throttle)
	_ = h.writeControl(core.TypeThrottle, core.FlagData, payload)

	if h.config.Metrics != nil {
		h.config.Metrics.BatchesNackedTotal.Inc()
	}
}

func (h *ConnectionHandler) sendAuthFail(code, reason string, retryable bool) {
	fail := core.AuthFailMessage{
		Code:      code,
		Reason:    reason,
		Retryable: retryable,
	}
	payload, _ := json.Marshal(fail)
	_ = h.writeControl(core.TypeAuthFail, core.FlagControl, payload)
}

func (h *ConnectionHandler) sendError(reason string, fatal bool) {
	errMsg := core.ErrorMessage{
		Code:      "protocol_error",
		Reason:    reason,
		Fatal:     fatal,
		Retryable: !fatal,
	}
	payload, _ := json.Marshal(errMsg)
	_ = h.writeControl(core.TypeError, core.FlagControl, payload)
}
