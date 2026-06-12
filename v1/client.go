package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/iuboy/mbta-go/core"
	"github.com/quic-go/quic-go"
)

// ClientConfig holds configuration for an MBTA client.
type ClientConfig struct {
	Transport    QUICClientConfig // QUIC connection settings
	AgentID      string           // unique agent identifier
	Hostname     string           // agent hostname (sent in HELLO)
	Token        string           // authentication token
	Capabilities []string         // negotiated capabilities (e.g. gzip, hmac-sha256)
	SpoolDir     string           // directory for durable event spooling (empty disables spool)
	PickStrategy string           // stream selection strategy: "single" or "hash"
}

// Client is an MBTA agent that connects to a server and sends event batches.
type Client struct {
	config     ClientConfig
	conn       *Conn
	sm         *core.StateMachine
	negotiated *core.NegotiateResult
	keys       *core.SessionKeys
	spool      *Spool
	seq        *core.SeqGenerator
	inflight   *core.Inflight
	window     *core.Window
	throttle   *core.ThrottleState
	picker     StreamPicker
	controlStr *quic.Stream
	controlMu  sync.Mutex // protects concurrent writes to controlStr
	sessionID  string
	challengeNonce string // server challenge from HELLO_ACK
	expiresAt      time.Time // 会话过期时间，从 AUTH_OK 的 expires_at_unix 获取

	// sendMu serializes SendBatch calls so that the throttle/window check
	// and the actual write happen atomically. Without this lock, concurrent
	// callers can both pass the window check and exceed inflight limits.
	sendMu sync.Mutex

	// pendingAcks tracks chunk_id -> batch info for ACK correlation.
	pendingAcks sync.Map // chunkID -> pendingBatch

	// ackHandler is called when an ACK is received from the server.
	// The handler receives the chunkID and ack_mode (e.g. "durable", "accepted").
	ackHandler atomic.Pointer[func(chunkID, ackMode string)]

	ackTimeout        time.Duration // max time to wait for ACK (default 5 min)
	heartbeatInterval time.Duration // PING 发送间隔（从 HELLO_ACK 获取，默认 30s）
	cancelACK         context.CancelFunc
	cancelReaper      context.CancelFunc
	cancelHeartbeat   context.CancelFunc
	drainCh           chan struct{} // signaled when pendingAcks reaches 0 during drain
}

type pendingBatch struct {
	Seq      uint64
	Events   int
	Bytes    int64
	SentAt   time.Time
	Deadline time.Time // when this batch expires if no ACK received
}

// quicStreamWrapper adapts *quic.Stream to the DataStream interface.
type quicStreamWrapper struct {
	stream *quic.Stream
	idx    int
}

func (w *quicStreamWrapper) Index() int                  { return w.idx }
func (w *quicStreamWrapper) Write(p []byte) (int, error) { return w.stream.Write(p) }

// NewClient creates a new MBTA client.
func NewClient(cfg ClientConfig) (*Client, error) {
	c := &Client{
		config:     cfg,
		sm:         core.NewStateMachine(),
		seq:        core.NewSeqGenerator(),
		inflight:   &core.Inflight{},
		window:     core.NewWindow(100, 10000, 16*1024*1024),
		throttle:   &core.ThrottleState{},
		ackTimeout: 5 * time.Minute,
		drainCh:    make(chan struct{}, 1),
	}

	if cfg.SpoolDir != "" {
		s, err := New(cfg.SpoolDir)
		if err != nil {
			return nil, core.WrapError(core.NumSpool, core.ErrSpool, "open spool", err)
		}
		c.spool = s
	}

	return c, nil
}

// Connect dials the server and completes the HELLO/AUTH handshake.
func (c *Client) Connect(ctx context.Context) error {
	// Dial QUIC
	if err := c.sm.Transition(core.StateConnecting); err != nil {
		return core.WrapError(core.NumSession, core.ErrSession, "transition to CONNECTING", err)
	}

	conn, err := Dial(ctx, c.config.Transport)
	if err != nil {
		return core.WrapError(core.NumTransport, core.ErrTransport, "dial", err)
	}
	c.conn = conn

	// Open control stream
	ctrlStr, err := conn.OpenControlStream(ctx)
	if err != nil {
		return core.WrapError(core.NumStream, core.ErrStream, "open control stream", err)
	}
	c.controlStr = ctrlStr
	if err := c.sm.Transition(core.StateControlStreamOpen); err != nil {
		return core.WrapError(core.NumSession, core.ErrSession, "transition to CONTROL_STREAM_OPEN", err)
	}

	// Send HELLO
	if err := c.sendHello(); err != nil {
		return core.WrapError(core.NumHandshake, core.ErrHandshake, "hello", err)
	}

	// Receive HELLO_ACK
	helloAck, err := c.recvHelloAck()
	if err != nil {
		return core.WrapError(core.NumHandshake, core.ErrHandshake, "hello_ack", err)
	}

	c.sessionID = helloAck.SessionID
	if err := c.sm.Transition(core.StateHelloAcked); err != nil {
		return core.WrapError(core.NumSession, core.ErrSession, "transition to HELLO_ACKED", err)
	}

	// Update window from HELLO_ACK
	c.window.Update(
		helloAck.InitialWindow.MaxInflightBatches,
		helloAck.InitialWindow.MaxInflightEvents,
		helloAck.InitialWindow.MaxInflightBytes,
	)

	// Store heartbeat interval from server
	if helloAck.HeartbeatIntervalSec > 0 {
		c.heartbeatInterval = time.Duration(helloAck.HeartbeatIntervalSec) * time.Second
	} else {
		c.heartbeatInterval = 30 * time.Second
	}

	// Send AUTH
	if err := c.sendAuth(); err != nil {
		return core.WrapError(core.NumHandshake, core.ErrHandshake, "auth", err)
	}

	// Receive AUTH_OK/FAIL
	if err := c.recvAuthResult(); err != nil {
		return core.WrapError(core.NumHandshake, core.ErrHandshake, "auth_result", err)
	}

	// Start ACK reader — derive from ctx so readControlLoop exits when
	// the caller's context is cancelled, not just on explicit Close().
	ackCtx, cancel := context.WithCancel(ctx)
	c.cancelACK = cancel
	go c.readControlLoop(ackCtx)

	// Start ACK timeout reaper — reclaims inflight slots for batches that
	// never received an ACK within the configured timeout.
	reaperCtx, cancelReaper := context.WithCancel(ctx)
	c.cancelReaper = cancelReaper
	go c.ackReaper(reaperCtx)

	// Start heartbeat — sends periodic PING frames to keep the connection alive.
	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	c.cancelHeartbeat = cancelHeartbeat
	go c.heartbeatLoop(heartbeatCtx)

	// Open initial data stream
	if c.picker == nil {
		ds, err := c.conn.OpenDataStream(ctx)
		if err != nil {
			// Clean up goroutines started above before returning error.
			cancel()
			cancelReaper()
			cancelHeartbeat()
			return core.WrapError(core.NumStream, core.ErrStream, "open data stream", err)
		}
		c.picker = NewSingleStream(&quicStreamWrapper{stream: ds, idx: 0})
	}

	slog.Info("MBTA client connected", "agent", c.config.AgentID, "session", c.sessionID)
	return nil
}

// SendBatch sends a SignalBatch through the MBTA protocol.
// Returns the chunkID assigned to this batch for ACK correlation, or an error.
func (c *Client) SendBatch(ctx context.Context, signalBatch *core.SignalBatch, tag, source string) (string, error) {
	if signalBatch == nil {
		return "", core.NewError(core.NumBatch, core.ErrBatch, "batch must not be nil")
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	if c.sm.State() != core.StateReady {
		return "", fmt.Errorf("%w, state=%s", ErrNotReady, c.sm.State())
	}

	// Check throttle
	if c.throttle.Active() {
		return "", fmt.Errorf("%w, retry after %v", ErrThrottled, c.throttle.WaitDuration())
	}

	seq := c.seq.Next()
	chunkID := uuid.Must(uuid.NewV7()).String()

	// Marshal SignalBatch to JSON for embedding in BatchMessage
	batchJSON, err := json.Marshal(signalBatch)
	if err != nil {
		return "", core.WrapError(core.NumBatch, core.ErrBatch, "marshal signal batch", err)
	}

	batch := core.BatchMessage{
		Seq:     seq,
		ChunkID: chunkID,
		Tag:     tag,
		Source:  source,
		Batch:   json.RawMessage(batchJSON),
	}
	batchPayload, err := json.Marshal(batch)
	if err != nil {
		return "", core.WrapError(core.NumBatch, core.ErrBatch, "marshal batch", err)
	}

	batchBytes := int64(len(batchPayload))
	batchEvents := len(signalBatch.Signals)

	// Check window — protected by sendMu so concurrent callers cannot
	// both pass and exceed inflight limits.
	if !c.window.CanSend(c.inflight, batchEvents, batchBytes) {
		return "", ErrWindowFull
	}

	// Build envelope
	params := core.Params{
		SessionID:   c.sessionID,
		KeyID:       "",
		Seq:         seq,
		ChunkID:     chunkID,
		Codec:       "json",
		Compression: "none",
		Encryption:  "none",
		HMACAlgo:    "none",
	}

	if c.negotiated != nil {
		params.Codec = c.negotiated.Codec
		params.Compression = c.negotiated.Compression
		params.Encryption = c.negotiated.Encryption
		params.HMACAlgo = c.negotiated.HMACAlgo
	}
	if c.keys != nil {
		params.KeyID = c.keys.KeyID
		params.HMACKey = c.keys.HMACKey
	}

	env, err := core.Build(params, batchPayload)
	if err != nil {
		return "", core.WrapError(core.NumEnvelope, core.ErrEnvelope, "build envelope", err)
	}

	envPayload, err := json.Marshal(env)
	if err != nil {
		return "", core.WrapError(core.NumEnvelope, core.ErrEnvelope, "marshal envelope", err)
	}

	// Pick stream
	ds, err := c.picker.Pick(batch)
	if err != nil {
		return "", core.WrapError(core.NumBatch, core.ErrBatch, "pick stream", err)
	}

	// Write frame
	if err := core.Write(ds, core.TypeBatch, core.FlagEnvelope|core.FlagData, envPayload); err != nil {
		return "", core.WrapError(core.NumBatch, core.ErrBatch, "write batch", err)
	}

	// Track inflight — still under sendMu, so the window check remains valid.
	c.inflight.Add(batchEvents, batchBytes)
	c.pendingAcks.Store(chunkID, &pendingBatch{
		Seq:      seq,
		Events:   batchEvents,
		Bytes:    batchBytes,
		SentAt:   time.Now(),
		Deadline: time.Now().Add(c.ackTimeout),
	})

	slog.Debug("batch sent", "seq", seq, "chunk", chunkID, "events", batchEvents)
	return chunkID, nil
}

// SetACKHandler registers a callback invoked when the server acknowledges a batch.
// The handler receives (chunkID, ackMode) where ackMode is "durable", "accepted", etc.
func (c *Client) SetACKHandler(h func(chunkID, ackMode string)) {
	c.ackHandler.Store(&h)
}

func (c *Client) loadACKHandler() func(chunkID, ackMode string) {
	if p := c.ackHandler.Load(); p != nil {
		return *p
	}
	return nil
}

// Close sends a CLOSE frame and shuts down.
func (c *Client) Close() error {
	if c.cancelACK != nil {
		c.cancelACK()
	}
	if c.cancelReaper != nil {
		c.cancelReaper()
	}
	if c.cancelHeartbeat != nil {
		c.cancelHeartbeat()
	}

	// Transition to Draining state.
	if err := c.sm.Transition(core.StateDraining); err != nil {
		slog.Debug("drain transition skipped", "error", err)
	}

	// Wait for drain with timeout. Event-driven: drainCh signals when
	// pendingAcks reaches 0. If the timeout fires first, force-close.
	if c.sm.State() == core.StateDraining {
		drainDeadline := time.NewTimer(core.DefaultDrainTimeout)
		defer drainDeadline.Stop()
		for c.sm.State() == core.StateDraining {
			select {
			case <-drainDeadline.C:
				slog.Warn("drain timeout exceeded, force-closing")
				_ = c.sm.Transition(core.StateClosed)
			case <-c.drainCh:
				_ = c.sm.Transition(core.StateClosed)
			}
		}
	}

	// Clear pending ACKs to release references.
	c.pendingAcks.Range(func(key, _ any) bool {
		c.pendingAcks.Delete(key)
		return true
	})

	if c.controlStr != nil {
		c.controlMu.Lock()
		closeMsg := core.CloseMessage{Code: "shutdown", Reason: "client closing"}
		if payload, err := json.Marshal(closeMsg); err == nil {
			if err := core.Write(c.controlStr, core.TypeClose, core.FlagControl, payload); err != nil {
				slog.Debug("write close frame", "error", err)
			}
		}
		c.controlMu.Unlock()
	}

	// Reset inflight counters so stale state does not block future sends.
	c.inflight.Reset()

	// Clear sensitive material from memory.
	c.config.Token = ""
	if c.keys != nil {
		for i := range c.keys.HMACKey {
			c.keys.HMACKey[i] = 0
		}
		c.keys = nil
	}

	if c.conn != nil {
		return c.conn.CloseWithError(0, "client shutdown")
	}
	return nil
}

// SessionID returns the current session ID.
func (c *Client) SessionID() string {
	return c.sessionID
}

// State returns the current client state.
func (c *Client) State() core.State {
	return c.sm.State()
}

// ackReaper periodically scans pendingAcks and removes entries that have exceeded
// their deadline. Reclaimed inflight slots allow new batches to be sent.
func (c *Client) ackReaper(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			c.pendingAcks.Range(func(key, val any) bool {
				pb, ok := val.(*pendingBatch)
				if !ok {
					return true
				}
				if !pb.Deadline.IsZero() && now.After(pb.Deadline) {
					c.pendingAcks.Delete(key)
					c.inflight.Remove(pb.Events, pb.Bytes)
					slog.Warn("reaped expired pending ACK",
						"chunk", key,
						"seq", pb.Seq,
						"age", now.Sub(pb.SentAt).Round(time.Second))
				}
				return true
			})
				c.notifyDrainIfEmpty()
		}
	}
}

// notifyDrainIfEmpty signals the drain channel when no pending ACKs remain.
// This is called after each ACK/NACK/reaper removal to unblock the Close drain loop.
func (c *Client) notifyDrainIfEmpty() {
	pending := 0
	c.pendingAcks.Range(func(_, _ any) bool {
		pending++
		return false // one hit is enough to know it's non-empty
	})
	if pending == 0 {
		select {
		case c.drainCh <- struct{}{}:
		default: // already signaled, no need to block
		}
	}
}

// heartbeatLoop periodically sends PING frames to keep the connection alive.
// The interval is negotiated with the server in HELLO_ACK (default 30s).
func (c *Client) heartbeatLoop(ctx context.Context) {
	if c.heartbeatInterval <= 0 {
		return
	}
	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ping := core.PingMessage{
				TimeUnixMs: time.Now().UnixMilli(),
				Nonce:      uuid.Must(uuid.NewV7()).String(),
			}
			payload, err := json.Marshal(ping)
			if err != nil {
				slog.Debug("marshal ping failed", "error", err)
				continue
			}
			c.controlMu.Lock()
			if err := core.Write(c.controlStr, core.TypePing, core.FlagControl, payload); err != nil {
				c.controlMu.Unlock()
				slog.Debug("write ping failed", "error", err)
				return
			}
			c.controlMu.Unlock()
		}
	}
}
