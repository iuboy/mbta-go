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
	sessionID  string

	// sendMu serializes SendBatch calls so that the throttle/window check
	// and the actual write happen atomically. Without this lock, concurrent
	// callers can both pass the window check and exceed inflight limits.
	sendMu sync.Mutex

	// pendingAcks tracks chunk_id -> batch info for ACK correlation.
	pendingAcks sync.Map // chunkID -> pendingBatch

	// ackHandler is called when an ACK is received from the server.
	// The handler receives the chunkID and ack_mode (e.g. "durable", "accepted").
	ackHandler atomic.Pointer[func(chunkID, ackMode string)]

	cancelACK context.CancelFunc
}

type pendingBatch struct {
	Seq    uint64
	Events int
	Bytes  int64
	SentAt time.Time
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
		config:   cfg,
		sm:       core.NewStateMachine(),
		seq:      core.NewSeqGenerator(),
		inflight: &core.Inflight{},
		window:   core.NewWindow(100, 10000, 16*1024*1024),
		throttle: &core.ThrottleState{},
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
		slog.Warn("state transition failed", "to", core.StateConnecting, "error", err)
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
		slog.Warn("state transition failed", "to", core.StateControlStreamOpen, "error", err)
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
		slog.Warn("state transition failed", "to", core.StateHelloAcked, "error", err)
	}

	// Update window from HELLO_ACK
	c.window.Update(
		helloAck.InitialWindow.MaxInflightBatches,
		helloAck.InitialWindow.MaxInflightEvents,
		helloAck.InitialWindow.MaxInflightBytes,
	)

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

	// Open initial data stream
	if c.picker == nil {
		ds, err := c.conn.OpenDataStream(ctx)
		if err != nil {
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
		Batch:   batchJSON,
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
		Seq:    seq,
		Events: batchEvents,
		Bytes:  batchBytes,
		SentAt: time.Now(),
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

	if c.controlStr != nil {
		closeMsg := core.CloseMessage{Code: "shutdown", Reason: "client closing"}
		if payload, err := json.Marshal(closeMsg); err == nil {
			_ = core.Write(c.controlStr, core.TypeClose, core.FlagControl, payload)
		}
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
