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

// ClientConfig holds configuration for an MBTA client.
type ClientConfig struct {
	Transport    QUICClientConfig
	AgentID      string
	Hostname     string
	Token        string
	Capabilities []string
	SpoolDir     string
	PickStrategy string // "single" or "hash"
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

	// pendingAcks tracks chunk_id -> batch info for ACK correlation.
	pendingAcks sync.Map // chunkID -> pendingBatch

	// ackHandler is called when an ACK is received from the server.
	// The handler receives the chunkID and ack_mode (e.g. "durable", "accepted").
	ackHandler func(chunkID, ackMode string)

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

func (w *quicStreamWrapper) Index() int { return w.idx }

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
			return nil, fmt.Errorf("open spool: %w", err)
		}
		c.spool = s
	}

	return c, nil
}

// Connect dials the server and completes the HELLO/AUTH handshake.
func (c *Client) Connect(ctx context.Context) error {
	// Dial QUIC
	_ = c.sm.Transition(core.StateConnecting)

	conn, err := Dial(ctx, c.config.Transport)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c.conn = conn

	// Open control stream
	ctrlStr, err := conn.OpenControlStream(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	c.controlStr = ctrlStr
	_ = c.sm.Transition(core.StateControlStreamOpen)

	// Send HELLO
	if err := c.sendHello(); err != nil {
		return fmt.Errorf("hello: %w", err)
	}

	// Receive HELLO_ACK
	helloAck, err := c.recvHelloAck()
	if err != nil {
		return fmt.Errorf("hello_ack: %w", err)
	}

	c.sessionID = helloAck.SessionID
	_ = c.sm.Transition(core.StateHelloAcked)

	// Update window from HELLO_ACK
	c.window.Update(
		helloAck.InitialWindow.MaxInflightBatches,
		helloAck.InitialWindow.MaxInflightEvents,
		helloAck.InitialWindow.MaxInflightBytes,
	)

	// Send AUTH
	if err := c.sendAuth(); err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	// Receive AUTH_OK/FAIL
	if err := c.recvAuthResult(); err != nil {
		return fmt.Errorf("auth_result: %w", err)
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
			return fmt.Errorf("open data stream: %w", err)
		}
		c.picker = NewSingleStream(&quicStreamWrapper{stream: ds, idx: 0})
	}

	slog.Info("MBTA client connected", "agent", c.config.AgentID, "session", c.sessionID)
	return nil
}

// SendBatch sends a SignalBatch through the MBTA protocol.
// Returns the chunkID assigned to this batch for ACK correlation, or an error.
func (c *Client) SendBatch(ctx context.Context, signalBatch *core.SignalBatch, tag, source string) (string, error) {
	if c.sm.State() != core.StateReady {
		return "", fmt.Errorf("client not ready, state=%s", c.sm.State())
	}

	// Check throttle
	if c.throttle.Active() {
		return "", fmt.Errorf("throttled, retry after %v", c.throttle.WaitDuration())
	}

	seq := c.seq.Next()
	chunkID := uuid.Must(uuid.NewV7()).String()

	// Marshal SignalBatch to JSON for embedding in BatchMessage
	batchJSON, err := json.Marshal(signalBatch)
	if err != nil {
		return "", fmt.Errorf("marshal signal batch: %w", err)
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
		return "", fmt.Errorf("marshal batch: %w", err)
	}

	batchBytes := int64(len(batchPayload))
	batchEvents := len(signalBatch.Signals)

	// Check window
	if !c.window.CanSend(c.inflight, batchEvents, batchBytes) {
		return "", fmt.Errorf("window full, cannot send batch")
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
		return "", fmt.Errorf("build envelope: %w", err)
	}

	envPayload, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}

	// Pick stream
	ds, err := c.picker.Pick(batch)
	if err != nil {
		return "", fmt.Errorf("pick stream: %w", err)
	}

	// Write frame
	w := ds.(*quicStreamWrapper).stream
	if err := core.Write(w, core.TypeBatch, core.FlagEnvelope|core.FlagData, envPayload); err != nil {
		return "", fmt.Errorf("write batch: %w", err)
	}

	// Track inflight
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
	c.ackHandler = h
}

// Close sends a CLOSE frame and shuts down.
func (c *Client) Close() error {
	if c.cancelACK != nil {
		c.cancelACK()
	}

	if c.controlStr != nil {
		closeMsg := core.CloseMessage{Code: "shutdown", Reason: "client closing"}
		payload, _ := json.Marshal(closeMsg)
		_ = core.Write(c.controlStr, core.TypeClose, core.FlagControl, payload)
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
