package v1

import (
	"context"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/protocol"
	"github.com/quic-go/quic-go"
)

// ClientConfig holds configuration for an MBTA client.
type ClientConfig struct {
	Transport    QUICClientConfig // QUIC connection settings
	AgentID      string           // unique agent identifier
	Hostname     string           // agent hostname (sent in HELLO)
	Token        string           // authentication token
	Capabilities []string         // negotiated capabilities (e.g. gzip, hmac-sha256)
	PickStrategy string           // stream selection strategy: "single" or "hash"
	StreamCount  int              // hash 模式下打开的数据流数量（<=0 用 defaultStreamCount）
}

// Client is an MBTA agent that connects to a server and sends event batches.
//
// Phase 2 重构后，Client 是薄包装：协议逻辑（状态机/握手/ACK/drain/heartbeat）
// 全部委托给 protocol.CoreClient，自身仅保留传输适配（v1ClientTransport）。
//
// 可靠投递语义：仅在内存追踪已发送未 ACK 的 batch。进程崩溃/重连后未 ACK 的
// batch 会丢失——持久化与重发由调用方负责。
type Client struct {
	core      *protocol.CoreClient
	cfg       ClientConfig
	conn      *Conn
	controlStr *quic.Stream
	picker    StreamPicker
	mu        sync.Mutex // 保护 conn/controlStr/picker 的读写
}

// v1ClientTransport 实现 protocol.ClientTransport，封装 QUIC 多流传输。
//
// control 帧（HELLO/AUTH/PING/PONG/CLOSE）走 controlMu + controlStr（单一控制流）；
// data 帧（BATCH）走 picker.Pick + per-stream mu（多流并发，绕过队头阻塞）。
type v1ClientTransport struct {
	conn       *Conn
	controlStr *quic.Stream
	picker     StreamPicker
	controlMu  sync.Mutex // 串行化 control stream 写
}

func (t *v1ClientTransport) ReadFrame() (core.Frame, error) {
	return core.Read(t.controlStr, core.DefaultLimits())
}

// WriteFrame 按 channel 路由：control 走 controlStr（controlMu 串行），
// data 走 picker 选流 + per-stream ctx 感知写。
func (t *v1ClientTransport) WriteFrame(ctx context.Context, typ uint8, flags, channel uint8, payload []byte) error {
	if channel == core.ChannelControl {
		t.controlMu.Lock()
		defer t.controlMu.Unlock()
		return core.Write(t.controlStr, core.Version, typ, flags, channel, payload)
	}
	// data 通道：picker 选流，ctx 感知写。
	ds, err := t.picker.Pick("", "") // tag/source 在多流选路中用于 hash 分流；CoreClient 传空
	if err != nil {
		return core.WrapError(core.NumBatch, core.CodeBatch, "pick stream", err)
	}
	if w, ok := ds.(*quicStreamWrapper); ok {
		return w.writeFrameCtx(ctx, typ, flags, channel, payload)
	}
	return core.Write(ds, core.Version, typ, flags, channel, payload)
}

func (t *v1ClientTransport) CloseConn() error {
	return t.conn.CloseWithError(0, "client shutdown")
}

// quicStreamWrapper adapts *quic.Stream to the DataStream interface.
//
// mu 串行化 SetWriteDeadline/Write/恢复 三步，使调用方 ctx 能安全绑定到写。
type quicStreamWrapper struct {
	stream *quic.Stream
	idx    int
	mu     sync.Mutex
}

func (w *quicStreamWrapper) Index() int                  { return w.idx }
func (w *quicStreamWrapper) Write(p []byte) (int, error) { return w.stream.Write(p) }

// writeFrameCtx 写一帧并受调用方 ctx 约束。
func (w *quicStreamWrapper) writeFrameCtx(ctx context.Context, typ uint8, flags byte, channel uint8, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if dl, ok := ctx.Deadline(); ok {
		if err := w.stream.SetWriteDeadline(dl); err != nil {
			return core.WrapError(core.NumStream, core.CodeStream, "set write deadline", err)
		}
		defer func() { _ = w.stream.SetWriteDeadline(time.Time{}) }()
	}
	return core.Write(w, core.Version, typ, flags, channel, payload)
}

// defaultStreamCount 是 hash 模式下默认打开的数据流数量。
const defaultStreamCount = 4

// NewClient creates a new MBTA client.
func NewClient(cfg ClientConfig) (*Client, error) {
	cc := protocol.NewCoreClient(nil, protocol.CoreClientConfig{
		AgentID:      cfg.AgentID,
		Hostname:     cfg.Hostname,
		Token:        cfg.Token,
		Capabilities: cfg.Capabilities,
	})
	cc.SetReadControlLoop(cc.ReadControlLoop)
	cc.SetHeartbeatLoop(cc.HeartbeatLoop)
	return &Client{core: cc, cfg: cfg}, nil
}

// Connect dials the server and completes the HELLO/AUTH handshake.
//
// ctx 仅用于控制握手阶段（Dial、开 stream、HELLO/AUTH）的超时与取消。
// 握手成功后，后台 goroutine 运行在独立的 lifecycle ctx 上。
func (c *Client) Connect(ctx context.Context) error {
	if err := c.core.SmTransitionConnecting(); err != nil {
		return err
	}

	conn, err := Dial(ctx, c.cfg.Transport)
	if err != nil {
		return core.WrapError(core.NumTransport, core.CodeTransport, "dial", err)
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	// Open control stream
	ctrlStr, err := conn.OpenControlStream(ctx)
	if err != nil {
		return core.WrapError(core.NumStream, core.CodeStream, "open control stream", err)
	}
	c.mu.Lock()
	c.controlStr = ctrlStr
	c.mu.Unlock()

	if err := c.core.SmTransition(core.StateControlStreamOpen); err != nil {
		return err
	}

	// 设置 transport（picker 在握手后、StartLifecycle 前打开）。
	tr := &v1ClientTransport{conn: conn, controlStr: ctrlStr}
	c.core.SetTransport(tr)

	if err := c.core.SendHello(); err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "hello", err)
	}
	helloAck, err := c.core.RecvHelloAck()
	if err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "hello_ack", err)
	}

	c.core.SetSessionID(helloAck.GetSessionId())
	if err := c.core.SmTransition(core.StateHelloAcked); err != nil {
		return err
	}
	if w := helloAck.GetInitialWindow(); w != nil {
		c.core.UpdateWindow(int(w.GetMaxInflightBatches()), int(w.GetMaxInflightEvents()), w.GetMaxInflightBytes())
	}
	if helloAck.GetHeartbeatIntervalSec() > 0 {
		c.core.SetHeartbeatInterval(time.Duration(helloAck.GetHeartbeatIntervalSec()) * time.Second)
	} else {
		c.core.SetHeartbeatInterval(30 * time.Second)
	}

	if err := c.core.SendAuth(); err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "auth", err)
	}
	// v1 独有：AUTH_OK 后调用 SetAuthed(true) 开放 data stream 门禁。
	c.core.SetOnAuthed(func(context.Context) { conn.SetAuthed(true) })
	if err := c.core.RecvAuthResult(); err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "auth_result", err)
	}

	c.core.StartLifecycle()

	// Open data stream(s) per PickStrategy（握手成功后，data stream 门禁已开放）。
	picker, err := c.openDataStreams(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.picker = picker
	tr.picker = picker
	c.mu.Unlock()

	return nil
}

// openDataStreams 按 PickStrategy 打开数据流并构造 StreamPicker。
func (c *Client) openDataStreams(ctx context.Context) (StreamPicker, error) {
	if c.cfg.PickStrategy == "hash" {
		picker := NewHashStreamPicker()
		n := c.cfg.StreamCount
		if n <= 0 {
			n = defaultStreamCount
		}
		opened := make([]*quic.Stream, 0, n)
		for i := 0; i < n; i++ {
			ds, err := c.conn.OpenDataStream(ctx)
			if err != nil {
				for _, s := range opened {
					_ = s.Close()
				}
				return nil, core.WrapError(core.NumStream, core.CodeStream, "open data stream", err)
			}
			opened = append(opened, ds)
			picker.AddStream(&quicStreamWrapper{stream: ds, idx: i})
		}
		return picker, nil
	}

	ds, err := c.conn.OpenDataStream(ctx)
	if err != nil {
		return nil, core.WrapError(core.NumStream, core.CodeStream, "open data stream", err)
	}
	return NewSingleStream(&quicStreamWrapper{stream: ds, idx: 0}), nil
}

// SendBatch sends a SignalBatch through the MBTA protocol.
func (c *Client) SendBatch(ctx context.Context, signalBatch *core.SignalBatch, tag, source string) (string, error) {
	return c.core.SendBatch(ctx, signalBatch, tag, source)
}

// SetACKHandler registers a callback invoked when the server acknowledges a batch.
func (c *Client) SetACKHandler(h func(chunkID, ackMode string)) {
	c.core.SetACKHandler(h)
}

// Close sends a CLOSE frame, drains pending ACKs, and shuts down.
func (c *Client) Close() error {
	return c.core.Close()
}

// State 返回当前连接状态。
func (c *Client) State() core.State {
	return c.core.State()
}

// SessionID 返回会话 ID。
func (c *Client) SessionID() string {
	return c.core.SessionID()
}
