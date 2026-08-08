package v1

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/binding"
	"github.com/iuboy/mbta-go/internal/protocol"
	"github.com/quic-go/quic-go"
)

// ClientConfig holds configuration for an MBTA client.
type ClientConfig struct {
	Transport    QUICClientConfig // QUIC连接配置
	AgentID      string           // agent ID
	Hostname     string           // agent 主机名 (sent in HELLO)
	Token        string           // 认证 token
	Capabilities []string         // 协商功能列表 (e.g. gzip, hmac-sha256)
	PickStrategy string           // 流选择策略: "single" or "hash"
	StreamCount  int              // hash 模式下打开的数据流数量（<=0 用 defaultStreamCount）

	// OS / AgentVersion 写入 HELLO（供服务端 OnSession 回调读取，空则不发/回退默认）。
	OS           string       // agent 操作系统（如 runtime.GOOS：linux/darwin/windows）
	AgentVersion string       // agent 构建版本（空则回退 "0.1.0"）
	Metrics      core.Metrics // 可选：客户端可观测性指标（nil=NoOp）
	// DrainTimeout 限制 Close 时等待未 ACK batch 的最长时间。0=用默认(30s)。
	// 缩短可减小"发完即 Close"的等待窗口；未确认的 batch 会丢（调用方负责重发）。
	DrainTimeout time.Duration
}

// Client is an MBTA agent that connects to a server and sends event batches.
//
// Client 是薄包装：协议逻辑（状态机/握手/ACK/drain/heartbeat）全部委托给
// protocol.CoreClient；传输帧 I/O 下沉到 v1ClientTransport（QUIC 多流适配）。
// 自身只保留 QUIC 连接引用，用于「已连接守卫」与 Connect 失败兜底关闭。
//
// 可靠投递语义：仅在内存追踪已发送未 ACK 的 batch。进程崩溃/重连后未 ACK 的
// batch 会丢失——持久化与重发由调用方负责。
type Client struct {
	core *protocol.CoreClient // 共享协议核心
	cfg  ClientConfig         // v1 专属配置（Transport，供 Dial 用）
	conn *Conn                // QUIC 连接（已连接守卫 + Connect 失败兜底关闭）
	mu   sync.Mutex           // 保护 conn 字段的读写（Connect 设置 / 失败清理）
}

// v1ClientTransport 实现 protocol.ClientTransport，封装 QUIC 多流传输。
//
// control 帧（HELLO/AUTH/PING/PONG/CLOSE）走 controlMu + controlStr（单一控制流）；
// data 帧（BATCH）走 picker.Pick + per-stream mu（多流并发，绕过队头阻塞）。
type v1ClientTransport struct {
	conn       *Conn
	controlStr *quic.Stream
	picker     atomic.Pointer[StreamPicker] // 原子读写，消除与 postAuth 写的 data race
	controlMu  sync.Mutex                   // 串行化 control stream 写
}

func (t *v1ClientTransport) ReadFrame(ctx context.Context) (core.Frame, error) {
	// ctx 感知读：通过 SetReadDeadline 让 ctx 取消/超时能中断阻塞读，
	// 避免对端静默断开时 control loop 永久阻塞（goroutine 泄漏）。
	if err := ctx.Err(); err != nil {
		return core.Frame{}, err
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(clientReadDefaultTimeout)
	}
	if err := t.controlStr.SetReadDeadline(dl); err != nil {
		return core.Frame{}, core.WrapError(core.ErrCodeStream, "set control read deadline", err)
	}
	defer func() { _ = t.controlStr.SetReadDeadline(time.Time{}) }()
	f, err := core.Read(t.controlStr, core.DefaultLimits())
	if err != nil && ctx.Err() != nil {
		return core.Frame{}, ctx.Err()
	}
	return f, err
}

// clientReadDefaultTimeout 是客户端 control stream 读在 ctx 无 deadline 时的默认上限。
const clientReadDefaultTimeout = 5 * time.Minute

// WriteFrame 按 channel 路由：control 走 controlStr（controlMu 串行），
// data 走 picker 选流 + per-stream ctx 感知写。
func (t *v1ClientTransport) WriteFrame(ctx context.Context, typ uint8, flags, channel uint8, payload []byte) error {
	if channel == core.ChannelControl {
		t.controlMu.Lock()
		defer t.controlMu.Unlock()
		return core.Write(t.controlStr, core.Version, typ, flags, channel, payload)
	}
	// data 通道：picker 选流，ctx 感知写。
	// picker 经 atomic 读取（postAuth 在 c.mu 下用 atomic.Pointer.Store 写）。
	// nil guard 防 postAuth 完成前进入 data 路径的 nil 解引用 panic。
	pickerPtr := t.picker.Load()
	if pickerPtr == nil {
		return core.NewError(core.ErrCodeSession, "data stream picker not initialized (auth incomplete?)")
	}
	ds, err := (*pickerPtr).Pick("", "") // tag/source 在多流选路中用于 hash 分流；CoreClient 传空
	if err != nil {
		return core.WrapError(core.ErrCodeBatch, "pick stream", err)
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
	// ctx 无 deadline 时设默认上限，避免 QUIC 流控背压下 Write 永久阻塞（goroutine 泄漏）。
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(30 * time.Second)
	}
	if err := w.stream.SetWriteDeadline(dl); err != nil {
		return core.WrapError(core.ErrCodeStream, "set write deadline", err)
	}
	defer func() { _ = w.stream.SetWriteDeadline(time.Time{}) }()
	return core.Write(w, core.Version, typ, flags, channel, payload)
}

// defaultStreamCount 是 hash 模式下默认打开的数据流数量。
const defaultStreamCount = 4

// NewClient creates a new MBTA client.
func NewClient(cfg ClientConfig) (*Client, error) {
	// fail-fast：构造期校验必填字段与格式，避免拖到 Connect 的 dial 层才报
	// 低层 resolver 错误（错误归因不准）。
	if cfg.AgentID == "" {
		return nil, core.NewError(core.ErrCodeConfig, "AgentID required")
	}
	if cfg.Token == "" {
		return nil, core.NewError(core.ErrCodeConfig, "Token required")
	}
	if err := core.ValidateHostPort(cfg.Transport.Server); err != nil {
		return nil, core.WrapError(core.ErrCodeConfig, "Transport.Server", err)
	}
	// Capabilities 复用 Negotiate 的未知 stable capability 检测，拼错的 stable
	// capability 在构造期即报错，而非拖到 HELLO 被服务端拒绝。
	if unknown := core.FilterUnknownStable(cfg.Capabilities); len(unknown) > 0 {
		return nil, core.NewError(core.ErrCodeProtocol, fmt.Sprintf("unknown stable capabilities: %v", unknown))
	}
	if cfg.PickStrategy != "" && cfg.PickStrategy != "single" && cfg.PickStrategy != "hash" {
		return nil, core.NewError(core.ErrCodeConfig, fmt.Sprintf("invalid PickStrategy %q (want \"single\" or \"hash\")", cfg.PickStrategy))
	}

	cc := protocol.NewCoreClient(nil, protocol.CoreClientConfig{
		AgentID:      cfg.AgentID,
		Hostname:     cfg.Hostname,
		Token:        cfg.Token,
		Capabilities: cfg.Capabilities,
		OS:           cfg.OS,
		AgentVersion: cfg.AgentVersion,
		// binding 默认算法（spec §8.3：跟随传输 binding 合规语境）。
		// v1 走 QUIC + TLS1.3 → 国际密码套件；codec/compression 用协议 baseline 默认。
		DefaultCodec:       corepb.Codec_CODEC_PROTO,
		DefaultCipherSuite: corepb.CipherSuite_CIPHER_SUITE_INTL,
		DefaultCompression: corepb.Compression_COMPRESSION_ZSTD,
		Metrics:            cfg.Metrics,
		DrainTimeout:       cfg.DrainTimeout,
	})
	cc.SetReadControlLoop(cc.ReadControlLoop)
	cc.SetHeartbeatLoop(cc.HeartbeatLoop)
	return &Client{core: cc, cfg: cfg}, nil
}

// Connect dials the server and completes the HELLO/AUTH handshake.
//
// ctx 仅控制握手阶段（Dial、开 stream、HELLO/AUTH）的超时与取消。握手成功后，
// 后台 goroutine 运行在独立的 lifecycle ctx 上，不随 ctx 取消而退出；client 生命周期
// 由 Close() 终结。
func (c *Client) Connect(ctx context.Context) error {
	// 防重复 Connect：已连接/连接中时拒绝，避免旧 QUIC 连接被覆盖（fd + 连接泄漏）。
	c.mu.Lock()
	if c.conn != nil {
		c.mu.Unlock()
		return core.NewError(core.ErrCodeSession, "already connected")
	}
	c.mu.Unlock()

	tr := &v1ClientTransport{}
	// conn 由 dial 设置，闭包内共享；connSet 标记本协程是否建立连接，并发 Connect 时失败方只关自己的连接。
	var conn *Conn
	var connSet bool
	err := binding.Handshake(ctx, c.core,
		// dial: 建立 QUIC 连接
		func(ctx context.Context) error {
			dialed, err := Dial(ctx, c.cfg.Transport)
			if err != nil {
				return core.WrapError(core.ErrCodeTransport, "dial", err)
			}
			// dial 回调内二次检查：消除入口 c.conn==nil 检查与赋值之间的 TOCTOU 窗口。
			c.mu.Lock()
			if c.conn != nil {
				// 另一个并发 Connect 已设置连接，关闭当前 dialed 避免泄漏。
				c.mu.Unlock()
				_ = dialed.CloseWithError(0, "connect race")
				return core.NewError(core.ErrCodeSession, "already connected (race)")
			}
			c.conn = dialed
			conn = dialed
			connSet = true
			c.mu.Unlock()
			return nil
		},
		// setupTransport: 开 control stream、设置 transport、注册 onAuthed
		func(ctx context.Context, cc *protocol.CoreClient) error {
			ctrlStr, err := conn.OpenControlStream(ctx)
			if err != nil {
				return core.WrapError(core.ErrCodeStream, "open control stream", err)
			}
			tr.conn = conn
			tr.controlStr = ctrlStr
			cc.SetTransport(tr)
			// v1 独有：AUTH_OK 后调用 SetAuthed(true) 开放 data stream 门禁。
			cc.SetOnAuthed(func(context.Context) { conn.SetAuthed(true) })
			return nil
		},
		// postAuth: StartLifecycle 后打开 data stream(s)
		func(ctx context.Context) error {
			picker, err := openDataStreams(ctx, conn, c.cfg.PickStrategy, c.cfg.StreamCount)
			if err != nil {
				return err
			}
			tr.picker.Store(&picker)
			return nil
		},
	)
	// 握手失败：cc.Close() 仅在 transport 已注册时关连接，dial 成功但 setupTransport 失败时需在此显式关闭（仅关本协程建立的连接）。
	if err != nil {
		c.mu.Lock()
		if connSet {
			_ = conn.CloseWithError(0, "connect failed")
			c.conn = nil
		}
		c.mu.Unlock()
	}
	return err
}

// openDataStreams 按 PickStrategy 打开数据流并构造 StreamPicker。
// 纯函数：不依赖 Client 实例状态，连接由调用方传入。
func openDataStreams(ctx context.Context, conn *Conn, pickStrategy string, streamCount int) (StreamPicker, error) {
	if pickStrategy == "hash" {
		picker := NewHashStreamPicker()
		n := streamCount
		if n <= 0 {
			n = defaultStreamCount
		}
		opened := make([]*quic.Stream, 0, n)
		for i := 0; i < n; i++ {
			ds, err := conn.OpenDataStream(ctx)
			if err != nil {
				for _, s := range opened {
					_ = s.Close()
				}
				return nil, core.WrapError(core.ErrCodeStream, "open data stream", err)
			}
			opened = append(opened, ds)
			picker.AddStream(&quicStreamWrapper{stream: ds, idx: i})
		}
		return picker, nil
	}

	ds, err := conn.OpenDataStream(ctx)
	if err != nil {
		return nil, core.WrapError(core.ErrCodeStream, "open data stream", err)
	}
	return NewSingleStream(&quicStreamWrapper{stream: ds, idx: 0}), nil
}

// SendBatch sends a SignalBatch through the MBTA protocol.
//
// opts 携带 per-call 发送选项（如 core.WithTraceContext），透传给协议核心。
func (c *Client) SendBatch(ctx context.Context, signalBatch *core.SignalBatch, tag, source string, opts ...core.SendOption) (string, error) {
	return c.core.SendBatch(ctx, signalBatch, tag, source, opts...)
}

// SetACKHandler registers a callback invoked when the server acknowledges a batch.
func (c *Client) SetACKHandler(h func(chunkID, ackMode string)) {
	c.core.SetACKHandler(h)
}

// SetRedirectHandler registers a callback invoked when the server sends a
// TypeRedirect frame (S→C cluster redirect to the HA leader).
func (c *Client) SetRedirectHandler(h func(payload []byte)) {
	c.core.SetRedirectHandler(h)
}

// Close sends a CLOSE frame, drains pending ACKs, and shuts down.
func (c *Client) Close() error {
	return c.core.Close()
}

func (c *Client) State() core.State {
	return c.core.State()
}

func (c *Client) SessionID() string {
	return c.core.SessionID()
}
