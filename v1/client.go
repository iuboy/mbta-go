package v1

import (
	"context"
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
	Transport    QUICClientConfig  // QUIC 连接配置
	AgentID      string            // agent ID
	Token        string            // 认证 token（不上 wire，仅参与 token_proof HMAC）
	Meta         map[string]string // HELLO 元数据（hostname/os/agent_version 等，可选）
	Capabilities []string          // 客户端能力（与服务端 policy 协商取交集）
	// Profile 是应用层密码组合。0 = 默认 PROFILE_INTL（v1 binding 即国际套件）。
	Profile corepb.Profile

	Metrics      core.Metrics  // 可选：客户端可观测性指标（nil=NoOp）
	DrainTimeout time.Duration // Close 时等待未终态 batch 的上限。0=默认(30s)
}

// Client is an MBTA agent that connects to a server and sends event batches.
//
// Client 是薄包装：协议逻辑（状态机/握手/RESULT/drain/heartbeat）全部委托给
// protocol.CoreClient；传输帧 I/O 下沉到 v1ClientTransport（QUIC 多流适配）。
// 自身只保留 QUIC 连接引用，用于「已连接守卫」与 Connect 失败兜底关闭。
//
// 实例单次使用：底层 CoreClient 的 lifecycle 由 closeOnce 保证一次性终结，
// Close 后或握手失败清理后不可复用——重连须新建 Client 实例。
// 例外：Connect 在 dial 阶段失败（网络不可达等）时状态机回退 Idle，
// 同实例重试 Connect 可用。
//
// 可靠投递语义：credit 账本仅在内存追踪已发送未终态的 batch。进程崩溃/重连后
// 未终态的 batch 会丢失——持久化与重发由调用方负责。
type Client struct {
	core *protocol.CoreClient // 共享协议核心
	cfg  ClientConfig         // v1 专属配置（Transport，供 Dial 用）
	conn *Conn                // QUIC 连接（已连接守卫 + Connect 失败兜底关闭）
	mu   sync.Mutex           // 保护 conn 字段的读写（Connect 设置 / 失败清理）
}

// v1ClientTransport 实现 protocol.ClientTransport，封装 QUIC 多流传输。
//
// 帧路由按 type 高位（通道域）：control 帧（HELLO/RESULT/CREDIT/CLOSE 等）走
// controlMu + controlStr（单一控制流）；data 帧（BATCH/DGRAM）走 picker.Pick +
// per-stream mu（多流并发，绕过队头阻塞）。
type v1ClientTransport struct {
	frameLimit atomic.Uint64 // 协商帧上限（0=默认 16MB）
	conn       *Conn
	controlStr *quic.Stream
	picker     atomic.Pointer[StreamPicker] // 原子读写，消除与 postAuth 写的 data race
	controlMu  sync.Mutex                   // 串行化 control stream 写
}

// frameLimit 原子存储协商帧上限（0=默认）。HELLO_ACK 后经 FrameLimitSetter 注入。
func (t *v1ClientTransport) SetFrameLimit(maxBytes uint64) { t.frameLimit.Store(maxBytes) }

func (t *v1ClientTransport) ReadFrame(ctx context.Context) (core.Frame, error) {
	fl := t.frameLimit.Load()
	if fl == 0 {
		return core.ReadFrameCtx(ctx, t.controlStr)
	}
	return core.ReadFrameCtxLimit(ctx, t.controlStr, core.FrameLimits{MaxFrameBytes: fl})
}

// 读超时统一用 core.DefaultReadTimeout。

// MarkAuthed 实现 protocol.AuthMarker：握手完成后协议层调用，开放 data stream
// 门禁（Conn.OpenDataStream 的 authed 检查）。时序上先于 postAuth 的 openDataStream，
// 门禁自然放行——替代旧 SetOnAuthed 回调面。
func (t *v1ClientTransport) MarkAuthed() { t.conn.SetAuthed(true) }

// WriteFrame 按通道域路由：control（type 高位=0）走 controlStr（controlMu 串行 +
// 写超时），data（type 高位=1）走 picker 选流 + per-stream ctx 感知写。
func (t *v1ClientTransport) WriteFrame(ctx context.Context, typ uint8, payload []byte) error {
	if core.IsControlType(typ) {
		t.controlMu.Lock()
		defer t.controlMu.Unlock()
		// 与 data 路径的 writeFrameCtx 对称：绑 ctx/deadline，无 deadline 时设
		// DefaultWriteTimeout 上限。否则对端停止读 control stream 且 QUIC 流控
		// 窗口耗尽时，CLOSE 等控制帧写会永久阻塞（CoreClient.close 构造的 5s 超时
		// ctx 在此路径被忽略，Close 卡死在第一步）。
		if err := ctx.Err(); err != nil {
			return err
		}
		dl, ok := ctx.Deadline()
		if !ok {
			dl = time.Now().Add(core.DefaultWriteTimeout)
		}
		if err := t.controlStr.SetWriteDeadline(dl); err != nil {
			return core.WrapError(core.ErrCodeStream, "set write deadline", err)
		}
		defer func() { _ = t.controlStr.SetWriteDeadline(time.Time{}) }()
		return core.Write(t.controlStr, typ, 0, payload)
	}
	// data 通道：picker 选流，ctx 感知写。
	// picker 经 atomic 读取（postAuth 在 c.mu 下用 atomic.Pointer.Store 写）。
	// nil guard 防 postAuth 完成前进入 data 路径的 nil 解引用 panic。
	pickerPtr := t.picker.Load()
	if pickerPtr == nil {
		return core.NewError(core.ErrCodeSession, "data stream picker not initialized (auth incomplete?)")
	}
	ds, err := (*pickerPtr).Pick()
	if err != nil {
		return core.WrapError(core.ErrCodeBatch, "pick stream", err)
	}
	if w, ok := ds.(*quicStreamWrapper); ok {
		return w.writeFrameCtx(ctx, typ, payload)
	}
	return core.Write(ds, typ, 0, payload)
}

func (t *v1ClientTransport) CloseConn() error {
	return t.conn.Close()
}

// SupportsDatagram 报告 QUIC 连接实际是否启用 DATAGRAM 扩展（本端+对端；
// 需 Dial 侧 quic.Config.EnableDatagrams=true）。CoreClient.SendDatagram 据此
// 决定走不可靠通道或降级可靠 BATCH。
func (t *v1ClientTransport) SupportsDatagram() bool {
	if t.conn == nil || t.conn.QC == nil {
		return false
	}
	// SupportsDatagrams 是 {Local, Remote} 结构体，本端 + 对端都必须启用，
	// 与服务端 quicTransport.SupportsDatagram 同判。
	ds := t.conn.QC.ConnectionState().SupportsDatagrams
	return ds.Local && ds.Remote
}

// SendDatagram 走 QUIC DATAGRAM 不可靠通道（payload 为完整 Envelope 编码，
// 帧类型语义 TypeDgram 由 Envelope AD 承载，非帧头承载）。
func (t *v1ClientTransport) SendDatagram(ctx context.Context, payload []byte) error {
	if t.conn == nil || t.conn.QC == nil {
		return core.NewError(core.ErrCodeStream, "datagram before connection established")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.conn.QC.SendDatagram(payload); err != nil {
		return core.WrapError(core.ErrCodeStream, "send datagram", err)
	}
	return nil
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
func (w *quicStreamWrapper) writeFrameCtx(ctx context.Context, typ uint8, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	// ctx 无 deadline 时设默认上限，避免 QUIC 流控背压下 Write 永久阻塞（goroutine 泄漏）。
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(core.DefaultWriteTimeout)
	}
	if err := w.stream.SetWriteDeadline(dl); err != nil {
		return core.WrapError(core.ErrCodeStream, "set write deadline", err)
	}
	defer func() { _ = w.stream.SetWriteDeadline(time.Time{}) }()
	return core.Write(w, typ, 0, payload)
}

// NewClient creates a new MBTA client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if err := core.ValidateHostPort(cfg.Transport.Server); err != nil {
		return nil, core.WrapError(core.ErrCodeConfig, "Transport.Server", err)
	}
	// v1 binding 默认国际 profile（X25519+HKDF-SHA256+AES-256-GCM）。
	if cfg.Profile == corepb.Profile_PROFILE_UNSPECIFIED {
		cfg.Profile = corepb.Profile_PROFILE_INTL
	}
	// 公共校验 + CoreClient 构造委托 binding.NewClientCore（v1/ntls 共享）。
	cc, err := binding.NewClientCore(binding.ClientCoreConfig{
		AgentID:      cfg.AgentID,
		Meta:         cfg.Meta,
		Token:        cfg.Token,
		Capabilities: cfg.Capabilities,
		Profile:      cfg.Profile,
		Metrics:      cfg.Metrics,
		DrainTimeout: cfg.DrainTimeout,
	})
	if err != nil {
		return nil, err
	}
	return &Client{core: cc, cfg: cfg}, nil
}

// Connect dials the server and completes the HELLO handshake (1-RTT).
//
// ctx 仅控制握手阶段（Dial、开 stream、HELLO）的超时与取消。握手成功后，
// 后台 goroutine 运行在独立的 lifecycle ctx 上，不随 ctx 取消而退出；client 生命周期
// 由 Close() 终结。
func (c *Client) Connect(ctx context.Context) error {
	// 防重复 Connect：已连接/连接中时拒绝，避免旧 QUIC 连接被覆盖（fd + 连接泄漏）。
	// Client 单次使用：Close 后（c.conn 不清，状态机已 CLOSED）或握手失败清理后，
	// 重连须新建实例——按状态区分报错，避免对已关闭实例报误导性的 "already connected"。
	// 例外：dial 阶段失败已回退 Idle，同实例重试放行（见 binding.Handshake）。
	c.mu.Lock()
	existing := c.conn
	c.mu.Unlock()
	if existing != nil || c.core.IsClosed() {
		if c.core.IsClosed() {
			return core.NewError(core.ErrCodeSession,
				"client closed or previous connect failed; Client is single-use, create a new instance")
		}
		return core.NewError(core.ErrCodeSession, "already connected")
	}

	tr := &v1ClientTransport{}
	// conn 由 dial 设置，闭包内共享；connSet 标记本协程是否建立连接，并发 Connect 时失败方只关自己的连接。
	var conn *Conn
	var connSet bool
	err := binding.Handshake(ctx, c.core,
		// dial: 建立 QUIC 连接
		func(ctx context.Context) error {
			dialed, err := Dial(ctx, c.cfg.Transport)
			if err != nil {
				return err // Dial 已 wrap ErrCodeTransport + "dial QUIC"
			}
			// dial 回调内二次检查：消除入口 c.conn==nil 检查与赋值之间的 TOCTOU 窗口。
			c.mu.Lock()
			if c.conn != nil {
				// 另一个并发 Connect 已设置连接，关闭当前 dialed 避免泄漏。
				c.mu.Unlock()
				_ = dialed.Close()
				return core.NewError(core.ErrCodeSession, "already connected (race)")
			}
			c.conn = dialed
			conn = dialed
			connSet = true
			c.mu.Unlock()
			return nil
		},
		// setupTransport: 开 control stream 并注入 transport（Handshake 前完成）
		func(ctx context.Context) error {
			ctrlStr, err := conn.OpenControlStream(ctx)
			if err != nil {
				return core.WrapError(core.ErrCodeStream, "open control stream", err)
			}
			tr.conn = conn
			tr.controlStr = ctrlStr
			c.core.SetTransport(tr)
			return nil
		},
		// postAuth: StartLifecycle 前执行（成功后才启动 lifecycle goroutine，
		// 防 postAuth 失败时已启动的 goroutine 泄漏），打开 data stream。
		// 此时握手已完成，MarkAuthed 已放行 Conn.OpenDataStream 的门禁。
		func(ctx context.Context) error {
			picker, err := openDataStream(ctx, conn)
			if err != nil {
				return err
			}
			tr.picker.Store(&picker)
			return nil
		},
	)
	// 握手失败清理：binding.Handshake 内部已调 cc.Close()（关 transport + 取消 lifecycle
	// + 等 goroutine），但 cc.Close 只关 QUIC conn 本身，不清外层 v1.Client 的 c.conn 引用。
	// 此处清理 c.conn（置 nil 防 use-after-close）并兜底关 conn（幂等，conn 可能已被 cc.Close 关闭）。
	// v1 client transport 自身不开 goroutine（lifecycle goroutine 由 StartLifecycle 启动，
	// 握手失败时未启动），故无 transport goroutine 泄漏风险。
	if err != nil {
		c.mu.Lock()
		if connSet {
			_ = conn.Close() // 幂等（含 UDP socket 回收）
			c.conn = nil
		}
		c.mu.Unlock()
	}
	return err
}

// openDataStream 打开单条数据流并构造 StreamPicker。
func openDataStream(ctx context.Context, conn *Conn) (StreamPicker, error) {
	ds, err := conn.OpenDataStream(ctx)
	if err != nil {
		return nil, core.WrapError(core.ErrCodeStream, "open data stream", err)
	}
	return NewSingleStream(&quicStreamWrapper{stream: ds, idx: 0}), nil
}

// SendBatch sends a SignalBatch through the MBTA protocol, 返回分配的 seq。
//
// opts 携带 per-call 发送选项（如 core.WithTraceContext），透传给协议核心。
func (c *Client) SendBatch(ctx context.Context, signalBatch *core.SignalBatch, opts ...core.SendOption) (uint64, error) {
	return c.core.SendBatch(ctx, signalBatch, opts...)
}

// SendDatagram 以 QUIC DATAGRAM 不可靠通道发送（at-most-once，豁免 credit）。
// 协商未含 datagram 能力或连接未启用 DATAGRAM 扩展时，降级为可靠 SendBatch
// 路径（消耗 credit、有 RESULT 反馈）——语义与直接调用 SendBatch 一致。
func (c *Client) SendDatagram(ctx context.Context, signalBatch *core.SignalBatch, opts ...core.SendOption) (uint64, error) {
	return c.core.SendDatagram(ctx, signalBatch, opts...)
}

// SetResultHandler 注册结果回调：服务端 RESULT（accepted/durable/rejected/released）
// 终态时调用，参数为 (seq, level, code, correlation)。
func (c *Client) SetResultHandler(h func(seq uint64, level string, code uint32, correlation string)) {
	c.core.SetResultHandler(h)
}

// SetRedirectHandler registers a callback invoked when the server sends a
// REDIRECT frame (S→C cluster redirect to the HA leader).
func (c *Client) SetRedirectHandler(h func(context.Context, []byte)) {
	c.core.SetRedirectHandler(h)
}

// Close sends a CLOSE frame, drains pending results, and shuts down.
func (c *Client) Close() error {
	return c.core.Close()
}

func (c *Client) State() core.State {
	return c.core.State()
}

func (c *Client) SessionID() string {
	return c.core.SessionID()
}

// SelectedCapabilities 返回握手协商选定的能力集（握手前为 nil）。
func (c *Client) SelectedCapabilities() []string {
	return c.core.SelectedCapabilities()
}
