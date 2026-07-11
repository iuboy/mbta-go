// Package protocol 实现 MBTA server/client 的共享协议核心。
package protocol

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// ClientTransport 抽象客户端侧的传输差异（v1 QUIC 多流 vs ntls 单 TCP 连接）。
//
// 与服务端 Transport 接口（RecvControlFrame/RecvDataFrame 双读路径）不同，
// 客户端只有一个读路径（readControlLoop 收 ACK/NACK/WINDOW/THROTTLE/PING/CLOSE），
// 故 ReadFrame 提供单一阻塞读原语。写侧用 ctx 区分 control（不超时）与 data（受 ctx 约束）。
//
// 各 binding 负责内部的写串行化：
//   - v1: control 帧走 controlMu+controlStr，data 帧走 picker+per-stream mu；
//   - ntls: 所有帧走 writeMu+单 conn。
type ClientTransport interface {
	// ReadFrame 阻塞读下一帧（HELLO_ACK / AUTH_OK / ACK / NACK / WINDOW / THROTTLE / PING / CLOSE）。
	ReadFrame() (core.Frame, error)

	// WriteFrame 写一帧。ctx 仅约束 data 通道（ChannelData）的写超时；
	// control 通道（ChannelControl）调用方通常传 context.Background()。
	// channel 区分控制/数据，binding 内部按 channel 路由到不同写路径。
	WriteFrame(ctx context.Context, typ uint8, flags, channel uint8, payload []byte) error

	// CloseConn 关闭底层连接。v1: CloseWithError(0,...)；ntls: conn.Close()。
	CloseConn() error
}

// CoreClientConfig 是 CoreClient 的公共配置（传输无关字段）。
// 各 binding 的 ClientConfig 内嵌或包装此结构，附加传输专属字段。
type CoreClientConfig struct {
	AgentID      string
	Hostname     string
	Token        string
	Capabilities []string // 客户端能力（HELLO 携带，与服务端协商）

	// DefaultCodec / DefaultCipherSuite / DefaultCompression：协商前（或 c.negotiated==nil
	// 兜底路径）使用的算法。由各 binding 在 NewClient 时注入，跟随 binding 合规语境
	// （v1 = intl/proto/zstd，ntls = gm/proto/zstd），避免协议核心硬编码 binding 相关默认
	// 值——这是「实现中立」原则的落地（spec §8.3：默认套件跟随传输 binding）。
	DefaultCodec       corepb.Codec       // 通常 CODEC_CODEC_PROTO
	DefaultCipherSuite corepb.CipherSuite // intl / gm，跟随 binding
	DefaultCompression corepb.Compression // 通常 COMPRESSION_ZSTD

	// Metrics 可选的可观测性接口（nil 回退 NoOpMetrics）。客户端侧指标
	// （BatchesSent/BatchLatency）由此上报。
	Metrics core.Metrics
}

// ackTask 是排队等待执行的用户 ACK/NACK 回调。
type ackTask struct {
	chunkID string
	mode    string
}

// ackQueueSize 限定 ACK 回调队列容量。满时 dispatchACK 丢弃回调（记录日志）
// 而非阻塞 control loop。
const ackQueueSize = 1024

// CoreClient 收敛 v1/ntls 客户端共享的协议逻辑：状态机、ACK worker、
// ackReaper、drain、heartbeat、inflight/window/throttle/pendingAcks、生命周期管理。
//
// 与服务端 CoreHandler 对称——两者都仅依赖 Transport 接口，不感知具体传输。
// v1.Client / ntls.Client 持有 *CoreClient 并提供 ClientTransport 实现，
// 自身仅保留传输适配（Dial/openStreams/writeMu/controlStr 等）。
//
// 可靠投递语义：CoreClient 仅在内存追踪已发送未 ACK 的 batch（pendingAcks/inflight）。
// 进程崩溃/重连后未 ACK 的 batch 会丢失——持久化与重发由调用方负责。
type CoreClient struct {
	tr      ClientTransport
	cfg     CoreClientConfig
	metrics core.Metrics
	sm      *core.StateMachine

	// 协商结果与密钥（握手后填充）
	negotiated     *core.NegotiateResult
	keys           *core.SessionKeys
	sessionID      []byte
	challengeNonce []byte    // server challenge from HELLO_ACK
	expiresAt      time.Time // 会话过期时间，从 AUTH_OK 获取

	// 发送追踪
	seq      *core.SeqGenerator
	inflight *core.Inflight
	window   *core.Window
	throttle *core.ThrottleState

	// sendMu 保护「window 检查 + 取 seq/chunkID + inflight/pending 登记」，
	// 保证并发 SendBatch 不会同时通过窗口后超限。重的 CPU 工作（marshal/Build/写）在锁外。
	sendMu sync.Mutex

	// pendingAcks 追踪 chunk_id -> batch info 用于 ACK 关联。
	pendingAcks  sync.Map     // chunkID -> *pendingBatch
	pendingCount atomic.Int64 // 与 pendingAcks 同步增减，notifyDrainIfEmpty 免 Range 扫描

	// ackHandler 在收到 ACK 时回调，接收 (chunkID, ackMode)。
	ackHandler atomic.Pointer[func(chunkID, ackMode string)]

	// redirectHandler 在收到 TypeRedirect 时回调，接收原始 payload（应用层解码）。
	redirectHandler atomic.Pointer[func(payload []byte)]

	ackTimeout        time.Duration // max time to wait for ACK (default 5 min)
	heartbeatInterval time.Duration // PING 发送间隔（从 HELLO_ACK 获取，默认 30s）

	// lifecycleCtx 驱动所有后台 goroutine，独立于 Connect 调用方 ctx，
	// 避免 WithTimeout + defer cancel 级联停掉后台 goroutine。
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	// done channel 在对应 goroutine 退出时关闭，Close() 等待它们以确保无 goroutine 跨越 Close。
	ackDone       chan struct{}
	reaperDone    chan struct{}
	heartbeatDone chan struct{}

	// ackQueue 串行化用户 ACK/NACK 回调到一个 worker，慢回调不阻塞 readControlLoop。
	ackQueue      chan ackTask
	ackWorkerDone chan struct{}

	drainCh   chan struct{} // drain 时 pendingAcks 归零通知
	closeOnce sync.Once     // 使 Close 幂等
	connErr   error         // closeOnce.Do 内捕获，作为 Close() 返回值

	// 可注入钩子（binding 提供）：
	onAuthed        func(context.Context) // AUTH_OK 后调用（v1: SetAuthed）；nil=no-op
	heartbeatLoopFn func(context.Context) // 心跳循环（PING 写依赖 transport）；nil=不启心跳
	readControlFn   func(context.Context) // readControlLoop（control 帧分发依赖 binding handle*）
}

// pendingBatch 记录一个待 ACK 的 batch 元信息。
type pendingBatch struct {
	Seq      uint64
	Events   int
	Bytes    int64
	SentAt   time.Time
	Deadline time.Time // 此 batch 若无 ACK 的超时时刻
}

// NewCoreClient 创建共享协议核心。tr 由各 binding 提供。
func NewCoreClient(tr ClientTransport, cfg CoreClientConfig) *CoreClient {
	// Metrics 为 nil（含 typed-nil，如 (*MBTAMetrics)(nil) 赋给接口）时回退到
	// NoOpMetrics，客户端无需逐处 nil 检查。与 NewCoreHandler 对称。
	if isNilMetrics(cfg.Metrics) {
		cfg.Metrics = core.NoOpMetrics{}
	}
	return &CoreClient{
		tr:         tr,
		cfg:        cfg,
		metrics:    cfg.Metrics,
		sm:         core.NewStateMachine(),
		seq:        core.NewSeqGenerator(),
		inflight:   &core.Inflight{},
		window:     core.NewWindow(100, 10000, 16*1024*1024),
		throttle:   &core.ThrottleState{},
		ackTimeout: 5 * time.Minute,
		drainCh:    make(chan struct{}, 1),
	}
}

// waitGoroutines 等待所有后台 goroutine 退出或超时（5s），防止 Close 无限挂起。
func (c *CoreClient) waitGoroutines() {
	const waitTimeout = 5 * time.Second
	deadline := time.NewTimer(waitTimeout)
	defer deadline.Stop()
	for _, ch := range []<-chan struct{}{c.ackDone, c.reaperDone, c.heartbeatDone, c.ackWorkerDone} {
		if ch == nil {
			continue // 防御：未初始化的 channel 跳过（从 nil channel 接收会永久阻塞）
		}
		select {
		case <-ch:
		case <-deadline.C:
			slog.Warn("goroutine wait timeout, proceeding with close")
			return
		}
	}
}

// Close sends a CLOSE frame, drains pending ACKs, and shuts down.
// Idempotent: subsequent calls return the error from the first close.
func (c *CoreClient) Close() error {
	c.closeOnce.Do(c.close)
	return c.connErr
}

// close 执行实际关闭（仅运行一次）。
func (c *CoreClient) close() {
	// 1. 发 CLOSE 帧（goroutine 仍存活，使 server 得知客户端关闭）。
	closeMsg := &corepb.CloseMessage{Code: "shutdown", Reason: "client closing"}
	if payload, err := core.Encode(closeMsg); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		// c.tr 可能为 nil（Connect 未完成或未调用即 Close），与下方 CloseConn 的 nil 检查对称。
		if c.tr != nil {
			if err := c.tr.WriteFrame(ctx, core.TypeClose, core.FlagControl, core.ChannelControl, payload); err != nil {
				slog.Warn("write close frame", "error", err)
			}
		}
		cancel()
	}

	// 2. 进入 Draining。
	if err := c.sm.Transition(core.StateDraining); err != nil {
		slog.Debug("drain transition skipped", "error", err)
	}

	// 3. 等待 drain。readControlLoop 仍运行，handleAck 持续触发 notifyDrainIfEmpty。
	if c.sm.State() == core.StateDraining {
		drainDeadline := time.NewTimer(core.DefaultDrainTimeout)
		for c.sm.State() == core.StateDraining {
			select {
			case <-drainDeadline.C:
				slog.Warn("drain timeout exceeded, force-closing",
					"pending", c.countPendingAcks())
				_ = c.sm.Transition(core.StateClosed)
			case <-c.drainCh:
				_ = c.sm.Transition(core.StateClosed)
			}
		}
		drainDeadline.Stop()
	}

	// 4. 取消所有后台 goroutine。
	if c.lifecycleCancel != nil {
		c.lifecycleCancel()
	}
	// 5. 关闭连接（transport 负责）。
	if c.tr != nil {
		c.connErr = c.tr.CloseConn()
	}
	// 6. 等待 goroutine 实际退出。
	c.waitGoroutines()

	// 7. 清理 pending ACKs 释放引用。
	c.pendingAcks.Range(func(key, _ any) bool {
		c.pendingAcks.Delete(key)
		return true
	})
	c.pendingCount.Store(0)

	// 8. 清零密钥（sendMu 保证无并发 SendBatch 读取）。
	c.sendMu.Lock()
	c.inflight.Reset()
	if c.keys != nil {
		c.keys.Zero()
		c.keys = nil
	}
	c.sendMu.Unlock()
}

// State 返回当前连接状态（供外部查询）。
func (c *CoreClient) State() core.State {
	return c.sm.State()
}

// SessionID 返回握手后分配的会话 ID（十六进制）。
func (c *CoreClient) SessionID() string {
	if len(c.sessionID) == 0 {
		return ""
	}
	if cid, err := core.ChunkIDFromBytes(c.sessionID); err == nil {
		return cid.String()
	}
	return ""
}

// StartLifecycle 初始化后台 goroutine 上下文与 done channel，启动 4 个 goroutine。
// 各 binding 的 Connect 在握手成功后调用此方法。readControlFn / heartbeatLoopFn
// 由 binding 通过 SetReadControlLoop / SetHeartbeatLoop 注入（control 帧分发与
// PING 写依赖 binding 的 handle* / transport）。
func (c *CoreClient) StartLifecycle() {
	c.lifecycleCtx, c.lifecycleCancel = context.WithCancel(context.Background())
	c.ackDone = make(chan struct{})
	c.reaperDone = make(chan struct{})
	c.heartbeatDone = make(chan struct{})
	c.ackQueue = make(chan ackTask, ackQueueSize)
	c.ackWorkerDone = make(chan struct{})

	if c.readControlFn != nil {
		fn := c.readControlFn
		go func() { defer close(c.ackDone); fn(c.lifecycleCtx) }()
	} else {
		close(c.ackDone) // 无 hook：立即关闭 done channel，避免 waitGoroutines 等到超时
	}
	if c.heartbeatLoopFn != nil {
		fn := c.heartbeatLoopFn
		go func() { defer close(c.heartbeatDone); fn(c.lifecycleCtx) }()
	} else {
		close(c.heartbeatDone) // 无 hook：同上
	}
	go func() { defer close(c.reaperDone); c.ackReaper(c.lifecycleCtx) }()
	go func() { defer close(c.ackWorkerDone); c.runACKWorker(c.lifecycleCtx) }()
}

// SetHeartbeatLoop 注入心跳循环实现（binding 提供，PING 写走 transport）。
// 必须在 StartLifecycle 前调用。
func (c *CoreClient) SetHeartbeatLoop(fn func(context.Context)) {
	c.heartbeatLoopFn = fn
}

// SetReadControlLoop 注入 control 帧读循环（binding 提供 handleAck/Nack 等）。
// 必须在 StartLifecycle 前调用。
func (c *CoreClient) SetReadControlLoop(fn func(context.Context)) {
	c.readControlFn = fn
}

// SetOnAuthed 注入 AUTH_OK 后置钩子（v1 binding 用于 SetAuthed(true)）。
func (c *CoreClient) SetOnAuthed(fn func(context.Context)) {
	c.onAuthed = fn
}

// --- binding 在 Connect 中调用的状态设置方法 ---

// SetTransport 设置/替换传输实现。Connect 拨号成功后由 binding 调用。
// 线程安全约束：仅在 Connect 的单线程路径调用，不可与 Close 并发。
func (c *CoreClient) SetTransport(tr ClientTransport) {
	c.tr = tr
}

// SetSessionID 设置握手后分配的会话 ID。
func (c *CoreClient) SetSessionID(id []byte) {
	c.sessionID = id
}

// UpdateWindow 更新流控窗口（从 HELLO_ACK 的 initial_window）。
func (c *CoreClient) UpdateWindow(batches, events int, bytes int64) {
	c.window.Update(batches, events, bytes)
}

// SetHeartbeatInterval 设置 PING 间隔（从 HELLO_ACK 或默认 30s）。
func (c *CoreClient) SetHeartbeatInterval(d time.Duration) {
	c.heartbeatInterval = d
}

// SmTransition 暴露状态机转换给 binding（Connect 流程需要）。
func (c *CoreClient) SmTransition(state core.State) error {
	return c.sm.Transition(state)
}

// SmTransitionConnecting 是 Connecting 转换的便捷方法。
func (c *CoreClient) SmTransitionConnecting() error {
	return c.sm.Transition(core.StateConnecting)
}
