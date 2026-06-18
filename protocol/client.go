// Package protocol 实现 MBTA server/client 的共享协议核心。
//
// 此文件为 CoreClient Phase 1 骨架。部分字段/方法（negotiated/challengeNonce/
// expiresAt/heartbeatInterval/dispatchACK 等）在 v1/ntls Client 迁移到 CoreClient
// 前（Phase 2）暂未被调用——nolint:unused 抑制期间的告警。
//
//nolint:unused
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
	tr  ClientTransport
	cfg CoreClientConfig
	sm  *core.StateMachine

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
	onAuthed        func(context.Context)         // AUTH_OK 后调用（v1: SetAuthed）；nil=no-op
	heartbeatLoopFn func(context.Context)         // 心跳循环（PING 写依赖 transport）；nil=不启心跳
	readControlFn   func(context.Context)         // readControlLoop（control 帧分发依赖 binding handle*）
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
	return &CoreClient{
		tr:        tr,
		cfg:       cfg,
		sm:        core.NewStateMachine(),
		seq:       core.NewSeqGenerator(),
		inflight:  &core.Inflight{},
		window:    core.NewWindow(100, 10000, 16*1024*1024),
		throttle:  &core.ThrottleState{},
		ackTimeout: 5 * time.Minute,
		drainCh:   make(chan struct{}, 1),
	}
}

// SetACKHandler registers a callback invoked when the server acknowledges a batch.
func (c *CoreClient) SetACKHandler(h func(chunkID, ackMode string)) {
	c.ackHandler.Store(&h)
}

func (c *CoreClient) loadACKHandler() func(chunkID, ackMode string) {
	if p := c.ackHandler.Load(); p != nil {
		return *p
	}
	return nil
}

// dispatchACK 入队用户 ACK/NACK 回调异步执行。永不阻塞：队列满时丢弃回调（warn）。
// 仅回调通知丢失——pendingAcks/inflight 在 handleAck/handleNack 同步更新，
// ackReaper 仍会回收未 ACK batch 的 inflight。
func (c *CoreClient) dispatchACK(chunkID, mode string) {
	select {
	case c.ackQueue <- ackTask{chunkID: chunkID, mode: mode}:
	default:
		slog.Warn("ack callback queue full, dropping callback",
			"chunk", chunkID, "mode", mode)
	}
}

// runACKWorker 消费 ackTask 并在单 goroutine 上调用已注册 handler，保持 ACK 到达顺序。
// 关闭时先排空队列，使已入队回调仍能投递。
func (c *CoreClient) runACKWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case t := <-c.ackQueue:
					c.invokeACKHandler(t)
				default:
					return
				}
			}
		case t := <-c.ackQueue:
			c.invokeACKHandler(t)
		}
	}
}

// invokeACKHandler 每次新鲜加载 handler，使 SetACKHandler 更新立即生效。
func (c *CoreClient) invokeACKHandler(t ackTask) {
	if h := c.loadACKHandler(); h != nil {
		h(t.chunkID, t.mode)
	}
}

// ackReaper 周期回收超时未 ACK 的 batch 的 inflight 配额（30s ticker）。
// 防止对端永不 ACK 时 inflight 永久占用窗口。
func (c *CoreClient) ackReaper(ctx context.Context) {
	const reaperInterval = 30 * time.Second
	ticker := time.NewTicker(reaperInterval)
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
				if now.After(pb.Deadline) {
					c.pendingAcks.Delete(key)
					c.pendingCount.Add(-1)
					c.inflight.Remove(pb.Events, pb.Bytes)
					slog.Warn("reaped expired unacked batch",
						"chunk", key, "seq", pb.Seq, "age", now.Sub(pb.SentAt).Round(time.Second))
					c.notifyDrainIfEmpty()
				}
				return true
			})
		}
	}
}

// notifyDrainIfEmpty 在 drain 状态且 pendingAcks 归零时通知 close 的 drain 循环。
// 非阻塞：drainCh 容量 1，重复通知无妨。
func (c *CoreClient) notifyDrainIfEmpty() {
	if c.pendingCount.Load() == 0 {
		select {
		case c.drainCh <- struct{}{}:
		default:
		}
	}
}

// countPendingAcks 返回当前待 ACK 的 batch 数（用于 close 日志）。
func (c *CoreClient) countPendingAcks() int {
	return int(c.pendingCount.Load())
}

// waitGoroutines 等待所有后台 goroutine 退出或超时（5s），防止 Close 无限挂起。
func (c *CoreClient) waitGoroutines() {
	const waitTimeout = 5 * time.Second
	deadline := time.NewTimer(waitTimeout)
	defer deadline.Stop()
	for _, ch := range []<-chan struct{}{c.ackDone, c.reaperDone, c.heartbeatDone, c.ackWorkerDone} {
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
		if err := c.tr.WriteFrame(ctx, core.TypeClose, core.FlagControl, core.ChannelControl, payload); err != nil {
			slog.Warn("write close frame", "error", err)
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
		for i := range c.keys.HMACKey {
			c.keys.HMACKey[i] = 0
		}
		for i := range c.keys.AEADKey {
			c.keys.AEADKey[i] = 0
		}
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
	}
	if c.heartbeatLoopFn != nil {
		fn := c.heartbeatLoopFn
		go func() { defer close(c.heartbeatDone); fn(c.lifecycleCtx) }()
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
