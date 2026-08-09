package protocol

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// 常量（core spec §9.5 limits；与 v1/handler 对齐）。
const (
	maxConcurrentQuicDataFrames       = 64
	maxConcurrentTCPBatches           = 8
	maxAuthAttempts                   = 3
	heartbeatIntervalSec              = 30
	maxFramePayloadBytes              = 16 * 1024 * 1024
	maxBatchBytes                     = 8 * 1024 * 1024
	maxEventBytes                     = 256 * 1024
	maxBatchEvents                    = 10000
	windowMaxBatches                  = 100
	windowMaxEvents                   = 10000
	windowMaxBytes              int64 = 16 * 1024 * 1024
	throttleRetryMs                   = 1000
	challengeNonceLen                 = 16
	// maxDrainTimeout 限制客户端 close_timeout_ms 的上限，防恶意客户端发 MaxUint32
	// 致 handler goroutine 阻塞 ~49 天（内存/goroutine DoS）。
	maxDrainTimeout = 30 * time.Second
	// defaultSinkQueueSize 是普通 EventSink 异步投递队列的默认容量。
	// 满 → 发 THROTTLE 让客户端重试，是 sink 处理跟不上时的精准背压信号。
	defaultSinkQueueSize = 256
	// defaultSinkWorkers 是异步投递 worker pool 的默认 worker 数。
	// runtime.NumCPU() 在多数场景平衡吞吐与 goroutine 开销。
	defaultSinkWorkers = 0 // 0 = 运行时按 runtime.NumCPU() 取
)

// envelope 算法一致性复核失败的 wire NACK code 定义在 core.ErrCodeEnvelopeAlgoMismatch
// （Code 字段 = "envelope_algo_mismatch"），不再在此重复定义。

// HandlerConfig 是 CoreHandler 的配置（传输无关）。
type HandlerConfig struct {
	Auth            core.TokenValidator
	Policy          core.Policy
	Sink            core.EventSink
	Metrics         core.Metrics // nil 时回退到 NoOpMetrics（见 NewCoreClient）
	ServerID        string
	SessionStore    *core.SessionStore   // 0-RTT resumption（可选，nil = 不支持 early_data）
	RedirectChecker core.RedirectChecker // HA：AUTH_OK 后检查角色，非 leader 发 TypeRedirect（可选，nil=禁用）
	OnSession       core.OnSession       // 会话生命周期回调（可选，nil=禁用）：AUTH_OK 后 CONNECTED、连接断开 DISCONNECTED
	// SinkQueueSize 是普通 EventSink 的异步投递队列容量（fire-and-forget）。
	// 0 = 默认 256；负 = 禁用异步（同步阻塞调用，仅测试用）。满则发 THROTTLE 背压。
	// 仅对普通 EventSink 生效（DurableEventSink/RawEventSink 仍同步，待阶段 3 改造）。
	SinkQueueSize int
}

// CoreHandler 是 server 端协议状态机核心，仅依赖 Transport 接口，
// 不感知 quic.Stream/net.Conn（core spec §10.2）。
// 吸收 v1/handler.go 与 ntls/handler.go 的全部共享协议逻辑。
type CoreHandler struct {
	tr     Transport
	config HandlerConfig

	sm         *core.ServerMachine
	negotiated atomic.Pointer[core.NegotiateResult] // controlLoop(handleHello) 写 / dataLoop(processBatch) 读，原子化避免数据竞争
	keys       atomic.Pointer[core.SessionKeys]     // 0-RTT：controlLoop(handleAuth) 与 dataLoop(processBatch) 并发读写
	replay     *core.ReplayCache
	window     *core.Window
	inflight   *core.Inflight

	// 握手字段：controlLoop（handleHello/handleAuth）写，dataLoop/processBatch（0-RTT）读。
	// 用 handshakeMu 保护，避免 0-RTT 场景下 agentID/sessionID 的数据竞争。
	agentID   string
	sessionID []byte
	// helloMeta 保存 HELLO 帧中除 agentID 外的身份字段，供 OnSession CONNECTED 回调读取。
	// 与 agentID/sessionID 一样在 handleHello 中写入，handshakeMu 保护。
	hostname       string
	instanceID     string
	agentVersion   string
	os             string
	challengeNonce []byte
	authAttempts   int
	handshakeMu    sync.RWMutex
	expiresAt      atomic.Int64
	closeTimeout   time.Duration // 优雅关闭 drain 超时（从 CloseMessage.close_timeout_ms 协商，默认 5s）
	earlyData      atomic.Bool   // 0-RTT resumption：HELLO 恢复 keys 后置位，dataLoop early 启动
	authed         atomic.Bool   // 是否已认证成功（到达 READY）；决定 DISCONNECTED 是否触发（必须与 CONNECTED 配对）
	lastPressure   atomic.Value
	pressureMu     sync.Mutex // 保护 lastPressure 的"比较-更新-下发"序列（§9.2 避免同值重复 WINDOW）

	dataOnce       sync.Once
	dataWG         sync.WaitGroup     // 跟踪 data frame 处理 goroutine
	batchSem       chan struct{}      // data frame 并发上限（QUIC=64 / TCP=8）
	cancelDataLoop context.CancelFunc // 取消 dataLoop 派生 context，使 processBatch 尽快退出

	// sinkQueue 是普通 EventSink 的异步投递队列（fire-and-forget）。
	// 非 nil 时 routeAndACK 把 batch 投到此队列立即返回 ACK；nil 表示同步（Durable/Raw sink 或禁用异步）。
	// worker（sinkWG）消费队列调 sink.OnSignalBatch。连接关闭时 close 队列等 worker 排空。
	sinkQueue chan sinkTask
	sinkWG    sync.WaitGroup
	// durableNotifier 在 sink 实现 AsyncDurableSink 时初始化（initSinkQueue），
	// 投递时注入 task，sink 持久化后回调发 durable 升级帧。nil 表示 sink 非异步 Durable。
	durableNotifier core.DurableNotifier
}

// sinkTask 是 sinkQueue 的投递单元，统一承载普通 EventSink 与 AsyncDurableSink 两路径。
// routeAndACK 投递、worker 消费；asyncDurable=false 走普通 EventSink（fire-and-forget），
// true 走 AsyncDurableSink（持久化后回调 notifier 发 durable 升级）。
type sinkTask struct {
	agentID      string
	batch        *core.SignalBatch // 普通 EventSink + AsyncDurableSink 共用
	asyncDurable bool              // true = AsyncDurableSink 路径
	// AsyncDurableSink 路径专用：发 durable 升级帧所需的元信息。
	seq         uint64
	chunkID     []byte
	eventsCount int
	notifier    core.DurableNotifier // 协议层注入，sink 持久化后回调
}

// getAgentID 返回当前 agentID（并发安全读取，供 processBatch 等读路径使用）。
func (h *CoreHandler) getAgentID() string {
	h.handshakeMu.RLock()
	defer h.handshakeMu.RUnlock()
	return h.agentID
}

// setAgentID 设置 agentID（并发安全写入，供 controlLoop 握手写路径使用）。
func (h *CoreHandler) setAgentID(id string) {
	h.handshakeMu.Lock()
	defer h.handshakeMu.Unlock()
	h.agentID = id
}

// getSessionID 返回 sessionID 的拷贝（并发安全读取）。
func (h *CoreHandler) getSessionID() []byte {
	h.handshakeMu.RLock()
	defer h.handshakeMu.RUnlock()
	cp := make([]byte, len(h.sessionID))
	copy(cp, h.sessionID)
	return cp
}

// setSessionID 设置 sessionID（并发安全写入，防御性拷贝与 getter 对称）。
func (h *CoreHandler) setSessionID(id []byte) {
	h.handshakeMu.Lock()
	defer h.handshakeMu.Unlock()
	h.sessionID = append(h.sessionID[:0], id...)
}

// setHelloMeta 保存 HELLO 帧的身份字段（hostname/instance_id/agent_version/os），
// 供 AUTH_OK 后构造 SessionEvent 使用。在 handleHello 中一次性写入，handshakeMu 保护。
func (h *CoreHandler) setHelloMeta(hostname, instanceID, agentVersion, os string) {
	h.handshakeMu.Lock()
	defer h.handshakeMu.Unlock()
	h.hostname = hostname
	h.instanceID = instanceID
	h.agentVersion = agentVersion
	h.os = os
}

// helloMeta 返回保存的 HELLO 身份字段（并发安全读取）。
func (h *CoreHandler) helloMeta() (hostname, instanceID, agentVersion, os string) {
	h.handshakeMu.RLock()
	defer h.handshakeMu.RUnlock()
	return h.hostname, h.instanceID, h.agentVersion, h.os
}

// getChallengeNonce 返回 challengeNonce 的拷贝（并发安全读取）。
func (h *CoreHandler) getChallengeNonce() []byte {
	h.handshakeMu.RLock()
	defer h.handshakeMu.RUnlock()
	cp := make([]byte, len(h.challengeNonce))
	copy(cp, h.challengeNonce)
	return cp
}

// setChallengeNonce 设置 challengeNonce（并发安全写入，防御性拷贝与 getter 对称）。
func (h *CoreHandler) setChallengeNonce(nonce []byte) {
	h.handshakeMu.Lock()
	defer h.handshakeMu.Unlock()
	h.challengeNonce = append(h.challengeNonce[:0], nonce...)
}

// NewCoreHandler 创建 handler。batchSem 容量按 Multiplexing 选（保留两套并发模型）。
func NewCoreHandler(tr Transport, cfg HandlerConfig) *CoreHandler {
	sem := maxConcurrentQuicDataFrames
	if tr.Multiplexing() == MultiplexTCPSingleConn {
		sem = maxConcurrentTCPBatches
	}
	// Metrics 为 nil（含 typed-nil，如 (*MBTAMetrics)(nil) 赋给接口）时回退到
	// NoOpMetrics，handler 无需逐处 nil 检查。typed-nil 检测必要：(*MBTAMetrics)(nil)
	// 转 core.Metrics 后 != nil（带类型信息），直接调用会 panic。
	if isNilMetrics(cfg.Metrics) {
		cfg.Metrics = core.NoOpMetrics{}
	}
	h := &CoreHandler{
		tr:       tr,
		config:   cfg,
		sm:       core.NewServerMachine(),
		replay:   core.NewReplayCache(),
		window:   core.NewWindow(windowMaxBatches, windowMaxEvents, windowMaxBytes),
		inflight: &core.Inflight{},
		batchSem: make(chan struct{}, sem),
	}
	h.lastPressure.Store(core.PressureNormal)
	h.replay.SetMetrics(cfg.Metrics)
	// 普通 EventSink（非 Durable/Raw）启用异步投递队列：协议层 fire-and-forget，
	// worker pool 异步调 OnSignalBatch。Durable/Raw sink 仍同步（需 RouteResult）。
	// SinkQueueSize < 0 显式禁用异步（测试用）。
	h.initSinkQueue()
	return h
}

// initSinkQueue 在 sink 支持异步投递时创建队列 + worker pool。
// 启用条件：sink 是普通 EventSink（fire-and-forget）或 AsyncDurableSink（持久化后回调升级）。
// 仅实现 DurableEventSink/RawEventSink 但未实现 AsyncDurableSink 的 sink 走同步路径（需 RouteResult）。
// SinkQueueSize < 0 显式禁用异步（测试用）。
func (h *CoreHandler) initSinkQueue() {
	if h.config.Sink == nil {
		return
	}
	// 判断是否可异步：普通 EventSink（非 Durable）或 AsyncDurableSink（Durable 的可选扩展）。
	_, isAsyncDurable := h.config.Sink.(core.AsyncDurableSink)
	_, isDurable := h.config.Sink.(core.DurableEventSink)
	if isDurable && !isAsyncDurable {
		return // 同步 Durable/Raw sink：需 RouteResult，不能异步
	}
	size := h.config.SinkQueueSize
	if size == 0 {
		size = defaultSinkQueueSize
	}
	if size < 0 {
		return // 显式禁用异步
	}
	h.sinkQueue = make(chan sinkTask, size)
	// AsyncDurableSink 路径需要 notifier 发 durable 升级帧。
	if _, isAsyncDurable := h.config.Sink.(core.AsyncDurableSink); isAsyncDurable {
		h.durableNotifier = &durableNotifier{handler: h}
	}
	workers := defaultSinkWorkers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	for i := 0; i < workers; i++ {
		h.sinkWG.Add(1)
		go h.sinkWorker()
	}
}

// sinkWorker 消费 sinkQueue，按 task 类型分发：普通 EventSink 调 OnSignalBatch，
// AsyncDurableSink 调 OnSignalBatchAsync（持久化后回调 notifier 发 durable 升级）。
func (h *CoreHandler) sinkWorker() {
	defer h.sinkWG.Done()
	for task := range h.sinkQueue {
		if task.asyncDurable {
			if asyncSink, ok := h.config.Sink.(core.AsyncDurableSink); ok {
				asyncSink.OnSignalBatchAsync(context.Background(), task.agentID, task.batch,
					task.notifier, task.seq, task.chunkID, task.eventsCount)
			}
		} else {
			_ = h.config.Sink.OnSignalBatch(context.Background(), task.agentID, task.batch)
		}
	}
}

// durableNotifier 是协议层提供给 AsyncDurableSink 的回调接口实现。
// sink 持久化完成后调 NotifyDurable，本实现发 ACK_MODE_DURABLE 升级帧。
// 幂等保护：已发 durable 的 seq 不重复发（防 sink 误多次回调）。
type durableNotifier struct {
	handler *CoreHandler
	seen    sync.Map // seq → struct{}{}，已发 durable 的去重
}

func (n *durableNotifier) NotifyDurable(seq uint64, chunkID []byte, eventsCount int) {
	if _, loaded := n.seen.LoadOrStore(seq, struct{}{}); loaded {
		return // 已发过 durable，幂等跳过
	}
	// durable 升级帧在 background ctx 发（worker goroutine 调，原 routeAndACK ctx 已退出）。
	n.handler.sendAck(context.Background(), seq, chunkID, eventsCount, corepb.AckMode_ACK_MODE_DURABLE)
}

// Handle 运行连接生命周期：control loop → READY 后启动 data loop。
func (h *CoreHandler) Handle(ctx context.Context) error {
	// dataExited 标记所有 data goroutine 是否在 drain 超时前退出。
	// cleanup 依据此标记决定是否零化 keys：仅在确认无 data goroutine 读 keys 时才清零，
	// 否则保留 keys（由 GC 在连接生命周期结束后回收），避免 cleanup 把 keys 置 nil
	// 后存活的 processBatch 跳过 HMAC 校验（安全绕过）。
	dataExited := false
	defer h.cleanup(&dataExited)
	// 会话生命周期回调：连接结束时触发 DISCONNECTED。
	// 仅当该连接此前认证成功（agentID 非空）才触发，避免对未通过 HELLO/AUTH 的连接
	// 误报 DISCONNECTED（无配对的 CONNECTED）。与 CONNECTED 严格成对。
	// 注意：DISCONNECTED 在 CONNECTED 之后、数据 drain 完成前后都可能；回调实现需容忍。
	defer func() {
		if h.config.OnSession == nil {
			return
		}
		if !h.authed.Load() {
			return // 未认证（或认证失败）的连接：没有配对的 CONNECTED，不报 DISCONNECTED
		}
		h.config.OnSession(core.SessionEvent{
			Type:       core.SessionDisconnected,
			AgentID:    h.getAgentID(),
			SessionID:  string(h.getSessionID()),
			RemoteAddr: h.tr.RemoteAddr(),
		})
	}()
	// 进入 CONTROL_WAIT（server 状态机初始为 Accepted）。
	if err := h.sm.Transition(core.ServerStateControlWait); err != nil {
		return core.WrapError(core.ErrCodeSession, "transition to CONTROL_WAIT", err)
	}
	err := h.controlLoop(ctx)
	// 等待所有 data frame 处理 goroutine 退出后再清密钥（避免与 processBatch 读 keys 竞态）。
	// drain 超时：从 CloseMessage.close_timeout_ms 协商，默认 5s（core spec §9.6）。
	drainTimeout := h.closeTimeout
	if drainTimeout == 0 {
		drainTimeout = 5 * time.Second
	}
	// 取消 dataLoop context，使仍在阻塞的 processBatch goroutine 尽快退出，
	// 避免 cleanup 后读 nil keys（h.keys.Store(nil)）或永久泄漏。
	if h.cancelDataLoop != nil {
		h.cancelDataLoop()
	}
	done := make(chan struct{})
	go func() { h.dataWG.Wait(); close(done) }()
	select {
	case <-done:
		dataExited = true
	case <-time.After(drainTimeout):
		// 超时：仍有 data goroutine 存活，cleanup 不会零化 keys，避免存活的
		// processBatch 因 keys==nil 跳过 HMAC 校验（安全绕过）。keys 由 GC 回收。
		slog.Warn("data frame goroutines did not exit within drain timeout; keeping keys to avoid HMAC bypass", "session", string(h.getSessionID()), "timeout", drainTimeout)
	}
	// data goroutine 退出后关闭 sink 投递队列，等 worker 排空剩余 task。
	// sinkQueue nil（Durable/Raw sink 或禁用异步）时跳过。
	if h.sinkQueue != nil {
		close(h.sinkQueue)
		h.sinkWG.Wait()
	}
	return err
}

// cleanup 零化会话密钥。仅当 dataExited 为 true（所有 data goroutine 已退出）时执行，
// 避免与存活的 processBatch goroutine 竞态读 keys。
func (h *CoreHandler) cleanup(dataExited *bool) {
	if dataExited == nil || !*dataExited {
		return
	}
	if k := h.keys.Load(); k != nil {
		k.Zero()
		h.keys.Store(nil)
	}
}

// controlLoop 处理控制帧：HELLO/AUTH/PING/CLOSE。
func (h *CoreHandler) controlLoop(ctx context.Context) error {
	for {
		f, err := h.tr.RecvControlFrame(ctx)
		if err != nil {
			return core.WrapError(core.ErrCodeProtocol, "read control frame", err)
		}
		switch f.Header.Type {
		case core.TypeHello:
			if h.sm.State() == core.ServerStateReady {
				h.sendError(ctx, core.ErrCodeUnsupportedMessage, "HELLO not allowed after auth", true)
				continue
			}
			if err := h.handleHello(ctx, f.Payload); err != nil {
				return err
			}
		case core.TypeAuth:
			if h.sm.State() == core.ServerStateReady {
				h.sendError(ctx, core.ErrCodeUnsupportedMessage, "AUTH not allowed after auth", true)
				continue
			}
			if err := h.handleAuth(ctx, f.Payload); err != nil {
				return err
			}
		case core.TypePing:
			if h.sm.State() != core.ServerStateReady {
				h.sendError(ctx, core.ErrCodeUnsupportedMessage, "PING not allowed before auth", true)
				continue
			}
			h.handlePing(ctx, f.Payload)
		case core.TypeClose:
			h.handleClose(f.Payload)
			return nil
		default:
			h.sendError(ctx, core.ErrCodeUnsupportedMessage, fmt.Sprintf("unexpected control type 0x%02x", f.Header.Type), true)
			return core.NewError(core.ErrCodeProtocol, fmt.Sprintf("unexpected control type 0x%02x", f.Header.Type))
		}

		// READY 或 0-RTT early_data 后启动 data loop（exactly once）
		if h.sm.State() == core.ServerStateReady || h.earlyData.Load() {
			h.dataOnce.Do(func() {
				// 派生可取消 context：controlLoop 退出后 Handle 调 cancelDataLoop，
				// 使阻塞在 sink 的 processBatch goroutine 收到取消信号尽快退出。
				dataCtx, cancel := context.WithCancel(ctx)
				h.cancelDataLoop = cancel
				h.dataWG.Add(1)
				go func() {
					defer h.dataWG.Done()
					h.dataLoop(dataCtx)
				}()
			})
		}
	}
}

// handleClose 处理 CLOSE 帧：解码 + clamp close_timeout 防恶意 DoS。提取自 controlLoop。
func (h *CoreHandler) handleClose(payload []byte) {
	var closeMsg core.CloseMessage
	if derr := core.Decode(payload, &closeMsg); derr != nil {
		slog.Warn("failed to decode close message", "session", string(h.getSessionID()), "error", derr)
	}
	if closeMsg.GetCloseTimeoutMs() > 0 {
		// 强制上限防止恶意客户端发 MaxUint32 导致 goroutine 长期占用资源（DoS）。
		requested := time.Duration(closeMsg.GetCloseTimeoutMs()) * time.Millisecond
		if requested > maxDrainTimeout {
			requested = maxDrainTimeout
		}
		h.closeTimeout = requested
	}
	slog.Info("close received", "session", string(h.getSessionID()), "drain_timeout", h.closeTimeout)
}

// dataLoop 读 BATCH 帧并发处理（batchSem 限流）。
func (h *CoreHandler) dataLoop(ctx context.Context) {
	for {
		f, err := h.tr.RecvDataFrame(ctx)
		if err != nil {
			slog.Debug("data frame stream ended", "session", string(h.getSessionID()), "error", err)
			return
		}
		switch f.Header.Type {
		case core.TypeBatch:
			// 并发处理，受 batchSem 限制。
			select {
			case h.batchSem <- struct{}{}:
				h.dataWG.Add(1)
				go func(pf core.Frame) {
					defer func() { <-h.batchSem; h.dataWG.Done() }()
					h.processBatch(ctx, pf.Payload)
				}(f)
			default:
				// 并发满，拒绝并要求退避。
				h.sendThrottle(ctx, throttleRetryMs, core.ErrCodeTooManyBatches, "max concurrent batches exceeded")
			}
		case core.TypeDatagram:
			// r2 unreliable 通道：at-most-once，无 ACK/spool，HMAC 失败静默丢弃（core spec §11.4）。
			h.processDatagram(ctx, f.Payload)
		default:
			slog.Debug("unexpected frame on data channel", "type", f.Header.Type)
		}
	}
}
