package protocol

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mbta-go/core"
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
)

// CodeEnvelopeAlgoMismatch 是 envelope 算法一致性复核失败时回送的 NACK code。
// 客户端 envelope 声明的 Codec/Compression/CipherSuite 与服务端协商结果不符时使用。
const CodeEnvelopeAlgoMismatch = "envelope_algo_mismatch"

// HandlerConfig 是 CoreHandler 的配置（传输无关）。
type HandlerConfig struct {
	Auth            core.TokenValidator
	Policy          core.Policy
	Sink            core.EventSink
	Metrics         core.Metrics // nil 时回退到 NoOpMetrics（见 NewCoreHandler）
	ServerID        string
	SessionStore    *core.SessionStore   // 0-RTT resumption（可选，nil = 不支持 early_data）
	RedirectChecker core.RedirectChecker // HA：AUTH_OK 后检查角色，非 leader 发 TypeRedirect（可选，nil=禁用）
}

// CoreHandler 是 server 端协议状态机核心，仅依赖 Transport 接口，
// 不感知 quic.Stream/net.Conn（core spec §10.2）。
// 吸收 v1/handler.go 与 ntls/handler.go 的全部共享协议逻辑。
type CoreHandler struct {
	tr     Transport
	config HandlerConfig

	sm         *core.ServerMachine
	negotiated atomic.Pointer[core.NegotiateResult] // controlLoop(handleHello) 写 / dataLoop(processBatch) 读，原子化避免数据竞争
	keys       atomic.Pointer[core.SessionKeys]      // 0-RTT：controlLoop(handleAuth) 与 dataLoop(processBatch) 并发读写
	replay     *core.ReplayCache
	window     *core.Window
	inflight   *core.Inflight

	agentID        string
	sessionID      []byte
	challengeNonce []byte
	authAttempts   int
	expiresAt      atomic.Int64
	closeTimeout   time.Duration // 优雅关闭 drain 超时（从 CloseMessage.close_timeout_ms 协商，默认 5s）
	earlyData      bool          // 0-RTT resumption：HELLO 恢复 keys 后置位，dataLoop early 启动
	lastPressure   atomic.Value
	pressureMu     sync.Mutex // 保护 lastPressure 的"比较-更新-下发"序列（§9.2 避免同值重复 WINDOW）

	dataOnce      sync.Once
	dataWG        sync.WaitGroup   // 跟踪 data frame 处理 goroutine
	batchSem      chan struct{}    // data frame 并发上限（QUIC=64 / TCP=8）
	cancelDataLoop context.CancelFunc // 取消 dataLoop 派生 context，使 processBatch 尽快退出
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
	return h
}

// Handle 运行连接生命周期：control loop → READY 后启动 data loop。
func (h *CoreHandler) Handle(ctx context.Context) error {
	defer h.cleanup()
	// 进入 CONTROL_WAIT（server 状态机初始为 Accepted）。
	if err := h.sm.Transition(core.ServerStateControlWait); err != nil {
		return core.WrapError(core.NumSession, core.CodeSession, "transition to CONTROL_WAIT", err)
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
	case <-time.After(drainTimeout):
		slog.Warn("data frame goroutines did not exit within drain timeout", "session", string(h.sessionID), "timeout", drainTimeout)
	}
	return err
}

func (h *CoreHandler) cleanup() {
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
			return core.WrapError(core.NumProtocol, core.CodeProtocol, "read control frame", err)
		}
		switch f.Header.Type {
		case core.TypeHello:
			if h.sm.State() == core.ServerStateReady {
				h.sendError(ctx, core.CodeUnsupportedMessage, "HELLO not allowed after auth", true)
				continue
			}
			if err := h.handleHello(ctx, f.Payload); err != nil {
				return err
			}
		case core.TypeAuth:
			if h.sm.State() == core.ServerStateReady {
				h.sendError(ctx, core.CodeUnsupportedMessage, "AUTH not allowed after auth", true)
				continue
			}
			if err := h.handleAuth(ctx, f.Payload); err != nil {
				return err
			}
		case core.TypePing:
			if h.sm.State() != core.ServerStateReady {
				h.sendError(ctx, core.CodeUnsupportedMessage, "PING not allowed before auth", true)
				continue
			}
			h.handlePing(ctx, f.Payload)
		case core.TypeClose:
			h.handleClose(f.Payload)
			return nil
		default:
			h.sendError(ctx, core.CodeUnsupportedMessage, fmt.Sprintf("unexpected control type 0x%02x", f.Header.Type), true)
			return core.NewError(core.NumProtocol, core.CodeProtocol, fmt.Sprintf("unexpected control type 0x%02x", f.Header.Type))
		}

		// READY 或 0-RTT early_data 后启动 data loop（exactly once）
		if h.sm.State() == core.ServerStateReady || h.earlyData {
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
		slog.Warn("failed to decode close message", "session", string(h.sessionID), "error", derr)
	}
	if closeMsg.GetCloseTimeoutMs() > 0 {
		// 强制上限防止恶意客户端发 MaxUint32 导致 goroutine 长期占用资源（DoS）。
		requested := time.Duration(closeMsg.GetCloseTimeoutMs()) * time.Millisecond
		if requested > maxDrainTimeout {
			requested = maxDrainTimeout
		}
		h.closeTimeout = requested
	}
	slog.Info("close received", "session", string(h.sessionID), "drain_timeout", h.closeTimeout)
}

// dataLoop 读 BATCH 帧并发处理（batchSem 限流）。
func (h *CoreHandler) dataLoop(ctx context.Context) {
	for {
		f, err := h.tr.RecvDataFrame(ctx)
		if err != nil {
			slog.Debug("data frame stream ended", "session", string(h.sessionID), "error", err)
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
				h.sendThrottle(ctx, throttleRetryMs, "too_many_batches", "max concurrent batches exceeded")
			}
		case core.TypeDatagram:
			// r2 unreliable 通道：at-most-once，无 ACK/spool，HMAC 失败静默丢弃（core spec §11.4）。
			h.processDatagram(ctx, f.Payload)
		default:
			slog.Debug("unexpected frame on data channel", "type", f.Header.Type)
		}
	}
}
