package core

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// PressureState 背压状态
type PressureState string

const (
	PressureNormal   PressureState = "normal"
	PressureDegraded PressureState = "degraded"
	PressureCritical PressureState = "critical"
)

// ACKStatus 确认状态
type ACKStatus string

const (
	ACKStatusDurable  ACKStatus = "durable"  // Successfully enqueued to reliable queue
	ACKStatusAccepted ACKStatus = "accepted" // Accepted to memory queue only
	ACKStatusThrottle ACKStatus = "throttle" // Server throttling, back off
)

// RouteResult 路由器返回给 handler 的路由结果，供 handler 选择 ACK/THROTTLE 模式。
// 仅 Status 和 Pressure 被 handler 读取（applyRouteResult）；其他曾是 speculative 字段。
type RouteResult struct {
	Status   ACKStatus     // "durable" | "accepted" | "throttle"
	Pressure PressureState // sink 反馈的背压状态（空则不调整窗口）
}

// EventSink 是 MBTA 协议层与上层的唯一桥接点。
// 上层（runtime）实现此接口，将 MBTA SignalBatch 投递到 pipeline。
type EventSink interface {
	// OnSignalBatch 接收一个已解码的 SignalBatch。
	// 返回 nil 表示成功，非 nil 表示投递失败。
	OnSignalBatch(ctx context.Context, agentID string, batch *SignalBatch) error

	// OnPressure 查询上层当前背压状态。
	OnPressure(agentID string) PressureState
}

// DurableEventSink 扩展 EventSink，提供 ACK 模式反馈。
// handler 通过此接口决定发送 ACK（durable/accepted）还是 THROTTLE 帧。
type DurableEventSink interface {
	EventSink
	// OnSignalBatchWithResult 投递 SignalBatch 并返回路由结果。
	OnSignalBatchWithResult(ctx context.Context, agentID string, batch *SignalBatch) (*RouteResult, error)
}

// RawEventSink 扩展 DurableEventSink，提供「不解码 signalBatch」的快速路径。
// 实现此接口的 sink（通常是纯转发/落盘场景，不需读取 signal 字段详情）接收原始
// batch proto 字节与事件数，服务端跳过 UnmarshalSignalBatch(signalBatch) 与 Validate，
// 省去逐事件解码的反射与 map 分配（约 13 allocs/event）。
// 不实现此接口的 sink 走原路径（完整解码 SignalBatch 后调用 OnSignalBatchWithResult）。
type RawEventSink interface {
	DurableEventSink
	// OnRawBatch 投递未解码的原始 batch 字节（协商 codec 编码的 SignalBatch）与事件数，返回路由结果。
	// eventsCount 来自 BatchMessage.EventsCount（客户端填充），batchData 为未解码的 SignalBatch 字节
	// （默认 proto，也可能是 cbor/json——按协商 codec）。
	OnRawBatch(ctx context.Context, agentID string, eventsCount int, batchData []byte) (*RouteResult, error)
}

// DurableNotifier 由协议层提供，sink 持有。持久化完成后调 NotifyDurable，
// 协议层据此发 ACK durable 升级帧（先 accepted 后 durable，sink 异步化设计 §3）。
//
// sink 实现 AsyncDurableSink 时，协议层在投递时注入本接口；持久化异步完成后回调。
// 未实现 AsyncDurableSink 的 sink 走同步路径（OnSignalBatchWithResult 直接返回 RouteResult）。
type DurableNotifier interface {
	// NotifyDurable 通知某 batch 已持久化。seq/chunkID/eventsCount 来自原 batch，
	// 协议层据此发 ACK_MODE_DURABLE。多次调用幂等（仅首次发 durable 帧）。
	NotifyDurable(seq uint64, chunkID []byte, eventsCount int)
}

// AsyncDurableSink 可选接口：实现此接口的 DurableEventSink 走异步投递路径。
// 协议层把 batch 投递到 sink queue 立即发 ACK accepted，worker 调 OnSignalBatchAsync；
// sink 持久化完成后调注入的 notifier.NotifyDurable，协议层发 durable 升级帧。
//
// 不实现此接口的 DurableEventSink/RawEventSink 走同步路径（OnSignalBatchWithResult
// / OnRawBatch 直接返回 RouteResult）。渐进式：老 sink 不受影响，新 sink 享异步。
type AsyncDurableSink interface {
	// OnSignalBatchAsync 异步投递 batch。立即返回（不阻塞协议层）；
	// 持久化完成后调 notifier.NotifyDurable(seq, chunkID, eventsCount)。
	OnSignalBatchAsync(ctx context.Context, agentID string, batch *SignalBatch, notifier DurableNotifier, seq uint64, chunkID []byte, eventsCount int)
}

// BatchTraceSink 扩展 EventSink，透传 batch 级 W3C trace 上下文（capability
// w3c_trace_context，spec §6.2.2）。顺项目「渐进 interface 扩展」范式（EventSink →
// DurableEventSink → RawEventSink）：不实现的 sink 不受影响，原路由路径不变。
//
// 这是旁路通知——不替代 OnSignalBatch/OnRawBatch 的路由语义，仅让上层有机会在
// batch 维度继承 trace 关联（如注入到下游 OTel context）。tc 为 nil 表示该 batch
// 未携带 batch 级 trace。
type BatchTraceSink interface {
	EventSink
	OnBatchTraceContext(ctx context.Context, agentID string, tc *TraceContext)
}

// Inflight tracks bytes, events, and batches that are in-flight (sent but not yet ACKed).
// 三个标量用 atomic 计数，避免高频数据流（服务端 64 stream × N 连接）下的互斥锁竞争。
type Inflight struct {
	batches atomic.Int64
	events  atomic.Int64
	bytes   atomic.Int64
}

// Add increases inflight counters for a batch being sent.
func (inf *Inflight) Add(events int, bytes int64) {
	inf.batches.Add(1)
	inf.events.Add(int64(events))
	inf.bytes.Add(bytes)
}

// Remove decreases inflight counters after receiving a response.
//
// 仅对实际出现负值的计数器执行 clampNonNeg，避免在「某个计数器 underflow」时
// 把并发 Add 写入的合法正值计数器一并清零（对三个计数器无条件 clamp 会导致
// inflight 持续低估，Window.CanSend 允许超额发送）。
func (inf *Inflight) Remove(events int, bytes int64) {
	nb := inf.batches.Add(-1)
	ne := inf.events.Add(int64(-events))
	nby := inf.bytes.Add(-bytes)
	if nb < 0 {
		slog.Warn("inflight batches underflow", "batches", nb, "removed_events", events, "removed_bytes", bytes)
		clampNonNeg(&inf.batches)
	}
	if ne < 0 {
		slog.Warn("inflight events underflow", "events", ne, "removed_events", events)
		clampNonNeg(&inf.events)
	}
	if nby < 0 {
		slog.Warn("inflight bytes underflow", "bytes", nby, "removed_bytes", bytes)
		clampNonNeg(&inf.bytes)
	}
}

// clampNonNeg 在计数器因并发 Remove 出现负值时将其 CAS 回零，避免持续负值阻塞窗口。
func clampNonNeg(a *atomic.Int64) {
	for {
		v := a.Load()
		if v >= 0 {
			return
		}
		if a.CompareAndSwap(v, 0) {
			return
		}
	}
}

// Snapshot returns current inflight counters.
func (inf *Inflight) Snapshot() (batches int, events int, bytes int64) {
	return int(inf.batches.Load()), int(inf.events.Load()), inf.bytes.Load()
}

// Window represents the server's current flow-control window.
// 三个上限用 atomic 存储，CanSend/Snapshot 无锁读，消除 Window↔Inflight 双锁的 TOCTOU 窗口。
type Window struct {
	maxBatches atomic.Int64
	maxEvents  atomic.Int64
	maxBytes   atomic.Int64
}

// NewWindow creates a window with initial limits.
func NewWindow(maxBatches int, maxEvents int, maxBytes int64) *Window {
	w := &Window{}
	w.maxBatches.Store(int64(maxBatches))
	w.maxEvents.Store(int64(maxEvents))
	w.maxBytes.Store(maxBytes)
	return w
}

// Update sets new window limits from a WINDOW message.
func (w *Window) Update(maxBatches int, maxEvents int, maxBytes int64) {
	w.maxBatches.Store(int64(maxBatches))
	w.maxEvents.Store(int64(maxEvents))
	w.maxBytes.Store(maxBytes)
}

// CanSend checks whether a batch of the given size fits in the window.
// A max of 0 means that dimension is paused (no sending allowed).
// 原子读无锁；check 与 inflight.Add 之间非原子，服务端 over-commit 由 routeAndACK 回退处理，客户端由 sendMu 保证原子性。
func (w *Window) CanSend(inf *Inflight, events int, bytes int64) bool {
	if w == nil || inf == nil {
		return false
	}

	winBatches := w.maxBatches.Load()
	winEvents := w.maxEvents.Load()
	winBytes := w.maxBytes.Load()

	// max=0 means paused
	if winBatches == 0 || winEvents == 0 || winBytes == 0 {
		return false
	}

	ib, ie, iby := inf.Snapshot()
	return (ib+1 <= int(winBatches)) &&
		(ie+events <= int(winEvents)) &&
		(iby+bytes <= winBytes)
}

// MaxThrottleDelay 是客户端接受的最大限流延迟（5分钟）。
// 超过此值的 retry_delay_ms 会被截断，防止恶意或异常的服务器无限期阻塞客户端。
const MaxThrottleDelay = 5 * time.Minute

// ThrottleState tracks the current throttle status.
// until 存 *time.Time（含单调时钟分量），nil 表示未限流。无锁原子读写。
//
// 用 *time.Time 而非 UnixNano 是为了保留 Go 的单调时钟读数，
// 使 NTP 时钟回拨不会导致节流时长异常（core spec §9.4 健壮性）。
type ThrottleState struct {
	until atomic.Pointer[time.Time]
}

// Apply sets the throttle from a THROTTLE message.
func (ts *ThrottleState) Apply(retryDelayMs int) {
	// 负值或零值 retry_delay_ms 视为"不限制"：清除节流而非设置零时长节流，
	// 避免 Active() 在极短窗口内误返回 true（恶意/有缺陷的服务端发送负值时）。
	if retryDelayMs <= 0 {
		ts.until.Store(nil)
		return
	}
	d := min(time.Duration(retryDelayMs)*time.Millisecond, MaxThrottleDelay)
	deadline := time.Now().Add(d) // time.Now() 含单调时钟，Add 保留
	ts.until.Store(&deadline)
}

// Active returns true if currently throttled.
func (ts *ThrottleState) Active() bool {
	p := ts.until.Load()
	if p == nil {
		return false
	}
	return time.Now().Before(*p) // Before/After 使用单调时钟比较
}

// WaitDuration returns how long until the throttle expires.
func (ts *ThrottleState) WaitDuration() time.Duration {
	p := ts.until.Load()
	if p == nil {
		return 0
	}
	remaining := time.Until(*p) // time.Until 对含单调时钟的 time.Time 用单调分量
	if remaining < 0 {
		return 0
	}
	return remaining
}
