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
	PressureNormal   PressureState = "normal" //
	PressureDegraded PressureState = "degraded"
	PressureCritical PressureState = "critical"
)

// ACKStatus 确认状态
type ACKStatus string

const (
	ACKStatusDurable  ACKStatus = "durable"  // Successfully enqueued to reliable queue
	ACKStatusAccepted ACKStatus = "accepted" // Accepted to memory queue only
	ACKStatusThrottle ACKStatus = "throttle" // Server throttling, back off
	ACKStatusNack     ACKStatus = "nack"     // Server rejected the batch
)

// RouteResult 路由器返回给 handler 的路由结果，供 handler 选择 ACK/THROTTLE 模式。
type RouteResult struct {
	Status      ACKStatus // "durable" | "accepted" | "throttle"
	EventsCount int
	QueueType   string
	Pressure    PressureState
	Error       error
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
	// OnRawBatch 投递原始 batch JSON 与事件数，返回路由结果。
	// eventsCount 来自 BatchMessage.EventsCount（客户端填充），batchData 为未解码的 SignalBatch proto。
	OnRawBatch(ctx context.Context, agentID string, eventsCount int, batchData []byte) (*RouteResult, error)
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
// 把并发 Add 写入的合法正值计数器一并清零（旧实现对三个计数器无条件 clamp，
// 导致 inflight 持续低估，Window.CanSend 允许超额发送）。
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

// Reset clears all inflight counters. Called on disconnect or reconnect
// to prevent stale counters from permanently blocking the window.
func (inf *Inflight) Reset() {
	inf.batches.Store(0)
	inf.events.Store(0)
	inf.bytes.Store(0)
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
//
// 全程原子读，无锁。check 与随后 inflight.Add 之间仍非原子——服务端多流并发下可能
// 轻微 over-commit，由 routeAndACK 的 window_exceeded 回退兜底；客户端由 sendMu 保证原子性。
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

// Snapshot returns current window limits.
func (w *Window) Snapshot() (maxBatches int, maxEvents int, maxBytes int64) {
	return int(w.maxBatches.Load()), int(w.maxEvents.Load()), w.maxBytes.Load()
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
	d := max(0, min(time.Duration(retryDelayMs)*time.Millisecond, MaxThrottleDelay))
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
