package core

import (
	"context"
	"sync"
	"time"
)

// PressureState 背压状态（string 枚举，匹配项目风格：model.Status、ACKStatus 等）。
type PressureState string

const (
	PressureNormal   PressureState = "normal"
	PressureDegraded PressureState = "degraded"
	PressureCritical PressureState = "critical"
)

// ACKStatus 确认状态（从 router_enhanced.go 迁移到 core）。
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

// AgentQueue 跟踪每个 agent 的投递状态。
type AgentQueue struct {
	AgentID   string
	QueueType string
	EventsIn  int64
	EventsOut int64
	CreatedAt time.Time
}

// Inflight tracks bytes, events, and batches that are in-flight (sent but not yet ACKed).
type Inflight struct {
	mu      sync.Mutex
	batches int
	events  int
	bytes   int64
}

// Add increases inflight counters for a batch being sent.
func (inf *Inflight) Add(events int, bytes int64) {
	inf.mu.Lock()
	defer inf.mu.Unlock()
	inf.batches++
	inf.events += events
	inf.bytes += bytes
}

// Remove decreases inflight counters after receiving a response.
func (inf *Inflight) Remove(events int, bytes int64) {
	inf.mu.Lock()
	defer inf.mu.Unlock()
	inf.batches--
	inf.events -= events
	inf.bytes -= bytes
	if inf.batches < 0 {
		inf.batches = 0
	}
	if inf.events < 0 {
		inf.events = 0
	}
	if inf.bytes < 0 {
		inf.bytes = 0
	}
}

// Snapshot returns current inflight counters.
func (inf *Inflight) Snapshot() (batches int, events int, bytes int64) {
	inf.mu.Lock()
	defer inf.mu.Unlock()
	return inf.batches, inf.events, inf.bytes
}

// Reset clears all inflight counters. Called on disconnect or reconnect
// to prevent stale counters from permanently blocking the window.
func (inf *Inflight) Reset() {
	inf.mu.Lock()
	defer inf.mu.Unlock()
	inf.batches = 0
	inf.events = 0
	inf.bytes = 0
}

// Window represents the server's current flow-control window.
type Window struct {
	mu                 sync.Mutex
	maxInflightBatches int
	maxInflightEvents  int
	maxInflightBytes   int64
}

// NewWindow creates a window with initial limits.
func NewWindow(maxBatches int, maxEvents int, maxBytes int64) *Window {
	return &Window{
		maxInflightBatches: maxBatches,
		maxInflightEvents:  maxEvents,
		maxInflightBytes:   maxBytes,
	}
}

// Update sets new window limits from a WINDOW message.
func (w *Window) Update(maxBatches int, maxEvents int, maxBytes int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.maxInflightBatches = maxBatches
	w.maxInflightEvents = maxEvents
	w.maxInflightBytes = maxBytes
}

// CanSend checks whether a batch of the given size fits in the window.
// A max of 0 means that dimension is paused (no sending allowed).
func (w *Window) CanSend(inf *Inflight, events int, bytes int64) bool {
	w.mu.Lock()
	winBatches := w.maxInflightBatches
	winEvents := w.maxInflightEvents
	winBytes := w.maxInflightBytes
	w.mu.Unlock()

	// max=0 means paused
	if winBatches == 0 || winEvents == 0 || winBytes == 0 {
		return false
	}

	ib, ie, iby := inf.Snapshot()
	return (ib+1 <= winBatches) &&
		(ie+events <= winEvents) &&
		(iby+bytes <= winBytes)
}

// Snapshot returns current window limits.
func (w *Window) Snapshot() (maxBatches int, maxEvents int, maxBytes int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.maxInflightBatches, w.maxInflightEvents, w.maxInflightBytes
}

// ThrottleState tracks the current throttle status.
type ThrottleState struct {
	mu         sync.Mutex
	until      time.Time // when throttle expires
	retryAfter time.Duration
}

// Apply sets the throttle from a THROTTLE message.
func (ts *ThrottleState) Apply(retryDelayMs int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.retryAfter = time.Duration(retryDelayMs) * time.Millisecond
	ts.until = time.Now().Add(ts.retryAfter)
}

// Active returns true if currently throttled.
func (ts *ThrottleState) Active() bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return time.Now().Before(ts.until)
}

// WaitDuration returns how long until the throttle expires.
func (ts *ThrottleState) WaitDuration() time.Duration {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	remaining := time.Until(ts.until)
	if remaining < 0 {
		return 0
	}
	return remaining
}
