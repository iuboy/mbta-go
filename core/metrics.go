package core

import "github.com/prometheus/client_golang/prometheus"

const namespace = "mbta"

// Counter 是单调递增计数器的最小接口（对应 prometheus.Counter 语义）。
// 抽象出此接口使 protocol 层不直接依赖 prometheus 具体类型，支持注入
// NoOp 实现（无 metrics 场景）或未来其他后端（如 OpenTelemetry）。
type Counter interface {
	Inc()
	Add(float64)
}

// Gauge 是可增可减的瞬时值接口（对应 prometheus.Gauge 语义）。
type Gauge interface {
	Set(float64)
	Inc()
	Dec()
	Add(float64)
}

// Histogram 是观测值分布接口（对应 prometheus.Histogram 语义）。
type Histogram interface {
	Observe(float64)
}

// Metrics 是 MBTA 协议层的可观测性抽象。
//
// protocol 层通过此接口记录指标，与具体后端解耦：
//   - 默认实现 MBTAMetrics（prometheus 后端，见 New）；
//   - NoOpMetrics 用于不需要指标的场景（测试、轻量嵌入）；
//   - 未来可添加 OpenTelemetry 等后端实现。
//
// 方法式 API（如 AuthFailure() 而非字段 AuthFailureTotal）让接口定义自包含，
// 且各实现可惰性构造返回值。HandlerConfig.Metrics 为 nil 时 handler 视作 NoOp。
type Metrics interface {
	// 连接与认证
	ConnectionsActive() Gauge
	AuthSuccess() Counter
	AuthFailure() Counter

	// 批次投递
	BatchesSent() Counter
	BatchesAcked() Counter
	BatchesNacked() Counter
	Throttled() Counter
	PartialAck() Counter

	// 重放保护
	ReplayCacheHits() Counter
	ReplayCacheEvictions() Counter

	// 安全失败
	HMACFailures() Counter
	DecryptFailures() Counter

	// 流控窗口
	WindowCurrentBatches() Gauge
	WindowCurrentEvents() Gauge
	WindowCurrentBytes() Gauge

	ThrottleSeconds() Counter

	// 关键 SLI 直方图
	BatchLatency() Histogram   // SendBatch → ACK latency
	BatchSizeEvents() Histogram // events per batch distribution
	BatchSizeBytes() Histogram  // bytes per batch distribution
	ConnectionDuration() Histogram
}

// MBTAMetrics 是 Metrics 的 prometheus 后端实现。
//
// 字段直接持有 prometheus 指标（向后兼容：现有代码若直接访问字段仍可工作），
// 同时实现 Metrics 接口供 protocol 层使用。New(reg) 返回的 *MBTAMetrics 可直接
// 赋值给 Metrics 类型的配置字段，零迁移成本。
type MBTAMetrics struct {
	ConnectionsActiveGauge prometheus.Gauge
	AuthSuccessTotal       prometheus.Counter
	AuthFailureTotal       prometheus.Counter

	BatchesSentTotal   prometheus.Counter
	BatchesAckedTotal  prometheus.Counter
	BatchesNackedTotal prometheus.Counter
	ThrottledTotal     prometheus.Counter
	PartialAckTotal    prometheus.Counter

	ReplayCacheHitsTotal prometheus.Counter

	ReplayCacheEvictionsTotal prometheus.Counter

	HMACFailuresTotal    prometheus.Counter
	DecryptFailuresTotal prometheus.Counter

	WindowCurrentBatchesGauge prometheus.Gauge
	WindowCurrentEventsGauge  prometheus.Gauge
	WindowCurrentBytesGauge   prometheus.Gauge

	ThrottleSecondsTotal prometheus.Counter

	// Key SLI histograms
	BatchLatencySeconds   prometheus.Histogram // SendBatch → ACK latency
	BatchSizeEventsHist   prometheus.Histogram // events per batch distribution
	BatchSizeBytesHist    prometheus.Histogram // bytes per batch distribution
	ConnectionDurationSec prometheus.Histogram // connection lifetime
}

// 接口实现：MBTAMetrics 满足 Metrics。每个方法返回底层 prometheus 指标
// （prometheus.Gauge/Counter/Histogram 已满足对应的最小接口）。
// 字段名加后缀（Gauge/Total/Hist/Sec）避免与方法名冲突。

func (m *MBTAMetrics) ConnectionsActive() Gauge      { return m.ConnectionsActiveGauge }
func (m *MBTAMetrics) AuthSuccess() Counter          { return m.AuthSuccessTotal }
func (m *MBTAMetrics) AuthFailure() Counter          { return m.AuthFailureTotal }
func (m *MBTAMetrics) BatchesSent() Counter          { return m.BatchesSentTotal }
func (m *MBTAMetrics) BatchesAcked() Counter         { return m.BatchesAckedTotal }
func (m *MBTAMetrics) BatchesNacked() Counter        { return m.BatchesNackedTotal }
func (m *MBTAMetrics) Throttled() Counter            { return m.ThrottledTotal }
func (m *MBTAMetrics) PartialAck() Counter           { return m.PartialAckTotal }
func (m *MBTAMetrics) ReplayCacheHits() Counter      { return m.ReplayCacheHitsTotal }
func (m *MBTAMetrics) ReplayCacheEvictions() Counter { return m.ReplayCacheEvictionsTotal }
func (m *MBTAMetrics) HMACFailures() Counter         { return m.HMACFailuresTotal }
func (m *MBTAMetrics) DecryptFailures() Counter      { return m.DecryptFailuresTotal }
func (m *MBTAMetrics) WindowCurrentBatches() Gauge   { return m.WindowCurrentBatchesGauge }
func (m *MBTAMetrics) WindowCurrentEvents() Gauge    { return m.WindowCurrentEventsGauge }
func (m *MBTAMetrics) WindowCurrentBytes() Gauge     { return m.WindowCurrentBytesGauge }
func (m *MBTAMetrics) ThrottleSeconds() Counter      { return m.ThrottleSecondsTotal }
func (m *MBTAMetrics) BatchLatency() Histogram       { return m.BatchLatencySeconds }
func (m *MBTAMetrics) BatchSizeEvents() Histogram    { return m.BatchSizeEventsHist }
func (m *MBTAMetrics) BatchSizeBytes() Histogram     { return m.BatchSizeBytesHist }
func (m *MBTAMetrics) ConnectionDuration() Histogram { return m.ConnectionDurationSec }

// New creates and registers all MBTA metrics with the given registerer.
// Pass prometheus.DefaultRegisterer for global registration,
// or a *prometheus.Registry for isolated registration (tests, multi-tenant).
func New(reg prometheus.Registerer) *MBTAMetrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}

	m := &MBTAMetrics{
		ConnectionsActiveGauge: newGauge(reg, prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "connections_active",
			Help:      "Current number of active MBTA connections",
		}),
		AuthSuccessTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "auth_success_total",
			Help:      "Total number of successful authentications",
		}),
		AuthFailureTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "auth_failure_total",
			Help:      "Total number of failed authentications",
		}),
		BatchesSentTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "batches_sent_total",
			Help:      "Total number of batches sent by agents",
		}),
		BatchesAckedTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "batches_acked_total",
			Help:      "Total number of batches acknowledged",
		}),
		BatchesNackedTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "batches_nacked_total",
			Help:      "Total number of batches rejected (NACK)",
		}),
		ThrottledTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "throttled_total",
			Help:      "Total number of THROTTLE frames sent to clients",
		}),
		PartialAckTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "partial_ack_total",
			Help:      "Total number of partial acknowledgements",
		}),
		ReplayCacheHitsTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "replay_cache_hits_total",
			Help:      "Total number of replay cache duplicate detections",
		}),
		HMACFailuresTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "hmac_failures_total",
			Help:      "Total number of HMAC verification failures",
		}),
		DecryptFailuresTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "decrypt_failures_total",
			Help:      "Total number of decryption failures",
		}),
		WindowCurrentBatchesGauge: newGauge(reg, prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "window_current_batches",
			Help:      "Current inflight batches against the flow-control window",
		}),
		WindowCurrentEventsGauge: newGauge(reg, prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "window_current_events",
			Help:      "Current inflight events against the flow-control window",
		}),
		WindowCurrentBytesGauge: newGauge(reg, prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "window_current_bytes",
			Help:      "Current inflight bytes against the flow-control window",
		}),
		ThrottleSecondsTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "throttle_seconds_total",
			Help:      "Total seconds the client has been throttled",
		}),
		BatchLatencySeconds: newHistogram(reg, prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "batch_latency_seconds",
			Help:      "Latency from SendBatch to ACK in seconds",
			Buckets:   []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}),
		BatchSizeEventsHist: newHistogram(reg, prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "batch_size_events",
			Help:      "Number of events per batch",
			Buckets:   []float64{1, 5, 10, 50, 100, 500, 1000, 5000, 10000},
		}),
		BatchSizeBytesHist: newHistogram(reg, prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "batch_size_bytes",
			Help:      "Batch size in bytes",
			Buckets:   []float64{100, 1000, 10000, 100000, 1000000, 10000000},
		}),
		ConnectionDurationSec: newHistogram(reg, prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "connection_duration_seconds",
			Help:      "Connection lifetime in seconds",
			Buckets:   []float64{60, 300, 900, 1800, 3600, 21600, 43200, 86400},
		}),
		ReplayCacheEvictionsTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "replay_cache_evictions_total",
			Help:      "Total number of replay cache evictions",
		}),
	}

	return m
}

// NoOpMetrics 是 Metrics 的空实现，所有方法返回 no-op 指标（零开销）。
// 用于不需要指标的场景（测试、轻量嵌入），或作为 HandlerConfig.Metrics 为 nil 时的回退。
type NoOpMetrics struct{}

func (NoOpMetrics) ConnectionsActive() Gauge      { return noopGauge{} }
func (NoOpMetrics) AuthSuccess() Counter          { return noopCounter{} }
func (NoOpMetrics) AuthFailure() Counter          { return noopCounter{} }
func (NoOpMetrics) BatchesSent() Counter          { return noopCounter{} }
func (NoOpMetrics) BatchesAcked() Counter         { return noopCounter{} }
func (NoOpMetrics) BatchesNacked() Counter        { return noopCounter{} }
func (NoOpMetrics) Throttled() Counter            { return noopCounter{} }
func (NoOpMetrics) PartialAck() Counter           { return noopCounter{} }
func (NoOpMetrics) ReplayCacheHits() Counter      { return noopCounter{} }
func (NoOpMetrics) ReplayCacheEvictions() Counter { return noopCounter{} }
func (NoOpMetrics) HMACFailures() Counter         { return noopCounter{} }
func (NoOpMetrics) DecryptFailures() Counter      { return noopCounter{} }
func (NoOpMetrics) WindowCurrentBatches() Gauge   { return noopGauge{} }
func (NoOpMetrics) WindowCurrentEvents() Gauge    { return noopGauge{} }
func (NoOpMetrics) WindowCurrentBytes() Gauge     { return noopGauge{} }
func (NoOpMetrics) ThrottleSeconds() Counter      { return noopCounter{} }
func (NoOpMetrics) BatchLatency() Histogram       { return noopHistogram{} }
func (NoOpMetrics) BatchSizeEvents() Histogram    { return noopHistogram{} }
func (NoOpMetrics) BatchSizeBytes() Histogram     { return noopHistogram{} }
func (NoOpMetrics) ConnectionDuration() Histogram { return noopHistogram{} }

type noopCounter struct{}

func (noopCounter) Inc()        {}
func (noopCounter) Add(float64) {}

type noopGauge struct{}

func (noopGauge) Set(float64)  {}
func (noopGauge) Inc()         {}
func (noopGauge) Dec()         {}
func (noopGauge) Add(float64)  {}

type noopHistogram struct{}

func (noopHistogram) Observe(float64) {}

func newCounter(reg prometheus.Registerer, opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	reg.MustRegister(c)
	return c
}

func newGauge(reg prometheus.Registerer, opts prometheus.GaugeOpts) prometheus.Gauge {
	g := prometheus.NewGauge(opts)
	reg.MustRegister(g)
	return g
}

func newHistogram(reg prometheus.Registerer, opts prometheus.HistogramOpts) prometheus.Histogram {
	h := prometheus.NewHistogram(opts)
	reg.MustRegister(h)
	return h
}

// 编译期断言：*MBTAMetrics 与 NoOpMetrics 都满足 Metrics 接口。
var (
	_ Metrics = (*MBTAMetrics)(nil)
	_ Metrics = NoOpMetrics{}
)
