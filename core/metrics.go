package core

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const namespace = "mbta"

// Counter 是单调递增计数器的最小接口（对应 prometheus.Counter 语义）。
// 抽象出此接口使 protocol 层不直接依赖 prometheus 具体类型，支持注入
// NoOp 实现（无 metrics 场景）或未来其他后端（如 OpenTelemetry）。
//
// Add 必须传入非负值：prometheus.Counter.Add 对负值 panic（进程崩溃）。
// 若调用方无法保证入参非负，建议使用 NewGuardedCounter 包装。
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

	// 重放保护

	// 安全失败
	HMACFailures() Counter
	DecryptFailures() Counter

	// sink 投递失败（BatchHandler 返回错误或 panic 时递增）。
	// ACK_MODE_ACCEPTED 已发但 sink 持久化失败=潜在数据丢失。
	SinkFailures() Counter

	// 流控窗口
	CreditsOutstanding() Gauge
	SinkQueueDepth() Gauge

	// 关键 SLI 直方图
	BatchLatency() Histogram    // SendBatch → ACK latency
	BatchSizeEvents() Histogram // events per batch distribution
	BatchSizeBytes() Histogram  // bytes per batch distribution
	ConnectionDuration() Histogram
}

// MBTAMetrics 是 Metrics 的 prometheus 后端实现。
//
// 所有字段为非导出（小写）：外部必须通过 Metrics 接口的 getter 方法访问，
// Counter 类方法返回 guardedCounter 包装，防止负值 Add 触发 prometheus panic。
// New(reg) 返回的 *MBTAMetrics 可直接赋值给 Metrics 类型的配置字段。
type MBTAMetrics struct {
	connectionsActiveGauge prometheus.Gauge
	authSuccessTotal       prometheus.Counter
	authFailureTotal       prometheus.Counter

	batchesSentTotal prometheus.Counter

	hmacFailuresTotal    prometheus.Counter
	decryptFailuresTotal prometheus.Counter
	sinkFailuresTotal    prometheus.Counter

	// Key SLI histograms
	batchLatencySeconds     prometheus.Histogram // SendBatch → ACK latency
	batchSizeEventsHist     prometheus.Histogram // events per batch distribution
	creditsOutstandingGauge prometheus.Gauge     // 当前 outstanding 批数（模型 B 服务端视图）
	sinkQueueDepthGauge     prometheus.Gauge     // sink 异步队列当前深度
	batchSizeBytesHist      prometheus.Histogram // bytes per batch distribution
	connectionDurationSec   prometheus.Histogram // connection lifetime
}

// 接口实现：MBTAMetrics 满足 Metrics。每个方法返回底层 prometheus 指标
// （prometheus.Gauge/Counter/Histogram 已满足对应的最小接口）。
// Counter 类方法统一返回 guardedCounter，防御负值 Add panic。

func (m *MBTAMetrics) ConnectionsActive() Gauge      { return m.connectionsActiveGauge }
func (m *MBTAMetrics) AuthSuccess() Counter          { return guardedCounter{m.authSuccessTotal} }
func (m *MBTAMetrics) AuthFailure() Counter          { return guardedCounter{m.authFailureTotal} }
func (m *MBTAMetrics) BatchesSent() Counter          { return guardedCounter{m.batchesSentTotal} }
func (m *MBTAMetrics) HMACFailures() Counter         { return guardedCounter{m.hmacFailuresTotal} }
func (m *MBTAMetrics) DecryptFailures() Counter      { return guardedCounter{m.decryptFailuresTotal} }
func (m *MBTAMetrics) SinkFailures() Counter         { return guardedCounter{m.sinkFailuresTotal} }
func (m *MBTAMetrics) BatchLatency() Histogram       { return m.batchLatencySeconds }
func (m *MBTAMetrics) BatchSizeEvents() Histogram    { return m.batchSizeEventsHist }
func (m *MBTAMetrics) CreditsOutstanding() Gauge     { return m.creditsOutstandingGauge }
func (m *MBTAMetrics) SinkQueueDepth() Gauge         { return m.sinkQueueDepthGauge }
func (m *MBTAMetrics) BatchSizeBytes() Histogram     { return m.batchSizeBytesHist }
func (m *MBTAMetrics) ConnectionDuration() Histogram { return m.connectionDurationSec }

// New creates and registers all MBTA metrics with the given registerer.
// Pass prometheus.DefaultRegisterer for global registration,
// or a *prometheus.Registry for isolated registration (tests, multi-tenant).
func New(reg prometheus.Registerer) *MBTAMetrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}

	m := &MBTAMetrics{
		connectionsActiveGauge: newGauge(reg, prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "connections_active",
			Help:      "Current number of active MBTA connections",
		}),
		authSuccessTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "auth_success_total",
			Help:      "Total number of successful authentications",
		}),
		authFailureTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "auth_failure_total",
			Help:      "Total number of failed authentications",
		}),
		batchesSentTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "batches_sent_total",
			Help:      "Total number of batches sent by agents",
		}),
		hmacFailuresTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "hmac_failures_total",
			Help:      "Total number of HMAC verification failures",
		}),
		decryptFailuresTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "decrypt_failures_total",
			Help:      "Total number of decryption failures",
		}),
		sinkFailuresTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "sink_failures_total",
			Help:      "Total sink delivery failures (handler error or panic after terminal result)",
		}),
		batchLatencySeconds: newHistogram(reg, prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "batch_latency_seconds",
			Help:      "Latency from SendBatch to ACK in seconds",
			Buckets:   []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}),
		creditsOutstandingGauge: newGauge(reg, prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "credits_outstanding",
			Help:      "Current outstanding credit batches (granted minus recovered)",
		}),
		sinkQueueDepthGauge: newGauge(reg, prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "sink_queue_depth",
			Help:      "Current sink async queue depth (tasks)",
		}),
		batchSizeEventsHist: newHistogram(reg, prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "batch_size_events",
			Help:      "Number of events per batch",
			Buckets:   []float64{1, 5, 10, 50, 100, 500, 1000, 5000, 10000},
		}),
		batchSizeBytesHist: newHistogram(reg, prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "batch_size_bytes",
			Help:      "Batch size in bytes",
			Buckets:   []float64{100, 1000, 10000, 100000, 1000000, 10000000},
		}),
		connectionDurationSec: newHistogram(reg, prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "connection_duration_seconds",
			Help:      "Connection lifetime in seconds",
			Buckets:   []float64{60, 300, 900, 1800, 3600, 21600, 43200, 86400},
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
func (NoOpMetrics) HMACFailures() Counter         { return noopCounter{} }
func (NoOpMetrics) DecryptFailures() Counter      { return noopCounter{} }
func (NoOpMetrics) SinkFailures() Counter         { return noopCounter{} }
func (NoOpMetrics) BatchLatency() Histogram       { return noopHistogram{} }
func (NoOpMetrics) CreditsOutstanding() Gauge     { return noopGauge{} }
func (NoOpMetrics) ResultsByLevel(string) Counter { return noopCounter{} }
func (NoOpMetrics) SinkQueueDepth() Gauge         { return noopGauge{} }
func (NoOpMetrics) BatchSizeEvents() Histogram    { return noopHistogram{} }
func (NoOpMetrics) BatchSizeBytes() Histogram     { return noopHistogram{} }
func (NoOpMetrics) ConnectionDuration() Histogram { return noopHistogram{} }

type noopCounter struct{}

func (noopCounter) Inc()        {}
func (noopCounter) Add(float64) {}

type noopGauge struct{}

func (noopGauge) Set(float64) {}
func (noopGauge) Inc()        {}
func (noopGauge) Dec()        {}
func (noopGauge) Add(float64) {}

type noopHistogram struct{}

func (noopHistogram) Observe(float64) {}

// guardedCounter 包装 prometheus.Counter，丢弃负值 Add（避免 Go client panic）。
type guardedCounter struct {
	c prometheus.Counter
}

func (g guardedCounter) Inc() { g.c.Inc() }
func (g guardedCounter) Add(v float64) {
	if v < 0 {
		slog.Warn("counter.Add called with negative value, dropping to prevent panic",
			"value", v)
		return
	}
	g.c.Add(v)
}
func (g guardedCounter) Desc() *prometheus.Desc              { return g.c.Desc() }
func (g guardedCounter) Write(m *dto.Metric) error           { return g.c.Write(m) }
func (g guardedCounter) Describe(ch chan<- *prometheus.Desc) { g.c.Describe(ch) }
func (g guardedCounter) Collect(ch chan<- prometheus.Metric) { g.c.Collect(ch) }

// compile-time assertions: guardedCounter satisfies prometheus.Counter and Counter.
var (
	_ prometheus.Counter = guardedCounter{}
	_ Counter            = guardedCounter{}
)

// registerOrExisting 注册 collector；已注册（重复 New）时返回已有 collector，跨包类型冲突时降级返回新 collector（避免 panic）。
func registerOrExisting[T prometheus.Collector](reg prometheus.Registerer, c T) T {
	if err := reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(T); ok {
				return existing
			}
			// 同名异类指标冲突：返回新建（未注册）的 collector，避免 panic。
			slog.Warn("metric registered with different type, returning new unregistered collector",
				"existing_type", fmt.Sprintf("%T", are.ExistingCollector))
			return c
		}
		// 非重复注册的意外错误：无法恢复，panic 保持与 MustRegister 一致的可观测性。
		panic(err)
	}
	return c
}

func newCounter(reg prometheus.Registerer, opts prometheus.CounterOpts) prometheus.Counter {
	return registerOrExisting(reg, prometheus.NewCounter(opts))
}

func newGauge(reg prometheus.Registerer, opts prometheus.GaugeOpts) prometheus.Gauge {
	return registerOrExisting(reg, prometheus.NewGauge(opts))
}

func newHistogram(reg prometheus.Registerer, opts prometheus.HistogramOpts) prometheus.Histogram {
	return registerOrExisting(reg, prometheus.NewHistogram(opts))
}

// 编译期断言：*MBTAMetrics 与 NoOpMetrics 都满足 Metrics 接口。
var (
	_ Metrics = (*MBTAMetrics)(nil)
	_ Metrics = NoOpMetrics{}
)
