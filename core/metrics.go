package core

import (
	"errors"
	"fmt"
	"log/slog"
	"math"

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
	// Inc 将计数器加 1。
	Inc()
	// Add 将计数器增加 v（必须为非负有限值，见接口说明）。
	Add(float64)
}

// Gauge 是可增可减的瞬时值接口（对应 prometheus.Gauge 语义）。
type Gauge interface {
	// Set 将瞬时值设为 v。
	Set(float64)
	// Inc 将瞬时值加 1。
	Inc()
	// Dec 将瞬时值减 1。
	Dec()
	// Add 将瞬时值增加 v。
	Add(float64)
}

// Histogram 是观测值分布接口（对应 prometheus.Histogram 语义）。
type Histogram interface {
	// Observe 记录一个观测值。
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
	// —— 连接与认证 ——

	// ConnectionsActive 返回当前活跃连接数的 Gauge。
	ConnectionsActive() Gauge
	// AuthSuccess 返回认证成功计数的 Counter。
	AuthSuccess() Counter
	// AuthFailure 返回认证失败计数的 Counter。
	AuthFailure() Counter

	// —— 批次投递 ——

	// BatchesSent 返回已发送 batch 计数的 Counter。
	BatchesSent() Counter

	// —— 安全失败 ——

	// HMACFailures 返回 HMAC 校验失败计数的 Counter。
	HMACFailures() Counter
	// DecryptFailures 返回解密失败计数的 Counter。
	DecryptFailures() Counter

	// SinkFailures 返回 sink 投递失败计数的 Counter：服务端侧 handler panic 时
	// 递增；客户端侧收到 rejected / released 终态 RESULT 时递增（批次未成功投递，
	// durable 模式下即潜在数据丢失）。
	SinkFailures() Counter

	// —— 流控与队列 ——

	// CreditsOutstanding 返回当前未回收 credit 批数的 Gauge（模型 B 服务端视图）。
	CreditsOutstanding() Gauge
	// SinkQueueDepth 返回 sink 异步投递队列当前深度的 Gauge。
	SinkQueueDepth() Gauge

	// —— 关键 SLI 直方图 ——

	// BatchLatency 观测 batch 从发送到收到 RESULT 反馈的时延（秒）。
	BatchLatency() Histogram
	// BatchSizeEvents 观测每 batch 的事件数分布。
	BatchSizeEvents() Histogram
	// BatchSizeBytes 观测每 batch 的字节大小分布。
	BatchSizeBytes() Histogram
	// ConnectionDuration 观测连接存续时长（秒）。
	ConnectionDuration() Histogram
}

// MBTAMetrics 是 Metrics 的 prometheus 后端实现。
//
// 所有字段为非导出（小写）：外部必须通过 Metrics 接口的 getter 方法访问，
// Counter 类方法返回 guardedCounter 包装，拒绝负值与 NaN/Inf 的 Add（防
// prometheus panic 与计数器永久毒化）。NewMetrics 返回的 *MBTAMetrics 可
// 直接赋值给 Metrics 类型的配置字段。
type MBTAMetrics struct {
	connectionsActiveGauge prometheus.Gauge
	authSuccessTotal       prometheus.Counter
	authFailureTotal       prometheus.Counter

	batchesSentTotal prometheus.Counter

	hmacFailuresTotal    prometheus.Counter
	decryptFailuresTotal prometheus.Counter
	sinkFailuresTotal    prometheus.Counter

	// 关键 SLI 直方图。
	batchLatencySeconds     prometheus.Histogram // SendBatch → RESULT 反馈时延（秒）
	batchSizeEventsHist     prometheus.Histogram // 每 batch 事件数分布
	creditsOutstandingGauge prometheus.Gauge     // 当前 outstanding 批数（模型 B 服务端视图）
	sinkQueueDepthGauge     prometheus.Gauge     // sink 异步队列当前深度
	batchSizeBytesHist      prometheus.Histogram // 每 batch 字节大小分布
	connectionDurationSec   prometheus.Histogram // 连接存续时长（秒）
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

// Deprecated: 语义不明（core.New 创建的是指标集），改用 NewMetrics。本别名
// 在破坏性重构收尾时删除。
//
// New 创建并注册全部 MBTA 指标。传 prometheus.DefaultRegisterer 做全局注册，
// 或传独立 *prometheus.Registry 做隔离注册（测试、多租户）。
func New(reg prometheus.Registerer) *MBTAMetrics { return NewMetrics(reg) }

// NewMetrics 创建并注册全部 MBTA 指标（reg=nil 时用全局 DefaultRegisterer；
// 测试/多租户传独立 *prometheus.Registry）。
func NewMetrics(reg prometheus.Registerer) *MBTAMetrics {
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
			Help:      "Total sink delivery failures (server: sink handler panic; client: rejected/released terminal RESULT)",
		}),
		batchLatencySeconds: newHistogram(reg, prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "batch_latency_seconds",
			Help:      "Latency from SendBatch to terminal RESULT in seconds",
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

// guardedCounter 包装 prometheus.Counter，丢弃非法 Add：负值（Go client panic）
// 与 NaN/+Inf（实测会静默通过并把计数器永久毒化为 NaN/Inf，scrape 持续输出
// 坏值且不可恢复——比 panic 更隐蔽）。
type guardedCounter struct {
	c prometheus.Counter
}

func (g guardedCounter) Inc() { g.c.Inc() }
func (g guardedCounter) Add(v float64) {
	if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		slog.Warn("counter.Add called with non-finite/negative value, dropping",
			"value", v)
		return
	}
	g.c.Add(v)
}
func (g guardedCounter) Desc() *prometheus.Desc              { return g.c.Desc() }
func (g guardedCounter) Write(m *dto.Metric) error           { return g.c.Write(m) }
func (g guardedCounter) Describe(ch chan<- *prometheus.Desc) { g.c.Describe(ch) }
func (g guardedCounter) Collect(ch chan<- prometheus.Metric) { g.c.Collect(ch) }

// 编译期断言：guardedCounter 同时满足 prometheus.Counter 与 Counter。
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
