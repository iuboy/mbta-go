package core

import "github.com/prometheus/client_golang/prometheus"

const namespace = "mbta"

// MBTAMetrics holds all Prometheus metrics for the MBTA protocol layer.
type MBTAMetrics struct {
	ConnectionsActive prometheus.Gauge
	AuthSuccessTotal  prometheus.Counter
	AuthFailureTotal  prometheus.Counter

	BatchesSentTotal   prometheus.Counter
	BatchesAckedTotal  prometheus.Counter
	BatchesNackedTotal prometheus.Counter
	PartialAckTotal    prometheus.Counter

	SpoolRecords prometheus.Gauge
	SpoolBytes   prometheus.Gauge

	ReplayCacheHitsTotal prometheus.Counter

	HMACFailuresTotal    prometheus.Counter
	DecryptFailuresTotal prometheus.Counter

	WindowCurrentBatches prometheus.Gauge
	WindowCurrentEvents  prometheus.Gauge
	WindowCurrentBytes   prometheus.Gauge

	ThrottleSecondsTotal prometheus.Counter
}

// New creates and registers all MBTA metrics with the given registerer.
// Pass prometheus.DefaultRegisterer for global registration,
// or a *prometheus.Registry for isolated registration (tests, multi-tenant).
func New(reg prometheus.Registerer) *MBTAMetrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}

	m := &MBTAMetrics{
		ConnectionsActive: newGauge(reg, prometheus.GaugeOpts{
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
		PartialAckTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "partial_ack_total",
			Help:      "Total number of partial acknowledgements",
		}),
		SpoolRecords: newGauge(reg, prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "spool_records",
			Help:      "Current number of records in the durable spool",
		}),
		SpoolBytes: newGauge(reg, prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "spool_bytes",
			Help:      "Current bytes consumed by the durable spool",
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
		WindowCurrentBatches: newGauge(reg, prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "window_current_batches",
			Help:      "Current inflight batches against the flow-control window",
		}),
		WindowCurrentEvents: newGauge(reg, prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "window_current_events",
			Help:      "Current inflight events against the flow-control window",
		}),
		WindowCurrentBytes: newGauge(reg, prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "window_current_bytes",
			Help:      "Current inflight bytes against the flow-control window",
		}),
		ThrottleSecondsTotal: newCounter(reg, prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "throttle_seconds_total",
			Help:      "Total seconds the client has been throttled",
		}),
	}

	return m
}

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
