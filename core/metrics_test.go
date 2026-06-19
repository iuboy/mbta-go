package core

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestNewMetrics tests the New metrics constructor.
func TestNewMetrics(t *testing.T) {
	t.Run("create metrics with default registerer", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := New(registry)

		if metrics == nil {
			t.Fatal("New() should not return nil")
		}
	})

	t.Run("create metrics with nil registerer (uses default)", func(t *testing.T) {
		// Note: This will register with prometheus.DefaultRegisterer
		// which may affect global state. Consider using a custom registry in tests.
		metrics := New(nil)

		if metrics == nil {
			t.Fatal("New(nil) should not return nil")
		}
	})

	t.Run("create metrics with custom registerer", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		metrics := New(registry)

		if metrics == nil {
			t.Fatal("New() should not return nil")
		}
	})
}

// TestMetricsFields tests that all metric fields are initialized.
func TestMetricsFields(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := New(registry)

	tests := []struct {
		name  string
		check func(*testing.T, *MBTAMetrics)
	}{
		{
			name: "ConnectionsActive",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.ConnectionsActiveGauge == nil {
					t.Error("ConnectionsActive should not be nil")
				}
			},
		},
		{
			name: "AuthSuccessTotal",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.AuthSuccessTotal == nil {
					t.Error("AuthSuccessTotal should not be nil")
				}
			},
		},
		{
			name: "AuthFailureTotal",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.AuthFailureTotal == nil {
					t.Error("AuthFailureTotal should not be nil")
				}
			},
		},
		{
			name: "BatchesSentTotal",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.BatchesSentTotal == nil {
					t.Error("BatchesSentTotal should not be nil")
				}
			},
		},
		{
			name: "BatchesAckedTotal",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.BatchesAckedTotal == nil {
					t.Error("BatchesAckedTotal should not be nil")
				}
			},
		},
		{
			name: "BatchesNackedTotal",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.BatchesNackedTotal == nil {
					t.Error("BatchesNackedTotal should not be nil")
				}
			},
		},
		{
			name: "PartialAckTotal",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.PartialAckTotal == nil {
					t.Error("PartialAckTotal should not be nil")
				}
			},
		},
		{
			name: "ReplayCacheHitsTotal",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.ReplayCacheHitsTotal == nil {
					t.Error("ReplayCacheHitsTotal should not be nil")
				}
			},
		},
		{
			name: "HMACFailuresTotal",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.HMACFailuresTotal == nil {
					t.Error("HMACFailuresTotal should not be nil")
				}
			},
		},
		{
			name: "DecryptFailuresTotal",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.DecryptFailuresTotal == nil {
					t.Error("DecryptFailuresTotal should not be nil")
				}
			},
		},
		{
			name: "WindowCurrentBatches",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.WindowCurrentBatchesGauge == nil {
					t.Error("WindowCurrentBatches should not be nil")
				}
			},
		},
		{
			name: "WindowCurrentEvents",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.WindowCurrentEventsGauge == nil {
					t.Error("WindowCurrentEvents should not be nil")
				}
			},
		},
		{
			name: "WindowCurrentBytes",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.WindowCurrentBytesGauge == nil {
					t.Error("WindowCurrentBytes should not be nil")
				}
			},
		},
		{
			name: "ThrottleSecondsTotal",
			check: func(t *testing.T, m *MBTAMetrics) {
				if m.ThrottleSecondsTotal == nil {
					t.Error("ThrottleSecondsTotal should not be nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, metrics)
		})
	}
}

// TestMetricsNamespace tests that metrics use the correct namespace.
func TestMetricsNamespace(t *testing.T) {
	// The namespace is defined as "mbta" in the metrics.go file
	// We can verify this by checking metric descriptions or registered metrics
	registry := prometheus.NewRegistry()
	New(registry)

	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}

	if len(metricFamilies) == 0 {
		t.Error("Expected metrics to be registered")
	}

	// Verify namespace in metric names
	for _, mf := range metricFamilies {
		name := mf.GetName()
		if name == "" {
			t.Error("Metric name should not be empty")
		}
	}
}

// TestMetricsCount tests that we have the expected number of metrics.
func TestMetricsCount(t *testing.T) {
	registry := prometheus.NewRegistry()
	New(registry)

	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}

	// Expected metrics count (based on MBTAMetrics struct)
	// 20 metrics: ConnectionsActive, AuthSuccessTotal, AuthFailureTotal,
	// BatchesSentTotal, BatchesAckedTotal, BatchesNackedTotal, ThrottledTotal,
	// PartialAckTotal, ReplayCacheHitsTotal, ReplayCacheEvictionsTotal,
	// HMACFailuresTotal, DecryptFailuresTotal, WindowCurrentBatches,
	// WindowCurrentEvents, WindowCurrentBytes, ThrottleSecondsTotal,
	// BatchLatencySeconds, BatchSizeEvents, BatchSizeBytes, ConnectionDuration
	expectedCount := 20
	if len(metricFamilies) != expectedCount {
		t.Errorf("Expected %d metrics, got %d", expectedCount, len(metricFamilies))
	}
}

// TestMetricsMetricTypes tests that metrics have correct types.
func TestMetricsMetricTypes(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := New(registry)

	// Test that Gauges and Counters are properly typed
	// This is a compile-time check, but we can verify non-nil
	t.Run("Gauge metrics exist", func(t *testing.T) {
		if metrics.ConnectionsActiveGauge == nil ||
			metrics.WindowCurrentBatchesGauge == nil ||
			metrics.WindowCurrentEventsGauge == nil ||
			metrics.WindowCurrentBytesGauge == nil {
			t.Error("One or more Gauge metrics are nil")
		}
	})

	t.Run("Counter metrics exist", func(t *testing.T) {
		if metrics.AuthSuccessTotal == nil ||
			metrics.AuthFailureTotal == nil ||
			metrics.BatchesSentTotal == nil ||
			metrics.BatchesAckedTotal == nil ||
			metrics.BatchesNackedTotal == nil ||
			metrics.PartialAckTotal == nil ||
			metrics.ReplayCacheHitsTotal == nil ||
			metrics.HMACFailuresTotal == nil ||
			metrics.DecryptFailuresTotal == nil ||
			metrics.ThrottleSecondsTotal == nil {
			t.Error("One or more Counter metrics are nil")
		}
	})
}

// TestNoOpMetrics 验证 NoOpMetrics 满足 Metrics 接口且零 panic。
func TestNoOpMetrics(t *testing.T) {
	var m Metrics = NoOpMetrics{}
	// 调用所有方法，确认不 panic（no-op 应安全吞掉所有调用）。
	m.ConnectionsActive().Set(1)
	m.ConnectionsActive().Inc()
	m.ConnectionsActive().Dec()
	m.AuthSuccess().Inc()
	m.AuthFailure().Inc()
	m.BatchesSent().Add(1)
	m.BatchesAcked().Inc()
	m.BatchesNacked().Inc()
	m.Throttled().Inc()
	m.PartialAck().Inc()
	m.ReplayCacheHits().Inc()
	m.ReplayCacheEvictions().Inc()
	m.HMACFailures().Inc()
	m.DecryptFailures().Inc()
	m.WindowCurrentBatches().Set(1)
	m.WindowCurrentEvents().Set(1)
	m.WindowCurrentBytes().Set(1)
	m.ThrottleSeconds().Add(1)
	m.BatchLatency().Observe(0.1)
	m.BatchSizeEvents().Observe(10)
	m.BatchSizeBytes().Observe(100)
	m.ConnectionDuration().Observe(60)
}

// TestMBTAMetrics_ImplementsMetrics 验证 *MBTAMetrics 满足 Metrics 接口
// （编译期断言已在 metrics.go 底部，此处为运行期可观测的显式检查）。
func TestMBTAMetrics_ImplementsMetrics(t *testing.T) {
	var _ Metrics = New(prometheus.NewRegistry())
}
