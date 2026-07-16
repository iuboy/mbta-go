package core

import (
	"strings"
	"testing"
)

// TestSignalBatchValidate tests the SignalBatch.Validate() method.
func TestSignalBatchValidate(t *testing.T) {
	tests := []struct {
		name    string
		batch   SignalBatch
		wantErr bool
		errSub  string
	}{
		{
			name: "valid SignalBatch",
			batch: SignalBatch{
				SchemaURL: "https://example.com/schema",
				Signals: []*SignalRecord{
					{SignalType: "log", Body: "hello"},
				},
			},
			wantErr: false,
		},
		{
			name: "empty signals",
			batch: SignalBatch{
				SchemaURL: "https://example.com/schema",
				Signals:   []*SignalRecord{},
			},
			wantErr: true,
			errSub:  "signals must not be empty",
		},
		{
			name: "nil signals",
			batch: SignalBatch{
				SchemaURL: "https://example.com/schema",
				Signals:   nil,
			},
			wantErr: true,
			errSub:  "signals must not be empty",
		},
		{
			name: "signal with empty signal_type",
			batch: SignalBatch{
				SchemaURL: "https://example.com/schema",
				Signals: []*SignalRecord{
					{SignalType: ""},
				},
			},
			wantErr: true,
			errSub:  "signal_type is required",
		},
		{
			name: "multiple signals all valid",
			batch: SignalBatch{
				SchemaURL: "https://example.com/schema",
				Signals: []*SignalRecord{
					{SignalType: "log", Body: "msg"},
					{SignalType: "counter", MetricName: "req_total"},
					{SignalType: "span", Name: "GET /api", TraceID: "0123456789abcdef0123456789abcdef", SpanID: "0123456789abcdef"},
				},
			},
			wantErr: false,
		},
		{
			name: "one signal with empty type among valid ones",
			batch: SignalBatch{
				SchemaURL: "https://example.com/schema",
				Signals: []*SignalRecord{
					{SignalType: "log", Body: "msg"},
					{SignalType: ""},
				},
			},
			wantErr: true,
			errSub:  "signal[1]: signal_type is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.batch.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("%s: expected error, got nil", tt.name)
				}
				if err != nil && !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("Error = %v, want error containing %q", err, tt.errSub)
				}
			} else {
				if err != nil {
					t.Errorf("%s: %v", tt.name, err)
				}
			}
		})
	}
}

// TestResource tests Resource structure.
func TestResource(t *testing.T) {
	t.Run("resource with attributes", func(t *testing.T) {
		r := Resource{
			Attributes: map[string]any{
				"service.name": "my-service",
				"host":         "localhost",
			},
		}

		if len(r.Attributes) != 2 {
			t.Errorf("Attributes count = %d, want 2", len(r.Attributes))
		}
		if r.Attributes["service.name"] != "my-service" {
			t.Errorf("service.name = %v, want 'my-service'", r.Attributes["service.name"])
		}
	})

	t.Run("resource with nil attributes", func(t *testing.T) {
		r := Resource{}
		if r.Attributes != nil {
			t.Errorf("Attributes should be nil by default")
		}
	})
}

// TestScope tests Scope structure.
func TestScope(t *testing.T) {
	t.Run("scope with all fields", func(t *testing.T) {
		s := Scope{
			Name:        "otel-collector",
			Version:     "1.0.0",
			CollectorID: "collector-123",
		}

		if s.Name != "otel-collector" {
			t.Errorf("Name = %q, want 'otel-collector'", s.Name)
		}
		if s.Version != "1.0.0" {
			t.Errorf("Version = %q, want '1.0.0'", s.Version)
		}
		if s.CollectorID != "collector-123" {
			t.Errorf("CollectorID = %q, want 'collector-123'", s.CollectorID)
		}
	})

	t.Run("scope with only required fields", func(t *testing.T) {
		s := Scope{Name: "my-collector"}

		if s.Name != "my-collector" {
			t.Errorf("Name = %q, want 'my-collector'", s.Name)
		}
		if s.Version != "" {
			t.Errorf("Version should be empty by default")
		}
	})
}

// TestSignalRecordFields tests SignalRecord with various signal types.
func TestSignalRecordFields(t *testing.T) {
	t.Run("log signal", func(t *testing.T) {
		sig := &SignalRecord{
			SignalType:     "log",
			EventID:        "evt-123",
			TimeUnixMs:     1234567890,
			SeverityNumber: 9,
			SeverityText:   "INFO",
			Body:           "Test log message",
		}

		if sig.SignalType != "log" {
			t.Errorf("SignalType = %q, want 'log'", sig.SignalType)
		}
		if sig.SeverityNumber != 9 {
			t.Errorf("SeverityNumber = %d, want 9", sig.SeverityNumber)
		}
	})

	t.Run("counter signal", func(t *testing.T) {
		sig := &SignalRecord{
			SignalType: "counter",
			MetricName: "http_requests_total",
			MetricFields: map[string]float64{
				"count": 100.0,
				"sum":   0.5,
			},
			Unit:        "1",
			Temporality: "cumulative",
			IsMonotonic: true,
		}

		if sig.SignalType != "counter" {
			t.Errorf("SignalType = %q, want 'counter'", sig.SignalType)
		}
		if sig.MetricName != "http_requests_total" {
			t.Errorf("MetricName = %q, want 'http_requests_total'", sig.MetricName)
		}
		if len(sig.MetricFields) != 2 {
			t.Errorf("MetricFields count = %d, want 2", len(sig.MetricFields))
		}
		if !sig.IsMonotonic {
			t.Errorf("IsMonotonic should be true")
		}
	})

	t.Run("span signal", func(t *testing.T) {
		sig := &SignalRecord{
			SignalType:      "span",
			TraceID:         "0123456789abcdef0123456789abcdef",
			SpanID:          "0123456789abcdef",
			ParentSpanID:    "fedcba9876543210",
			Name:            "HTTP GET /api/users",
			Kind:            "client",
			StartTimeUnixMs: 1234567890,
			EndTimeUnixMs:   1234567900,
			StatusCode:      "OK",
		}

		if sig.SignalType != "span" {
			t.Errorf("SignalType = %q, want 'span'", sig.SignalType)
		}
		if sig.Name != "HTTP GET /api/users" {
			t.Errorf("Name = %q, want 'HTTP GET /api/users'", sig.Name)
		}
		if sig.Kind != "client" {
			t.Errorf("Kind = %q, want 'client'", sig.Kind)
		}
	})
}

// TestSignalRecordWithAttributes tests SignalRecord attributes.
func TestSignalRecordWithAttributes(t *testing.T) {
	sig := &SignalRecord{
		SignalType: "log",
		Attributes: map[string]any{
			"http.method":      "GET",
			"http.status_code": 200,
			"user.id":          "user-123",
		},
	}

	if len(sig.Attributes) != 3 {
		t.Errorf("Attributes count = %d, want 3", len(sig.Attributes))
	}
	if sig.Attributes["http.method"] != "GET" {
		t.Errorf("http.method = %v, want 'GET'", sig.Attributes["http.method"])
	}
}

// TestSignalRecordWithBody tests SignalRecord body field.
func TestSignalRecordWithBody(t *testing.T) {
	tests := []struct {
		name string
		body any
	}{
		{
			name: "string body",
			body: "Test log message",
		},
		{
			name: "nil body",
			body: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := &SignalRecord{
				SignalType: "log",
				Body:       tt.body,
			}

			if sig.Body != tt.body {
				t.Errorf("Body = %v, want %v", sig.Body, tt.body)
			}
		})
	}

	// Test map body separately since we cannot compare maps directly
	t.Run("map body", func(t *testing.T) {
		sig := &SignalRecord{
			SignalType: "log",
			Body:       map[string]any{"message": "Test", "code": 123},
		}

		if sig.Body == nil {
			t.Error("Body should not be nil for map body")
		}
		// Verify we can access the map
		bodyMap, ok := sig.Body.(map[string]any)
		if !ok {
			t.Error("Body should be a map")
		}
		if bodyMap["message"] != "Test" {
			t.Errorf("message = %v, want 'Test'", bodyMap["message"])
		}
	})
}

// TestSignalBatchWithResourceAndScope tests complete SignalBatch.
func TestSignalBatchWithResourceAndScope(t *testing.T) {
	batch := &SignalBatch{
		SchemaURL: "https://opentelemetry.io/schemas/1.0.0",
		Resource: Resource{
			Attributes: map[string]any{
				"service.name":   "my-service",
				"deployment.env": "production",
			},
		},
		Scope: Scope{
			Name:        "my-processor",
			Version:     "1.0.0",
			CollectorID: "collector-123",
		},
		Signals: []*SignalRecord{
			{
				SignalType: "log",
				EventID:    "evt-1",
				Body:       "Test message",
			},
		},
	}

	err := batch.Validate()
	if err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}

	if batch.Resource.Attributes["service.name"] != "my-service" {
		t.Errorf("service.name = %v, want 'my-service'", batch.Resource.Attributes["service.name"])
	}
	if batch.Scope.Name != "my-processor" {
		t.Errorf("Scope Name = %q, want 'my-processor'", batch.Scope.Name)
	}
}

// TestSignalBatchWithMultipleSignals tests batch with multiple signals.
func TestSignalBatchWithMultipleSignals(t *testing.T) {
	batch := &SignalBatch{
		Signals: []*SignalRecord{
			{SignalType: "log", EventID: "evt-1", Body: "msg1"},
			{SignalType: "counter", EventID: "evt-2", MetricName: "m1"},
			{SignalType: "span", EventID: "evt-3", Name: "s1", TraceID: "0123456789abcdef0123456789abcdef", SpanID: "0123456789abcdef"},
			{SignalType: "log", EventID: "evt-4", Body: "msg4"},
		},
	}

	err := batch.Validate()
	if err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}

	if len(batch.Signals) != 4 {
		t.Errorf("Signals count = %d, want 4", len(batch.Signals))
	}
}

// TestSignalRecordTimestamps tests timestamp fields.
func TestSignalRecordTimestamps(t *testing.T) {
	sig := &SignalRecord{
		SignalType:     "log",
		TimeUnixMs:     1234567890,
		ObservedTimeMs: 1234567895,
	}

	if sig.TimeUnixMs != 1234567890 {
		t.Errorf("TimeUnixMs = %d, want 1234567890", sig.TimeUnixMs)
	}
	if sig.ObservedTimeMs != 1234567895 {
		t.Errorf("ObservedTimeMs = %d, want 1234567895", sig.ObservedTimeMs)
	}
}

// TestSignalRecordTraceContext tests trace context fields.
func TestSignalRecordTraceContext(t *testing.T) {
	sig := &SignalRecord{
		SignalType:   "span",
		TraceID:      "0123456789abcdef0123456789abcdef",
		SpanID:       "0123456789abcdef",
		ParentSpanID: "fedcba9876543210",
	}

	if sig.TraceID != "0123456789abcdef0123456789abcdef" {
		t.Errorf("TraceID = %q, want '0123456789abcdef0123456789abcdef'", sig.TraceID)
	}
	if sig.SpanID != "0123456789abcdef" {
		t.Errorf("SpanID = %q, want '0123456789abcdef'", sig.SpanID)
	}
	if sig.ParentSpanID != "fedcba9876543210" {
		t.Errorf("ParentSpanID = %q, want 'fedcba9876543210'", sig.ParentSpanID)
	}
}

// TestSignalRecordW3CTraceContext 校验 W3C trace_flags/trace_state 的协议级承载
// （capability w3c_trace_context，§6.2.2）：校验规则 + proto 编解码往返不丢字段。
func TestSignalRecordW3CTraceContext(t *testing.T) {
	const validTraceID = "0123456789abcdef0123456789abcdef"

	t.Run("trace_flags over 8-bit rejected", func(t *testing.T) {
		b := SignalBatch{Signals: []*SignalRecord{
			{SignalType: "span", Name: "s", TraceID: validTraceID, TraceFlags: 0x100},
		}}
		if err := b.Validate(); err == nil {
			t.Error("expected error for trace_flags > 0xff")
		}
	})

	t.Run("trace_state over 32 entries rejected", func(t *testing.T) {
		sig := &SignalRecord{
			SignalType: "span", Name: "s", TraceID: validTraceID,
			TraceState: make([]*TraceStateEntry, 33),
		}
		for i := range sig.TraceState {
			sig.TraceState[i] = &TraceStateEntry{Key: "k", Value: "v"}
		}
		if err := (&SignalBatch{Signals: []*SignalRecord{sig}}).Validate(); err == nil {
			t.Error("expected error for > 32 trace_state entries")
		}
	})

	t.Run("valid trace context passes", func(t *testing.T) {
		b := SignalBatch{Signals: []*SignalRecord{
			{SignalType: "span", Name: "s", TraceID: validTraceID,
				SpanID: "0123456789abcdef", TraceFlags: 0x01,
				TraceState: []*TraceStateEntry{{Key: "vendor", Value: "value"}}},
		}}
		if err := b.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("proto round-trip preserves trace_flags and trace_state", func(t *testing.T) {
		orig := &SignalBatch{Signals: []*SignalRecord{
			{SignalType: "span", Name: "s", TraceID: validTraceID,
				SpanID: "0123456789abcdef", TraceFlags: 0x01,
				TraceState: []*TraceStateEntry{{Key: "a", Value: "1"}, {Key: "b", Value: "2"}}},
		}}
		data, err := MarshalSignalBatch(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got, err := UnmarshalSignalBatch(data)
		if err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		s := got.Signals[0]
		if s.TraceFlags != 0x01 {
			t.Errorf("TraceFlags = 0x%x, want 0x01", s.TraceFlags)
		}
		if len(s.TraceState) != 2 || s.TraceState[0].Key != "a" || s.TraceState[1].Value != "2" {
			t.Errorf("TraceState order/content lost: %+v", s.TraceState)
		}
	})
}
