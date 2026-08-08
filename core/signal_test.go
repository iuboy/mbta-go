package core

import (
	"strings"
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/testutil"
)

// TestSignalBatchValidate tests the SignalBatch.Validate() method.
func TestSignalBatchValidate(t *testing.T) {
	schemaURL := "https://" + testutil.RandString(10) + ".com/schema"
	tests := []struct {
		name    string
		batch   SignalBatch
		wantErr bool
		errSub  string
	}{
		{
			name: "valid SignalBatch",
			batch: SignalBatch{
				SchemaURL: schemaURL,
				Signals: []*SignalRecord{
					{SignalType: "log", Body: testutil.RandPayloadString(8)},
				},
			},
			wantErr: false,
		},
		{
			name: "empty signals",
			batch: SignalBatch{
				SchemaURL: schemaURL,
				Signals:   []*SignalRecord{},
			},
			wantErr: true,
			errSub:  "signals must not be empty",
		},
		{
			name: "nil signals",
			batch: SignalBatch{
				SchemaURL: schemaURL,
				Signals:   nil,
			},
			wantErr: true,
			errSub:  "signals must not be empty",
		},
		{
			name: "signal with empty signal_type",
			batch: SignalBatch{
				SchemaURL: schemaURL,
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
				SchemaURL: schemaURL,
				Signals: []*SignalRecord{
					{SignalType: "log", Body: testutil.RandPayloadString(6)},
					{SignalType: "counter", MetricName: testutil.RandString(10)},
					{SignalType: "span", Name: testutil.RandString(12), TraceID: testutil.RandTraceID(), SpanID: testutil.RandSpanID()},
				},
			},
			wantErr: false,
		},
		{
			name: "one signal with empty type among valid ones",
			batch: SignalBatch{
				SchemaURL: schemaURL,
				Signals: []*SignalRecord{
					{SignalType: "log", Body: testutil.RandPayloadString(6)},
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
		svcName := "svc-" + testutil.RandString(8)
		hostName := testutil.RandHost()
		r := Resource{
			Attributes: map[string]any{
				"service.name": svcName,
				"host":         hostName,
			},
		}

		if len(r.Attributes) != 2 {
			t.Errorf("Attributes count = %d, want 2", len(r.Attributes))
		}
		if r.Attributes["service.name"] != svcName {
			t.Errorf("service.name = %v, want %q", r.Attributes["service.name"], svcName)
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
		name := "scope-" + testutil.RandString(6)
		version := testutil.RandVersion()
		collector := "collector-" + testutil.RandString(6)
		s := Scope{
			Name:        name,
			Version:     version,
			CollectorID: collector,
		}

		if s.Name != name {
			t.Errorf("Name = %q, want %q", s.Name, name)
		}
		if s.Version != version {
			t.Errorf("Version = %q, want %q", s.Version, version)
		}
		if s.CollectorID != collector {
			t.Errorf("CollectorID = %q, want %q", s.CollectorID, collector)
		}
	})

	t.Run("scope with only required fields", func(t *testing.T) {
		name := "scope-" + testutil.RandString(6)
		s := Scope{Name: name}

		if s.Name != name {
			t.Errorf("Name = %q, want %q", s.Name, name)
		}
		if s.Version != "" {
			t.Errorf("Version should be empty by default")
		}
	})
}

// TestSignalRecordFields tests SignalRecord with various signal types.
func TestSignalRecordFields(t *testing.T) {
	t.Run("log signal", func(t *testing.T) {
		eventID := testutil.RandEventID()
		ts := int64(testutil.RandInt(1, 2_000_000_000))
		severity := testutil.RandInt(1, 24)
		body := "log-" + testutil.RandString(12)
		sig := &SignalRecord{
			SignalType:     "log",
			EventID:        eventID,
			TimeUnixMs:     ts,
			SeverityNumber: severity,
			SeverityText:   "INFO",
			Body:           body,
		}

		if sig.SignalType != "log" {
			t.Errorf("SignalType = %q, want 'log'", sig.SignalType)
		}
		if sig.SeverityNumber != severity {
			t.Errorf("SeverityNumber = %d, want %d", sig.SeverityNumber, severity)
		}
	})

	t.Run("counter signal", func(t *testing.T) {
		metricName := "metric-" + testutil.RandString(10)
		sig := &SignalRecord{
			SignalType: "counter",
			MetricName: metricName,
			MetricFields: map[string]float64{
				"count": float64(testutil.RandInt(1, 1000)),
				"sum":   float64(testutil.RandInt(1, 1000)) / 10.0,
			},
			Unit:        "1",
			Temporality: "cumulative",
			IsMonotonic: true,
		}

		if sig.SignalType != "counter" {
			t.Errorf("SignalType = %q, want 'counter'", sig.SignalType)
		}
		if sig.MetricName != metricName {
			t.Errorf("MetricName = %q, want %q", sig.MetricName, metricName)
		}
		if len(sig.MetricFields) != 2 {
			t.Errorf("MetricFields count = %d, want 2", len(sig.MetricFields))
		}
		if !sig.IsMonotonic {
			t.Errorf("IsMonotonic should be true")
		}
	})

	t.Run("span signal", func(t *testing.T) {
		traceID := testutil.RandTraceID()
		spanID := testutil.RandSpanID()
		parentSpanID := testutil.RandSpanID()
		name := "op-" + testutil.RandString(10)
		sig := &SignalRecord{
			SignalType:      "span",
			TraceID:         traceID,
			SpanID:          spanID,
			ParentSpanID:    parentSpanID,
			Name:            name,
			Kind:            "client",
			StartTimeUnixMs: int64(testutil.RandInt(1, 2_000_000_000)),
			EndTimeUnixMs:   int64(testutil.RandInt(1, 2_000_000_000)),
			StatusCode:      "OK",
		}

		if sig.SignalType != "span" {
			t.Errorf("SignalType = %q, want 'span'", sig.SignalType)
		}
		if sig.Name != name {
			t.Errorf("Name = %q, want %q", sig.Name, name)
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
			"http.status_code": testutil.RandInt(100, 600),
			"user.id":          "user-" + testutil.RandString(8),
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
			body: "log-" + testutil.RandString(12),
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
		msgVal := "val-" + testutil.RandString(6)
		sig := &SignalRecord{
			SignalType: "log",
			Body:       map[string]any{"message": msgVal, "code": testutil.RandInt(1, 1000)},
		}

		if sig.Body == nil {
			t.Error("Body should not be nil for map body")
		}
		// Verify we can access the map
		bodyMap, ok := sig.Body.(map[string]any)
		if !ok {
			t.Error("Body should be a map")
		}
		if bodyMap["message"] != msgVal {
			t.Errorf("message = %v, want %q", bodyMap["message"], msgVal)
		}
	})
}

// TestSignalBatchWithResourceAndScope tests complete SignalBatch.
func TestSignalBatchWithResourceAndScope(t *testing.T) {
	svcName := "svc-" + testutil.RandString(8)
	scopeName := "scope-" + testutil.RandString(8)
	batch := &SignalBatch{
		SchemaURL: "https://opentelemetry.io/schemas/1.0.0",
		Resource: Resource{
			Attributes: map[string]any{
				"service.name":   svcName,
				"deployment.env": "production",
			},
		},
		Scope: Scope{
			Name:        scopeName,
			Version:     testutil.RandVersion(),
			CollectorID: "collector-" + testutil.RandString(6),
		},
		Signals: []*SignalRecord{
			{
				SignalType: "log",
				EventID:    testutil.RandEventID(),
				Body:       "msg-" + testutil.RandString(10),
			},
		},
	}

	err := batch.Validate()
	if err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}

	if batch.Resource.Attributes["service.name"] != svcName {
		t.Errorf("service.name = %v, want %q", batch.Resource.Attributes["service.name"], svcName)
	}
	if batch.Scope.Name != scopeName {
		t.Errorf("Scope Name = %q, want %q", batch.Scope.Name, scopeName)
	}
}

// TestSignalBatchWithMultipleSignals tests batch with multiple signals.
func TestSignalBatchWithMultipleSignals(t *testing.T) {
	batch := &SignalBatch{
		Signals: []*SignalRecord{
			{SignalType: "log", EventID: testutil.RandEventID(), Body: "msg-" + testutil.RandString(8)},
			{SignalType: "counter", EventID: testutil.RandEventID(), MetricName: "m-" + testutil.RandString(6)},
			{SignalType: "span", EventID: testutil.RandEventID(), Name: "s-" + testutil.RandString(6), TraceID: testutil.RandTraceID(), SpanID: testutil.RandSpanID()},
			{SignalType: "log", EventID: testutil.RandEventID(), Body: "msg-" + testutil.RandString(8)},
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
	ts := int64(testutil.RandInt(1, 2_000_000_000))
	obs := ts + int64(testutil.RandInt(1, 100))
	sig := &SignalRecord{
		SignalType:     "log",
		TimeUnixMs:     ts,
		ObservedTimeMs: obs,
	}

	if sig.TimeUnixMs != ts {
		t.Errorf("TimeUnixMs = %d, want %d", sig.TimeUnixMs, ts)
	}
	if sig.ObservedTimeMs != obs {
		t.Errorf("ObservedTimeMs = %d, want %d", sig.ObservedTimeMs, obs)
	}
}

// TestSignalRecordTraceContext tests trace context fields.
func TestSignalRecordTraceContext(t *testing.T) {
	traceID := testutil.RandTraceID()
	spanID := testutil.RandSpanID()
	parentSpanID := testutil.RandSpanID()
	sig := &SignalRecord{
		SignalType:   "span",
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: parentSpanID,
	}

	if sig.TraceID != traceID {
		t.Errorf("TraceID = %q, want %q", sig.TraceID, traceID)
	}
	if sig.SpanID != spanID {
		t.Errorf("SpanID = %q, want %q", sig.SpanID, spanID)
	}
	if sig.ParentSpanID != parentSpanID {
		t.Errorf("ParentSpanID = %q, want %q", sig.ParentSpanID, parentSpanID)
	}
}

// TestSignalRecordW3CTraceContext 校验 W3C trace_flags/trace_state 的协议级承载
// （capability w3c_trace_context，§6.2.2）：校验规则 + proto 编解码往返不丢字段。
func TestSignalRecordW3CTraceContext(t *testing.T) {
	// 合法的 32 hex trace_id（非全零），随机生成以满足 W3C 格式。
	validTraceID := testutil.RandTraceID()

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
				SpanID: testutil.RandSpanID(), TraceFlags: 0x01,
				TraceState: []*TraceStateEntry{{Key: "vendor", Value: "value"}}},
		}}
		if err := b.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("proto round-trip preserves trace_flags and trace_state", func(t *testing.T) {
		orig := &SignalBatch{Signals: []*SignalRecord{
			{SignalType: "span", Name: "s", TraceID: validTraceID,
				SpanID: testutil.RandSpanID(), TraceFlags: 0x01,
				TraceState: []*TraceStateEntry{{Key: "a", Value: "1"}, {Key: "b", Value: "2"}}},
		}}
		data, err := MarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got, err := UnmarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, data)
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
