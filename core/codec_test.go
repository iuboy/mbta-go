package core

import (
	"bytes"
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/testutil"
)

// richSignalBatch 构造一个含多种 any 动态类型的 SignalBatch，用于验证各 codec
// 对 attributes/body 的类型保真度。
func richSignalBatch() *SignalBatch {
	bodyStr := "service-" + testutil.RandString(8)
	hostName := testutil.RandHost()
	return &SignalBatch{
		SchemaURL: "https://" + testutil.RandString(8) + ".example/mbta/v1",
		Resource:  Resource{Attributes: map[string]any{"host": hostName, "region": "us-east"}},
		Scope:     Scope{Name: "collector-" + testutil.RandString(4), Version: testutil.RandVersion(), CollectorID: "dc-" + testutil.RandString(4)},
		Signals: []*SignalRecord{
			{
				SignalType:     "log",
				EventID:        testutil.RandEventID(),
				TimeUnixMs:     int64(testutil.RandInt(1, 2_000_000_000)),
				Body:           bodyStr,
				SeverityNumber: testutil.RandInt(1, 24),
				SeverityText:   "INFO",
				Attributes: map[string]any{
					"str":    "hello",
					"int":    int64(42),
					"float":  3.14,
					"bool":   true,
					"bytes":  []byte{0xDE, 0xAD, 0xBE, 0xEF},
					"nested": map[string]any{"k": "v", "n": int64(7)},
				},
			},
			{
				SignalType:   "counter",
				MetricName:   "metric-" + testutil.RandString(6),
				Unit:         "%",
				Temporality:  "gauge",
				MetricFields: map[string]float64{"value": float64(testutil.RandInt(1, 1000)) / 10.0},
			},
			{
				SignalType:      "span",
				Name:            "http-" + testutil.RandString(6),
				Kind:            "client",
				TraceID:         "trace-" + testutil.RandString(6),
				SpanID:          "span-" + testutil.RandString(4),
				StartTimeUnixMs: int64(testutil.RandInt(1, 2_000_000_000)),
				EndTimeUnixMs:   int64(testutil.RandInt(1, 2_000_000_000)),
				StatusCode:      "OK",
			},
		},
	}
}

// TestCodec_RoundTrip 验证三种 codec 各自能无损往返一个含多种类型的 SignalBatch。
func TestCodec_RoundTrip(t *testing.T) {
	t.Parallel()
	original := richSignalBatch()

	for _, tc := range []struct {
		name  string
		codec corepb.Codec
	}{
		{"proto", corepb.Codec_CODEC_PROTO},
		{"cbor", corepb.Codec_CODEC_CBOR},
		{"json", corepb.Codec_CODEC_JSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := LookupCodec(tc.codec)
			if c == nil {
				t.Fatalf("LookupCodec(%v) = nil, want registered", tc.codec)
			}
			if got := c.Codec(); got != tc.codec {
				t.Errorf("Codec() = %v, want %v", got, tc.codec)
			}

			data, err := c.Marshal(original)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("Marshal returned empty data")
			}

			decoded, err := c.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			assertSignalBatchEqual(t, original, decoded, tc.name)
		})
	}
}

// TestCodec_DispatchFuncs 验证 MarshalSignalBatchCodec/UnmarshalSignalBatchCodec 按 codec 分发。
func TestCodec_DispatchFuncs(t *testing.T) {
	t.Parallel()
	sb := richSignalBatch()

	for _, codec := range []corepb.Codec{
		corepb.Codec_CODEC_PROTO,
		corepb.Codec_CODEC_CBOR,
		corepb.Codec_CODEC_JSON,
	} {
		data, err := MarshalSignalBatchCodec(codec, sb)
		if err != nil {
			t.Fatalf("MarshalSignalBatchCodec(%v): %v", codec, err)
		}
		decoded, err := UnmarshalSignalBatchCodec(codec, data)
		if err != nil {
			t.Fatalf("UnmarshalSignalBatchCodec(%v): %v", codec, err)
		}
		if len(decoded.Signals) != len(sb.Signals) {
			t.Errorf("codec %v: signals len = %d, want %d", codec, len(decoded.Signals), len(sb.Signals))
		}
	}
}

// TestCodec_CrossCodecIncompatible 验证不同 codec 的 wire bytes 不可互读（防 codec 字段篡改后被另一 codec 误解码）。
func TestCodec_CrossCodecIncompatible(t *testing.T) {
	t.Parallel()
	sb := &SignalBatch{Signals: []*SignalRecord{{SignalType: "log", Body: "x"}}}

	protoData, err := MarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, sb)
	if err != nil {
		t.Fatalf("proto marshal: %v", err)
	}

	// proto bytes 不是合法 CBOR，cbor 解码应失败。
	if _, err := UnmarshalSignalBatchCodec(corepb.Codec_CODEC_CBOR, protoData); err == nil {
		t.Error("cbor unmarshal of proto bytes: expected error, got nil")
	}
	// proto bytes 不是合法 JSON（非 { 开头），json 解码应失败。
	if _, err := UnmarshalSignalBatchCodec(corepb.Codec_CODEC_JSON, protoData); err == nil {
		t.Error("json unmarshal of proto bytes: expected error, got nil")
	}
}

// TestCodec_LookupUnknown 验证未注册的 codec 返回 nil（分发函数返回错误）。
func TestCodec_LookupUnknown(t *testing.T) {
	t.Parallel()
	if c := LookupCodec(corepb.Codec_CODEC_UNSPECIFIED); c != nil {
		t.Errorf("LookupCodec(UNSPECIFIED) = %v, want nil", c)
	}
	sb := &SignalBatch{Signals: []*SignalRecord{{SignalType: "log"}}}
	if _, err := MarshalSignalBatchCodec(corepb.Codec_CODEC_UNSPECIFIED, sb); err == nil {
		t.Error("MarshalSignalBatchCodec(UNSPECIFIED): expected error, got nil")
	}
	if _, err := UnmarshalSignalBatchCodec(corepb.Codec_CODEC_UNSPECIFIED, []byte{0x01}); err == nil {
		t.Error("UnmarshalSignalBatchCodec(UNSPECIFIED): expected error, got nil")
	}
}

// TestCodec_NilEmpty 验证 nil/空输入的边界处理。
func TestCodec_NilEmpty(t *testing.T) {
	t.Parallel()
	if _, err := MarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, nil); err == nil {
		t.Error("MarshalSignalBatchCodec(nil): expected error")
	}
	if _, err := UnmarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, nil); err == nil {
		t.Error("UnmarshalSignalBatchCodec(nil): expected error")
	}
	if _, err := UnmarshalSignalBatchCodec(corepb.Codec_CODEC_PROTO, []byte{}); err == nil {
		t.Error("UnmarshalSignalBatchCodec(empty): expected error")
	}
}

// assertSignalBatchEqual 比较 SignalBatch 的关键字段。注意 JSON codec 因 float64 统一，
// int64 attributes 往返后可能变为 float64（>2^53 才丢精度），故用数值近似比较。
func assertSignalBatchEqual(t *testing.T, want, got *SignalBatch, codecName string) {
	t.Helper()
	if got.SchemaURL != want.SchemaURL {
		t.Errorf("%s: schema_url = %q, want %q", codecName, got.SchemaURL, want.SchemaURL)
	}
	if got.Resource.Attributes["host"] != want.Resource.Attributes["host"] {
		t.Errorf("%s: resource.host = %v, want %v", codecName, got.Resource.Attributes["host"], want.Resource.Attributes["host"])
	}
	if got.Scope.Name != want.Scope.Name {
		t.Errorf("%s: scope.name = %q, want %q", codecName, got.Scope.Name, want.Scope.Name)
	}
	if len(got.Signals) != len(want.Signals) {
		t.Fatalf("%s: signals len = %d, want %d", codecName, len(got.Signals), len(want.Signals))
	}

	// log signal
	log := got.Signals[0]
	if log.SignalType != "log" {
		t.Errorf("%s: signal[0].type = %q, want log", codecName, log.SignalType)
	}
	if log.Body != want.Signals[0].Body {
		t.Errorf("%s: signal[0].body = %v, want %v", codecName, log.Body, want.Signals[0].Body)
	}
	// attributes 类型保真（JSON 可能把 int64 变 float64，分别断言）
	if log.Attributes["str"] != "hello" {
		t.Errorf("%s: signal[0].attr.str = %v, want hello", codecName, log.Attributes["str"])
	}
	if log.Attributes["bool"] != true {
		t.Errorf("%s: signal[0].attr.bool = %v, want true", codecName, log.Attributes["bool"])
	}
	switch v := log.Attributes["int"].(type) {
	case int64:
		if v != 42 {
			t.Errorf("%s: signal[0].attr.int = %v, want 42", codecName, v)
		}
	case uint64: // CBOR：小正整数编码为无符号（RFC 8949 §3.1）
		if v != 42 {
			t.Errorf("%s: signal[0].attr.int = %v, want 42", codecName, v)
		}
	case float64: // JSON 统一 Number
		if v != 42 {
			t.Errorf("%s: signal[0].attr.int = %v, want 42", codecName, v)
		}
	default:
		t.Errorf("%s: signal[0].attr.int = %T(%v), want int64/uint64/float64", codecName, v, v)
	}
	// bytes：JSON 走 base64（[]byte 的 json 默认行为），往返为 []byte 即可
	if codecName != "json" {
		if b, ok := log.Attributes["bytes"].([]byte); !ok || !bytes.Equal(b, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
			t.Errorf("%s: signal[0].attr.bytes = %v, want deadbeef", codecName, log.Attributes["bytes"])
		}
	}

	// metric signal
	metric := got.Signals[1]
	if metric.SignalType != "counter" {
		t.Errorf("%s: signal[1].type = %q, want counter", codecName, metric.SignalType)
	}
	if metric.MetricName != want.Signals[1].MetricName {
		t.Errorf("%s: signal[1].metric_name = %q, want %q", codecName, metric.MetricName, want.Signals[1].MetricName)
	}

	// span signal
	span := got.Signals[2]
	if span.SignalType != "span" {
		t.Errorf("%s: signal[2].type = %q, want span", codecName, span.SignalType)
	}
	if span.TraceID != want.Signals[2].TraceID {
		t.Errorf("%s: signal[2].trace_id = %q, want %q", codecName, span.TraceID, want.Signals[2].TraceID)
	}
}
