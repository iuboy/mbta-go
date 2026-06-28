package core

import (
	"strings"
	"testing"
)

func TestHasControlChars(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"plain text", false},
		{"line1\nline2\ttab\rwin", false}, // 常见空白允许
		{"bad\x00null", true},             // NUL
		{"esc\x1b[0m", true},              // ANSI ESC
		{"del\x7f", true},                 // DEL
		{"bell\x07", true},                // BEL
	}
	for _, tt := range tests {
		if got := hasControlChars(tt.in); got != tt.want {
			t.Errorf("hasControlChars(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestValidateTextField(t *testing.T) {
	if err := validateTextField("f", "ok"); err != nil {
		t.Errorf("legit value rejected: %v", err)
	}
	if err := validateTextField("f", strings.Repeat("a", MaxSignalFieldLen)); err != nil {
		t.Errorf("value at exact limit rejected: %v", err)
	}
	if err := validateTextField("f", strings.Repeat("a", MaxSignalFieldLen+1)); err == nil {
		t.Error("over-limit value accepted")
	}
	if err := validateTextField("f", "x\x01y"); err == nil {
		t.Error("control-char value accepted")
	}
}

func TestSanitizeForLog(t *testing.T) {
	if got := SanitizeForLog("plain"); got != "plain" {
		t.Errorf("plain changed: %q", got)
	}
	// 所有控制字符（含 \n \r \t \0 ESC）替换为空格——防御换行注入。
	if got := SanitizeForLog("a\x00b\x1bc\nd"); got != "a b c d" {
		t.Errorf("control chars not replaced: %q", got)
	}
	// 超长截断到 MaxSignalFieldLen。
	long := strings.Repeat("a", MaxSignalFieldLen+10)
	if got := SanitizeForLog(long); len(got) != MaxSignalFieldLen {
		t.Errorf("truncated len = %d, want %d", len(got), MaxSignalFieldLen)
	}
}

// TestSignalBatchValidate_FieldLimits: 超长字段与控制字符字段在 Validate 入口被拒，
// 合法多行 status_message（含 \n）通过 (L-2)。
func TestSignalBatchValidate_FieldLimits(t *testing.T) {
	t.Run("over-long metric_name rejected", func(t *testing.T) {
		long := strings.Repeat("a", MaxSignalFieldLen+1)
		b := &SignalBatch{Signals: []*SignalRecord{{SignalType: "metric", MetricName: long}}}
		if err := b.Validate(); err == nil {
			t.Error("expected error for over-long metric_name")
		}
	})
	t.Run("control char in trace_id rejected", func(t *testing.T) {
		b := &SignalBatch{Signals: []*SignalRecord{
			{SignalType: "span", Name: "op", TraceID: "bad\x00id"},
		}}
		if err := b.Validate(); err == nil {
			t.Error("expected error for control char in trace_id")
		}
	})
	t.Run("legit multiline status_message accepted", func(t *testing.T) {
		b := &SignalBatch{Signals: []*SignalRecord{
			{SignalType: "log", Body: "x", StatusMessage: "line1\nline2"},
		}}
		if err := b.Validate(); err != nil {
			t.Errorf("legit multiline status_message rejected: %v", err)
		}
	})
	t.Run("legit short fields accepted", func(t *testing.T) {
		b := &SignalBatch{Signals: []*SignalRecord{
			{SignalType: "metric", MetricName: "cpu.usage", Unit: "%"},
		}}
		if err := b.Validate(); err != nil {
			t.Errorf("legit short fields rejected: %v", err)
		}
	})
}

// TestValidateHexID 验证 trace/span ID 的 W3C/OTel 格式约束（spec §6.2.1）：
// 非空时必须是指定长度的小写 hex + 非全零。这是 signal_type="span" 无损映射
// OTLP Traces Span 的正确性保证。
func TestValidateHexID(t *testing.T) {
	validTraceID := "0123456789abcdef0123456789abcdef" // 32 hex (16 bytes)
	validSpanID := "0123456789abcdef"                   // 16 hex (8 bytes)

	tests := []struct {
		name      string
		field     string
		val       string
		wantBytes int
		wantErr   bool
	}{
		{"empty trace_id ok (no trace participation)", "trace_id", "", 16, false},
		{"valid trace_id", "trace_id", validTraceID, 16, false},
		{"valid span_id", "span_id", validSpanID, 8, false},
		{"trace_id wrong length (too short)", "trace_id", "0123", 16, true},
		{"trace_id wrong length (too long)", "trace_id", validTraceID + "ab", 16, true},
		{"span_id wrong length", "span_id", "0123", 8, true},
		{"trace_id uppercase hex rejected", "trace_id", "0123456789ABCDEF0123456789ABCDEF", 16, true},
		{"trace_id non-hex rejected", "trace_id", "ghij56789abcdef0123456789abcdef", 16, true},
		{"trace_id all-zeros rejected", "trace_id", "00000000000000000000000000000000", 16, true},
		{"span_id all-zeros rejected", "span_id", "0000000000000000", 8, true},
		{"hyphenated uuid rejected (W3C incompat)", "trace_id", "0190a1b2-3c4d-7e8f-9012-3456789abcde", 16, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHexID(tt.field, tt.val, tt.wantBytes)
			if tt.wantErr && err == nil {
				t.Errorf("validateHexID(%q) expected error, got nil", tt.val)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateHexID(%q) unexpected error: %v", tt.val, err)
			}
		})
	}
}
