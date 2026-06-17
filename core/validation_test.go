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
