package core

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

// MaxSignalFieldLen 是 SignalRecord 单个字符串字段的最大字节长度。取值保守
// （远小于 maxEventBytes 256KB），用于在协议入口拒绝异常长输入，兼顾日志注入
// 防护与内存放大抑制。
const MaxSignalFieldLen = 4096

// hasControlChars 报告 s 是否含非法控制字符。允许 \t \n \r 三种常见空白
// （status_message 等字段可能合法地含多行文本）。
func hasControlChars(s string) bool {
	for _, r := range s {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f {
			return true
		}
	}
	return false
}

// validateTextField 校验单个字符串字段的长度与控制字符。仅对非空字段调用；
// 返回的 error 已包含字段名，便于定位。
func validateTextField(name, val string) error {
	if len(val) > MaxSignalFieldLen {
		return NewError(NumValidation, CodeValidation,
			fmt.Sprintf("%s exceeds maximum length %d", name, MaxSignalFieldLen))
	}
	if hasControlChars(val) {
		return NewError(NumValidation, CodeValidation,
			fmt.Sprintf("%s contains control characters", name))
	}
	return nil
}

// validateHexID 校验 trace/span ID 字段的 W3C/OTel 格式约束（spec §6.2.1）：
// 非空时必须是指定长度的小写 hex，且全零值非法。空值合法（表示该 signal 不参与
// trace 关联）。wantBytes 是期望的字节数（trace_id=16，span_id=8）。
//
// 这是支撑 signal_type="span" 无损映射 OTLP Traces Span 的正确性保证：OTel 的
// TraceIDFromHex/SpanIDFromHex 拒绝非 hex、错误长度、全零值，若上游传入 UUID
// （带连字符）或其他编码，下游 Jaeger/Tempo 无法重建 trace 树。
func validateHexID(name, val string, wantBytes int) error {
	if val == "" {
		return nil // 空 = 不参与 trace 关联，合法
	}
	wantHexLen := wantBytes * 2
	if len(val) != wantHexLen {
		return NewError(NumValidation, CodeValidation,
			fmt.Sprintf("%s must be %d lowercase hex chars (%d bytes), got len %d",
				name, wantHexLen, wantBytes, len(val)))
	}
	// 必须是小写 hex（解码同时校验字符集；hex.DecodeString 接受大小写，但 W3C
	// 规定小写，这里对大写显式拒绝以保证互操作一致）。
	for _, r := range val {
		isLowerHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
		if !isLowerHex {
			return NewError(NumValidation, CodeValidation,
				fmt.Sprintf("%s must be lowercase hex, contains invalid char %q", name, r))
		}
	}
	decoded := make([]byte, wantBytes)
	if _, err := hex.Decode(decoded, []byte(val)); err != nil {
		return NewError(NumValidation, CodeValidation,
			fmt.Sprintf("%s is not valid hex: %v", name, err))
	}
	// 全零值非法（对齐 OTel）。
	allZero := true
	for _, b := range decoded {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return NewError(NumValidation, CodeValidation,
			fmt.Sprintf("%s must not be all zeros", name))
	}
	return nil
}

// validateTraceState 校验 W3C tracestate 成员（spec §6.2.2 / W3C Trace Context）。
// tracestate 最多 32 个成员，每个 key/value 不超 256 字符且不含控制字符。
// 多余成员不静默截断——返回错误让调用方显式收敛，避免无声丢语义。
func validateTraceState(entries []*TraceStateEntry) error {
	if len(entries) > 32 {
		return NewError(NumValidation, CodeValidation,
			fmt.Sprintf("trace_state exceeds 32 entries (got %d)", len(entries)))
	}
	for i, e := range entries {
		if e == nil || e.Key == "" {
			return NewError(NumValidation, CodeValidation,
				fmt.Sprintf("trace_state[%d]: empty key", i))
		}
		if err := validateTextField(fmt.Sprintf("trace_state[%d].key", i), e.Key); err != nil {
			return err
		}
		if err := validateTextField(fmt.Sprintf("trace_state[%d].value", i), e.Value); err != nil {
			return err
		}
	}
	return nil
}

// ValidateBatchTraceContext 校验 batch 级 W3C trace 上下文（spec §6.2.2，capability
// w3c_trace_context）。客户端发送前置与服务端解码后共用。
//
// 与 validateSignalTraceContext 的关键区别：batch 级 TraceContext 一旦显式提供，
// trace_id/span_id 必须非空——它是整批共享的继承点，没有「空=不参与」的退化语义
// （不参与则不应携带 TraceContext）。parent_span_id 仍可选。
func ValidateBatchTraceContext(tc *TraceContext) error {
	if tc == nil {
		return nil
	}
	const (
		fieldTCID     = "trace_context.trace_id"
		fieldTCSpan   = "trace_context.span_id"
		fieldTCParent = "trace_context.parent_span_id"
	)
	if tc.TraceId == "" {
		return NewError(NumValidation, CodeValidation, fieldTCID+" must not be empty")
	}
	if tc.SpanId == "" {
		return NewError(NumValidation, CodeValidation, fieldTCSpan+" must not be empty")
	}
	if err := validateHexID(fieldTCID, tc.TraceId, 16); err != nil {
		return err
	}
	if err := validateHexID(fieldTCSpan, tc.SpanId, 8); err != nil {
		return err
	}
	if err := validateHexID(fieldTCParent, tc.ParentSpanId, 8); err != nil {
		return err
	}
	// trace-flags 是 W3C traceparent 的 1 字节字段（仅低 8 位有效）。
	if tc.TraceFlags > 0xff {
		return NewError(NumValidation, CodeValidation,
			fmt.Sprintf("trace_context.trace_flags exceeds 8-bit W3C range (0x%x)", tc.TraceFlags))
	}
	if err := validateTraceState(tc.TraceState); err != nil {
		return err
	}
	return nil
}

// SanitizeForLog 清洗用于日志输出的网络来源字符串：截断超长值，把所有 C0 控制字符
// （0x00-0x1F）和 DEL（0x7F）替换为空格。用于 slog 打印 reason 等不可信字段，
// 防御日志注入（换行伪造日志行、ANSI 转义终端注入、null 截断等）。
//
// 注意：\n \r 也被替换——防御换行注入。slog 自身已对结构化值做转义，
// 但当日志被转发到 syslog/journald/ELK 等外部系统时，中间层可能丢失转义。
// SanitizeForLog 提供 defense-in-depth。
func SanitizeForLog(s string) string {
	truncated := false
	if len(s) > MaxSignalFieldLen {
		// 截断到最后一个有效 UTF-8 边界，避免在多字节字符中间截断产生无效 UTF-8。
		end := MaxSignalFieldLen
		for end > 0 && !utf8.RuneStart(s[end]) {
			end--
		}
		s = s[:end]
		truncated = true
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if truncated {
		s += "…(truncated)"
	}
	return s
}
