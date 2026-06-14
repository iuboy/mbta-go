package core

import (
	"fmt"
	"strings"
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

// SanitizeForLog 清洗用于日志输出的网络来源字符串：截断超长值，把非法控制字符
// （除 \t \n \r）替换为空格。用于 slog 打印 reason/agentID 等不可信字段，缓解
// 日志注入（换行/ANSI 转义伪造日志行）。
func SanitizeForLog(s string) string {
	if len(s) > MaxSignalFieldLen {
		s = s[:MaxSignalFieldLen]
	}
	return strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
