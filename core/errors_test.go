package core

import (
	"errors"
	"strings"
	"testing"
)

// TestWireCodes_Registered 验证所有具体 wire 错误码均已注册到 wireCodeRegistry，
// 客户端 MatchWireCode 能按 wire 字符串反查回正确的 ErrorCode（含大类 Num）。
func TestWireCodes_Registered(t *testing.T) {
	cases := []struct {
		c       ErrorCode
		wantNum int
	}{
		{ErrCodeHMACMismatch, NumHMAC},
		{ErrCodeTooManyEvents, NumBatch},
		{ErrCodeInvalidToken, NumAuth},
		{ErrCodeInvalidAuth, NumAuth},
		{ErrCodeTooManyAttempts, NumAuth},
		{ErrCodeChallengeMismatch, NumAuth},
		{ErrCodeSessionExpired, NumSession},
		{ErrCodeEnvelopeOpenError, NumEnvelope},
		{ErrCodeEnvelopeAlgoMismatch, NumEnvelope},
		{ErrCodeBatchTooLarge, NumBatch},
		{ErrCodeInvalidBatch, NumBatch},
		{ErrCodeBatchValidation, NumValidation},
		{ErrCodeBatchTraceContext, NumValidation},
		{ErrCodeInvalidSignalBatch, NumValidation},
		{ErrCodeSignalValidation, NumValidation},
		{ErrCodeWindowExceeded, NumWindowFull},
		{ErrCodeTooManyBatches, NumWindowFull},
		{ErrCodeQueuePressure, NumThrottle},
		{ErrCodeDecodeFailed, NumProtocol},
		{ErrCodeUnsupportedMessage, NumProtocol},
		{ErrCodeInternalError, NumProtocol},
	}
	for _, tc := range cases {
		t.Run(tc.c.Code, func(t *testing.T) {
			if tc.c.Num != tc.wantNum {
				t.Errorf("%s: Num = %d, want %d", tc.c.Code, tc.c.Num, tc.wantNum)
			}
			// MatchWireCode 必须反查回同一个 ErrorCode。
			got := MatchWireCode(tc.c.Code)
			if got != tc.c {
				t.Errorf("MatchWireCode(%q) = %+v, want %+v", tc.c.Code, got, tc.c)
			}
		})
	}
}

// TestRegistry_NoDuplicatesOrEmpty 验证 registry 内每个码 Code 非空、无重复（register 的 panic 兜底，此测试作文档化断言）。
func TestRegistry_NoDuplicatesOrEmpty(t *testing.T) {
	for code, c := range registry {
		if code == "" || c.Code == "" {
			t.Errorf("registry contains empty Code: %+v", c)
		}
		if code != c.Code {
			t.Errorf("registry key %q != Code %q", code, c.Code)
		}
	}
}

// TestMatchWireCode_Unknown 验证未注册的 wire 码返回 ErrCodeUnknown（Num=0）。
func TestMatchWireCode_Unknown(t *testing.T) {
	got := MatchWireCode("not_a_registered_code")
	if got != ErrCodeUnknown {
		t.Errorf("MatchWireCode(unknown) = %+v, want ErrCodeUnknown", got)
	}
}

// TestCodeOf 验证 CodeOf 从 *Error 提取 Code 字符串，用于按 ErrorCode 匹配。
func TestCodeOf(t *testing.T) {
	// *Error 返回其 Code。
	e := NewError(ErrCodeHMACMismatch, "hmac failed")
	if got := CodeOf(e); got != ErrCodeHMACMismatch.Code {
		t.Errorf("CodeOf(HMACMismatch) = %q, want %q", got, ErrCodeHMACMismatch.Code)
	}
	// 不同 Code 区分。
	if CodeOf(e) == ErrCodeAuth.Code {
		t.Error("CodeOf(HMACMismatch) == Auth.Code, want different")
	}
	// 非 *Error 返回空串。
	if got := CodeOf(errors.New("plain")); got != "" {
		t.Errorf("CodeOf(plain) = %q, want empty", got)
	}
	// nil 安全。
	if got := CodeOf(nil); got != "" {
		t.Errorf("CodeOf(nil) = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// Error 类型测试
// ---------------------------------------------------------------------------

func TestMBTAError_Error(t *testing.T) {
	e := NewError(ErrCodeConfig, "invalid config")
	want := "[1000 invalid_config] invalid config"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestMBTAError_ErrorWrapped(t *testing.T) {
	inner := errors.New("listen failed")
	e := WrapError(ErrCodeTransport, "dial QUIC", inner)
	want := "[2000 transport_error] dial QUIC: listen failed"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestErrorCode_Binding 验证 ErrCodeXxx 常量把 Num 与 Code 绑定，
// 调用方传一个值即同时携带两者（NewError 无需再手动配对 NumX/CodeX）。
func TestErrorCode_Binding(t *testing.T) {
	cases := []struct {
		c    ErrorCode
		num  int
		code string
	}{
		{ErrCodeConfig, NumConfig, "invalid_config"},
		{ErrCodeAuth, NumAuth, "auth_error"},
		{ErrCodeValidation, NumValidation, "validation_error"},
		{ErrCodeEnvelope, NumEnvelope, "envelope_error"},
		{ErrCodeHMAC, NumHMAC, "hmac_error"},
		{ErrCodeVersion, NumVersion, "unsupported_version"},
	}
	for _, tc := range cases {
		if tc.c.Num != tc.num {
			t.Errorf("%+v: Num = %d, want %d", tc.c, tc.c.Num, tc.num)
		}
		if tc.c.Code != tc.code {
			t.Errorf("%+v: Code = %q, want %q", tc.c, tc.c.Code, tc.code)
		}
	}
}

// TestErrorCode_NewErrorCarriesBoth 验证 NewError 从 ErrorCode 同时填入 Error.Num 与 Error.Code。
func TestErrorCode_NewErrorCarriesBoth(t *testing.T) {
	e := NewError(ErrCodeSession, "bad state")
	if e.Num != NumSession || e.Code != "session_error" {
		t.Errorf("NewError carried Num=%d Code=%q, want %d/%q", e.Num, e.Code, NumSession, "session_error")
	}
}

// TestMBTAError_Detail 验证 Detail 字段非 nil 时拼入 Error() 输出，nil 时省略。
func TestMBTAError_Detail(t *testing.T) {
	// nil Detail：与无 Detail 一致（向后格式不变）。
	e := NewError(ErrCodeConfig, "invalid config")
	if got := e.Error(); got != "[1000 invalid_config] invalid config" {
		t.Errorf("nil Detail Error() = %q", got)
	}

	// 非 nil Detail：在 Message 后以 :{...} 插入。
	detail := map[string]any{"field": "version", "val": "v2"}
	e2 := &Error{ErrorCode: ErrCodeConfig, Message: "invalid config", Detail: detail}
	got := e2.Error()
	if !strings.HasPrefix(got, "[1000 invalid_config] invalid config:{") {
		t.Errorf("Detail output missing prefix: %q", got)
	}
	if !strings.Contains(got, "version") || !strings.Contains(got, "v2") {
		t.Errorf("Detail content lost: %q", got)
	}

	// Detail + Err 同时存在：Detail 在前，Err 在后。
	inner := errors.New("root cause")
	e3 := &Error{ErrorCode: ErrCodeTransport, Message: "dial", Detail: detail, Err: inner}
	got3 := e3.Error()
	if !strings.Contains(got3, ":{") {
		t.Errorf("Detail missing in wrapped: %q", got3)
	}
	if !strings.HasSuffix(got3, ": root cause") {
		t.Errorf("Err missing at tail in wrapped: %q", got3)
	}
}

func TestMBTAError_Unwrap(t *testing.T) {
	inner := errors.New("base error")
	e := WrapError(ErrCodeTLS, "tls failed", inner)
	if !errors.Is(e, inner) {
		t.Error("Unwrap should return inner error")
	}
}

// TestCodeOfMatching 验证用 CodeOf 按 ErrorCode 匹配错误（替代旧 sentinel errors.Is）。
func TestCodeOfMatching(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		code    ErrorCode
		matches bool
	}{
		{"session matches", NewError(ErrCodeSession, "bad state"), ErrCodeSession, true},
		{"transport matches", WrapError(ErrCodeTransport, "dial", errors.New("refused")), ErrCodeTransport, true},
		{"auth matches through wrap", WrapError(ErrCodeAuth, "token", errors.New("expired")), ErrCodeAuth, true},
		{"config matches", NewError(ErrCodeConfig, "missing"), ErrCodeConfig, true},
		// Different code must NOT match.
		{"transport not session", NewError(ErrCodeTransport, "dial"), ErrCodeSession, false},
		{"auth not config", WrapError(ErrCodeAuth, "tok", nil), ErrCodeConfig, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CodeOf(tc.err) == tc.code.Code
			if got != tc.matches {
				t.Errorf("CodeOf(%v) == %s.Code = %v, want %v", tc.err, tc.code.Code, got, tc.matches)
			}
		})
	}
}

func TestNumCodeRanges(t *testing.T) {
	tests := []struct {
		code int
		min  int
		max  int
		cat  string
	}{
		{NumConfig, 1000, 1099, "config"},
		{NumCredential, 1000, 1099, "config"},
		{NumTransport, 2000, 2099, "transport"},
		{NumTLS, 2000, 2099, "transport"},
		{NumStream, 2000, 2099, "transport"},
		{NumHandshake, 3000, 3099, "protocol"},
		{NumAuth, 3000, 3099, "protocol"},
		{NumSession, 3000, 3099, "protocol"},
		{NumProtocol, 3000, 3099, "protocol"},
		{NumBatch, 4000, 4099, "data"},
		{NumEnvelope, 4000, 4099, "data"},
		{NumValidation, 4000, 4099, "data"},
		{NumHMAC, 4000, 4099, "data"},
		{NumWindowFull, 5000, 5099, "flow"},
		{NumThrottle, 5000, 5099, "flow"},
		{NumVersion, 7000, 7099, "version"},
	}
	for _, tt := range tests {
		if tt.code < tt.min || tt.code > tt.max {
			t.Errorf("%s (%d) not in range %d-%d (%s)", tt.cat, tt.code, tt.min, tt.max, tt.cat)
		}
	}
}
