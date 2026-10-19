package conformance

// errors_test.go：错误码注册表完整性（v2-design §8 / §14.2 append-only）。

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/iuboy/mbta-go/core"
)

// TestErrors_RegistryComplete 验证全部导出 ErrCode 均已注册、编号唯一、
// CodeName 反查一致、分组段位正确。
func TestErrors_RegistryComplete(t *testing.T) {
	all := []core.ErrCode{
		core.ErrCodeOK,                 // 0
		core.ErrCodeAuthFailed,         // 10（握手）
		core.ErrCodeUnsupportedProfile, // 12
		core.ErrCodeUnsupportedCap,     // 13
		core.ErrCodeBadHandshake,       // 14
		core.ErrCodeBatchTooLarge,      // 20（数据）
		core.ErrCodeBatchInvalid,       // 21
		core.ErrCodeDecompressLimit,    // 22
		core.ErrCodeEnvelopeOpenFail,   // 23
		core.ErrCodeWindowExceeded,     // 24
		core.ErrCodeStaleEpoch,         // 25
		core.ErrCodeLedgerDivergence,   // 26
		core.ErrCodeResultLevelBad,     // 27
		core.ErrCodeAckModeBad,         // 28
		core.ErrCodeCreditInvalid,      // 29
		core.ErrCodeHelloEphInvalid,    // 30
		core.ErrCodeHelloProofInvalid,  // 31
		core.ErrCodeServerDraining,     // 32（会话）
		core.ErrCodeInternal,           // 40（服务端）
		core.ErrCodeUnavailable,        // 41
		core.ErrCodeProtocolError,      // 42
	}
	seen := map[uint32]string{}
	for _, e := range all {
		if prev, dup := seen[e.Num]; dup {
			t.Errorf("duplicate code number %d: %s vs %s（注册表编号必须唯一）", e.Num, prev, e.Name)
			continue
		}
		seen[e.Num] = e.Name
		if got := core.CodeName(e.Num); got != e.Name {
			t.Errorf("CodeName(%d) = %q, want %q", e.Num, got, e.Name)
		}
	}
	// 分组段位抽查：0=ok / 1x 握手 / 2x 数据 / 3x 会话与数据段扩展 / 4x 服务端。
	segments := []struct {
		code  uint32
		seg   int
		label string
	}{
		{core.CodeAuthFailed, 1, "handshake"},
		{core.CodeBadHandshakeMessage, 1, "handshake"},
		{core.CodeBatchInvalid, 2, "data"},
		{core.CodeWindowExceeded, 2, "data"},
		{core.CodeInternal, 4, "server"},
		{core.CodeUnavailable, 4, "server"},
		{core.CodeProtocolError, 4, "server"},
	}
	for _, s := range segments {
		if int(s.code/10) != s.seg {
			t.Errorf("code %d (%s) outside %dxx segment", s.code, s.label, s.seg)
		}
	}
}

// TestErrors_CodeNameUnknown 验证未注册编号反查 "unknown"，本地哨兵不入 wire 注册表。
func TestErrors_CodeNameUnknown(t *testing.T) {
	for _, c := range []uint32{1, 9, 11, 99, 99999, ^uint32(0)} {
		if got := core.CodeName(c); got != "unknown" {
			t.Errorf("CodeName(%d) = %q, want unknown", c, got)
		}
	}
	for _, sentinel := range []core.ErrCode{
		core.ErrCodeConfig, core.ErrCodeSession, core.ErrCodeBatch,
		core.ErrCodeHandshake, core.ErrCodeTransport, core.ErrCodeTLS,
	} {
		if got := core.CodeName(sentinel.Num); got == sentinel.Name {
			t.Errorf("local sentinel %s (num %d) leaked into wire registry", sentinel.Name, sentinel.Num)
		}
	}
}

// TestErrors_CodeNumOf 验证错误链提取、CodeOf 名称提取与 Unwrap 链保持。
func TestErrors_CodeNumOf(t *testing.T) {
	base := errors.New("io timeout")
	err := core.WrapError(core.ErrCodeEnvelopeOpenFail, "open envelope", base)
	if got := core.CodeNumOf(err); got != core.CodeEnvelopeOpenFail {
		t.Errorf("CodeNumOf(wrapped) = %d, want %d", got, core.CodeEnvelopeOpenFail)
	}
	if got := core.CodeNumOf(base); got != core.ErrCodeUnknown.Num {
		t.Errorf("CodeNumOf(non-core) = %d, want unknown sentinel", got)
	}
	if got := core.CodeOf(err); got != core.ErrCodeEnvelopeOpenFail.Name {
		t.Errorf("CodeOf = %q, want %q", got, core.ErrCodeEnvelopeOpenFail.Name)
	}
	if !strings.Contains(err.Error(), "envelope_open_failed") {
		t.Errorf("Error() = %q, want code name embedded", err.Error())
	}
	if !errors.Is(err, base) {
		t.Error("Unwrap chain broken")
	}
	if got := core.CodeNumOf(nil); got != core.ErrCodeUnknown.Num {
		t.Errorf("CodeNumOf(nil) = %d, want unknown", got)
	}
}

// TestErrors_NewErrorFormat 验证标准错误字符串格式 [num name] message。
func TestErrors_NewErrorFormat(t *testing.T) {
	err := core.NewError(core.ErrCodeWindowExceeded, "seq beyond window")
	want := fmt.Sprintf("[%d %s] seq beyond window", core.CodeWindowExceeded, "window_exceeded")
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}
