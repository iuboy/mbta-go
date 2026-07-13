package protocol

import (
	"context"
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
)

// noopClientTransport 满足 ClientTransport 接口；本测试组的门控/校验/白盒路径
// 均不触达 WriteFrame（门控与校验在 SendBatch 早期返回，reserveInflight 不写帧）。
type noopClientTransport struct{}

func (noopClientTransport) ReadFrame() (core.Frame, error) {
	return core.Frame{}, context.Canceled
}
func (noopClientTransport) WriteFrame(context.Context, uint8, uint8, uint8, []byte) error {
	return nil
}
func (noopClientTransport) CloseConn() error { return nil }

// validBatchTC 返回一个合法的 batch 级 TraceContext（32 hex trace_id / 16 hex span_id）。
func validBatchTC() *core.TraceContext {
	return &core.TraceContext{
		TraceId:    "0123456789abcdef0123456789abcdef",
		SpanId:     "0123456789abcdef",
		TraceFlags: 0x01,
	}
}

func newTraceTestClient(negotiatedCaps []string) *CoreClient {
	c := NewCoreClient(noopClientTransport{}, CoreClientConfig{
		DefaultCodec:       corepb.Codec_CODEC_PROTO,
		DefaultCipherSuite: corepb.CipherSuite_CIPHER_SUITE_INTL,
		DefaultCompression: corepb.Compression_COMPRESSION_NONE,
	})
	if negotiatedCaps != nil {
		c.negotiated.Store(&core.NegotiateResult{SelectedCapabilities: negotiatedCaps})
	}
	// reserveInflight 加锁后会重新检查 state（TOCTOU 防护），测试需把状态机推到 Ready。
	// 状态机从 Disconnected 开始，需依次转换到 Ready。
	for _, target := range []core.State{
		core.StateConnecting,
		core.StateControlStreamOpen,
		core.StateHelloSent,
		core.StateHelloAcked,
		core.StateAuthSent,
		core.StateReady,
	} {
		_ = c.sm.Transition(target)
	}
	// Build 现在校验 HMACKey 非空（core spec §5.1），测试客户端需注入会话密钥。
	hmacKey := make([]byte, core.HMACKeyLenIntl)
	c.keys.Store(core.NewSessionKeys("test", corepb.CipherSuite_CIPHER_SUITE_INTL, hmacKey))
	return c
}

// TestSendBatch_TraceContextCapabilityGate 验证：携带 TraceContext 但未协商
// w3c_trace_context → 显式 CodeBatch 错误（不静默丢弃）。
func TestSendBatch_TraceContextCapabilityGate(t *testing.T) {
	c := newTraceTestClient([]string{"codec_proto"}) // 不含 w3c_trace_context
	sb := &core.SignalBatch{Signals: []*core.SignalRecord{{SignalType: "log", Body: "x"}}}

	_, err := c.SendBatch(context.Background(), sb, "tag", "src",
		core.WithTraceContext(validBatchTC()))
	if err == nil {
		t.Fatal("expected capability-gate error, got nil")
	}
	mbe, ok := err.(*core.Error)
	if !ok || mbe.Code != core.CodeBatch {
		t.Errorf("expected CodeBatch error, got %v", err)
	}
}

// TestSendBatch_TraceContextValidation 验证：cap 已协商但 TraceContext 非法 →
// CodeValidation 错误（门控通过后前置校验拦截，不浪费往返）。
func TestSendBatch_TraceContextValidation(t *testing.T) {
	c := newTraceTestClient([]string{core.CapW3CTraceContext})
	sb := &core.SignalBatch{Signals: []*core.SignalRecord{{SignalType: "log", Body: "x"}}}

	// 全零 trace_id 非法。
	bad := validBatchTC()
	bad.TraceId = "00000000000000000000000000000000"
	_, err := c.SendBatch(context.Background(), sb, "tag", "src",
		core.WithTraceContext(bad))
	if err == nil {
		t.Fatal("expected validation error for all-zero trace_id, got nil")
	}
	mbe, ok := err.(*core.Error)
	if !ok || mbe.Code != core.CodeValidation {
		t.Errorf("expected CodeValidation error, got %v", err)
	}
}

// TestSendBatch_NoOpts_NoGate 验证回归：不传 opts 时门控不误触发（返回的是
// 状态相关错误而非 capability 错误），证明变参对旧调用零影响。
func TestSendBatch_NoOpts_NoGate(t *testing.T) {
	c := newTraceTestClient(nil) // negotiated==nil
	sb := &core.SignalBatch{Signals: []*core.SignalRecord{{SignalType: "log", Body: "x"}}}

	_, err := c.SendBatch(context.Background(), sb, "tag", "src")
	if err == nil {
		// 走到状态检查会因非 Ready 报错；无论哪种，都不应是 capability 门控错误。
		return
	}
	if mbe, ok := err.(*core.Error); ok && mbe.Code == core.CodeBatch {
		t.Errorf("no-opts call must not hit capability gate, got CodeBatch: %v", err)
	}
}

// TestReserveInflight_TraceContextPassthrough 白盒验证：traceContext 被正确设入
// BatchMessage proto（field 7）；nil 时不设（wire 与旧版一致）。
func TestReserveInflight_TraceContextPassthrough(t *testing.T) {
	c := newTraceTestClient(nil)
	batchJSON := []byte("any-payload")

	// 非 nil → BatchMessage.TraceContext 携带其值。
	tc := validBatchTC()
	_, _, payload, err := c.reserveInflight("tag", "src", batchJSON, 1, tc)
	if err != nil {
		t.Fatalf("reserveInflight with tc failed: %v", err)
	}
	var msg corepb.BatchMessage
	if err := core.Decode(payload, &msg); err != nil {
		t.Fatalf("decode BatchMessage: %v", err)
	}
	if msg.GetTraceContext() == nil {
		t.Fatal("TraceContext not set on BatchMessage")
	}
	if got := msg.GetTraceContext().GetTraceId(); got != tc.TraceId {
		t.Errorf("trace_id = %q, want %q", got, tc.TraceId)
	}

	// nil → TraceContext 不设（与旧版 wire 一致）。
	_, _, payloadNil, err := c.reserveInflight("tag", "src", batchJSON, 1, nil)
	if err != nil {
		t.Fatalf("reserveInflight without tc failed: %v", err)
	}
	var msgNil corepb.BatchMessage
	if err := core.Decode(payloadNil, &msgNil); err != nil {
		t.Fatalf("decode BatchMessage: %v", err)
	}
	if msgNil.GetTraceContext() != nil {
		t.Errorf("expected nil TraceContext when not provided, got %v", msgNil.GetTraceContext())
	}
}
