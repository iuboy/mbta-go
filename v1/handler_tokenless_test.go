package v1

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/iuboy/mbta-go/core"
)

// mockResolverValidator 同时实现 TokenValidator 与 TokenResolver，用于 tokenless
// 成功路径测试。
type mockResolverValidator struct {
	token   string
	agentID string
}

func (m *mockResolverValidator) Validate(token string) (*core.AgentIdentity, error) {
	if token != m.token {
		return nil, core.ErrInvalidToken
	}
	return &core.AgentIdentity{AgentID: m.agentID}, nil
}

func (m *mockResolverValidator) ResolveToken(agentID string) (string, error) {
	if agentID != m.agentID {
		return "", core.ErrAgentNotFound
	}
	return m.token, nil
}

// mockFailingResolver 实现 TokenResolver 但 ResolveToken 恒失败，用于 resolve
// 失败路径测试。
type mockFailingResolver struct{}

func (m *mockFailingResolver) Validate(string) (*core.AgentIdentity, error) {
	return &core.AgentIdentity{AgentID: "agent-1"}, nil
}

func (m *mockFailingResolver) ResolveToken(string) (string, error) {
	return "", core.ErrAgentNotFound
}

// newTokenlessTestHandler 构造可直接调用 handleHello/handleAuth 的 handler：
// controlW 注入 bytes.Buffer 捕获所有控制帧，状态机先置 ControlWait。
func newTokenlessTestHandler(auth core.TokenValidator, policy core.Policy) *ConnectionHandler {
	h := &ConnectionHandler{
		config:   ConnectionHandlerConfig{Auth: auth, Policy: policy, ServerID: "test-server"},
		conn:     &Conn{}, // handleAuth 成功后调 conn.SetAuthed(true)（仅用 atomic.Bool）
		sm:       core.NewServerMachine(),
		replay:   core.NewReplayCache(),
		window:   core.NewWindow(100, 10000, 16*1024*1024),
		controlW: &bytes.Buffer{},
	}
	// handleHello 调用 Transition(ServerStateHelloReceived)，需先到 ControlWait。
	if err := h.sm.Transition(core.ServerStateControlWait); err != nil {
		panic(err)
	}
	return h
}

// lastControlFrame 读取 buf 中的最后一帧并断言其类型。
func lastControlFrame(t *testing.T, buf *bytes.Buffer, wantType uint16) *core.Frame {
	t.Helper()
	var last core.Frame
	haveFrame := false
	r := bytes.NewReader(buf.Bytes())
	for {
		f, err := core.Read(r, core.DefaultLimits())
		if err != nil {
			break
		}
		last = f
		haveFrame = true
	}
	if !haveFrame {
		t.Fatalf("no control frame written; want type 0x%04x", wantType)
	}
	if last.Header.Type != wantType {
		t.Fatalf("control frame type = 0x%04x, want 0x%04x", last.Header.Type, wantType)
	}
	return &last
}

func containsCap(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

func helloOffering(caps ...string) []byte {
	hello := core.HelloMessage{AgentID: "agent-1", Version: 1, Capabilities: caps}
	b, _ := json.Marshal(hello)
	return b
}

// TestHandleHello_TokenlessRetainedWithResolver: Auth 实现 TokenResolver 时，
// 协商选中 tokenless 后保留在 HELLO_ACK 的 SelectedCapabilities 中。
func TestHandleHello_TokenlessRetainedWithResolver(t *testing.T) {
	h := newTokenlessTestHandler(
		&mockResolverValidator{token: "tok1", agentID: "agent-1"},
		core.Policy{EnableHMACSHA256: true, EnableAuthTokenless: true},
	)
	if err := h.handleHello(helloOffering(core.CapCodecJSON, core.CapHMACSHA256, core.CapAuthTokenless)); err != nil {
		t.Fatalf("handleHello: %v", err)
	}
	var ack core.HelloAckMessage
	json.Unmarshal(lastControlFrame(t, h.controlW.(*bytes.Buffer), core.TypeHelloAck).Payload, &ack)

	if !containsCap(ack.SelectedCapabilities, core.CapAuthTokenless) {
		t.Errorf("expected auth_tokenless retained; got %v", ack.SelectedCapabilities)
	}
	if h.challengeNonce == "" {
		t.Error("challenge nonce should be set after HELLO")
	}
}

// TestHandleHello_TokenlessPrunedWithoutResolver: Auth 仅实现 TokenValidator 时，
// 二次裁剪移除 tokenless，回退 legacy。
func TestHandleHello_TokenlessPrunedWithoutResolver(t *testing.T) {
	h := newTokenlessTestHandler(
		&mockTokenValidator{}, // server_test.go: 仅 Validate
		core.Policy{EnableHMACSHA256: true, EnableAuthTokenless: true},
	)
	if err := h.handleHello(helloOffering(core.CapCodecJSON, core.CapHMACSHA256, core.CapAuthTokenless)); err != nil {
		t.Fatalf("handleHello: %v", err)
	}
	var ack core.HelloAckMessage
	json.Unmarshal(lastControlFrame(t, h.controlW.(*bytes.Buffer), core.TypeHelloAck).Payload, &ack)

	if containsCap(ack.SelectedCapabilities, core.CapAuthTokenless) {
		t.Errorf("auth_tokenless must be pruned when Auth is not a TokenResolver; got %v", ack.SelectedCapabilities)
	}
}

// TestHandleAuth_TokenlessSuccess: tokenless 全流程——AUTH 不带 Token，服务端反查
// token 重算 HMAC 验证，再 Validate，发 AUTH_OK。
func TestHandleAuth_TokenlessSuccess(t *testing.T) {
	h := newTokenlessTestHandler(
		&mockResolverValidator{token: "tok1", agentID: "agent-1"},
		core.Policy{EnableHMACSHA256: true, EnableAuthTokenless: true},
	)
	buf := h.controlW.(*bytes.Buffer)
	if err := h.handleHello(helloOffering(core.CapCodecJSON, core.CapHMACSHA256, core.CapAuthTokenless)); err != nil {
		t.Fatalf("handleHello: %v", err)
	}
	var ack core.HelloAckMessage
	json.Unmarshal(lastControlFrame(t, buf, core.TypeHelloAck).Payload, &ack)

	// AUTH: Token 刻意留空，AuthNonce 用真实 token 计算（客户端持有自己的 token）。
	auth := core.AuthMessage{
		AgentID:   "agent-1",
		SessionID: ack.SessionID,
		AuthNonce: core.ComputeChallengeResponse("tok1", ack.ChallengeNonce, core.HMACAlgoSHA256),
		HMACAlgo:  core.HMACAlgoSHA256,
	}
	ap, _ := json.Marshal(auth)
	if err := h.handleAuth(ap); err != nil {
		t.Fatalf("handleAuth tokenless: %v", err)
	}

	okFrame := lastControlFrame(t, buf, core.TypeAuthOK)
	var ok core.AuthOKMessage
	json.Unmarshal(okFrame.Payload, &ok)
	if h.keys == nil {
		t.Error("session keys should be generated on tokenless success")
	}
}

// TestHandleAuth_TokenlessResolveFails: ResolveToken 返回错误时发 AUTH_FAIL，且
// code 模糊（invalid_auth），不泄露 agentID 是否存在。
func TestHandleAuth_TokenlessResolveFails(t *testing.T) {
	h := newTokenlessTestHandler(
		&mockFailingResolver{},
		core.Policy{EnableHMACSHA256: true, EnableAuthTokenless: true},
	)
	buf := h.controlW.(*bytes.Buffer)
	if err := h.handleHello(helloOffering(core.CapCodecJSON, core.CapHMACSHA256, core.CapAuthTokenless)); err != nil {
		t.Fatalf("handleHello: %v", err)
	}
	var ack core.HelloAckMessage
	json.Unmarshal(lastControlFrame(t, buf, core.TypeHelloAck).Payload, &ack)

	auth := core.AuthMessage{
		AgentID:   "agent-1",
		SessionID: ack.SessionID,
		AuthNonce: core.ComputeChallengeResponse("tok1", ack.ChallengeNonce, core.HMACAlgoSHA256),
		HMACAlgo:  core.HMACAlgoSHA256,
	}
	ap, _ := json.Marshal(auth)
	if err := h.handleAuth(ap); err == nil {
		t.Fatal("expected auth error when ResolveToken fails, got nil")
	}

	var fail core.AuthFailMessage
	json.Unmarshal(lastControlFrame(t, buf, core.TypeAuthFail).Payload, &fail)
	if fail.Code != "invalid_auth" {
		t.Errorf("AUTH_FAIL code = %q, want invalid_auth (must not leak agent existence)", fail.Code)
	}
}

// TestHandleAuth_LegacyRequiresToken: 未协商 tokenless（policy 未开）时走 legacy，
// token 来源是 msg.Token；Token 为空则 HMAC mismatch（因服务端用 "" 重算）。
func TestHandleAuth_LegacyRequiresToken(t *testing.T) {
	h := newTokenlessTestHandler(
		core.NewStaticTokenValidator(map[string]string{"tok1": "agent-1"}),
		core.Policy{EnableHMACSHA256: true}, // 未开 EnableAuthTokenless -> legacy
	)
	buf := h.controlW.(*bytes.Buffer)
	if err := h.handleHello(helloOffering(core.CapCodecJSON, core.CapHMACSHA256)); err != nil {
		t.Fatalf("handleHello: %v", err)
	}
	var ack core.HelloAckMessage
	json.Unmarshal(lastControlFrame(t, buf, core.TypeHelloAck).Payload, &ack)

	// legacy 路径下，客户端若不发 Token（Token=""），服务端用 "" 重算 HMAC，
	// 与客户端用真实 token 算的 AuthNonce 不匹配 -> challenge_mismatch。
	auth := core.AuthMessage{
		AgentID:   "agent-1",
		SessionID: ack.SessionID,
		AuthNonce: core.ComputeChallengeResponse("tok1", ack.ChallengeNonce, core.HMACAlgoSHA256),
		HMACAlgo:  core.HMACAlgoSHA256,
	}
	ap, _ := json.Marshal(auth)
	if err := h.handleAuth(ap); err == nil {
		t.Fatal("expected auth failure in legacy mode with empty token, got nil")
	}

	var fail core.AuthFailMessage
	json.Unmarshal(lastControlFrame(t, buf, core.TypeAuthFail).Payload, &fail)
	if fail.Code != "challenge_mismatch" {
		t.Errorf("AUTH_FAIL code = %q, want challenge_mismatch", fail.Code)
	}
}
