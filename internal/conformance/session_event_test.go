package conformance

import (
	"context"
	"sync"
	"testing"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// runAuthedHandshakeWithOnSession 复用 doHandshake 的握手骨架，但注入 OnSession 回调
// 并在 HELLO 中填充 hostname/instance_id/agent_version/os（用于校验 CONNECTED 携带完整身份）。
// 返回捕获到的事件（按到达顺序）与 cancel（测试调用以触发 DISCONNECTED）。
func runAuthedHandshakeWithOnSession(t *testing.T, helloHostname, helloOS, helloVersion string) (*sessionRecorder, context.CancelFunc) {
	t.Helper()
	tr := NewFakeTransport(false)
	policy := core.Policy{
		SupportedCapabilities: []string{"codec_proto", "comp_zstd", "cs_intl", "durable_ack"},
		DefaultCodec:          corepb.Codec_CODEC_PROTO,
		DefaultCompression:    corepb.Compression_COMPRESSION_NONE,
		CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
	}
	auth := core.NewStaticTokenValidator(map[string]string{"secret-token": "agent-1"})

	rec := &sessionRecorder{}
	h := protocol.NewCoreHandler(tr, protocol.HandlerConfig{
		Auth: auth, Policy: policy, Sink: &noopSink{}, ServerID: "srv-1", OnSession: rec.append,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = h.Handle(ctx) }()

	// HELLO（带完整身份字段）
	hello := &corepb.HelloMessage{
		AgentId:      "agent-1",
		Hostname:     helloHostname,
		InstanceId:   "inst-xyz",
		AgentVersion: helloVersion,
		FrameVersion: 1,
		Capabilities: []string{"codec_proto", "cs_intl"},
	}
	if helloOS != "" {
		hello.Os = &helloOS
	}
	hp, err := core.Encode(hello)
	if err != nil {
		cancel()
		t.Fatalf("encode hello: %v", err)
	}
	tr.ControlIn <- MakeFrame(core.TypeHello, core.FlagControl, core.ChannelControl, hp)
	ackF := ReadFrame(t, tr.Sent)
	if ackF.Header.Type != core.TypeHelloAck {
		cancel()
		t.Fatalf("expected HELLO_ACK, got type %d", ackF.Header.Type)
	}
	var ack core.HelloAckMessage
	_ = core.Decode(ackF.Payload, &ack)
	cs := ack.GetCipherSuite()

	// AUTH
	authNonce := core.ComputeChallengeResponse("secret-token", string(ack.GetChallengeNonce()), cs)
	authMsg := &corepb.AuthMessage{
		Token:     "secret-token",
		AgentId:   "agent-1",
		SessionId: ack.GetSessionId(),
		AuthNonce: authNonce,
	}
	ap, _ := core.Encode(authMsg)
	tr.ControlIn <- MakeFrame(core.TypeAuth, core.FlagControl, core.ChannelControl, ap)
	if okF := ReadFrame(t, tr.Sent); okF.Header.Type != core.TypeAuthOK {
		cancel()
		t.Fatalf("expected AUTH_OK, got type %d", okF.Header.Type)
	}

	// CONNECTED 应在 AUTH_OK 后同步触发；等待它落盘。
	dead := time.After(2 * time.Second)
	for {
		if rec.hasConnected() {
			break
		}
		select {
		case <-dead:
			cancel()
			t.Fatalf("CONNECTED event not fired within timeout; events=%d", rec.len())
		case <-time.After(5 * time.Millisecond):
		}
	}
	return rec, cancel
}

// sessionRecorder 线程安全地收集 SessionEvent；避免测试通过 slice header 读到过期快照。
type sessionRecorder struct {
	mu     sync.Mutex
	events []core.SessionEvent
}

func (r *sessionRecorder) append(ev core.SessionEvent) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func (r *sessionRecorder) snapshot() []core.SessionEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]core.SessionEvent, len(r.events))
	copy(out, r.events)
	return out
}

func (r *sessionRecorder) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func (r *sessionRecorder) hasConnected() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ev := range r.events {
		if ev.Type == core.SessionConnected {
			return true
		}
	}
	return false
}

// waitForDisconnected 轮询直到 DISCONNECTED 落盘或超时。
func (r *sessionRecorder) waitForDisconnected(timeout time.Duration) (*core.SessionEvent, bool) {
	dead := time.After(timeout)
	for {
		r.mu.Lock()
		for i := range r.events {
			if r.events[i].Type == core.SessionDisconnected {
				ev := r.events[i]
				r.mu.Unlock()
				return &ev, true
			}
		}
		r.mu.Unlock()
		select {
		case <-dead:
			return nil, false
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestOnSession_Connected 验证 CONNECTED 在 AUTH_OK 后触发并携带完整 HELLO 身份字段。
func TestOnSession_Connected(t *testing.T) {
	rec, cancel := runAuthedHandshakeWithOnSession(t, "host-1", "linux", "9.9.9")
	defer cancel()

	var connected *core.SessionEvent
	for _, ev := range rec.snapshot() {
		if ev.Type == core.SessionConnected {
			connected = &ev
			break
		}
	}
	if connected == nil {
		t.Fatalf("no CONNECTED event; got %+v", rec.snapshot())
	}
	if connected.AgentID != "agent-1" {
		t.Errorf("AgentID = %q, want agent-1", connected.AgentID)
	}
	if connected.Hostname != "host-1" {
		t.Errorf("Hostname = %q, want host-1", connected.Hostname)
	}
	if connected.OS != "linux" {
		t.Errorf("OS = %q, want linux", connected.OS)
	}
	if connected.AgentVersion != "9.9.9" {
		t.Errorf("AgentVersion = %q, want 9.9.9", connected.AgentVersion)
	}
	if connected.InstanceID != "inst-xyz" {
		t.Errorf("InstanceID = %q, want inst-xyz", connected.InstanceID)
	}
}

// TestOnSession_DisconnectedOnCancel 验证连接结束（ctx 取消）时触发 DISCONNECTED，
// 且 AgentID 与 CONNECTED 配对。FakeTransport 的 RemoteAddr 为 nil，不做断言。
func TestOnSession_DisconnectedOnCancel(t *testing.T) {
	rec, cancel := runAuthedHandshakeWithOnSession(t, "host-1", "linux", "1.0.0")

	// 已确认 CONNECTED。取消 ctx 结束连接，等待 DISCONNECTED。
	cancel()
	ev, ok := rec.waitForDisconnected(3 * time.Second)
	if !ok {
		t.Fatalf("DISCONNECTED event not fired within timeout; events=%+v", rec.snapshot())
	}
	if ev.AgentID != "agent-1" {
		t.Errorf("DISCONNECTED AgentID = %q, want agent-1", ev.AgentID)
	}
}

// TestOnSession_NoDisconnectedForUnauthedConnection 验证未通过认证的连接不产生
// DISCONNECTED（没有配对的 CONNECTED）。发一个无效 AUTH 触发认证失败后结束。
func TestOnSession_NoDisconnectedForUnauthedConnection(t *testing.T) {
	tr := NewFakeTransport(false)
	policy := core.Policy{
		SupportedCapabilities: []string{"codec_proto", "cs_intl"},
		DefaultCodec:          corepb.Codec_CODEC_PROTO,
		CipherSuite:           corepb.CipherSuite_CIPHER_SUITE_INTL,
	}
	auth := core.NewStaticTokenValidator(map[string]string{"secret-token": "agent-1"})

	var rec sessionRecorder
	h := protocol.NewCoreHandler(tr, protocol.HandlerConfig{
		Auth: auth, Policy: policy, Sink: &noopSink{}, ServerID: "srv-1",
		OnSession: rec.append,
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.Handle(ctx) }()

	// HELLO（合法），但随后发错误 AUTH。
	hello := &corepb.HelloMessage{AgentId: "agent-1", FrameVersion: 1, Capabilities: []string{"codec_proto", "cs_intl"}}
	hp, _ := core.Encode(hello)
	tr.ControlIn <- MakeFrame(core.TypeHello, core.FlagControl, core.ChannelControl, hp)
	ackF := ReadFrame(t, tr.Sent) // HELLO_ACK
	var ack core.HelloAckMessage
	_ = core.Decode(ackF.Payload, &ack)
	cs := ack.GetCipherSuite()

	// 用错误 token 计算 challenge-response（必然校验失败）。
	badNonce := core.ComputeChallengeResponse("wrong-token", string(ack.GetChallengeNonce()), cs)
	authMsg := &corepb.AuthMessage{
		Token: "wrong-token", AgentId: "agent-1", SessionId: ack.GetSessionId(), AuthNonce: badNonce,
	}
	ap, _ := core.Encode(authMsg)
	// 连续发送错误 AUTH 直到达到 maxAuthAttempts，handler 返回 error，Handle 退出。
	for i := 0; i < 5; i++ {
		select {
		case tr.ControlIn <- MakeFrame(core.TypeAuth, core.FlagControl, core.ChannelControl, ap):
		case <-time.After(200 * time.Millisecond):
		}
	}

	// 等待 handler 退出（不再有事件到达）。
	time.Sleep(150 * time.Millisecond)
	cancel()
	time.Sleep(150 * time.Millisecond)

	for _, ev := range rec.snapshot() {
		if ev.Type == core.SessionDisconnected {
			t.Errorf("未认证连接不应触发 DISCONNECTED，但收到 %+v", ev)
		}
		if ev.Type == core.SessionConnected {
			t.Errorf("认证失败的连接不应触发 CONNECTED，但收到 %+v", ev)
		}
	}
}

// noopSink 满足 core.EventSink，丢弃所有事件（握手测试不关心数据投递）。
type noopSink struct{}

func (n *noopSink) OnSignalBatch(_ context.Context, _ string, _ *core.SignalBatch) error { return nil }
func (n *noopSink) OnPressure(_ string) core.PressureState                                 { return core.PressureNormal }
