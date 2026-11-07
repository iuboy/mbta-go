package conformance

// redirect_test.go：REDIRECT 全链路一致性（spec §3.1/§11.4/§11.6）。
//
// 服务端：RedirectChecker 命中 → 发 REDIRECT 帧（leader 地址经 ValidateHostPort
// 校验）+ Handle 以错误收场；地址非法 → 静默忽略、连接存活。
// 客户端：dispatchRedirect 单飞行 CAS、panic 防护、payload 原样透传回调。

import (
	"context"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// TestRedirect_IssuedAfterHandshake 验证 RedirectChecker 命中时：握手完成即
// 发 REDIRECT（leader_addr/leader_id 原样下发）且 Handle 返回错误（连接拆除非
// nil 返回——调用方据此回收连接槽）。
func TestRedirect_IssuedAfterHandshake(t *testing.T) {
	env := startEnv(t, envConfig{redirect: func(context.Context) (core.RedirectInfo, bool) {
		return core.RedirectInfo{LeaderAddr: "10.0.0.1:7400", LeaderID: "leader-a"}, true
	}})

	f := ReadFrame(t, env.tr.Sent)
	if f.Header.Type != core.TypeRedirect {
		t.Fatalf("expected REDIRECT, got type 0x%02x", f.Header.Type)
	}
	var rd core.Redirect
	if err := core.Decode(f.Payload, &rd); err != nil {
		t.Fatalf("decode redirect: %v", err)
	}
	if rd.GetLeaderAddr() != "10.0.0.1:7400" || rd.GetLeaderId() != "leader-a" {
		t.Errorf("redirect = (%q, %q), want (10.0.0.1:7400, leader-a)", rd.GetLeaderAddr(), rd.GetLeaderId())
	}

	select {
	case err := <-env.handleErr:
		if err == nil {
			t.Error("Handle returned nil after redirect, want non-nil（redirect 后连接拆除）")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return after redirect")
	}
}

// TestRedirect_InvalidAddrIgnoredConnectionAlive 验证 leader 地址非法
// （ValidateHostPort 拒绝）时 REDIRECT 不下发、连接存活——握手后 PING 仍得
// PONG（§11.4：校验通过才可使用，防配置错误把全舰队断连）。
func TestRedirect_InvalidAddrIgnoredConnectionAlive(t *testing.T) {
	env := startEnv(t, envConfig{redirect: func(context.Context) (core.RedirectInfo, bool) {
		return core.RedirectInfo{LeaderAddr: "not a host:port!", LeaderID: "leader-a"}, true
	}})

	// 握手本身已完成（startEnv 断言过 HELLO_ACK）；发 PING 验证连接存活。
	ping, err := core.Encode(&core.PingMsg{TimeUnixNs: time.Now().UnixNano(), Nonce: []byte{0x07, 0x89}})
	if err != nil {
		t.Fatalf("encode ping: %v", err)
	}
	env.tr.ControlIn <- MakeFrame(core.TypePing, ping)

	f := ReadFrame(t, env.tr.Sent)
	if f.Header.Type != core.TypePong {
		t.Fatalf("expected PONG (connection alive), got type 0x%02x", f.Header.Type)
	}
	var pong core.PongMsg
	if err := core.Decode(f.Payload, &pong); err != nil {
		t.Fatalf("decode pong: %v", err)
	}
	if string(pong.GetNonce()) != "\x07\x89" {
		t.Errorf("pong nonce = %x, want 0789（回显）", pong.GetNonce())
	}
	// 无迟到 REDIRECT（静默窗口）。
	if f, ok := NextFrame(env.tr.Sent, 100*time.Millisecond); ok && f.Header.Type == core.TypeRedirect {
		t.Error("unexpected REDIRECT frame for invalid leader address")
	}
}

// TestRedirect_ClientDispatchSingleFlight 验证客户端 dispatchRedirect：payload
// 原样透传回调；handler 执行中（30s 窗口内）重复 REDIRECT 帧被丢弃。
func TestRedirect_ClientDispatchSingleFlight(t *testing.T) {
	cc, pipe := startClientEnv(t, nil, false, nil)

	got := make(chan []byte, 4)
	block := make(chan struct{}) // handler 主动阻塞制造单飞行窗口
	cc.SetRedirectHandler(func(ctx context.Context, payload []byte) {
		got <- payload
		<-block
	})

	rd, err := core.Encode(&core.Redirect{LeaderAddr: "10.0.0.2:7400", LeaderId: "leader-b"})
	if err != nil {
		t.Fatalf("encode redirect: %v", err)
	}
	// 经 Sent 通道注入（clientPipeTransport.ReadFrame 的消费源）——与
	// ReadControlLoop 的真实到达路径一致。
	pipe.tr.Sent <- MakeFrame(core.TypeRedirect, rd)

	select {
	case p := <-got:
		var dec core.Redirect
		if err := core.Decode(p, &dec); err != nil || dec.GetLeaderAddr() != "10.0.0.2:7400" {
			t.Errorf("redirect payload = %q (err=%v), want decoded leader 10.0.0.2:7400", p, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for redirect handler invocation")
	}

	// 单飞行：handler 未返回期间第二帧到达 → 丢弃（不排队、不并发回调）。
	pipe.tr.Sent <- MakeFrame(core.TypeRedirect, rd)
	select {
	case p := <-got:
		t.Errorf("duplicate REDIRECT dispatched while handler in flight, want dropped (got %q)", p)
	case <-time.After(300 * time.Millisecond):
		// 静默窗口无第二次派发 = 单飞行生效。
	}
	close(block)
}

// TestRedirect_ClientHandlerPanicRecovered 验证 REDIRECT 回调 panic 不撕裂
// 客户端：连接保持 Ready，后续 PING 由服务端回 PONG 证活。
func TestRedirect_ClientHandlerPanicRecovered(t *testing.T) {
	cc, pipe := startClientEnv(t, nil, false, nil)

	cc.SetRedirectHandler(func(context.Context, []byte) {
		panic("redirect handler bug")
	})
	rd, err := core.Encode(&core.Redirect{LeaderAddr: "10.0.0.3:7400"})
	if err != nil {
		t.Fatalf("encode redirect: %v", err)
	}
	pipe.tr.Sent <- MakeFrame(core.TypeRedirect, rd)

	// panic 后连接存活：客户端仍可发送（SendBatch 成功返回 seq）。
	if cc.State() != core.StateReady {
		t.Fatalf("client state = %v after redirect handler panic, want READY", cc.State())
	}
	if cc.IsClosed() {
		t.Fatal("client closed after redirect handler panic, want alive")
	}
	if _, err := cc.SendBatch(context.Background(), signalsOf(t, 1, "post-panic")); err != nil {
		t.Fatalf("SendBatch after redirect handler panic: %v", err)
	}
}
