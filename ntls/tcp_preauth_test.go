package ntls

// tcp_preauth_test.go 验证认证前读超时（未认证连接钉死 connSem 槽位的 DoS 修复）。

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestRegression_TCPTransport_PreAuthReadTimeout 验证：静默对端（完成 TCP 连接后
// 不发任何 MBTA 帧）在认证前的等待是有界的——readLoop 的 pre-auth 读 deadline 到期
// 后逻辑通道关闭，RecvControlFrame 返回错误。修复前 readLoop 无任何读超时，
// 未认证连接可无限占用并发槽位。
func TestRegression_TCPTransport_PreAuthReadTimeout(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	silent, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("silent client dial: %v", err)
	}
	defer silent.Close() // 全程不发送任何字节

	srvConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer srvConn.Close()

	old := tcpPreAuthReadTimeout
	tcpPreAuthReadTimeout = 200 * time.Millisecond
	defer func() { tcpPreAuthReadTimeout = old }()

	tr := newTCPTransport(srvConn, 0)
	defer tr.Close()

	start := time.Now()
	_, rerr := tr.RecvControlFrame(context.Background())
	if rerr == nil {
		t.Fatal("expected error after pre-auth read timeout")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("pre-auth timeout took %v to fire (unauthenticated slot-pinning regression)", elapsed)
	}
}
