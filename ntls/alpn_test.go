package ntls

// alpn_test.go：TLCP ALPN 协商接入回归（pollux-go 支持 RFC 7301 后，ntls
// 双侧声明 mbta-ntls/1——spec §0.1 版本身份在 TLCP wire 上恢复）。
//
// 单元级：双侧 Config 构造断言（NextProtos 声明）。
// 端到端：真实 TLCP 握手后 NegotiatedProtocol 断言（证书缺失跳过——
// 与 transport_mtls_test 同一 fixture 约定）。

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBuildTLCPConfigsDeclareALPN 断言双侧 TLCP Config 均声明 mbta-ntls/1
// （客户端提议 + 服务端偏好——一侧缺失即协商失败或身份信号缺位）。
func TestBuildTLCPConfigsDeclareALPN(t *testing.T) {
	dir := filepath.Join("..", "test", "data", "ntls")
	for _, f := range []string{"sm2_sign_cert.pem", "sm2_sign_key.pem", "sm2_enc_cert.pem", "sm2_enc_key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Skipf("SM2 certificates not generated (go run test/data/ntls/gen_certs.go): %v", err)
		}
	}
	srvCfg := &ServerConfig{
		SignCertFile: filepath.Join(dir, "sm2_sign_cert.pem"),
		SignKeyFile:  filepath.Join(dir, "sm2_sign_key.pem"),
		EncCertFile:  filepath.Join(dir, "sm2_enc_cert.pem"),
		EncKeyFile:   filepath.Join(dir, "sm2_enc_key.pem"),
	}
	stc, err := buildServerTLCP(srvCfg)
	if err != nil {
		t.Fatalf("buildServerTLCP: %v", err)
	}
	if len(stc.NextProtos) != 1 || stc.NextProtos[0] != ALPNProtocol {
		t.Fatalf("server NextProtos = %v, want [%s]", stc.NextProtos, ALPNProtocol)
	}

	// TLCP 引擎硬性要求客户端双证书（pollux Validate）——与集成测试同款
	// fixture（服务端自签 CA 签发的同一套双证书）。
	ctc, err := buildClientTLCP(&ClientCredentials{
		SignCertFile: filepath.Join(dir, "sm2_sign_cert.pem"),
		SignKeyFile:  filepath.Join(dir, "sm2_sign_key.pem"),
		EncCertFile:  filepath.Join(dir, "sm2_enc_cert.pem"),
		EncKeyFile:   filepath.Join(dir, "sm2_enc_key.pem"),
		CAFile:       filepath.Join(dir, "sm2_ca.pem"),
	}, "127.0.0.1:7400")
	if err != nil {
		t.Fatalf("buildClientTLCP: %v", err)
	}
	if len(ctc.NextProtos) != 1 || ctc.NextProtos[0] != ALPNProtocol {
		t.Fatalf("client NextProtos = %v, want [%s]", ctc.NextProtos, ALPNProtocol)
	}
}

// TestTLCPHandshakeNegotiatedProtocol 端到端：真实 TLCP 握手完成后
// NegotiatedProtocol 返回 mbta-ntls/1（spec §0.1「版本唯一来源是 ALPN」
// 在 TLCP 模式的 wire 级落地）。
func TestTLCPHandshakeNegotiatedProtocol(t *testing.T) {
	dir := filepath.Join("..", "test", "data", "ntls")
	for _, f := range []string{"sm2_sign_cert.pem", "sm2_sign_key.pem", "sm2_enc_cert.pem", "sm2_enc_key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Skipf("SM2 certificates not generated (go run test/data/ntls/gen_certs.go): %v", err)
		}
	}
	srvCfg := &ServerConfig{
		Address:      "127.0.0.1:0",
		SignCertFile: filepath.Join(dir, "sm2_sign_cert.pem"),
		SignKeyFile:  filepath.Join(dir, "sm2_sign_key.pem"),
		EncCertFile:  filepath.Join(dir, "sm2_enc_cert.pem"),
		EncKeyFile:   filepath.Join(dir, "sm2_enc_key.pem"),
	}
	ln, err := Listen(srvCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type result struct {
		proto string
		err   error
	}
	srvCh := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvCh <- result{"", err}
			return
		}
		// TLCP 服务端需显式驱动握手（Accept 返回的是未握手连接）。
		hs := c.(interface {
			HandshakeContext(context.Context) error
			NegotiatedProtocol() string
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := hs.HandshakeContext(ctx); err != nil {
			srvCh <- result{"", err}
			return
		}
		srvCh <- result{hs.NegotiatedProtocol(), nil}
	}()

	cliCfg := &ClientConfig{
		Server: ln.Addr().String(),
		Credentials: &ClientCredentials{
			SignCertFile: filepath.Join(dir, "sm2_sign_cert.pem"),
			SignKeyFile:  filepath.Join(dir, "sm2_sign_key.pem"),
			EncCertFile:  filepath.Join(dir, "sm2_enc_cert.pem"),
			EncKeyFile:   filepath.Join(dir, "sm2_enc_key.pem"),
			CAFile:       filepath.Join(dir, "sm2_ca.pem"),
		},
	}
	conn, err := Dial(context.Background(), cliCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case r := <-srvCh:
		if r.err != nil {
			t.Fatalf("server accept: %v", r.err)
		}
		if r.proto != ALPNProtocol {
			t.Fatalf("server negotiated = %q, want %q", r.proto, ALPNProtocol)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for server side")
	}
	if cl := conn.(interface{ NegotiatedProtocol() string }); cl.NegotiatedProtocol() != ALPNProtocol {
		t.Fatalf("client negotiated = %q, want %q", cl.NegotiatedProtocol(), ALPNProtocol)
	}
}
