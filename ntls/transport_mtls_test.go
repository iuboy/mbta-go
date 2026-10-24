package ntls

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/iuboy/pollux-go/tlcp"
)

// P0 审查裁决回归：CAFile 配置即启用 mTLS——TLCP 服务端必须设置
// ClientAuth=RequireAndVerifyClientCert 且填充 ClientCACertificates。
// LoadRootCAs 只填服务端证书链的信任锚、不触碰 mTLS 字段（pollux NewConfig
// 默认 NoClientCert），修复前 mTLS 静默失效且无任何告警。
func TestBuildServerTLCP_CAFileEnablesMTLS(t *testing.T) {
	dir := filepath.Join("..", "test", "data", "ntls")
	for _, f := range []string{
		"sm2_sign_cert.pem", "sm2_sign_key.pem", "sm2_enc_cert.pem", "sm2_enc_key.pem", "sm2_ca.pem",
	} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Skipf("SM2 certificates not generated (go run test/data/ntls/gen_certs.go): %v", err)
		}
	}
	cfg := &ServerConfig{
		SignCertFile: filepath.Join(dir, "sm2_sign_cert.pem"),
		SignKeyFile:  filepath.Join(dir, "sm2_sign_key.pem"),
		EncCertFile:  filepath.Join(dir, "sm2_enc_cert.pem"),
		EncKeyFile:   filepath.Join(dir, "sm2_enc_key.pem"),
		CAFile:       filepath.Join(dir, "sm2_ca.pem"),
	}
	tc, err := buildServerTLCP(cfg)
	if err != nil {
		t.Fatalf("buildServerTLCP: %v", err)
	}
	if tc.ClientAuth != tlcp.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert (mTLS silently disabled)", tc.ClientAuth)
	}
	if len(tc.ClientCACertificates) == 0 {
		t.Fatal("ClientCACertificates empty; client certs cannot be verified")
	}
}

// 无 CAFile 时不得启用 mTLS（纯服务端 TLS 部署面保持原语义）。
func TestBuildServerTLCP_NoCAFileKeepsNoClientCert(t *testing.T) {
	dir := filepath.Join("..", "test", "data", "ntls")
	for _, f := range []string{"sm2_sign_cert.pem", "sm2_sign_key.pem", "sm2_enc_cert.pem", "sm2_enc_key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Skipf("SM2 certificates not generated: %v", err)
		}
	}
	tc, err := buildServerTLCP(&ServerConfig{
		SignCertFile: filepath.Join(dir, "sm2_sign_cert.pem"),
		SignKeyFile:  filepath.Join(dir, "sm2_sign_key.pem"),
		EncCertFile:  filepath.Join(dir, "sm2_enc_cert.pem"),
		EncKeyFile:   filepath.Join(dir, "sm2_enc_key.pem"),
	})
	if err != nil {
		t.Fatalf("buildServerTLCP: %v", err)
	}
	if tc.ClientAuth != tlcp.NoClientCert {
		t.Fatalf("ClientAuth = %v, want NoClientCert without CAFile", tc.ClientAuth)
	}
}
