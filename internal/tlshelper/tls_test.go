package tlshelper

import (
	"errors"
	"testing"
)

func TestLoadCertPool_EmptyPath(t *testing.T) {
	pool, err := LoadCertPool("")
	if pool != nil {
		t.Errorf("pool = %v, want nil", pool)
	}
	if !errors.Is(err, ErrNoCAFile) {
		t.Errorf("err = %v, want ErrNoCAFile", err)
	}
}

func TestLoadCertPool_MissingFile(t *testing.T) {
	_, err := LoadCertPool("/nonexistent/path/ca.pem")
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
	if errors.Is(err, ErrNoCAFile) {
		t.Error("missing file should not be ErrNoCAFile")
	}
}

func TestLoadKeyPair(t *testing.T) {
	// 无效路径 → 错误（具体内容依赖 tls.LoadX509KeyPair）。
	_, err := LoadKeyPair("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for missing cert/key files")
	}
}
