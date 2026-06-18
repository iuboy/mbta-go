package v2

import (
	"testing"

	"github.com/iuboy/mbta-go/core"
)

// v2 是未实现的占位包（需 GM TLS 库）。NewServer/NewClient 在构造时即返回
// 明确的「未实现」错误，而非返回一个在 Start/Connect 时才失败的实例——
// 避免「构造成功、运行失败」的误导性 API。以下测试锁定此契约。

func TestNewServer_NotImplemented(t *testing.T) {
	_, err := NewServer(ServerConfig{
		Transport: QUICServerConfig{Address: "localhost:7400"},
	})
	if err == nil {
		t.Fatal("expected not-implemented error from NewServer")
	}
	if core.GetErrorCode(err) != core.NumConfig {
		t.Errorf("error code = %d, want %d (NumConfig)", core.GetErrorCode(err), core.NumConfig)
	}
}

func TestNewClient_NotImplemented(t *testing.T) {
	_, err := NewClient(ClientConfig{
		Transport: QUICClientConfig{Server: "localhost:7400"},
	})
	if err == nil {
		t.Fatal("expected not-implemented error from NewClient")
	}
	if core.GetErrorCode(err) != core.NumConfig {
		t.Errorf("error code = %d, want %d (NumConfig)", core.GetErrorCode(err), core.NumConfig)
	}
}
