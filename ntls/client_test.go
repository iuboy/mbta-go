package ntls

import (
	"testing"

	"github.com/iuboy/mbta-go/core"
)

// TestClientCloseClearsSessionKeys 验证 close() 将 HMACKey 与 SM4Key 就地清零。
// 与 v1 客户端及服务端 handler 保持一致，避免会话对称密钥在内存中残留。
// 通过保留对同一底层数组的引用，在 c.keys 被置 nil 后仍可观察到清零结果。
func TestClientCloseClearsSessionKeys(t *testing.T) {
	c, err := NewClient(ClientConfig{
		Server:  "localhost:0",
		AgentID: "test",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	hmacKey := make([]byte, 32)
	sm4Key := make([]byte, 16)
	for i := range hmacKey {
		hmacKey[i] = 0xAB
	}
	for i := range sm4Key {
		sm4Key[i] = 0xCD
	}
	// 注入密钥：直接复用上面 slice 的底层数组，清零对它们可见。
	c.keys = &core.SessionKeys{HMACKey: hmacKey, SM4Key: sm4Key}

	c.close()

	if c.keys != nil {
		t.Fatalf("keys should be nil after close, got %+v", c.keys)
	}
	for i, b := range hmacKey {
		if b != 0 {
			t.Errorf("HMACKey[%d] = 0x%02x, want 0x00 (cleared)", i, b)
		}
	}
	for i, b := range sm4Key {
		if b != 0 {
			t.Errorf("SM4Key[%d] = 0x%02x, want 0x00 (cleared)", i, b)
		}
	}
}
