package ntls

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

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

// TestWriteFrameCtx_DeadlineAbortsWrite 验证调用方 ctx 的 deadline 能中断阻塞写。
// net.Pipe 是同步无缓冲管道：对端不读时，本端 Write 永久阻塞。绑定短 deadline 后，
// Write 应在 ~deadline 时返回错误，而非无限阻塞——这是 SendBatch ctx 真正受尊重的保证。
func TestWriteFrameCtx_DeadlineAbortsWrite(t *testing.T) {
	c, err := NewClient(ClientConfig{Server: "localhost:0", AgentID: "test"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c1, c2 := net.Pipe()
	c.conn = c1
	defer c1.Close()
	defer c2.Close()

	// 100ms deadline；payload 足够大确保对端不读时 Write 必然阻塞到 deadline。
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	payload := make([]byte, 4096)

	start := time.Now()
	err = c.writeFrameCtx(ctx, core.TypeBatch, core.FlagData, payload)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected write to fail on deadline, got nil")
	}
	// 必须及时返回（远小于无 deadline 时的无限阻塞）；放宽到 deadline 的 5 倍容差。
	if elapsed > 500*time.Millisecond {
		t.Errorf("write returned too late: %v (deadline 100ms)", elapsed)
	}
}

// TestWriteFrameCtx_AlreadyCancelled 验证进入时 ctx 已取消则立即返回、不触碰连接。
func TestWriteFrameCtx_AlreadyCancelled(t *testing.T) {
	c, err := NewClient(ClientConfig{Server: "localhost:0", AgentID: "test"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	// conn 故意不设置：若实现误触碰连接会 nil panic，证明早退。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err = c.writeFrameCtx(ctx, core.TypeBatch, core.FlagData, []byte("x"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error on already-cancelled ctx")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if elapsed > 20*time.Millisecond {
		t.Errorf("returned too late for already-cancelled ctx: %v", elapsed)
	}
}
