package v1

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/iuboy/mbta-go/core"
)

// TestWriteFrameCtx_AlreadyCancelled 验证 writeFrameCtx 在 ctx 已取消时立即返回、
// 不触碰 stream（stream 故意 nil，误访问会 panic）。deadline-触发路径与 ntls.writeFrameCtx
// 同构（后者已在 ntls/client_test.go 用 net.Pipe 验证）。
func TestWriteFrameCtx_AlreadyCancelled(t *testing.T) {
	w := &quicStreamWrapper{} // stream 故意 nil：实现误访问会 panic
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := w.writeFrameCtx(ctx, core.TypeBatch, core.FlagData, []byte("x"))
	if err == nil {
		t.Fatal("expected error on already-cancelled ctx")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestNewClient(t *testing.T) {
	cfg := ClientConfig{
		AgentID:      "test-agent",
		Token:        "test-token",
		Capabilities: []string{core.CapCodecJSON, core.CapCompressGzip},
		PickStrategy: "single",
	}

	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if c.State() != core.StateDisconnected {
		t.Errorf("initial state = %s, want DISCONNECTED", c.State())
	}
	if c.SessionID() != "" {
		t.Error("session_id should be empty before connect")
	}
}

func TestDecodeBase64Key(t *testing.T) {
	// Valid 32-byte key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(key)

	got, err := decodeBase64Key(b64, 32)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 32 {
		t.Errorf("length = %d, want 32", len(got))
	}

	// Wrong length
	_, err = decodeBase64Key(b64, 16)
	if err == nil {
		t.Error("should fail on wrong length")
	}

	// Invalid base64
	_, err = decodeBase64Key("not-valid-base64!!!", 32)
	if err == nil {
		t.Error("should fail on invalid base64")
	}
}

func TestPendingBatchTracking(t *testing.T) {
	c, _ := NewClient(ClientConfig{AgentID: "test"})

	// Simulate storing a pending batch
	c.pendingAcks.Store("chunk-1", &pendingBatch{
		Seq:    1,
		Events: 10,
		Bytes:  1024,
	})

	// Retrieve it
	val, ok := c.pendingAcks.Load("chunk-1")
	if !ok {
		t.Fatal("pending batch not found")
	}
	pb := val.(*pendingBatch)
	if pb.Seq != 1 || pb.Events != 10 || pb.Bytes != 1024 {
		t.Errorf("pending batch mismatch: %+v", pb)
	}

	// Delete it
	c.pendingAcks.Delete("chunk-1")
	_, ok = c.pendingAcks.Load("chunk-1")
	if ok {
		t.Error("pending batch should be deleted")
	}
}

// TestClientCloseClearsSessionKeys 验证 close() 将 HMACKey 与 SM4Key 就地清零。
// 服务端 handler 已做对称清零；客户端必须一致，避免会话对称密钥在内存中残留。
// 通过保留对同一底层数组的引用，在 c.keys 被置 nil 后仍可观察到清零结果。
func TestClientCloseClearsSessionKeys(t *testing.T) {
	c, _ := NewClient(ClientConfig{AgentID: "test"})

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

func TestStreamPickerIntegration(t *testing.T) {
	cfg := ClientConfig{
		AgentID:      "test-agent",
		PickStrategy: "hash",
	}
	c, _ := NewClient(cfg)

	// Default picker should be nil before connect
	if c.picker != nil {
		t.Error("picker should be nil before connect")
	}
}
