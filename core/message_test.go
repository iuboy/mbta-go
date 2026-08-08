package core

import (
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/testutil"
)

// r2 message 测试：corepb 类型 + Validate 函数 + proto Encode/Decode。

func TestValidateHello(t *testing.T) {
	if err := ValidateHello(&HelloMessage{AgentId: testutil.RandAgentID(), FrameVersion: 1}); err != nil {
		t.Errorf("valid hello: %v", err)
	}
	if err := ValidateHello(&HelloMessage{AgentId: "", FrameVersion: 1}); err == nil {
		t.Error("empty agent_id should fail")
	}
	if err := ValidateHello(nil); err == nil {
		t.Error("nil should fail")
	}
}

func TestValidateAuth(t *testing.T) {
	m := &AuthMessage{AgentId: testutil.RandAgentID(), SessionId: []byte("s"), AuthNonce: []byte("n"), Token: testutil.RandToken()}
	if err := ValidateAuth(m); err != nil {
		t.Errorf("valid auth: %v", err)
	}
	if err := ValidateAuth(&AuthMessage{AgentId: testutil.RandAgentID(), SessionId: []byte("s"), Token: testutil.RandToken()}); err == nil {
		t.Error("missing auth_nonce should fail")
	}
	// token 可以为空：tokenless AUTH 模式下服务端通过 TokenResolver 反查 token。
	// token 必填校验由 handleAuth 在 resolveAuthToken 之后执行。
	if err := ValidateAuth(&AuthMessage{AgentId: testutil.RandAgentID(), SessionId: []byte("s"), AuthNonce: []byte("n")}); err != nil {
		t.Errorf("missing token should not fail ValidateAuth (tokenless mode): %v", err)
	}
}

func TestValidateBatch(t *testing.T) {
	cid := NewChunkID()
	m := &BatchMessage{Seq: 1, ChunkId: cid.Bytes(), Batch: []byte(testutil.RandPayloadString(8))}
	if err := ValidateBatch(m); err != nil {
		t.Errorf("valid batch: %v", err)
	}
	if err := ValidateBatch(&BatchMessage{Seq: 0, ChunkId: cid.Bytes(), Batch: []byte(testutil.RandString(2))}); err == nil {
		t.Error("seq=0 should fail")
	}
	if err := ValidateBatch(&BatchMessage{Seq: 1, ChunkId: nil, Batch: []byte(testutil.RandString(2))}); err == nil {
		t.Error("empty chunk_id should fail")
	}
	if err := ValidateBatch(&BatchMessage{Seq: 1, ChunkId: make([]byte, 17), Batch: []byte(testutil.RandString(2))}); err == nil {
		t.Error("oversized chunk_id should fail")
	}
	// 回归：1-15 字节的截断 chunk_id 现在必须被拒绝（之前只检查 >16）。
	for _, n := range []int{1, 8, 15} {
		if err := ValidateBatch(&BatchMessage{Seq: 1, ChunkId: make([]byte, n), Batch: []byte(testutil.RandString(2))}); err == nil {
			t.Errorf("truncated chunk_id (%d bytes) should fail; must be exactly 16", n)
		}
	}
	if err := ValidateBatch(&BatchMessage{Seq: 1, ChunkId: cid.Bytes(), Batch: nil}); err == nil {
		t.Error("empty batch should fail")
	}
}

func TestEncodeDecodeMessageRoundTrip(t *testing.T) {
	orig := &HelloMessage{
		AgentId:      testutil.RandAgentID(),
		Hostname:     testutil.RandHost(),
		FrameVersion: 1,
		AgentVersion: testutil.RandVersion(),
		Capabilities: []string{CapCodecProto, CapCompZstd},
	}
	wire, err := Encode(orig)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got HelloMessage
	if err := Decode(wire, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.GetAgentId() != orig.GetAgentId() {
		t.Errorf("agent_id = %q, want %q", got.GetAgentId(), orig.GetAgentId())
	}
	if len(got.GetCapabilities()) != 2 {
		t.Errorf("capabilities len = %d, want 2", len(got.GetCapabilities()))
	}
}

// TestDatagramMessageExists 验证 r2 新增的 DATAGRAM 消息类型可用（core spec §4 type=7）。
func TestDatagramMessageExists(t *testing.T) {
	dg := &DatagramMessage{Seq: 1, ChunkId: NewChunkID().Bytes(), Batch: []byte(testutil.RandPayloadString(4)), EventsCount: 1}
	wire, err := Encode(dg)
	if err != nil {
		t.Fatalf("Encode datagram: %v", err)
	}
	var got DatagramMessage
	if err := Decode(wire, &got); err != nil {
		t.Fatalf("Decode datagram: %v", err)
	}
	if got.GetEventsCount() != 1 {
		t.Errorf("events_count = %d, want 1", got.GetEventsCount())
	}
}

// 编译期确认 AckMode enum 可用（双轨 cipher 配套）。
var _ corepb.AckMode = corepb.AckMode_ACK_MODE_DURABLE
