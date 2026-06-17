package core

import (
	"testing"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// r2 message 测试：corepb 类型 + Validate 函数 + proto Encode/Decode。

func TestValidateHello(t *testing.T) {
	if err := ValidateHello(&HelloMessage{AgentId: "agent-1", FrameVersion: 1}); err != nil {
		t.Errorf("valid hello: %v", err)
	}
	if err := ValidateHello(&HelloMessage{AgentId: "", FrameVersion: 1}); err == nil {
		t.Error("empty agent_id should fail")
	}
	if err := ValidateHello(nil); err == nil {
		t.Error("nil should fail")
	}
}

func TestValidateHelloAck(t *testing.T) {
	if err := ValidateHelloAck(&HelloAckMessage{SessionId: []byte("s")}); err != nil {
		t.Errorf("valid hello_ack: %v", err)
	}
	if err := ValidateHelloAck(&HelloAckMessage{SessionId: nil}); err == nil {
		t.Error("empty session_id should fail")
	}
}

func TestValidateAuth(t *testing.T) {
	m := &AuthMessage{AgentId: "a", SessionId: []byte("s"), AuthNonce: []byte("n")}
	if err := ValidateAuth(m); err != nil {
		t.Errorf("valid auth: %v", err)
	}
	if err := ValidateAuth(&AuthMessage{AgentId: "a", SessionId: []byte("s")}); err == nil {
		t.Error("missing auth_nonce should fail")
	}
}

func TestValidateBatch(t *testing.T) {
	cid := NewChunkID()
	m := &BatchMessage{Seq: 1, ChunkId: cid.Bytes(), Batch: []byte("payload")}
	if err := ValidateBatch(m); err != nil {
		t.Errorf("valid batch: %v", err)
	}
	if err := ValidateBatch(&BatchMessage{Seq: 0, ChunkId: cid.Bytes(), Batch: []byte("p")}); err == nil {
		t.Error("seq=0 should fail")
	}
	if err := ValidateBatch(&BatchMessage{Seq: 1, ChunkId: nil, Batch: []byte("p")}); err == nil {
		t.Error("empty chunk_id should fail")
	}
	if err := ValidateBatch(&BatchMessage{Seq: 1, ChunkId: make([]byte, 17), Batch: []byte("p")}); err == nil {
		t.Error("oversized chunk_id should fail")
	}
	if err := ValidateBatch(&BatchMessage{Seq: 1, ChunkId: cid.Bytes(), Batch: nil}); err == nil {
		t.Error("empty batch should fail")
	}
}

func TestEncodeDecodeMessageRoundTrip(t *testing.T) {
	orig := &HelloMessage{
		AgentId:      "agent-1",
		Hostname:     "host",
		FrameVersion: 1,
		AgentVersion: "0.1.0",
		Capabilities: []string{"codec_proto", "comp_zstd"},
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
	dg := &DatagramMessage{Seq: 1, ChunkId: NewChunkID().Bytes(), Batch: []byte("dg"), EventsCount: 1}
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
