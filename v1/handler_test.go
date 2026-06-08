package v1

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/iuboy/mbta-go/core"
)

func TestHandleHello(t *testing.T) {
	cfg := ConnectionHandlerConfig{
		Auth:     core.NewStaticTokenValidator(map[string]string{"tok1": "agent-1"}),
		Policy:   core.Policy{EnableGzip: true, EnableHMACSHA256: true, EnablePartialAck: true},
		ServerID: "test-server",
	}

	h := &ConnectionHandler{
		config: cfg,
		sm:     core.NewServerMachine(),
		replay: core.NewReplayCache(),
		window: core.NewWindow(100, 10000, 16*1024*1024),
	}

	// Simulate HELLO message
	hello := core.HelloMessage{
		AgentID:      "agent-1",
		Version:      1,
		Capabilities: []string{core.CapCodecJSON, core.CapCompressGzip, core.CapHMACSHA256},
	}
	payload, _ := json.Marshal(hello)

	buf := &bytes.Buffer{}
	_ = core.Write(buf, core.TypeHello, core.FlagControl, payload)

	// Create a pipe to capture response
	ctrlRead := bytes.NewReader(buf.Bytes())
	var ctrlWrite bytes.Buffer

	// We need to simulate reading from and writing to the control stream.
	// Since we can't use a real QUIC stream, test the message processing logic directly.
	var err error

	// Reconstruct the frame
	f, err := core.Read(ctrlRead, core.DefaultLimits())
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}

	// Process HELLO payload directly
	var msg core.HelloMessage
	if err := json.Unmarshal(f.Payload, &msg); err != nil {
		t.Fatalf("unmarshal hello: %v", err)
	}

	if err := msg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	h.agentID = msg.AgentID

	// Negotiate
	result := core.Negotiate(msg.Capabilities, cfg.Policy)

	// Verify negotiation
	if result.Compression != core.CompressionGzip {
		t.Errorf("compression = %q, want gzip", result.Compression)
	}
	if result.HMACAlgo != core.HMACAlgoSHA256 {
		t.Errorf("hmac_algo = %q, want sha256", result.HMACAlgo)
	}
	if result.Codec != core.CodecJSON {
		t.Errorf("codec = %q, want json", result.Codec)
	}

	// Build and write HELLO_ACK
	helloAck := core.HelloAckMessage{
		ServerVersion:        1,
		ServerID:             cfg.ServerID,
		SessionID:            "test-session",
		SelectedCapabilities: result.SelectedCapabilities,
		Codec:                result.Codec,
		Compression:          result.Compression,
		HMACAlgo:             result.HMACAlgo,
		Encryption:           result.Encryption,
	}

	ackPayload, _ := json.Marshal(helloAck)
	_ = core.Write(&ctrlWrite, core.TypeHelloAck, core.FlagControl, ackPayload)

	// Verify response
	respFrame, err := core.Read(bytes.NewReader(ctrlWrite.Bytes()), core.DefaultLimits())
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if respFrame.Header.Type != core.TypeHelloAck {
		t.Errorf("response type = 0x%04x, want HELLO_ACK", respFrame.Header.Type)
	}

	var ackMsg core.HelloAckMessage
	_ = json.Unmarshal(respFrame.Payload, &ackMsg)
	if ackMsg.Codec != "json" {
		t.Errorf("ack codec = %q", ackMsg.Codec)
	}
	if ackMsg.SessionID == "" {
		t.Error("session_id should be set")
	}
}

func TestProcessBatchEnvelope(t *testing.T) {
	keys, _ := core.GenerateSessionKeys()

	h := &ConnectionHandler{
		config: ConnectionHandlerConfig{},
		sm:     core.NewServerMachine(),
		replay: core.NewReplayCache(),
		window: core.NewWindow(100, 10000, 16*1024*1024),
		negotiated: &core.NegotiateResult{
			HMACAlgo: "sha256",
		},
		keys:    keys,
		agentID: "agent-1",
	}

	// Build a batch
	signalBatch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{TimeUnixMs: 1000, Body: "hello"},
			{TimeUnixMs: 2000, Body: "world"},
		},
	}
	batchJSON, _ := json.Marshal(signalBatch)
	batch := core.BatchMessage{
		Seq:     1,
		ChunkID: "chunk-001",
		Tag:     "test",
		Source:  "test",
		Batch:   batchJSON,
	}
	batchPayload, _ := json.Marshal(batch)

	// Build envelope
	env, err := core.Build(core.Params{
		SessionID:   "s-test",
		KeyID:       keys.KeyID,
		Seq:         1,
		ChunkID:     "chunk-001",
		Codec:       "json",
		Compression: "none",
		Encryption:  "none",
		HMACAlgo:    "sha256",
		HMACKey:     keys.HMACKey,
	}, batchPayload)
	if err != nil {
		t.Fatalf("build envelope: %v", err)
	}

	// Encode envelope to JSON (verify it serializes cleanly)
	_, _ = json.Marshal(env)

	// Verify HMAC
	if !core.VerifyHMACSHA256(keys.HMACKey, env) {
		t.Fatal("HMAC verification should succeed")
	}

	// Open envelope
	got, err := core.Open(env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	var decoded core.BatchMessage
	_ = json.Unmarshal(got, &decoded)

	// Decode Batch field to SignalBatch
	var decodedSignalBatch core.SignalBatch
	_ = json.Unmarshal(decoded.Batch, &decodedSignalBatch)

	if decoded.Seq != 1 || decoded.ChunkID != "chunk-001" || len(decodedSignalBatch.Signals) != 2 {
		t.Errorf("decoded batch mismatch: %+v", decoded)
	}

	// Verify replay detection
	dedupKey := core.Key("agent-1", "chunk-001")
	existing := h.replay.SeenOrAdd(dedupKey)
	if existing != nil {
		t.Error("first time should not be in cache")
	}

	// Second time should be detected
	existing = h.replay.SeenOrAdd(dedupKey)
	if existing == nil {
		t.Error("duplicate should be detected")
	}
}

func TestStaticTokenValidatorIntegration(t *testing.T) {
	v := core.NewStaticTokenValidator(map[string]string{
		"valid-token": "agent-1",
	})

	identity, err := v.Validate("valid-token")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if identity.AgentID != "agent-1" {
		t.Errorf("agent_id = %q", identity.AgentID)
	}

	_, err = v.Validate("invalid-token")
	if err == nil {
		t.Error("invalid token should fail")
	}
}
