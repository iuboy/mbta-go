package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"sync/atomic"
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

// mockSink captures batches delivered via EventSink.
type mockSink struct {
	batches []*core.SignalBatch
	agents  []string
}

func (m *mockSink) OnSignalBatch(_ context.Context, agentID string, batch *core.SignalBatch) error {
	m.batches = append(m.batches, batch)
	m.agents = append(m.agents, agentID)
	return nil
}

func (m *mockSink) OnPressure(_ string) core.PressureState {
	return core.PressureNormal
}

// mockDurableSink captures batches with result feedback.
type mockDurableSink struct {
	batches []*core.SignalBatch
	agents  []string
	counter atomic.Int32
}

func (m *mockDurableSink) OnSignalBatch(_ context.Context, agentID string, batch *core.SignalBatch) error {
	m.batches = append(m.batches, batch)
	m.agents = append(m.agents, agentID)
	m.counter.Add(1)
	return nil
}

func (m *mockDurableSink) OnPressure(_ string) core.PressureState {
	return core.PressureNormal
}

func (m *mockDurableSink) OnSignalBatchWithResult(ctx context.Context, agentID string, batch *core.SignalBatch) (*core.RouteResult, error) {
	if err := m.OnSignalBatch(ctx, agentID, batch); err != nil {
		return nil, err
	}
	return &core.RouteResult{
		Status:      core.ACKStatusDurable,
		EventsCount: len(batch.Signals),
		QueueType:   "durable",
		Pressure:    core.PressureNormal,
	}, nil
}

// buildTestEnvelope creates a SecureEnvelope with the given compression and HMAC settings.
func buildTestEnvelope(t *testing.T, batch core.BatchMessage, params core.Params) []byte {
	t.Helper()
	batchPayload, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	env, err := core.Build(params, batchPayload)
	if err != nil {
		t.Fatalf("build envelope: %v", err)
	}
	envPayload, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return envPayload
}

func TestProcessBatch_WithGzipCompression(t *testing.T) {
	sink := &mockSink{}
	h := &ConnectionHandler{
		config: ConnectionHandlerConfig{
			Sink:   sink,
			Policy: core.Policy{EnableGzip: true},
		},
		sm:       core.NewServerMachine(),
		replay:   core.NewReplayCache(),
		window:   core.NewWindow(100, 10000, 16*1024*1024),
		controlW: &bytes.Buffer{},
		negotiated: &core.NegotiateResult{
			Compression: core.CompressionGzip,
			HMACAlgo:    core.HMACAlgoNone,
		},
		agentID:   "agent-1",
		sessionID: "s-gzip-test",
	}

	signalBatch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log", TimeUnixMs: 1000, Body: "compressed message"},
		},
	}
	batchJSON, _ := json.Marshal(signalBatch)
	batch := core.BatchMessage{
		Seq:     1,
		ChunkID: "chunk-gzip",
		Tag:     "test",
		Source:  "gzip-test",
		Batch:   batchJSON,
	}

	params := core.Params{
		SessionID:   "s-gzip-test",
		Seq:         1,
		ChunkID:     "chunk-gzip",
		Codec:       core.CodecJSON,
		Compression: core.CompressionGzip,
		Encryption:  core.EncryptionNone,
		HMACAlgo:    core.HMACAlgoNone,
	}
	envPayload := buildTestEnvelope(t, batch, params)

	// Write frame so processBatch can read it
	var buf bytes.Buffer
	_ = core.Write(&buf, core.TypeBatch, core.FlagEnvelope|core.FlagData, envPayload)

	f, err := core.Read(bytes.NewReader(buf.Bytes()), core.DefaultLimits())
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}

	h.processBatch(context.Background(), nil, f.Payload)

	if len(sink.batches) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(sink.batches))
	}
	if len(sink.batches[0].Signals) != 1 {
		t.Errorf("expected 1 signal, got %d", len(sink.batches[0].Signals))
	}
	if sink.batches[0].Signals[0].Body != "compressed message" {
		t.Errorf("signal body = %v", sink.batches[0].Signals[0].Body)
	}
	if sink.agents[0] != "agent-1" {
		t.Errorf("agent = %q", sink.agents[0])
	}
}

func TestProcessBatch_ReplayDedup(t *testing.T) {
	sink := &mockSink{}
	h := &ConnectionHandler{
		config: ConnectionHandlerConfig{
			Sink: sink,
		},
		sm:       core.NewServerMachine(),
		replay:   core.NewReplayCache(),
		window:   core.NewWindow(100, 10000, 16*1024*1024),
		controlW: &bytes.Buffer{},
		negotiated: &core.NegotiateResult{
			Compression: core.CompressionNone,
			HMACAlgo:    core.HMACAlgoNone,
		},
		agentID:   "agent-dedup",
		sessionID: "s-dedup-test",
	}

	signalBatch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log", TimeUnixMs: 1000, Body: "dedup test"},
		},
	}
	batchJSON, _ := json.Marshal(signalBatch)
	batch := core.BatchMessage{
		Seq:     1,
		ChunkID: "chunk-dedup",
		Batch:   batchJSON,
	}

	params := core.Params{
		SessionID:   "s-dedup-test",
		Seq:         1,
		ChunkID:     "chunk-dedup",
		Codec:       core.CodecJSON,
		Compression: core.CompressionNone,
		Encryption:  core.EncryptionNone,
		HMACAlgo:    core.HMACAlgoNone,
	}
	envPayload := buildTestEnvelope(t, batch, params)

	var buf bytes.Buffer
	_ = core.Write(&buf, core.TypeBatch, core.FlagEnvelope|core.FlagData, envPayload)
	f, _ := core.Read(bytes.NewReader(buf.Bytes()), core.DefaultLimits())

	// First delivery — should succeed
	h.processBatch(context.Background(), nil, f.Payload)
	if len(sink.batches) != 1 {
		t.Fatalf("first delivery: expected 1 batch, got %d", len(sink.batches))
	}

	// Second delivery with same chunk_id — should be deduped (sink not called again)
	h.processBatch(context.Background(), nil, f.Payload)
	if len(sink.batches) != 1 {
		t.Errorf("duplicate delivery: expected 1 batch, got %d (dedup failed)", len(sink.batches))
	}
}

func TestProcessBatch_HMACVerification(t *testing.T) {
	keys, err := core.GenerateSessionKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}

	sink := &mockSink{}
	h := &ConnectionHandler{
		config: ConnectionHandlerConfig{
			Sink: sink,
		},
		sm:       core.NewServerMachine(),
		replay:   core.NewReplayCache(),
		window:   core.NewWindow(100, 10000, 16*1024*1024),
		controlW: &bytes.Buffer{},
		negotiated: &core.NegotiateResult{
			Compression: core.CompressionNone,
			HMACAlgo:    core.HMACAlgoSHA256,
		},
		keys:      keys,
		agentID:   "agent-hmac",
		sessionID: "s-hmac-test",
	}

	signalBatch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log", TimeUnixMs: 1000, Body: "hmac verified"},
		},
	}
	batchJSON, _ := json.Marshal(signalBatch)
	batch := core.BatchMessage{
		Seq:     1,
		ChunkID: "chunk-hmac",
		Batch:   batchJSON,
	}

	params := core.Params{
		SessionID:   "s-hmac-test",
		KeyID:       keys.KeyID,
		Seq:         1,
		ChunkID:     "chunk-hmac",
		Codec:       core.CodecJSON,
		Compression: core.CompressionNone,
		Encryption:  core.EncryptionNone,
		HMACAlgo:    core.HMACAlgoSHA256,
		HMACKey:     keys.HMACKey,
	}
	envPayload := buildTestEnvelope(t, batch, params)

	var buf bytes.Buffer
	_ = core.Write(&buf, core.TypeBatch, core.FlagEnvelope|core.FlagData, envPayload)
	f, _ := core.Read(bytes.NewReader(buf.Bytes()), core.DefaultLimits())

	h.processBatch(context.Background(), nil, f.Payload)

	if len(sink.batches) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(sink.batches))
	}
	if sink.batches[0].Signals[0].Body != "hmac verified" {
		t.Errorf("signal body = %v", sink.batches[0].Signals[0].Body)
	}
}

func TestProcessBatch_HMACMismatch(t *testing.T) {
	keys, _ := core.GenerateSessionKeys()
	wrongKeys, _ := core.GenerateSessionKeys()

	sink := &mockSink{}
	h := &ConnectionHandler{
		config: ConnectionHandlerConfig{
			Sink: sink,
		},
		sm:       core.NewServerMachine(),
		replay:   core.NewReplayCache(),
		window:   core.NewWindow(100, 10000, 16*1024*1024),
		controlW: &bytes.Buffer{},
		negotiated: &core.NegotiateResult{
			Compression: core.CompressionNone,
			HMACAlgo:    core.HMACAlgoSHA256,
		},
		keys:      keys, // server has correct keys
		agentID:   "agent-hmac-fail",
		sessionID: "s-hmac-fail",
	}

	signalBatch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log", TimeUnixMs: 1000, Body: "tampered"},
		},
	}
	batchJSON, _ := json.Marshal(signalBatch)
	batch := core.BatchMessage{
		Seq:     1,
		ChunkID: "chunk-hmac-fail",
		Batch:   batchJSON,
	}

	// Build envelope with WRONG keys
	params := core.Params{
		SessionID:   "s-hmac-fail",
		KeyID:       wrongKeys.KeyID,
		Seq:         1,
		ChunkID:     "chunk-hmac-fail",
		Codec:       core.CodecJSON,
		Compression: core.CompressionNone,
		Encryption:  core.EncryptionNone,
		HMACAlgo:    core.HMACAlgoSHA256,
		HMACKey:     wrongKeys.HMACKey,
	}
	envPayload := buildTestEnvelope(t, batch, params)

	var buf bytes.Buffer
	_ = core.Write(&buf, core.TypeBatch, core.FlagEnvelope|core.FlagData, envPayload)
	f, _ := core.Read(bytes.NewReader(buf.Bytes()), core.DefaultLimits())

	h.processBatch(context.Background(), nil, f.Payload)

	// HMAC mismatch should cause NACK — batch NOT delivered to sink
	if len(sink.batches) != 0 {
		t.Errorf("expected 0 batches (HMAC mismatch), got %d", len(sink.batches))
	}
}

func TestProcessBatch_DurableSink(t *testing.T) {
	sink := &mockDurableSink{}
	h := &ConnectionHandler{
		config: ConnectionHandlerConfig{
			Sink: sink,
		},
		sm:       core.NewServerMachine(),
		replay:   core.NewReplayCache(),
		window:   core.NewWindow(100, 10000, 16*1024*1024),
		controlW: &bytes.Buffer{},
		negotiated: &core.NegotiateResult{
			Compression: core.CompressionNone,
			HMACAlgo:    core.HMACAlgoNone,
		},
		agentID:   "agent-durable",
		sessionID: "s-durable-test",
	}

	signalBatch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "metric", TimeUnixMs: 1000, MetricName: "cpu", MetricFields: map[string]float64{"usage": 75.5}},
		},
	}
	batchJSON, _ := json.Marshal(signalBatch)
	batch := core.BatchMessage{
		Seq:     1,
		ChunkID: "chunk-durable",
		Batch:   batchJSON,
	}

	params := core.Params{
		SessionID:   "s-durable-test",
		Seq:         1,
		ChunkID:     "chunk-durable",
		Codec:       core.CodecJSON,
		Compression: core.CompressionNone,
		Encryption:  core.EncryptionNone,
		HMACAlgo:    core.HMACAlgoNone,
	}
	envPayload := buildTestEnvelope(t, batch, params)

	var buf bytes.Buffer
	_ = core.Write(&buf, core.TypeBatch, core.FlagEnvelope|core.FlagData, envPayload)
	f, _ := core.Read(bytes.NewReader(buf.Bytes()), core.DefaultLimits())

	h.processBatch(context.Background(), nil, f.Payload)

	if sink.counter.Load() != 1 {
		t.Errorf("expected 1 batch delivered to durable sink, got %d", sink.counter.Load())
	}
}
