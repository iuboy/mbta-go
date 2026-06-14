package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/iuboy/mbta-go/core"
)

// TestProcessBatch_AlgoMismatchNacked: 服务端协商了 gzip，但客户端发送的 envelope
// compression 为 none（且 HMAC 通过）→ 必须被 NACK envelope_algo_mismatch，不得
// 投递给 sink。证明已认证客户端无法用非协商算法绕过 (L-1)。
func TestProcessBatch_AlgoMismatchNacked(t *testing.T) {
	sink := &mockSink{}
	h := &ConnectionHandler{
		config:         ConnectionHandlerConfig{Sink: sink, Policy: core.Policy{}},
		sm:             core.NewServerMachine(),
		replay:         core.NewReplayCache(),
		window:         core.NewWindow(100, 10000, 16*1024*1024),
		serverInflight: &core.Inflight{},
		controlW:       &bytes.Buffer{},
		negotiated: &core.NegotiateResult{
			HMACAlgo:    core.HMACAlgoNone,
			Compression: core.CompressionGzip, // 协商了 gzip
		},
		agentID:   "agent-1",
		sessionID: "s-algo",
	}

	signalBatch := &core.SignalBatch{
		Signals: []*core.SignalRecord{{SignalType: "log", TimeUnixMs: 1, Body: "x"}},
	}
	batchJSON, _ := json.Marshal(signalBatch)
	batch := core.BatchMessage{Seq: 1, ChunkID: "chunk-algo", Batch: batchJSON}
	// params 不设 Compression → Build 归一化为 none，与 negotiated gzip 不匹配。
	params := core.Params{
		SessionID: "s-algo", Seq: 1, ChunkID: "chunk-algo",
		Codec: core.CodecJSON, HMACAlgo: core.HMACAlgoNone,
	}
	envPayload := buildTestEnvelope(t, batch, params)

	var buf bytes.Buffer
	_ = core.Write(&buf, core.TypeBatch, core.FlagEnvelope|core.FlagData, envPayload)
	f, err := core.Read(bytes.NewReader(buf.Bytes()), core.DefaultLimits())
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}

	h.processBatch(context.Background(), nil, f.Payload)

	if len(sink.batches) != 0 {
		t.Fatalf("expected 0 batches delivered on algo mismatch, got %d", len(sink.batches))
	}
	out := h.controlW.(*bytes.Buffer).Bytes()
	frame, err := core.Read(bytes.NewReader(out), core.DefaultLimits())
	if err != nil {
		t.Fatalf("expected NACK frame on control stream, got read error: %v", err)
	}
	if frame.Header.Type != core.TypeNack {
		t.Fatalf("expected NACK frame, got 0x%04x", frame.Header.Type)
	}
	var nack core.NackMessage
	if err := json.Unmarshal(frame.Payload, &nack); err != nil {
		t.Fatalf("unmarshal nack: %v", err)
	}
	if nack.Code != "envelope_algo_mismatch" {
		t.Errorf("NACK code = %q, want envelope_algo_mismatch", nack.Code)
	}
}

// TestProcessBatch_AlgoMatchDelivers: compression 与协商一致（均 none）时正常投递，
// 确认 L-1 校验不误伤合法流量。
func TestProcessBatch_AlgoMatchDelivers(t *testing.T) {
	sink := &mockSink{}
	h := &ConnectionHandler{
		config:         ConnectionHandlerConfig{Sink: sink, Policy: core.Policy{}},
		sm:             core.NewServerMachine(),
		replay:         core.NewReplayCache(),
		window:         core.NewWindow(100, 10000, 16*1024*1024),
		serverInflight: &core.Inflight{},
		controlW:       &bytes.Buffer{},
		negotiated: &core.NegotiateResult{
			HMACAlgo:    core.HMACAlgoNone,
			Compression: core.CompressionNone,
		},
		agentID:   "agent-1",
		sessionID: "s-ok",
	}

	signalBatch := &core.SignalBatch{
		Signals: []*core.SignalRecord{{SignalType: "log", TimeUnixMs: 1, Body: "ok"}},
	}
	batchJSON, _ := json.Marshal(signalBatch)
	batch := core.BatchMessage{Seq: 1, ChunkID: "chunk-ok", Batch: batchJSON}
	params := core.Params{
		SessionID: "s-ok", Seq: 1, ChunkID: "chunk-ok",
		Codec: core.CodecJSON, Compression: core.CompressionNone, HMACAlgo: core.HMACAlgoNone,
	}
	envPayload := buildTestEnvelope(t, batch, params)

	var buf bytes.Buffer
	_ = core.Write(&buf, core.TypeBatch, core.FlagEnvelope|core.FlagData, envPayload)
	f, _ := core.Read(bytes.NewReader(buf.Bytes()), core.DefaultLimits())

	h.processBatch(context.Background(), nil, f.Payload)

	if len(sink.batches) != 1 {
		t.Fatalf("expected 1 batch delivered on algo match, got %d", len(sink.batches))
	}
}
