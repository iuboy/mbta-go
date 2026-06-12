package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
)

// ---------------------------------------------------------------------------
// Step 5: Session TTL 强制执行
// ---------------------------------------------------------------------------

func TestProcessBatch_SessionExpired(t *testing.T) {
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
		agentID:   "agent-expired",
		sessionID: "s-expired",
		// 设置过期时间为 1 小时前
		expiresAt: func() atomic.Int64 { v := atomic.Int64{}; v.Store(time.Now().Add(-1 * time.Hour).Unix()); return v }(),
	}

	signalBatch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log", TimeUnixMs: 1000, Body: "expired session"},
		},
	}
	batchJSON, _ := json.Marshal(signalBatch)
	batch := core.BatchMessage{
		Seq:     1,
		ChunkID: "chunk-expired",
		Batch:   batchJSON,
	}

	params := core.Params{
		SessionID:   "s-expired",
		Seq:         1,
		ChunkID:     "chunk-expired",
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

	// 过期会话的 batch 不应投递到 sink
	if len(sink.batches) != 0 {
		t.Errorf("expected 0 batches (session expired), got %d", len(sink.batches))
	}

	// 控制流应收到 NACK（包含 "session_expired"）
	ctrlOutput := h.controlW.(*bytes.Buffer).Bytes()
	if len(ctrlOutput) == 0 {
		t.Fatal("expected NACK frame on control stream")
	}
	respFrame, err := core.Read(bytes.NewReader(ctrlOutput), core.DefaultLimits())
	if err != nil {
		t.Fatalf("read nack frame: %v", err)
	}
	if respFrame.Header.Type != core.TypeNack {
		t.Errorf("response type = 0x%04x, want NACK", respFrame.Header.Type)
	}
	var nack core.NackMessage
	_ = json.Unmarshal(respFrame.Payload, &nack)
	if nack.Code != "session_expired" {
		t.Errorf("nack code = %q, want session_expired", nack.Code)
	}
}

func TestProcessBatch_SessionNotExpired(t *testing.T) {
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
		agentID:   "agent-valid",
		sessionID: "s-valid",
		// 设置过期时间为 1 小时后
		expiresAt: func() atomic.Int64 { v := atomic.Int64{}; v.Store(time.Now().Add(1 * time.Hour).Unix()); return v }(),
	}

	signalBatch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log", TimeUnixMs: 1000, Body: "valid session"},
		},
	}
	batchJSON, _ := json.Marshal(signalBatch)
	batch := core.BatchMessage{
		Seq:     1,
		ChunkID: "chunk-valid",
		Batch:   batchJSON,
	}

	params := core.Params{
		SessionID:   "s-valid",
		Seq:         1,
		ChunkID:     "chunk-valid",
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

	// 未过期的 batch 应正常投递
	if len(sink.batches) != 1 {
		t.Errorf("expected 1 batch, got %d", len(sink.batches))
	}
}

func TestProcessBatch_ZeroExpiry(t *testing.T) {
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
		agentID:   "agent-zero",
		sessionID: "s-zero",
		// expiresAt 为零值 — 不检查过期
	}

	signalBatch := &core.SignalBatch{
		Signals: []*core.SignalRecord{
			{SignalType: "log", TimeUnixMs: 1000, Body: "no expiry"},
		},
	}
	batchJSON, _ := json.Marshal(signalBatch)
	batch := core.BatchMessage{
		Seq:     1,
		ChunkID: "chunk-zero",
		Batch:   batchJSON,
	}

	params := core.Params{
		SessionID:   "s-zero",
		Seq:         1,
		ChunkID:     "chunk-zero",
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

	if len(sink.batches) != 1 {
		t.Errorf("expected 1 batch (no expiry set), got %d", len(sink.batches))
	}
}

// ---------------------------------------------------------------------------
// Step 8: 挑战-响应 HMAC 集成验证
// ---------------------------------------------------------------------------

func TestChallengeResponse_Integration(t *testing.T) {
	token := "secret-token-123"
	nonce := "server-challenge-abc"

	// 客户端计算
	clientResponse := core.ComputeChallengeResponse(token, nonce, core.HMACAlgoSHA256)

	// 服务端用相同的 token 和 nonce 验证
	serverExpected := core.ComputeChallengeResponse(token, nonce, core.HMACAlgoSHA256)

	if clientResponse != serverExpected {
		t.Error("client and server should compute the same challenge response")
	}

	// 使用错误的 token 应产生不同结果
	wrongResponse := core.ComputeChallengeResponse("wrong-token", nonce, core.HMACAlgoSHA256)
	if clientResponse == wrongResponse {
		t.Error("wrong token should produce different response")
	}
}

func TestChallengeResponse_RawNonceRejected(t *testing.T) {
	token := "secret-token-123"
	nonce := "server-challenge-abc"

	// 客户端正确计算 HMAC 响应
	correctResponse := core.ComputeChallengeResponse(token, nonce, core.HMACAlgoSHA256)

	// 如果客户端仅回显原始 nonce（旧行为），应该与服务端期望的不匹配
	if nonce == correctResponse {
		t.Error("raw nonce echo should NOT match HMAC response — challenge-response is effective")
	}

	// 验证服务端比较逻辑
	if !strings.HasPrefix(correctResponse, " ") {
		// 结果应为 base64 编码（不是原始 nonce）
		if correctResponse == nonce {
			t.Error("HMAC response should not equal the raw nonce")
		}
	}
}
