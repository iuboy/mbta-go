package core

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	mbtatest "github.com/iuboy/mbta-go/testing"
)

// ---------------------------------------------------------------------------
// Step 2: Throttle 上限保护
// ---------------------------------------------------------------------------

func TestThrottleStateApply_ClampsToMax(t *testing.T) {
	t.Parallel()
	ts := &ThrottleState{}
	// 传入一个超过 MaxThrottleDelay 的值（10 分钟）
	ts.Apply(10 * 60 * 1000)

	if !ts.Active() {
		t.Error("throttle should be active")
	}
	wd := ts.WaitDuration()
	if wd > MaxThrottleDelay {
		t.Errorf("WaitDuration() = %v, want <= %v", wd, MaxThrottleDelay)
	}
}

func TestThrottleStateApply_NegativeValue(t *testing.T) {
	t.Parallel()
	ts := &ThrottleState{}
	ts.Apply(-5000)

	if ts.Active() {
		t.Error("negative delay should not activate throttle")
	}
}

func TestThrottleStateApply_NormalValue(t *testing.T) {
	t.Parallel()
	ts := &ThrottleState{}
	ts.Apply(3000) // 3 秒

	if !ts.Active() {
		t.Error("throttle should be active for 3s")
	}
	wd := ts.WaitDuration()
	if wd < 2*time.Second || wd > 4*time.Second {
		t.Errorf("WaitDuration() = %v, want ~3s", wd)
	}
}

// ---------------------------------------------------------------------------
// Step 3: HMAC Nonce 填充
// ---------------------------------------------------------------------------

func TestBuild_NonceGeneratedWhenHMACEnabled(t *testing.T) {
	t.Parallel()
	params := Params{
		SessionID:   "sess-1",
		KeyID:       "key-1",
		Seq:         1,
		ChunkID:     "chunk-1",
		Codec:       CodecJSON,
		Compression: CompressionNone,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoSHA256,
		HMACKey:     make([]byte, 32),
	}

	env, err := Build(params, []byte(`{"test":true}`))
	mbtatest.AssertNoError(t, err, "Build with HMAC")

	if env.Nonce == "" {
		t.Error("Nonce should be non-empty when HMAC is enabled")
	}
	// 验证 nonce 是合法的 base64
	decoded, err := base64.StdEncoding.DecodeString(env.Nonce)
	mbtatest.AssertNoError(t, err, "decode nonce")
	if len(decoded) != 16 {
		t.Errorf("nonce length = %d, want 16", len(decoded))
	}
}

func TestBuild_NoNonceWithoutHMAC(t *testing.T) {
	t.Parallel()
	params := Params{
		SessionID:   "sess-1",
		Seq:         1,
		ChunkID:     "chunk-1",
		Codec:       CodecJSON,
		Compression: CompressionNone,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoNone,
	}

	env, err := Build(params, []byte(`{"test":true}`))
	mbtatest.AssertNoError(t, err, "Build without HMAC")

	if env.Nonce != "" {
		t.Errorf("Nonce should be empty when HMAC is disabled, got %q", env.Nonce)
	}
}

func TestBuild_DifferentNoncesPerBuild(t *testing.T) {
	t.Parallel()
	params := Params{
		SessionID:   "sess-1",
		KeyID:       "key-1",
		Seq:         1,
		ChunkID:     "chunk-1",
		Codec:       CodecJSON,
		Compression: CompressionNone,
		Encryption:  EncryptionNone,
		HMACAlgo:    HMACAlgoSHA256,
		HMACKey:     make([]byte, 32),
	}

	env1, err := Build(params, []byte(`{}`))
	mbtatest.AssertNoError(t, err, "Build 1")
	params.Seq = 2
	params.ChunkID = "chunk-2"
	env2, err := Build(params, []byte(`{}`))
	mbtatest.AssertNoError(t, err, "Build 2")

	if env1.Nonce == env2.Nonce {
		t.Error("two builds should produce different nonces")
	}
}

// ---------------------------------------------------------------------------
// Step 4: ReplayCache 状态感知淘汰
// ---------------------------------------------------------------------------

func TestReplayCacheEvict_PrefersNonProcessing(t *testing.T) {
	t.Parallel()
	rc := NewReplayCacheWithSize(3)

	// 填充 3 个条目，全部标记为 Accepted
	rc.SeenOrAdd("key-1")
	rc.Update("key-1", ReplayAccepted)
	rc.SeenOrAdd("key-2")
	rc.Update("key-2", ReplayAccepted)
	rc.SeenOrAdd("key-3")
	rc.Update("key-3", ReplayAccepted)

	// 添加第 4 个条目，应淘汰 key-1（最早的 Accepted）
	result := rc.SeenOrAdd("key-4")
	if result != nil {
		t.Fatal("key-4 should be new")
	}

	// key-1 应被淘汰
	if rc.Get("key-1") != nil {
		t.Error("key-1 should have been evicted (oldest Accepted)")
	}
	// key-2, key-3 应保留
	if rc.Get("key-2") == nil {
		t.Error("key-2 should still exist")
	}
	if rc.Get("key-3") == nil {
		t.Error("key-3 should still exist")
	}
}

func TestReplayCacheEvict_SkipsProcessing(t *testing.T) {
	t.Parallel()
	rc := NewReplayCacheWithSize(3)

	// 填充 3 个条目：2 个 Processing，1 个 Accepted
	rc.SeenOrAdd("key-1") // Processing
	rc.SeenOrAdd("key-2")
	rc.Update("key-2", ReplayAccepted)
	rc.SeenOrAdd("key-3") // Processing

	// 添加第 4 个条目，应淘汰 key-2（唯一的非 Processing）
	result := rc.SeenOrAdd("key-4")
	if result != nil {
		t.Fatal("key-4 should be new")
	}

	// key-2 (Accepted) 应被淘汰
	if rc.Get("key-2") != nil {
		t.Error("key-2 (Accepted) should have been evicted first")
	}
	// key-1, key-3 (Processing) 应保留
	if rc.Get("key-1") == nil {
		t.Error("key-1 (Processing) should be preserved")
	}
	if rc.Get("key-3") == nil {
		t.Error("key-3 (Processing) should be preserved")
	}
}

func TestReplayCacheEvict_AllProcessingFallback(t *testing.T) {
	t.Parallel()
	rc := NewReplayCacheWithSize(3)

	// 填充 3 个条目，全部 Processing
	rc.SeenOrAdd("key-1")
	rc.SeenOrAdd("key-2")
	rc.SeenOrAdd("key-3")

	// 添加第 4 个条目，全部 Processing 时应回退淘汰最早的
	result := rc.SeenOrAdd("key-4")
	if result != nil {
		t.Fatal("key-4 should be new")
	}

	// key-1 应被淘汰（回退策略）
	if rc.Get("key-1") != nil {
		t.Error("key-1 should have been evicted as fallback (oldest Processing)")
	}
	// key-2, key-3 应保留
	if rc.Get("key-2") == nil {
		t.Error("key-2 should still exist")
	}
	if rc.Get("key-3") == nil {
		t.Error("key-3 should still exist")
	}
}

// ---------------------------------------------------------------------------
// Step 7: SignalRecord 类型校验
// ---------------------------------------------------------------------------

func TestSignalValidate_MetricRequiresName(t *testing.T) {
	t.Parallel()
	batch := &SignalBatch{
		Signals: []*SignalRecord{
			{SignalType: "metric"}, // 缺少 MetricName
		},
	}
	err := batch.Validate()
	mbtatest.AssertError(t, err, "metric without name")
	if !strings.Contains(err.Error(), "metric_name") {
		t.Errorf("error should mention metric_name, got: %v", err)
	}
}

func TestSignalValidate_SpanRequiresName(t *testing.T) {
	t.Parallel()
	batch := &SignalBatch{
		Signals: []*SignalRecord{
			{SignalType: "span", TraceID: "t1"}, // 缺少 Name
		},
	}
	err := batch.Validate()
	mbtatest.AssertError(t, err, "span without name")
	if !strings.Contains(err.Error(), "name is required for span") {
		t.Errorf("error should mention name, got: %v", err)
	}
}

func TestSignalValidate_SpanRequiresTraceID(t *testing.T) {
	t.Parallel()
	batch := &SignalBatch{
		Signals: []*SignalRecord{
			{SignalType: "span", Name: "GET /"}, // 缺少 TraceID
		},
	}
	err := batch.Validate()
	mbtatest.AssertError(t, err, "span without trace_id")
	if !strings.Contains(err.Error(), "trace_id") {
		t.Errorf("error should mention trace_id, got: %v", err)
	}
}

func TestSignalValidate_LogRequiresBody(t *testing.T) {
	t.Parallel()
	batch := &SignalBatch{
		Signals: []*SignalRecord{
			{SignalType: "log"}, // 缺少 Body
		},
	}
	err := batch.Validate()
	mbtatest.AssertError(t, err, "log without body")
	if !strings.Contains(err.Error(), "body is required for log") {
		t.Errorf("error should mention body, got: %v", err)
	}
}

func TestSignalValidate_UnknownTypeAccepted(t *testing.T) {
	t.Parallel()
	batch := &SignalBatch{
		Signals: []*SignalRecord{
			{SignalType: "custom"},
		},
	}
	err := batch.Validate()
	mbtatest.AssertNoError(t, err, "unknown signal type should be accepted")
}

// ---------------------------------------------------------------------------
// Step 8: ComputeChallengeResponse
// ---------------------------------------------------------------------------

func TestComputeChallengeResponse_SHA256(t *testing.T) {
	t.Parallel()
	token := "my-secret-token"
	nonce := "challenge-nonce-123"

	result1 := ComputeChallengeResponse(token, nonce, HMACAlgoSHA256)
	result2 := ComputeChallengeResponse(token, nonce, HMACAlgoSHA256)

	// 确定性：相同输入应产生相同输出
	if result1 != result2 {
		t.Error("ComputeChallengeResponse should be deterministic")
	}
	// 结果应为合法 base64
	_, err := base64.StdEncoding.DecodeString(result1)
	mbtatest.AssertNoError(t, err, "result should be valid base64")
}

func TestComputeChallengeResponse_DifferentTokens(t *testing.T) {
	t.Parallel()
	nonce := "same-nonce"

	r1 := ComputeChallengeResponse("token-a", nonce, HMACAlgoSHA256)
	r2 := ComputeChallengeResponse("token-b", nonce, HMACAlgoSHA256)

	if r1 == r2 {
		t.Error("different tokens should produce different responses")
	}
}

func TestComputeChallengeResponse_DifferentNonces(t *testing.T) {
	t.Parallel()
	token := "same-token"

	r1 := ComputeChallengeResponse(token, "nonce-a", HMACAlgoSHA256)
	r2 := ComputeChallengeResponse(token, "nonce-b", HMACAlgoSHA256)

	if r1 == r2 {
		t.Error("different nonces should produce different responses")
	}
}

func TestComputeChallengeResponse_SM3(t *testing.T) {
	t.Parallel()
	token := "my-secret-token"
	nonce := "challenge-nonce-123"

	result := ComputeChallengeResponse(token, nonce, HMACAlgoSM3)
	if result == "" {
		t.Error("SM3 result should not be empty")
	}

	// SM3 和 SHA256 应产生不同的结果
	shaResult := ComputeChallengeResponse(token, nonce, HMACAlgoSHA256)
	if result == shaResult {
		t.Error("SM3 and SHA256 should produce different results")
	}
}
