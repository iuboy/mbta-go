package conformance

// batch_test.go：BATCH 处理路径（v2-design §6.2 credit 生命周期 / §18-B5 校验次序）。
//
//   - accepted_only：accepted 即终态 + credit 回收 → CREDIT 帧；
//   - durable：accepted 中间态不返还 credit，done(Durable) 后返还；
//   - 负路径：envelope_open_failed / batch_invalid（seq 失配）/ batch_too_large
//     的 RESULT 反馈（已知实现缺陷：terminal() 不发送 RESULT，见任务报告 bug-D，
//     下列三个负路径测试当前红——规格要求客户端必须收到 rejected 反馈）。

import (
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// TestBatch_AcceptedOnly_TerminalAndCredit 验证 accepted_only 模式：
// RESULT(accepted) 即终态，随后额度攒批（threshold=1）立即以 CREDIT 帧返还；
// correlation 原样回显；sink 收到投递元信息。
func TestBatch_AcceptedOnly_TerminalAndCredit(t *testing.T) {
	sink := newSinkCapture()
	env := startEnv(t, envConfig{
		ackMode:              corepb.AckMode_ACK_MODE_ACCEPTED_ONLY,
		initialCreditBatches: 4, // threshold = max(1, 4/4) = 1 → 单批回收即 flush
		sink:                 sink.handler,
	})

	env.sendBatch(t, 1, "hello-batch", "corr-1")

	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED {
		t.Errorf("result level = %v, want ACCEPTED", r.GetLevel())
	}
	if r.GetCode() != 0 {
		t.Errorf("result code = %d, want 0", r.GetCode())
	}
	if r.GetCorrelation() != "corr-1" {
		t.Errorf("correlation = %q, want echo corr-1", r.GetCorrelation())
	}
	c := AwaitCredit(t, env.tr.Sent, 5*time.Second)
	if c.GetBatches() != 1 {
		t.Errorf("credit batches = %d, want 1（accepted_only：accepted 即终态并回收）", c.GetBatches())
	}
	if c.GetBytes() == 0 {
		t.Error("credit bytes = 0, want frame bytes")
	}

	ev := sink.waitEvent(t, 1, 5*time.Second)
	if ev.Meta.Seq != 1 {
		t.Errorf("sink meta.seq = %d, want 1", ev.Meta.Seq)
	}
	if ev.Agent != env.cfg.agentID {
		t.Errorf("sink agent = %q, want %q", ev.Agent, env.cfg.agentID)
	}
	if ev.Meta.EventsCount != 1 {
		t.Errorf("sink meta.events_count = %d, want 1", ev.Meta.EventsCount)
	}
	if ev.Raw != nil {
		t.Error("sink raw supplied although SinkOptions.Raw=false")
	}
	// Decoded 供给的正确性由 TestSink_DecodedSupply 单独断言（当前为已知实现缺陷）。
}

// TestSink_DecodedSupply 验证 SinkOptions.Raw=false 时 Decoded 必须供给解码后的
// SignalBatch。
//
// 已知实现缺陷（见任务报告 bug-B）：makeEvent 把 Batch 消息编码（而非
// Batch.payload 内的 SignalBatch 编码）交给 decodeSignalBatch，proto 解码必然
// 失败 → Decoded 恒为 nil。本测试钉住契约，待实现修复后转绿。
func TestSink_DecodedSupply(t *testing.T) {
	sink := newSinkCapture()
	env := startEnv(t, envConfig{sink: sink.handler})
	env.sendBatch(t, 1, "decoded-batch", "")
	AwaitResult(t, env.tr.Sent, 1, 5*time.Second)

	ev := sink.waitEvent(t, 1, 5*time.Second)
	if ev.Decoded == nil {
		t.Fatal("Decoded = nil although SinkOptions.Raw=false（makeEvent 解码了错误的字节层）")
	}
	if len(ev.Decoded.Signals) != 1 || ev.Decoded.Signals[0].SignalType != core.SignalTypeLog {
		t.Errorf("decoded signals = %+v, want 1 log signal", ev.Decoded.Signals)
	}
}

// TestBatch_Durable_TwoPhaseSettlement 验证 durable 模式两段确认（§16-1）：
// accepted 为中间态（额度保留，不产生 CREDIT）；done(Durable) 后 RESULT(durable)
// 并返还额度。durable RESULT 的 correlation 回显由 TestResult_CorrelationEcho 断言。
func TestBatch_Durable_TwoPhaseSettlement(t *testing.T) {
	sink := newSinkCapture()
	env := startEnv(t, envConfig{
		ackMode:              corepb.AckMode_ACK_MODE_DURABLE,
		initialCreditBatches: 4,
		sinkOpts:             core.SinkOptions{Durable: true},
		sink:                 sink.handler,
	})

	env.sendBatch(t, 1, "durable-batch", "corr-d")

	// 第一阶段：accepted（中间态）。
	r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED {
		t.Fatalf("first result level = %v, want ACCEPTED", r.GetLevel())
	}
	// 中间态不返还 credit：CREDIT 帧不应出现。
	if f, ok := NextFrame(env.tr.Sent, 300*time.Millisecond); ok {
		t.Fatalf("frame type 0x%02x arrived after accepted（durable 中间态不得返还 credit）", f.Header.Type)
	}
	// done 尚未调用：handler 持有 done，测试侧择机触发。
	sink.waitEvent(t, 1, 5*time.Second)

	// 第二阶段：done(Durable) → RESULT(durable) + CREDIT。
	sink.callDone(1, core.Outcome{Level: core.OutcomeDurable})
	r2 := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
	if r2.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_DURABLE {
		t.Errorf("second result level = %v, want DURABLE", r2.GetLevel())
	}
	c := AwaitCredit(t, env.tr.Sent, 5*time.Second)
	if c.GetBatches() != 1 {
		t.Errorf("credit batches = %d, want 1（durable 终态回收）", c.GetBatches())
	}
}

// TestResult_CorrelationEcho 验证 RESULT.correlation 在全部回执路径原样回显：
// done(Durable) 合成的终态 RESULT 与幂等 duplicate 回执。
//
// 已知实现缺陷（见任务报告 bug-C）：InflightSlot.Correlation 由 batchCorr 桩
// 恒置空串、deliver 未补充登记，done 路径与 duplicate 路径的 RESULT 均丢失 echo。
// 本测试钉住契约，待实现修复后转绿。
func TestResult_CorrelationEcho(t *testing.T) {
	t.Run("durable", func(t *testing.T) {
		sink := newSinkCapture()
		env := startEnv(t, envConfig{
			ackMode:              corepb.AckMode_ACK_MODE_DURABLE,
			initialCreditBatches: 4,
			sinkOpts:             core.SinkOptions{Durable: true},
			sink:                 sink.handler,
		})
		env.sendBatch(t, 1, "corr-path", "corr-durable")
		AwaitResult(t, env.tr.Sent, 1, 5*time.Second) // accepted（echo 正常）
		sink.waitEvent(t, 1, 5*time.Second)
		sink.callDone(1, core.Outcome{Level: core.OutcomeDurable})
		r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
		if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_DURABLE {
			t.Fatalf("level = %v, want DURABLE", r.GetLevel())
		}
		if r.GetCorrelation() != "corr-durable" {
			t.Errorf("durable RESULT correlation = %q, want echo corr-durable", r.GetCorrelation())
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		sink := newSinkCapture()
		env := startEnv(t, envConfig{
			ackMode:              corepb.AckMode_ACK_MODE_DURABLE,
			initialCreditBatches: 8,
			sinkOpts:             core.SinkOptions{Durable: true},
			sink:                 sink.handler,
		})
		p := env.sendBatch(t, 1, "corr-dup", "corr-duplicate")
		AwaitResult(t, env.tr.Sent, 1, 5*time.Second) // accepted
		sink.waitEvent(t, 1, 5*time.Second)           // 在途（done 未调）
		env.tr.DataIn <- MakeFrame(core.TypeBatch, p)
		r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
		if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED {
			t.Fatalf("duplicate reply level = %v, want ACCEPTED", r.GetLevel())
		}
		if r.GetCorrelation() != "corr-duplicate" {
			t.Errorf("duplicate RESULT correlation = %q, want echo corr-duplicate", r.GetCorrelation())
		}
	})
}

// TestBatch_Rejected_EnvelopeSeqMismatch 验证 Envelope.seq ≠ Batch.seq →
// RESULT(rejected, batch_invalid)。
//
// 已知实现缺陷（见任务报告 bug-D）：processBatch 负路径只调 terminal()（记终态 +
// 回收 credit）而从不发送 RESULT 帧——客户端收不到任何反馈。本测试钉住规格，
// 待实现修复后转绿。
func TestBatch_Rejected_EnvelopeSeqMismatch(t *testing.T) {
	sink := newSinkCapture()
	env := startEnv(t, envConfig{sink: sink.handler})

	p := env.sealBatch(t, 2, "mismatch", "", 5, corepb.Compression_COMPRESSION_NONE) // env=2, batch=5
	env.tr.DataIn <- MakeFrame(core.TypeBatch, p)

	r := AwaitResult(t, env.tr.Sent, 2, 2*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_REJECTED {
		t.Errorf("level = %v, want REJECTED", r.GetLevel())
	}
	if r.GetCode() != core.CodeBatchInvalid {
		t.Errorf("code = %d (%s), want %d (batch_invalid)",
			r.GetCode(), core.CodeName(r.GetCode()), core.CodeBatchInvalid)
	}
}

// TestBatch_Rejected_EnvelopeOpenFail 验证 AD 失配（session_id 篡改）→
// RESULT(rejected, envelope_open_failed)。（已知实现缺陷 bug-D，见上。）
func TestBatch_Rejected_EnvelopeOpenFail(t *testing.T) {
	sink := newSinkCapture()
	env := startEnv(t, envConfig{sink: sink.handler})

	// 用错误 session_id 封装（服务端以真实 session_id 开箱 → AD 失配）。
	batch := &core.Batch{Seq: 3, EventsCount: 1, Payload: makeSignalBatch(t, 1, "x")}
	bw, err := core.Encode(batch)
	if err != nil {
		t.Fatal(err)
	}
	p, err := core.SealEnvelope(core.SealParams{
		FrameType: core.TypeBatch, SessionID: []byte("attacker-session"), Seq: 3,
		Compression: corepb.Compression_COMPRESSION_NONE, Keys: env.keys, BatchWire: bw,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.tr.DataIn <- MakeFrame(core.TypeBatch, p)

	r := AwaitResult(t, env.tr.Sent, 3, 2*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_REJECTED {
		t.Errorf("level = %v, want REJECTED", r.GetLevel())
	}
	if r.GetCode() != core.CodeEnvelopeOpenFail {
		t.Errorf("code = %d (%s), want %d (envelope_open_failed)",
			r.GetCode(), core.CodeName(r.GetCode()), core.CodeEnvelopeOpenFail)
	}
}

// TestBatch_Rejected_TooLarge 验证解压后 payload 超 limits.max_batch_bytes →
// RESULT(rejected, batch_too_large)。（已知实现缺陷 bug-D，见上。）
func TestBatch_Rejected_TooLarge(t *testing.T) {
	sink := newSinkCapture()
	env := startEnv(t, envConfig{
		maxBatchBytes: 128,
		sink:          sink.handler,
	})
	// batch 编码（proto）远超 128B：SignalRecord 带 512B body。
	batch := &core.Batch{Seq: 4, EventsCount: 1, Payload: makeSignalBatch(t, 1, longBody(512))}
	bw, err := core.Encode(batch)
	if err != nil {
		t.Fatal(err)
	}
	p, err := core.SealEnvelope(core.SealParams{
		FrameType: core.TypeBatch, SessionID: env.sessionID, Seq: 4,
		Compression: corepb.Compression_COMPRESSION_NONE, Keys: env.keys, BatchWire: bw,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.tr.DataIn <- MakeFrame(core.TypeBatch, p)

	r := AwaitResult(t, env.tr.Sent, 4, 2*time.Second)
	if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_REJECTED {
		t.Errorf("level = %v, want REJECTED", r.GetLevel())
	}
	if r.GetCode() != core.CodeBatchTooLarge {
		t.Errorf("code = %d (%s), want %d (batch_too_large)",
			r.GetCode(), core.CodeName(r.GetCode()), core.CodeBatchTooLarge)
	}
}

// TestBatch_RawSink 验证 SinkOptions.Raw=true 供给路径：Raw 非 nil、Decoded 为 nil。
func TestBatch_RawSink(t *testing.T) {
	sink := newSinkCapture()
	env := startEnv(t, envConfig{
		sinkOpts: core.SinkOptions{Raw: true},
		sink:     sink.handler,
	})
	env.sendBatch(t, 1, "raw-batch", "")
	AwaitResult(t, env.tr.Sent, 1, 5*time.Second)

	ev := sink.waitEvent(t, 1, 5*time.Second)
	if len(ev.Raw) == 0 {
		t.Error("sink raw empty although SinkOptions.Raw=true")
	}
	if ev.Decoded != nil {
		t.Error("sink decoded supplied although SinkOptions.Raw=true")
	}
}

// longBody 生成长度 n 的可打印填充串。
func longBody(n int) string {
	const unit = "0123456789abcdef"
	b := make([]byte, 0, n)
	for len(b) < n {
		b = append(b, unit...)
	}
	return string(b[:n])
}

// TestBatch_AllCompressions_HandlerPath 验证四个注册压缩算法经真实 handler
// 路径（seal → processBatch → 解压 → sink）全部可解（§8.4：收端 MUST 全支持，
// 发送端逐帧自选，无协商前提）。
func TestBatch_AllCompressions_HandlerPath(t *testing.T) {
	comps := []corepb.Compression{
		corepb.Compression_COMPRESSION_NONE,
		corepb.Compression_COMPRESSION_GZIP,
		corepb.Compression_COMPRESSION_ZSTD,
		corepb.Compression_COMPRESSION_LZ4,
	}
	for _, comp := range comps {
		t.Run(comp.String(), func(t *testing.T) {
			sink := newSinkCapture()
			env := startEnv(t, envConfig{sink: sink.handler})
			body := "compressed-handler-path-" + longBody(2048)
			p := env.sealBatch(t, 1, body, "corr-comp", 0, comp)
			env.tr.DataIn <- MakeFrame(core.TypeBatch, p)

			r := AwaitResult(t, env.tr.Sent, 1, 5*time.Second)
			if r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED || r.GetCode() != core.CodeOK {
				t.Fatalf("%v: result = %v/%d, want accepted/ok", comp, r.GetLevel(), r.GetCode())
			}
			ev := sink.waitEvent(t, 1, 5*time.Second)
			if ev.Decoded == nil || len(ev.Decoded.Signals) != 1 || ev.Decoded.Signals[0].Body != body {
				t.Errorf("%v: sink payload mismatch after decompress", comp)
			}
		})
	}
}
