package protocol

// handler_batch.go：BATCH/DGRAM 处理（根治版：SettleGrant 令牌流程）。
//
// RESULT 发送权/终态环/额度回收三件事由 grant 原子持有——本文件任何路径都不
// 直接构造终态 RESULT（历史双发 ×3 与 sem-full 漏偿的结构性根治）。
// 共享校验管线 decodeAndValidate 消除 BATCH/DGRAM 双清单手抄漂移。
//
// BATCH 路径（校验次序 = r3 §18-B5 裁决）：
// 帧层 MaxFrameBytes（binding）→ 准入占位+额度 → AD/解密 → 解压上限 → max_batch_bytes。

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// sender 是 grant 的 RESULT 发送函数（handler 注入，锁外执行）。
func (h *CoreHandler) sender(ctx context.Context) func(*core.Result) {
	return func(r *core.Result) {
		p, err := core.Encode(r)
		if err != nil {
			return
		}
		if err := SendControlFrame(ctx, h.tr, core.TypeResult, p); err != nil {
			slog.Debug("write result failed", "error", err)
		}
	}
}

// maybeScheduleFlush 懒 arm：首个 Settle 后安排一次 100ms 定时 flush，
// 替代常驻 100ms ticker（万连接下省 10k/s 定时器唤醒）。CAS 保证同一时刻
// 至多一个 pending flush。
func (h *CoreHandler) maybeScheduleFlush() {
	if h.flushArmed.CompareAndSwap(false, true) {
		time.AfterFunc(creditFlushInterval, func() {
			h.flushArmed.Store(false)
			h.flushPending()
		})
	}
}

// flushPending 取出攒批回收量并下发 CREDIT（发放=移回 outstanding+通知客户端）。
func (h *CoreHandler) flushPending() {
	b, y := h.credit.TakeRecovered()
	if b <= 0 && y <= 0 {
		return
	}
	c := &core.Credit{Batches: uint64(b), Bytes: uint64(y)}
	p, err := core.Encode(c)
	if err != nil {
		// TakeRecovered 已清空攒批缓冲——Encode 失败即该笔回收永久滞留（客户端
		// credit 单向泄漏直至重连）。proto 对 Credit 实际不会失败，此处留痕以
		// 兜底可观测（AGENTS.md：关键兜底路径失败 MUST 留日志）。
		slog.Warn("encode credit failed; recovered quota stranded", "batches", b, "bytes", y, "error", err)
		return
	}
	if err := SendControlFrame(context.Background(), h.tr, core.TypeCredit, p); err != nil {
		slog.Debug("write credit failed", "error", err)
	}
}

// rejectAtCapacity 是 batchSem 满的 grant 化直拒：占位 → 扣额度 → Settle(released)。
// 客户端已为该 seq 扣除额度——Settle 的回收保证守恒闭环（终态环同时记录，
// 客户端同 seq 重试得到幂等回执而非重新投递）。
func (h *CoreHandler) rejectAtCapacity(ctx context.Context, payload []byte) {
	var env core.Envelope
	if core.Decode(payload, &env) != nil {
		return // 无法定夺 seq：静默丢弃（客户端重发兜底）
	}
	seq := env.GetSeq()
	ar := h.credit.Admit(seq)
	switch ar.Decision {
	case core.AdmitAccept:
		send := h.sender(ctx)
		if cerr := ar.Grant.Consume(int64(len(payload))); cerr != nil {
			h.abort(ctx, core.CodeWindowExceeded, "credit exhausted")
			return
		}
		ar.Grant.Settle(send, corepb.ResultLevel_RESULT_LEVEL_RELEASED,
			core.CodeServerDraining, 1000, int64(len(payload)))
		h.maybeScheduleFlush()
	case core.AdmitDuplicate, core.AdmitTerminalHit:
		// 常规回执路径已覆盖；capacity 直拒不重复处理。
	case core.AdmitBelowUnknown:
		// 与 processBatch 对齐（宁重发不吞数据）：环外旧 seq 也回执 released，
		// 否则 sem-full 时到达的陈旧重发无任何应答，客户端白等满 AckTimeout。
		h.sendResult(ctx, &core.Result{RefSeq: env.GetSeq(),
			Level: corepb.ResultLevel_RESULT_LEVEL_RELEASED, Code: core.CodeInternal})
	default:
		h.abort(ctx, core.CodeWindowExceeded, "invalid seq")
	}
}

// releaseStuck 回收 AddedAt 早于 age 的在途项（reaper + Handle 收尾）。
// ForceSettle 与 grant.Settle 共享防双回收守卫（terminal 环已命中即跳过额度）。
// 观测语义（imhk 复盘）：逐条 DEBUG 留 seq 明细，循环结束一条 WARN 汇总
// count/age_max——durable 等待链被 sink 慢写拖长时 reaper 是主要释放路径，
// 汇总行直接反映积压规模与最长等待（age=0 的 age=now-AddedAt）。
func (h *CoreHandler) releaseStuck(ctx context.Context, code uint32, age time.Duration) {
	now := time.Now()
	cutoff := now.Add(-age)
	send := h.sender(ctx)
	var count int
	var oldestAge time.Duration
	for {
		seq, slot, ok := h.credit.OldestBefore(cutoff)
		if !ok {
			break
		}
		if a := now.Sub(slot.AddedAt); a > oldestAge {
			oldestAge = a
		}
		slog.Debug("releasing stuck inflight", "seq", seq, "code", core.CodeName(code), "age", now.Sub(slot.AddedAt).String())
		h.credit.ForceSettle(send, seq, corepb.ResultLevel_RESULT_LEVEL_RELEASED, code, 1000, slot.Bytes)
		count++
	}
	if count > 0 {
		slog.Warn("reaper released stuck inflight", "count", count, "oldest_age", oldestAge.String(), "reason", core.CodeName(code))
	}
	h.maybeScheduleFlush()
}

// decodeAndValidate 是 BATCH/DGRAM 共享的解码校验管线（单一清单，消除双路径
// 手抄漂移：DGRAM 此前缺 TTL/events 上限且尺寸检查次序在解码后）。
// 返回错误码 0=通过；否则调用方按各自语义处置（BATCH=Settle(REJECTED)，DGRAM=静默丢）。
// decodeAndValidate 接受调用方已解码的 Envelope（processBatch 需先拿 seq 做准入
// 占位——占位先于解密是设计次序；此处不重复解析）。
//
// SignalBatch 解码与 sb.Validate() 在此接线（P1-2 审查裁决）：signal_type 闭合
// 枚举、属性条数/字段长度/控制字符、trace 上下文全部在协议入口拦截——不可信
// 数据不再直达 sink；实际解码条数上限（非客户端自报 events_count）在此收紧。
// 解码结果贯穿返回，makeEvent 不再二次解码（此前的静默吞错使 Decoded=nil
// 仍回 accepted——数据丢失伪装成投递成功）。
func (h *CoreHandler) decodeAndValidate(env *core.Envelope, frameType uint8) (*core.Batch, *core.SignalBatch, []byte, uint32) {
	keys := h.keys.Load()
	if keys == nil {
		return nil, nil, nil, core.CodeInternal // 未握手（防御；binding 保证 Ready 前不投递）
	}
	if exp := h.expiresAt.Load(); exp > 0 && time.Now().Unix() > exp {
		return nil, nil, nil, core.CodeServerDraining // 会话过期：客户端应重连
	}
	batchWire, err := core.OpenEnvelope(frameType, h.getSessionID(), keys, h.config.Zdict, env)
	if err != nil {
		// 解压超限（decompress_limit）与解密失败分开归因：统一计入
		// DecryptFailures 会把「合法大批超解压天花板」误导向密钥/会话排查方向。
		if core.CodeNumOf(err) == core.CodeDecompressLimit {
			return nil, nil, nil, core.CodeDecompressLimit
		}
		h.metrics.DecryptFailures().Inc()
		return nil, nil, nil, core.CodeEnvelopeOpenFail
	}
	if int64(len(batchWire)) > int64(h.config.Policy.MaxBatchBytes) {
		return nil, nil, nil, core.CodeBatchTooLarge
	}
	var batch core.Batch
	if err := core.Decode(batchWire, &batch); err != nil {
		return nil, nil, nil, core.CodeBatchInvalid
	}
	if batch.GetSeq() != env.GetSeq() {
		return nil, nil, nil, core.CodeBatchInvalid
	}
	if len(batch.GetCorrelation()) > core.MaxBatchCorrelationLen {
		return nil, nil, nil, core.CodeBatchInvalid
	}
	if int(batch.GetEventsCount()) > maxBatchEvents {
		return nil, nil, nil, core.CodeBatchInvalid
	}
	sb, err := h.decodeSignalBatch(batch.GetPayload())
	if err != nil {
		return nil, nil, nil, core.CodeBatchInvalid
	}
	if len(sb.Signals) > maxBatchEvents {
		return nil, nil, nil, core.CodeBatchInvalid
	}
	if err := sb.Validate(); err != nil {
		return nil, nil, nil, core.CodeBatchInvalid
	}
	if tc := batch.GetTrace(); tc != nil {
		if err := core.ValidateBatchTraceContext(tc); err != nil {
			return nil, nil, nil, core.CodeBatchInvalid
		}
	}
	return &batch, sb, batchWire, 0
}

// processBatch 处理可靠 BATCH。
func (h *CoreHandler) processBatch(ctx context.Context, payload []byte) {
	var env core.Envelope
	if err := core.Decode(payload, &env); err != nil {
		slog.Debug("invalid envelope", "error", err)
		return
	}
	seq := env.GetSeq()
	// 准入（占位式：Accept 即占位，并发同 seq 得 Duplicate）。
	ar := h.credit.Admit(seq)
	var grant *core.SettleGrant
	switch ar.Decision {
	case core.AdmitAccept:
		grant = ar.Grant
	case core.AdmitViolation:
		h.abort(ctx, core.CodeWindowExceeded, "invalid seq")
		return
	case core.AdmitTerminalHit:
		h.sendResult(ctx, &core.Result{RefSeq: seq,
			Level: corepb.ResultLevel(ar.Terminal.Level), Code: ar.Terminal.Code})
		return
	case core.AdmitBelowUnknown:
		// 终态环外旧 seq：宁重发不吞数据。
		h.sendResult(ctx, &core.Result{RefSeq: seq, Level: corepb.ResultLevel_RESULT_LEVEL_RELEASED, Code: core.CodeInternal})
		return
	case core.AdmitDuplicate:
		h.sendResult(ctx, &core.Result{RefSeq: seq, Level: corepb.ResultLevel_RESULT_LEVEL_ACCEPTED,
			Correlation: ar.DupSlot.Correlation})
		return
	}
	send := h.sender(ctx)

	// Draining 强制执行（close 注释承诺的「此后新 seq → released(server_draining)」）：
	// CLOSE 后连接尚未断开期间到达的新 BATCH 不再投递 sink——未 Consume 的 grant
	// 直接 Settle（按帧字节数回收，客户端已扣额度守恒闭环）。
	if h.sm.State() == core.ServerStateDraining {
		grant.Settle(send, corepb.ResultLevel_RESULT_LEVEL_RELEASED,
			core.CodeServerDraining, 1000, int64(len(payload)))
		h.maybeScheduleFlush()
		return
	}

	frameBytes := int64(len(payload))
	if cerr := grant.Consume(frameBytes); cerr != nil {
		h.abort(ctx, core.CodeWindowExceeded, "credit exhausted")
		return
	}

	// 共享解码校验管线（Envelope 已在准入阶段解码，不重复解析）。
	batch, sb, batchWire, code := h.decodeAndValidate(&env, core.TypeBatch)
	if code != 0 {
		if code == core.CodeInternal {
			grant.Release() // 未定夺内容：占位释放，无 wire 动作
			return
		}
		if code == core.CodeServerDraining {
			h.abort(ctx, code, "session expired")
			return
		}
		slog.Debug("batch rejected", "seq", seq, "code", core.CodeName(code))
		grant.Settle(send, corepb.ResultLevel_RESULT_LEVEL_REJECTED, code, 0, frameBytes)
		h.maybeScheduleFlush()
		return
	}
	grant.Backfill(batch.GetCorrelation())

	h.deliver(ctx, grant, batch, sb, batchWire, frameBytes)
}

// deliver 投递到 sink 并完成 RESULT 生命周期。
// 两个分支统一为 enqueue-then-settle：入队成功才发终态 accepted——
// 「先 ACK 后入队、队列满静默丢数据」在顺序上不可再发生。
func (h *CoreHandler) deliver(ctx context.Context, grant *core.SettleGrant, batch *core.Batch, sb *core.SignalBatch, batchWire []byte, frameBytes int64) {
	send := h.sender(ctx)

	if h.config.SinkHandler == nil {
		grant.Settle(send, corepb.ResultLevel_RESULT_LEVEL_ACCEPTED, 0, 0, frameBytes)
		h.maybeScheduleFlush()
		return
	}

	durable := h.config.Policy.AckMode == corepb.AckMode_ACK_MODE_DURABLE
	if !h.enqueueSink(ctx, grant, batch, sb, batchWire, frameBytes, durable) {
		// 队列满/收尾：released（客户端以新 seq 重投）。
		grant.Settle(send, corepb.ResultLevel_RESULT_LEVEL_RELEASED, core.CodeServerDraining, 1000, frameBytes)
		h.maybeScheduleFlush()
		return
	}
	if durable {
		grant.Accept(send) // 中间态：额度保留，done 回调驱动 Settle(durable/released)
		return
	}
	// accepted_only：入队成功，accepted 即终态。
	grant.Settle(send, corepb.ResultLevel_RESULT_LEVEL_ACCEPTED, 0, 0, frameBytes)
	h.maybeScheduleFlush()
}

// sendResult 仅供幂等回执路径（TerminalHit/Duplicate/BelowUnknown——不触碰
// 终态与额度的只读应答）。终态 RESULT 一律经 grant。
func (h *CoreHandler) sendResult(ctx context.Context, r *core.Result) {
	p, err := core.Encode(r)
	if err != nil {
		return
	}
	if err := SendControlFrame(ctx, h.tr, core.TypeResult, p); err != nil {
		slog.Debug("write result failed", "error", err)
	}
}

// processDatagram 处理不可靠 DGRAM（at-most-once；豁免 credit，令牌桶+并发槽）。
func (h *CoreHandler) processDatagram(ctx context.Context, payload []byte) {
	// Draining 期新 DGRAM 静默丢弃（BATCH 路径回 released 回执，DGRAM 无回执
	// 通道——at-most-once 语义允许丢弃；与 close 后语义一致）。
	if h.sm.State() == core.ServerStateDraining {
		return
	}
	if !h.dgramAllow(int64(len(payload))) {
		return // 速率超限：静默丢弃（at-most-once 语义允许）
	}
	var denv core.Envelope
	if core.Decode(payload, &denv) != nil {
		return
	}
	batch, sb, batchWire, code := h.decodeAndValidate(&denv, core.TypeDgram)
	if code != 0 {
		return // DGRAM 失败一律静默丢弃
	}
	// 解压后计量补扣：入口按压缩后 wire 字节扣桶，高压缩比 payload（如 8MB 全零
	// 压至 ~30KB）会让 wire 计量下的实际解压吞吐失真（8MB/s 预算 → 2.2GB/s 实际）。
	// 差额允许记负（负债压低未来可用额度），真实成本由此回归桶计量。
	if extra := int64(len(batchWire)) - int64(len(payload)); extra > 0 {
		h.dgramCharge(extra)
	}
	if h.config.SinkHandler != nil {
		ev := h.makeEvent(batch, sb, batchWire)
		h.callHandler(ctx, ev, func(core.Outcome) {}) // at-most-once：done 无 wire 语义
	}
}

// dgramCharge 无条件扣减令牌桶（可记负）。dgramAllow 的「不足即拒」只适用于
// 入口预检；解压后的补扣是事后计量——拒绝已无意义，记负让债务抑制后续帧。
func (h *CoreHandler) dgramCharge(n int64) {
	if h.dgramRate <= 0 {
		return
	}
	h.dgramBucketMu.Lock()
	defer h.dgramBucketMu.Unlock()
	if h.dgramLast.IsZero() {
		h.dgramLast = time.Now()
	}
	h.dgramAvail -= n
}

// dgramAllow 令牌桶（Policy.DatagramRateBytes；0 = 不限，仅并发槽防护）。
func (h *CoreHandler) dgramAllow(n int64) bool {
	if h.dgramRate <= 0 {
		return true
	}
	h.dgramBucketMu.Lock()
	defer h.dgramBucketMu.Unlock()
	now := time.Now()
	if h.dgramLast.IsZero() {
		h.dgramLast = now
		h.dgramAvail = h.dgramRate
	} else {
		elapsed := now.Sub(h.dgramLast).Seconds()
		h.dgramAvail += int64(elapsed * float64(h.dgramRate))
		if h.dgramAvail > h.dgramRate {
			h.dgramAvail = h.dgramRate
		}
		h.dgramLast = now
	}
	if h.dgramAvail >= n {
		h.dgramAvail -= n
		return true
	}
	return false
}

// abort 发送 ABORT 并拆除（协议违规/写失败）。
func (h *CoreHandler) abort(ctx context.Context, code uint32, detail string) {
	a := &core.AbortMsg{Code: code, Detail: detail}
	p, err := core.Encode(a)
	if err == nil {
		_ = SendControlFrame(ctx, h.tr, core.TypeAbort, p)
	}
	_ = h.tr.Close()
}

// makeDone 构造 sink 的 done 回调：驱动 grant 的终态 Settle（单次生效；
// grant 已终态（reaper/超时抢先）后安全丢弃）。
func (h *CoreHandler) makeDone(grant *core.SettleGrant, durable bool) func(core.Outcome) {
	var once sync.Once
	return func(o core.Outcome) {
		once.Do(func() {
			if !durable {
				if o.Level == core.OutcomeUnspecified {
					// 零值在 accepted_only 下同样无 wire 效果，但漏设是 handler
					// 缺陷信号——告警而非静默（与 durable 分支同因）。
					slog.Warn("sink done called with unspecified Outcome level (accepted_only; no wire effect)")
				}
				return // accepted_only：done 无 wire 效果（终态已在 deliver 完成）
			}
			send := h.sender(context.Background())
			switch o.Level {
			case core.OutcomeDurable, core.OutcomeAccepted:
				grant.Settle(send, corepb.ResultLevel_RESULT_LEVEL_DURABLE, 0, 0, 0)
			case core.OutcomeUnspecified:
				// 漏设 Level：按 handler 缺陷处置为 released(internal)——
				// 此前零值=Accepted 会静默合成 DURABLE 终态（数据未落盘却回执
				// 已持久化，语义倒挂）。告警 + released 让客户端按可重试路径收敛。
				slog.Warn("sink done called with unspecified Outcome level; synthesizing released(internal)")
				grant.Settle(send, corepb.ResultLevel_RESULT_LEVEL_RELEASED, core.CodeInternal, 1000, 0)
			case core.OutcomeReleased, core.OutcomeRejected:
				code := o.Code
				if code == 0 {
					code = core.CodeInternal
				}
				lvl := corepb.ResultLevel_RESULT_LEVEL_RELEASED
				retry := uint32(1000)
				if o.Level == core.OutcomeRejected {
					lvl = corepb.ResultLevel_RESULT_LEVEL_REJECTED
					retry = 0
				}
				grant.Settle(send, lvl, code, retry, 0)
			}
			h.maybeScheduleFlush()
		})
	}
}

// makeEvent 构造 BatchEvent（按 SinkOptions 供给 Raw/Decoded）。
// sb 由 decodeAndValidate 解码并校验后贯穿传入——本函数不再解码，
// 消除「解码失败静默得 Decoded=nil 仍回 accepted」的数据丢失伪装路径。
// raw 是解密后的 batch 消息编码（Batch wire）。
func (h *CoreHandler) makeEvent(batch *core.Batch, sb *core.SignalBatch, raw []byte) core.BatchEvent {
	ev := core.BatchEvent{
		Agent: h.getAgentID(),
		Meta: core.BatchMeta{
			Seq:         batch.GetSeq(),
			Correlation: batch.GetCorrelation(),
			EventsCount: int(batch.GetEventsCount()),
			ReceivedAt:  time.Now(),
			Trace:       batch.GetTrace(),
		},
	}
	if h.config.SinkOpts.Raw {
		ev.Raw = raw
	} else {
		ev.Decoded = sb
	}
	return ev
}

// decodeSignalBatch 按协商 codec 解码 SignalBatch。
func (h *CoreHandler) decodeSignalBatch(raw []byte) (*core.SignalBatch, error) {
	codec := corepb.Codec_CODEC_PROTO
	if c, ok := h.codec.Load().(corepb.Codec); ok {
		codec = c
	}
	return core.UnmarshalSignalBatchCodec(codec, raw)
}

// callHandler 调用 sink handler（panic 防护：合成 released 走 grant）。
func (h *CoreHandler) callHandler(ctx context.Context, ev core.BatchEvent, done func(core.Outcome)) {
	defer func() {
		if r := recover(); r != nil {
			h.metrics.SinkFailures().Inc()
			slog.Warn("sink handler panicked", "seq", ev.Meta.Seq, "panic", r)
			done(core.Outcome{Level: core.OutcomeReleased, Code: core.CodeInternal})
		}
	}()
	h.config.SinkHandler(ctx, ev, done)
}
