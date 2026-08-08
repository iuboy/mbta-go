package core

import (
	"log/slog"
	"sync"
	"time"
)

// AckRingSize 是 client 端流控 ring buffer 的固定槽位数，编译期确定内存。
//
// 取 baseline windowMaxBatches 上限（docs/mbta-core-spec.md §9.2 / handler.go）。
// 运行时 WINDOW 缩放（degraded→½、critical→1/10）只改 AckTracker 的容量阈值，
// 不重建 ring —— 缩窗时 ring 利用率下降但绝对内存恒定，嵌入式可精确预估。
const AckRingSize = 100

// AckSlot 是 ring buffer 的一个槽位，承载单个 inflight batch 的全部元信息。
//
// 零值 Seq==0 表示空槽（ULID 虽理论上可产生全零，但概率 2^-128，工程上视为不可能）。
// ChunkID 存 raw [16]byte（ChunkID 具名类型），零分配；Release 时与 ACK 帧携带的
// chunk_id 比对，作为 seq 取模索引的二次校验，防 seq 复用碰撞。
type AckSlot struct {
	Seq      uint64    // 0=空；>0=占用，存 seq 做碰撞校验（seq 由 SeqGenerator 全局单调递增分配）
	ChunkID  ChunkID   // ULID 原始 16 字节，claim 校验（seq % AckRingSize 索引的最后防线）
	Events   int       // 本 batch 事件数
	Bytes    int64     // 本 batch 字节数
	SentAt   time.Time // 发送时刻，BatchLatency 观测 + reaper 超时判定
	Deadline time.Time // 此 batch 无 ACK 的超时时刻，供 ReapExpired 判定
}

// AckTracker 是 client 端流控的单一数据结构，定长，编译期确定内存。
//
// 替代原三结构（pendingAcks sync.Map + inflight 计数器 + window 容量上限），
// 消除 sync.Map 的动态分配与 chunkID 文本 key 开销。用 seq 做 ring 索引：
// ACK/NACK 帧自带 seq（core spec §4，AckMessage.Seq / NackMessage.Seq），
// 直接定位 slot，O(1)。
//
// 数学碰撞消除：CanSend 的序号跨度检查保证「最老未 ACK seq → 最新 seq」跨度
// < AckRingSize，使 seq%AckRingSize 索引在存活 slot 内唯一。chunkID 比对作为
// 防御性兜底（应对跨度检查因 bug 失效）。
//
// 并发模型：单 mu 保护全部状态。sendMu（CoreClient 层）保护「取 seq + CanSend +
// Reserve」复合原子操作；tracker.mu 在其内部短暂获取，无反向依赖。
// 三路并发 claim（handleAck / handleNack / ackReaper）都经 Release/ReapExpired，
// 第一个 claim 成功者清空 slot.seq，后续 claim 见 seq==0 直接返回 false，
// 天然避免双减。
type AckTracker struct {
	mu         sync.Mutex
	slots      [AckRingSize]AckSlot
	count      int    // 已占用 slot 数（替代 pendingCount）
	events     int64  // 总 events（替代 inflight.events）
	bytes      int64  // 总 bytes（替代 inflight.bytes）
	maxBatches int    // 容量阈值：批数上限（WINDOW 帧可缩放）
	maxEvents  int    // 容量阈值：事件数上限
	maxBytes   int64  // 容量阈值：字节数上限
	oldestSeq  uint64 // 最老占用 slot 的 seq（跨度检查用；0=空 tracker）
}

// NewAckTracker 创建流控 tracker。max* 为初始容量阈值（通常为 baseline 上限）。
func NewAckTracker(maxBatches int, maxEvents int, maxBytes int64) *AckTracker {
	return &AckTracker{
		maxBatches: maxBatches,
		maxEvents:  maxEvents,
		maxBytes:   maxBytes,
	}
}

// CanSend 检查给定 batch 是否可发送：容量阈值 + 序号跨度均通过。
//
// 任一维度 max==0 视为该维度暂停（与原 Window.CanSend 语义一致）。
// 序号跨度检查（路线 B 核心）：newSeq 与当前最老未 ACK seq 的跨度 >= AckRingSize
// 则拒绝 —— 这数学上保证 newSeq%AckRingSize 不会命中任一存活 slot，消除取模碰撞。
// 该检查也带来温和队头阻塞：队头 batch 超 AckRingSize 个发送周期未 ACK 时新发送被拒，
// 由 ackReaper 周期回收超时 slot 自愈。
func (t *AckTracker) CanSend(newSeq uint64, events int, bytes int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	// 任一维度暂停（max==0）→ 拒绝。
	if t.maxBatches == 0 || t.maxEvents == 0 || t.maxBytes == 0 {
		return false
	}

	// 容量阈值检查。
	if t.count+1 > t.maxBatches {
		return false
	}
	if t.events+int64(events) > int64(t.maxEvents) {
		return false
	}
	if t.bytes+bytes > t.maxBytes {
		return false
	}

	// 序号跨度检查（仅 tracker 非空时）。newSeq 单调递增 >= oldestSeq，
	// 不存在下溢。
	if t.oldestSeq != 0 && newSeq-t.oldestSeq >= AckRingSize {
		return false
	}
	return true
}

// Reserve 占用 seq 对应的 slot 并登记 batch 元信息。
//
// 调用方必须保证此前 CanSend(seq, ...) 返回 true，且 CanSend 与 Reserve 在同一
// 外层锁（CoreClient.sendMu）内原子执行，防止并发 Reserve 双占同 slot。
//
// slot 碰撞处理：若目标 slot 仍被占用（理论上跨度检查已避免，此处为兜底），
// 记录 warn 并覆盖 —— 不扣减旧 slot 的聚合计数（旧 batch 的 ACK 可能仍会到，
// 扣减会让计数偏低导致超发；不扣减则计数偏高导致保守降速，fail-safe）。
func (t *AckTracker) Reserve(seq uint64, chunkID ChunkID, events int, bytes int64, sentAt, deadline time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	idx := seq % AckRingSize
	existing := t.slots[idx]
	if existing.Seq != 0 && existing.Seq != seq {
		slog.Warn("ack ring slot overwrite (seq span check should prevent this)",
			"old_seq", existing.Seq, "new_seq", seq, "slot", idx)
		// 不扣减 existing 的 events/bytes：fail-safe 保守偏高。
	}

	t.slots[idx] = AckSlot{
		Seq:      seq,
		ChunkID:  chunkID,
		Events:   events,
		Bytes:    bytes,
		SentAt:   sentAt,
		Deadline: deadline,
	}
	// 若是覆盖（existing.Seq!=0），count 不变；否则 count++。
	if existing.Seq == 0 {
		t.count++
	}
	t.events += int64(events)
	t.bytes += bytes

	// oldestSeq 维护：空 tracker 的首个 batch 成为队头。
	// 正常路径下 seq 单调递增，新 seq > oldestSeq，不更新；仅空→非空时设置。
	if t.oldestSeq == 0 {
		t.oldestSeq = seq
	}
}

// Release 释放 seq 对应的 slot，返回原 slot 内容供调用方观测 latency。
//
// 按 seq 取模索引定位 slot，再用 chunkID 二次校验：seq 不匹配或 chunkID 不匹配
// 均返回 (zero, false)。这保证三路并发 claim（handleAck/handleNack/ackReaper）
// 中只有第一个成功的会清空 slot，后续 claim 见 seq==0 直接失败，天然避免双减。
//
// 释放队头（seq == oldestSeq）后重新计算 oldestSeq。由于 seq 单调且跨度 < AckRingSize
// （CanSend 保证），新 oldest 必然 > 释放的 seq；最坏 O(AckRingSize) 线性扫描。
func (t *AckTracker) Release(seq uint64, chunkID ChunkID) (AckSlot, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	idx := seq % AckRingSize
	s := t.slots[idx]
	if s.Seq != seq || s.ChunkID != chunkID {
		return AckSlot{}, false
	}

	t.slots[idx] = AckSlot{} // 清空（seq 归零）
	t.count--
	t.events -= int64(s.Events)
	t.bytes -= s.Bytes

	t.recomputeOldestSeqLocked()
	return s, true
}

// ReapExpired 回收所有 deadline 早于 now 的 slot，返回被回收的 slot 列表。
//
// 在单次 mu 锁定内批量扫描 + 释放，避免逐个 Release 的重复加锁。每个回收的 slot
// 已扣减聚合计数；调用方据此触发 drain 判空。
func (t *AckTracker) ReapExpired(now time.Time) []AckSlot {
	t.mu.Lock()
	defer t.mu.Unlock()

	var reaped []AckSlot
	for i := range t.slots {
		s := &t.slots[i]
		if s.Seq == 0 {
			continue
		}
		if now.After(s.Deadline) {
			reaped = append(reaped, *s)
			t.count--
			t.events -= int64(s.Events)
			t.bytes -= s.Bytes
			*s = AckSlot{} // 清空
		}
	}
	if len(reaped) > 0 {
		t.recomputeOldestSeqLocked()
	}
	return reaped
}

// UpdateLimits 更新容量阈值（WINDOW 帧下发时）。仅改阈值，不动已占用 slot。
func (t *AckTracker) UpdateLimits(maxBatches int, maxEvents int, maxBytes int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.maxBatches = maxBatches
	t.maxEvents = maxEvents
	t.maxBytes = maxBytes
}

// Reset 清零全部 slot 与聚合计数（close 时调用，防 stale 计数永久阻塞窗口）。
// 容量阈值保留（重连后沿用协商值）。
func (t *AckTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.slots {
		t.slots[i] = AckSlot{}
	}
	t.count = 0
	t.events = 0
	t.bytes = 0
	t.oldestSeq = 0
}

// Empty 报告是否无 inflight slot（drain 判空用，替代 pendingCount==0）。
func (t *AckTracker) Empty() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count == 0
}

// PendingCount 返回当前 inflight slot 数（close 日志用，替代 countPendingAcks）。
func (t *AckTracker) PendingCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count
}

// recomputeOldestSeqLocked 在 count 变化后重新计算 oldestSeq。调用方必须持 mu。
//
// 由于存活 slot 的 seq 跨度 < AckRingSize（CanSend 保证），线性扫描 AckRingSize
// 个槽即可找到最小非零 seq。count==0 时归零。
func (t *AckTracker) recomputeOldestSeqLocked() {
	if t.count == 0 {
		t.oldestSeq = 0
		return
	}
	var min uint64
	for i := range t.slots {
		s := &t.slots[i]
		if s.Seq != 0 && (min == 0 || s.Seq < min) {
			min = s.Seq
		}
	}
	t.oldestSeq = min // count>0 时 min 必非零
}
