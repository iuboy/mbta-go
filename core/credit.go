package core

// credit.go：r3 流控与去重的数据结构（根治版）。
//
// 客户端 CreditLedger：credit 只经 CREDIT 帧返还（RESULT 不隐含返还）；
// Rollback 供写失败路径补偿（服务端从未见帧、不会返还）。
//
// 服务端 CreditManager：准入/去重/credit 守恒的单一真相（单锁）。
// 历史上 RESULT 双发 ×3、窗口 cap 与账本两处真相同步 bug、sem-full 路径漏回收、
// 乱序前缀下幂等重发失效——全部是"发送权/终态/额度三件事靠调用纪律同步"的结构
// 温床。根治设计：
//
//   - SettleGrant 令牌：Admit 返回一次性 grant，Accept/Settle/Release 内部原子完成
//     「RESULT 构造与发送（经注入的 sender）+ 终态环记录 + 额度回收」。
//     双发与漏偿在构造上不可表达——grant 单次生效，持有者不调即无帧。
//   - 占位式准入：Admit 即在 seen 占位（防并发同 seq 双 Accept 的解密间隙竞态），
//     Backfill 回填明文侧 correlation，失败路径 Release 归还占位。
//   - 无 cap 判定：超发的真正防线是额度消耗（Consume 失败即违规）；seq 空间
//     含 DGRAM（单计数器保证 nonce 安全），按 batches 计的 cap 会把混发连接
//     误杀 ABORT。去重窗口退化为纯去重职责（seen/accepted/终态环/low 前缀）。
//   - 守恒不变式：每个客户端已扣额度的 seq，服务端必有恰好一次对应的
//     Settle（回收 1 批 + 该帧字节）或对等回收——额度不凭空消失。

import (
	"container/list"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	corepb "github.com/iuboy/mbta-go/corepb"
)

// SeqGenerator 生成连接级单调 seq（BATCH/DGRAM 共享单一计数器——分设会跨通道
// 复用 nonce，GCM 灾难）。从 1 起；0 为非法哨兵。
type SeqGenerator struct{ seq atomic.Uint64 }

// NewSeqGenerator 创建 seq 生成器（首个 Next 返回 1）。
func NewSeqGenerator() *SeqGenerator { return &SeqGenerator{} }

// Next 返回下一个 seq（原子自增，BATCH/DGRAM 共享同一实例）。
func (g *SeqGenerator) Next() uint64 { return g.seq.Add(1) }

// --- 客户端账本 ---

// OutSlot 记录一个在途 batch（RESULT 关联/回调/超时观测用）。
type OutSlot struct {
	Seq         uint64
	Bytes       int64
	Correlation string
	SentAt      time.Time
	Deadline    time.Time
	// Failed 由客户端 reaper 标记（RESULT 迟到/丢失）；不回补 credit，
	// 由服务端 reaper 保证最终 RESULT(released)+CREDIT。
	Failed bool
}

// CreditLedger 是客户端 credit 账本。
//
// available = granted − consumed + returned（逐维度）。
// consumed 在发送时递增；returned 只在收到 CREDIT 时递增（模型 B 核心：
// RESULT 到达不释放额度，额度返还的权威在服务端）；Rollback 在写失败时
// 补偿 returned（服务端从未见帧，不会为该 seq 返还——不补偿即单向泄漏）。
type CreditLedger struct {
	mu         sync.Mutex
	grantedB   int64
	grantedY   int64
	consumedB  int64
	consumedY  int64
	returnedB  int64
	returnedY  int64
	clampB     int64 // 本地钳制（恶意/受损服务端防护）
	clampY     int64
	slots      map[uint64]*OutSlot
	timedOut   map[uint64]bool // 已派发 timeout 回调的 seq（ReapExpired 写、Terminal 消费即清除）
	violations int
}

// DefaultCreditClampBatches 是批数维的本地钳制上限（65536 批）。
const DefaultCreditClampBatches = 1 << 16

// DefaultCreditClampBytes 是字节维的本地钳制上限（4GiB）。
const DefaultCreditClampBytes = 1 << 32

// NewCreditLedger 以 HELLO_ACK 初始 credit 建账。clamp ≤0 = 默认钳制。
func NewCreditLedger(initialB, initialY int64, clampB, clampY int64) *CreditLedger {
	if clampB <= 0 {
		clampB = DefaultCreditClampBatches
	}
	if clampY <= 0 {
		clampY = DefaultCreditClampBytes
	}
	if initialB > clampB {
		initialB = clampB
	}
	if initialY > clampY {
		initialY = clampY
	}
	return &CreditLedger{
		grantedB: initialB,
		grantedY: initialY,
		clampB:   clampB,
		clampY:   clampY,
		slots:    make(map[uint64]*OutSlot),
		timedOut: make(map[uint64]bool),
	}
}

// Available 返回当前可用额度。
func (l *CreditLedger) Available() (batches, bytes int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.grantedB - l.consumedB + l.returnedB, l.grantedY - l.consumedY + l.returnedY
}

// Consume 消耗额度并登记 slot。额度不足返回错误（不改变状态）。
func (l *CreditLedger) Consume(seq uint64, bytes int64, correlation string, deadline time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	availB := l.grantedB - l.consumedB + l.returnedB
	availY := l.grantedY - l.consumedY + l.returnedY
	if availB < 1 || availY < bytes {
		return NewError(ErrCodeWindowExceeded, "credit exhausted")
	}
	l.consumedB++
	l.consumedY += bytes
	l.slots[seq] = &OutSlot{Seq: seq, Bytes: bytes, Correlation: correlation, SentAt: time.Now(), Deadline: deadline}
	return nil
}

// OnCredit 处理 CREDIT 帧增量：双零 delta 忽略；负值（uint64 回绕）违规丢弃；
// 超出已消耗未返还量的部分钳制并计违规。
func (l *CreditLedger) OnCredit(dB, dY int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if dB == 0 && dY == 0 {
		return
	}
	if dB < 0 || dY < 0 {
		l.violations++
		return
	}
	// 钳制：returned 不得超过 consumed 未返还部分（Rollback 已补的额度在此被
	// 吸收，守恒不破），且可用不得超本地钳制。
	maxRetB := l.consumedB - l.returnedB
	if dB > maxRetB {
		dB = maxRetB
		l.violations++
	}
	maxRetY := l.consumedY - l.returnedY
	if dY > maxRetY {
		dY = maxRetY
		l.violations++
	}
	l.returnedB += dB
	l.returnedY += dY
}

// Terminal 处理某 seq 的 RESULT（不触碰 credit——返还权威在服务端 CREDIT）。
// terminal=true 表示终态 level（durable/rejected/released）：移出 pending slot，
// drain 计数谓词（spec §3.7「全部已发 seq 均达终态」）随之收敛。durable 模式下
// ACCEPTED 是中间态——terminal=false 不移出（drain 不得在中间态提前完成，
// 否则 durable 未落盘即关连接丢数据）。
//
// 返回 slot 与该 seq 的 timeout 抑制标记：timedOut=true 表示客户端 reaper 已
// 派发 timeout 回调，本帧（迟到真实 RESULT）不再二次回调（标记读取与清除在
// 账本锁内原子完成——与 ReapExpired 的登记构成同一临界区，消除「reaper 删
// slot 与登记之间真实 RESULT 先行派发」的双回调窗口）。slot 为 nil（已
// reap/rollback/未知 seq）不影响派发判定：durable 模式下 DURABLE（终态）在
// ACCEPTED 之后仍须到达应用。
func (l *CreditLedger) Terminal(seq uint64, terminal bool) (*OutSlot, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.slots[seq]
	if ok && terminal {
		delete(l.slots, seq)
	}
	timedOut := l.timedOut[seq]
	delete(l.timedOut, seq)
	return s, timedOut
}

// Rollback 写失败路径专用：移出 slot 并把额度补偿回 returned。
// 服务端从未收到该帧、不会为它返还 CREDIT——不补偿即单向泄漏。
// 若服务端实际已收到帧并随后 CREDIT，OnCredit 的 maxRet 钳制会吸收多补部分。
func (l *CreditLedger) Rollback(seq uint64) *OutSlot {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.slots[seq]
	if !ok {
		return nil
	}
	delete(l.slots, seq)
	dB, dY := int64(1), s.Bytes
	if dB > l.consumedB-l.returnedB {
		dB = l.consumedB - l.returnedB
	}
	if dY > l.consumedY-l.returnedY {
		dY = l.consumedY - l.returnedY
	}
	l.returnedB += dB
	l.returnedY += dY
	return s
}

// ReapExpired 回收 deadline 已过的 slot（标记失败并移出 pending；不回补 credit）。
// 移出与 timedOut 登记同一锁内完成：迟到的真实 RESULT 经 Terminal 读到标记后
// 抑制回调——「timeout + 真实」双终态回调窗口在构造上关闭。
func (l *CreditLedger) ReapExpired(now time.Time) []*OutSlot {
	l.mu.Lock()
	defer l.mu.Unlock()
	var reaped []*OutSlot
	for seq, s := range l.slots {
		if now.After(s.Deadline) {
			s.Failed = true
			reaped = append(reaped, s)
			delete(l.slots, seq)
			l.timedOut[seq] = true
		}
	}
	return reaped
}

// Drained 报告全部已发 seq 是否移出 pending（drain 判定的客户端侧）。
func (l *CreditLedger) Drained() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.slots) == 0
}

// Pending 返回在途 slot 数。
func (l *CreditLedger) Pending() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.slots)
}

// Reset 清空全部状态（close 时）。
func (l *CreditLedger) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.slots = make(map[uint64]*OutSlot)
	l.timedOut = make(map[uint64]bool)
}

// --- 服务端 CreditManager + SettleGrant ---

// AdmitDecision 是 Admit 的判定结果。
type AdmitDecision int

const (
	AdmitAccept       AdmitDecision = iota // 窗内未见：接受（已占位），返回 grant
	AdmitDuplicate                         // 在途占位中：幂等回执（查当前状态）
	AdmitTerminalHit                       // 终态环命中：回存储 outcome
	AdmitBelowUnknown                      // 环外旧 seq：released（宁重发不吞数据）
	AdmitViolation                         // seq==0：协议违规（ABORT）
)

// TerminalEntry 是终态环条目。
type TerminalEntry struct {
	Level uint32 // corepb.ResultLevel 数值
	Code  uint32
}

// InflightSlot 是在途 batch 状态（占位/回填后均存在，Settle 时移除）。
type InflightSlot struct {
	Seq         uint64
	Bytes       int64
	Correlation string
	AddedAt     time.Time
}

// CreditManager 是服务端准入/去重/credit 守恒的单一真相（单锁）。
//
// 去重语义（乱序安全）：
//   - low = 连续已接受前缀 + 1：[1, low) 全部接受过（在途或已终态）；
//   - accepted：已接受（含已终态）未被前缀覆盖的 seq——乱序终态（3 先于 1、2）
//     停留于此，重放查终态环（不依赖前缀推进这一时序副产物）；
//   - seen：在途（Admit 占位起，Settle/Release 止）——占位使「至多一个 goroutine
//     拿到 Accept」成为构造保证（消除 Admit→Register 解密间隙的并发双接受）；
//   - terminal：最近 K 条终态（LRU 淘汰）。
type CreditManager struct {
	mu           sync.Mutex
	outstandingB int64 // 已发放未回收批数
	outstandingY int64
	recoveredB   int64 // 已回收待发放（攒批缓冲）
	recoveredY   int64

	low      uint64
	accepted map[uint64]bool
	seen     map[uint64]*InflightSlot
	terminal map[uint64]TerminalEntry
	ringOrd  *list.List
	ringCap  int
}

// NewCreditManager 创建管理器（initial 为 HELLO_ACK 初始 credit）。ringCap ≤0 取 256。
func NewCreditManager(initialB, initialY int64, ringCap int) *CreditManager {
	if ringCap <= 0 {
		ringCap = 256
	}
	return &CreditManager{
		outstandingB: initialB,
		outstandingY: initialY,
		low:          1, // seq 从 1 起
		accepted:     make(map[uint64]bool),
		seen:         make(map[uint64]*InflightSlot),
		terminal:     make(map[uint64]TerminalEntry),
		ringOrd:      list.New(),
		ringCap:      ringCap,
	}
}

// AdmitResult 是 Admit 的复合返回：判定 + grant（Accept 时非 nil）/回执数据。
type AdmitResult struct {
	Decision AdmitDecision
	Grant    *SettleGrant // Decision==AdmitAccept 时非 nil
	// Duplicate/TerminalHit/BelowUnknown 的回执数据（handler 直接回 RESULT）。
	DupSlot  InflightSlot
	Terminal TerminalEntry
}

// Admit 判定 seq 准入。Accept 即占位（并发同 seq 的后来者得 Duplicate）。
// 无 cap 判定：超发防线是 Consume 的额度检查（seq 空间含 DGRAM，
// 按 batches 计的 cap 会误杀混发连接——已在审查中确认为缺陷并移除）。
func (m *CreditManager) Admit(seq uint64) AdmitResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if seq == 0 {
		return AdmitResult{Decision: AdmitViolation}
	}
	if s, ok := m.seen[seq]; ok {
		return AdmitResult{Decision: AdmitDuplicate, DupSlot: *s}
	}
	if m.accepted[seq] || seq < m.low {
		// 已接受（含已终态）：查终态环——乱序终态的重放（accepted 停留，前缀未
		// 推进）与前缀已推进（accepted 被清理、ring 保留）两种情况都在此幂等应答。
		if e, ok := m.terminal[seq]; ok {
			return AdmitResult{Decision: AdmitTerminalHit, Terminal: e}
		}
		return AdmitResult{Decision: AdmitBelowUnknown}
	}
	// 占位：占位期间并发同 seq → Duplicate；额度不足路径 Release 归还。
	m.seen[seq] = &InflightSlot{Seq: seq, AddedAt: time.Now()}
	return AdmitResult{Decision: AdmitAccept, Grant: &SettleGrant{m: m, seq: seq}}
}

// acceptedCap 是 accepted 集合的上限（连接级去重窗口外的乱序终态存量）。
// 常规顺序流量下 advanceLowLocked 使 accepted 趋近空集；上限只在「前缀空洞
// 长期不闭合」时生效——持有有效 token 的对端刻意永不发送 low 指向的 seq、
// 持续发送更高 seq 时，accepted 否则会无界增长（认证后内存 DoS，审查 F1）。
const defaultAcceptedCap = 4096

// SettleGrant 是一次准入的独占处置权。
//
// 生命周期：Admit 占位 → Consume 扣额度（或直拒路径跳过）→ Backfill 回填元数据
// → Accept（可选中间态）→ Settle 终态 / Release 异常释放。
// Accept 与 Settle 各自单次生效；Settle 后一切调用为 no-op——RESULT 双发与
// 额度漏偿在构造上不可表达。
type SettleGrant struct {
	m        *CreditManager
	seq      uint64
	consumed bool
	done     bool // Settle/Release 单次生效
	accepted bool // Accept（中间态）单次生效
}

// Consume 扣减额度并登记帧字节数。额度不足返回错误并自动释放占位
// （调用方应 ABORT：客户端在无额度下发送属协议违规）。
// 负 frameBytes 是调用方 bug——守恒核心不接受反向记账（负值走
// outstandingY-=frameBytes 会凭空造出额度），自动释放占位并报 Internal。
func (g *SettleGrant) Consume(frameBytes int64) error {
	m := g.m
	m.mu.Lock()
	defer m.mu.Unlock()
	if g.done {
		return NewError(ErrCodeInternal, "grant already settled")
	}
	if frameBytes < 0 {
		m.releaseLocked(g.seq)
		g.done = true
		return NewError(ErrCodeInternal, fmt.Sprintf("negative frame bytes %d", frameBytes))
	}
	if m.outstandingB < 1 || m.outstandingY < frameBytes {
		m.releaseLocked(g.seq)
		g.done = true
		return NewError(ErrCodeWindowExceeded, "credit exhausted at admission")
	}
	m.outstandingB--
	m.outstandingY -= frameBytes
	if s, ok := m.seen[g.seq]; ok {
		s.Bytes = frameBytes
	}
	g.consumed = true
	return nil
}

// Backfill 回填明文侧元数据（correlation）——解密后调用。
func (g *SettleGrant) Backfill(correlation string) {
	g.m.mu.Lock()
	defer g.m.mu.Unlock()
	if s, ok := g.m.seen[g.seq]; ok {
		s.Correlation = correlation
	}
}

// Accept 发送中间态 accepted RESULT（durable 模式）；单次生效。
// 不触碰终态/额度（durable 才是终态）。
func (g *SettleGrant) Accept(send func(*corepb.Result)) {
	if send == nil {
		return
	}
	g.m.mu.Lock()
	corr := ""
	if s, ok := g.m.seen[g.seq]; ok {
		corr = s.Correlation
	}
	first := !g.accepted && !g.done
	g.accepted = true
	g.m.mu.Unlock()
	if first {
		send(&corepb.Result{RefSeq: g.seq, Level: corepb.ResultLevel_RESULT_LEVEL_ACCEPTED, Correlation: corr})
	}
}

// Settle 终态处置：发送 RESULT + 终态环记录 + 额度回收。单次生效（幂等）。
// 未 Consume 的 grant（sem-full 直拒等路径）也允许 Settle——按 frameBytes 补回收，
// 保证客户端侧已扣额度最终必有对应返还（守恒闭环）。
func (g *SettleGrant) Settle(send func(*corepb.Result), level corepb.ResultLevel, code uint32, retryMs uint32, frameBytes int64) {
	if send == nil {
		send = func(*corepb.Result) {}
	}
	m := g.m
	m.mu.Lock()
	if g.done {
		m.mu.Unlock()
		return
	}
	g.done = true
	corr := ""
	if s, ok := m.seen[g.seq]; ok {
		corr = s.Correlation
		if s.Bytes > 0 {
			frameBytes = s.Bytes // 已 Consume：以登记值为准
		}
	}
	if frameBytes < 0 {
		frameBytes = 0
	}
	// stale grant 检查：seq 已不在 seen 且终态环已命中——本 grant 已被
	// ForceSettle（reaper/收尾）抢先处置，迟到的持有者（如 sink 晚调 done）
	// 必须完全 no-op（终态不可变；幂等回执重放是 ForceSettle 的显式职责）。
	if _, termExists := m.terminal[g.seq]; termExists {
		if _, inSeen := m.seen[g.seq]; !inSeen {
			m.mu.Unlock()
			return
		}
	}
	// 终态环 + 集合迁移（seen → accepted，前缀水位推进）。
	delete(m.seen, g.seq)
	m.accepted[g.seq] = true
	if _, exists := m.terminal[g.seq]; !exists {
		m.ringOrd.PushBack(g.seq)
		if m.ringOrd.Len() > m.ringCap {
			front := m.ringOrd.Front()
			delete(m.terminal, front.Value.(uint64))
			m.ringOrd.Remove(front)
		}
	}
	m.terminal[g.seq] = TerminalEntry{Level: uint32(level), Code: code}
	// 额度回收入攒批缓冲（未 Consume 的直拒同样回收——客户端已扣额度）。
	// stale grant 已在上面的早路径 no-op，此处必为首次处置。
	m.recoveredB++
	m.recoveredY += frameBytes
	m.advanceLowLocked()
	m.trimAcceptedLocked()
	r := &corepb.Result{RefSeq: g.seq, Level: level, Code: code, RetryHintMs: retryMs, Correlation: corr}
	m.mu.Unlock()
	send(r)
}

// Release 无 wire 动作的占位释放（Consume 前的异常路径：解码失败且无法定夺 seq
// 的场景。生产主路径的解码失败发生在 Consume 后，走 Settle(REJECTED)）。
func (g *SettleGrant) Release() {
	g.m.mu.Lock()
	defer g.m.mu.Unlock()
	if g.done {
		return
	}
	g.done = true
	g.m.releaseLocked(g.seq)
}

// ForceSettle 对仍在途（占位）的 seq 做恢复性终态（服务端 reaper 与 Handle
// 收尾）：grant 对象可能已随 panic 丢失，此处绕过 grant 直接处置。与
// grant.Settle 共享防双回收守卫（terminal 环命中即跳过额度，仅重发 RESULT）。
func (m *CreditManager) ForceSettle(send func(*corepb.Result), seq uint64, level corepb.ResultLevel, code uint32, retryMs uint32, frameBytes int64) {
	if send == nil {
		send = func(*corepb.Result) {}
	}
	m.mu.Lock()
	s, inSeen := m.seen[seq]
	if !inSeen {
		if m.accepted[seq] || seq < m.low {
			// 已处置过：幂等重发存储 outcome。
			if e, ok := m.terminal[seq]; ok {
				r := &corepb.Result{RefSeq: seq, Level: corepb.ResultLevel(e.Level), Code: e.Code}
				m.mu.Unlock()
				send(r)
				return
			}
		}
		m.mu.Unlock()
		return
	}
	if s.Bytes > 0 {
		frameBytes = s.Bytes
	}
	m.mu.Unlock()
	// 经一次性 grant 走统一路径（复用 Settle 的守卫与回收语义）。
	g := &SettleGrant{m: m, seq: seq, consumed: true, done: false}
	g.Settle(send, level, code, retryMs, frameBytes)
}

// TakeRecovered 取出攒批缓冲的回收量（发放 CREDIT 前调用；移入 outstanding）。
// 无回收返回 (0,0)。
func (m *CreditManager) TakeRecovered() (batches, bytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recoveredB <= 0 && m.recoveredY <= 0 {
		return 0, 0
	}
	b, y := m.recoveredB, m.recoveredY
	m.recoveredB, m.recoveredY = 0, 0
	m.outstandingB += b
	m.outstandingY += y
	return b, y
}

// Pending 返回在途占位数。
func (m *CreditManager) Pending() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.seen)
}

// OldestBefore 返回 AddedAt 早于 cutoff 的最旧在途条目（服务端 reaper 用）。
func (m *CreditManager) OldestBefore(cutoff time.Time) (uint64, InflightSlot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var bestSeq uint64
	var best *InflightSlot
	for seq, s := range m.seen {
		if s.AddedAt.Before(cutoff) && (best == nil || seq < bestSeq) {
			best, bestSeq = s, seq
		}
	}
	if best == nil {
		return 0, InflightSlot{}, false
	}
	return bestSeq, *best, true
}

func (m *CreditManager) releaseLocked(seq uint64) {
	delete(m.seen, seq)
	// 占位未进入 accepted（未完成准入流水），直接清除即可。
}

// advanceLowLocked 沿连续已接受前缀推进 low（乱序不推进；全终态后 = max+1）。
func (m *CreditManager) advanceLowLocked() {
	for m.accepted[m.low] {
		delete(m.accepted, m.low)
		m.low++
	}
}

// trimAcceptedLocked 在 accepted 超上限时沿最小 seq 跳过前缀空洞：把 low 推进到
// 最小已接受 seq 后再沿连续段删除。被跳过空洞区间的 seq 此后命中 `seq < low` →
// BelowUnknown released——与终态环淘汰同一降级语义（宁重发不吞数据，不重复投递）。
// 每次 Settle 至少删除最小段的连续运行，故 len(accepted) 恒 ≤ cap+1（有界）。
// 仅在超过上限时做 O(n) 扫描：常规流量下 accepted 趋近空集，零开销。
func (m *CreditManager) trimAcceptedLocked() {
	if len(m.accepted) <= defaultAcceptedCap {
		return
	}
	minSeq := ^uint64(0)
	for s := range m.accepted {
		if s < minSeq {
			minSeq = s
		}
	}
	m.low = minSeq
	m.advanceLowLocked()
}

// String 状态快照（日志）。
func (m *CreditManager) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fmt.Sprintf("credit{outstanding=%d/%d recovered=%d/%d low=%d pending=%d}",
		m.outstandingB, m.outstandingY, m.recoveredB, m.recoveredY, m.low, len(m.seen))
}
