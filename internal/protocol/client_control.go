package protocol

// client_control.go：客户端 control loop（RESULT/CREDIT/PING/PONG/CLOSE/REDIRECT/
// ABORT/COMMAND）+ 结果回调 worker + 心跳（双 binding 注入）。

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// ReadControlLoop 读 control 帧并分发（StartLifecycle 启动为后台 goroutine）。
func (c *CoreClient) ReadControlLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		f, err := c.transport().ReadFrame(ctx)
		if err != nil {
			if isTemporaryError(err) && ctx.Err() == nil {
				continue
			}
			if ctx.Err() == nil {
				slog.Warn("control loop read error", "error", err)
				c.fatalTeardown("read error")
			}
			return
		}
		switch f.Header.Type {
		case core.TypeResult:
			c.handleResult(f.Payload)
		case core.TypeCredit:
			c.handleCredit(f.Payload)
		case core.TypeClose:
			slog.Info("server sent close")
			c.fatalTeardown("server close")
			return
		case core.TypeAbort:
			var a core.AbortMsg
			if err := core.Decode(f.Payload, &a); err == nil {
				// Detail 由对端控制（帧上限内任意字符串），入日志前必须清洗
				// （spec §11.3；本文件其余网络字符串均已过 SanitizeForLog）。
				slog.Warn("server aborted", "code", core.CodeName(a.GetCode()),
					"detail", core.SanitizeForLog(a.GetDetail()))
			}
			c.fatalTeardown("server abort")
			return
		case core.TypePing:
			c.handlePing(ctx, f.Payload)
		case core.TypePong:
			// TCP 心跳应答：忽略（保活由发送侧判定）
		case core.TypeRedirect:
			c.dispatchRedirect(f.Payload)
		case core.TypeCommand:
			c.dispatchCommand(ctx, f.Payload)
		case core.TypeDict:
			c.handleDict(f.Payload)
		case core.TypeHello, core.TypeHelloAck, core.TypeHelloNak:
			slog.Debug("handshake frame after ready; ignoring", "type", f.Header.Type)
		default:
			slog.Debug("unknown control type; skipping", "type", f.Header.Type)
		}
	}
}

// handleResult 处理 RESULT：slot 终态 + 回调 + drain 唤醒。
func (c *CoreClient) handleResult(payload []byte) {
	var r core.Result
	if err := core.Decode(payload, &r); err != nil {
		slog.Debug("invalid result payload", "error", err)
		return
	}
	if err := core.ValidateResultLevel(r.GetLevel()); err != nil {
		slog.Debug("invalid result level", "level", r.GetLevel())
		return
	}
	if r.GetRefSeq() == 0 {
		slog.Debug("result without ref_seq; ignoring")
		return
	}
	// correlation 由对端控制：超限值清洗为空串而非丢帧——终态记账（Terminal/
	// drain 唤醒）必须继续，仅应用回显字段不可信（恶意服务端 16MB 字符串 ×
	// 1024 槽 ackQueue 的驻留放大由此钳掉）。
	if len(r.GetCorrelation()) > core.MaxBatchCorrelationLen {
		r.Correlation = ""
	}
	l := c.ledger.Load()
	if l == nil {
		return
	}
	// RESULT 不隐含返还 credit（模型 B：返还经 CREDIT）；帧照常派发——
	// durable 模式下 ACCEPTED（中间态）与 DURABLE（终态）都要到达应用。
	// drain 计数谓词按终态收敛（spec §3.7）：durable 模式的 ACCEPTED 是中间态
	// （slot 保留），其余 level 即终态（slot 移出）。
	terminal := r.GetLevel() != corepb.ResultLevel_RESULT_LEVEL_ACCEPTED ||
		c.ackModeLoad() != corepb.AckMode_ACK_MODE_DURABLE
	// timedOut 抑制与 slot 处置在账本锁内原子完成（见 CreditLedger.Terminal）：
	// reaper 已派发 timeout 的 seq，迟到的真实 RESULT 不再二次回调。
	_, timedOut := l.Terminal(r.GetRefSeq(), terminal)
	c.notifyDrainIfEmpty()
	if timedOut {
		return
	}
	c.dispatchResult(resultNotify{
		seq: r.GetRefSeq(), level: r.GetLevel().String(), code: r.GetCode(), correlation: r.GetCorrelation(),
	})
	if r.GetLevel() == corepb.ResultLevel_RESULT_LEVEL_REJECTED ||
		r.GetLevel() == corepb.ResultLevel_RESULT_LEVEL_RELEASED {
		c.metrics.SinkFailures().Inc()
	}
}

// handleCredit 处理 CREDIT 增量（r3 §6.3 修订）：
// 双零 delta 忽略；单零维度不再视为协议违规——服务端合法路径可产生
// CREDIT{b>0, y=0}（占位未 Consume 的 reaper ForceSettle 只回收批数、不回收
// 字节，见 handler_batch.releaseStuck），此前的 fatalTeardown 会把合法服务端
// 状态误判为违规并拆连接。各维交由 CreditLedger.OnCredit 独立钳制消化：
// 双零忽略 / 负值回绕丢弃计违规 / 超钳制部分吸收，均非致命。
func (c *CoreClient) handleCredit(payload []byte) {
	var cr core.Credit
	if err := core.Decode(payload, &cr); err != nil {
		slog.Debug("invalid credit payload", "error", err)
		return
	}
	if cr.GetBatches() == 0 && cr.GetBytes() == 0 {
		return // 双零 delta 忽略
	}
	if cr.GetBatches() == 0 || cr.GetBytes() == 0 {
		slog.Debug("single-zero credit dimension; ledger clamps per-dimension",
			"batches", cr.GetBatches(), "bytes", cr.GetBytes())
	}
	l := c.ledger.Load()
	if l == nil {
		return
	}
	l.OnCredit(int64(cr.GetBatches()), int64(cr.GetBytes()))
}

// dispatchResult 入队结果回调（队列满丢弃 + warn，不阻塞 control loop）。
func (c *CoreClient) dispatchResult(n resultNotify) {
	if c.ackQueue == nil {
		return
	}
	select {
	case c.ackQueue <- n:
	default:
		slog.Warn("result callback queue full, dropping", "seq", n.seq)
	}
}

// runResultWorker 串行执行结果回调（保序；panic recover）。
func (c *CoreClient) runResultWorker(ctx context.Context) {
	invoke := func(n resultNotify) {
		defer func() {
			if r := recover(); r != nil {
				slog.Warn("result handler panicked", "seq", n.seq, "panic", r)
			}
		}()
		if p := c.resultHandler.Load(); p != nil {
			(*p)(n.seq, n.level, n.code, n.correlation)
		}
	}
	for {
		select {
		case <-ctx.Done():
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
		drain:
			for {
				select {
				case n := <-c.ackQueue:
					invoke(n)
				case <-deadline.C:
					if q := len(c.ackQueue); q > 0 {
						slog.Warn("result worker drain timed out", "pending", q)
					}
					break drain
				default:
					break drain
				}
			}
			return
		case n := <-c.ackQueue:
			invoke(n)
		}
	}
}

// fatalTeardown 控制读循环致命退出后的会话收敛（僵尸会话防护）：
// 取消 lifecycle、退回 Idle（非 Ready 状态可重连语义）、清空账本、关闭连接。
// 不消耗 closeOnce——用户随后的 Close 仍执行完整清理（幂等）。
func (c *CoreClient) fatalTeardown(cause string) {
	c.closed.Store(true) // 与 close 共享终态语义（IsClosed 立即真；StartLifecycle 被拒）
	c.teardownPhase(cause)
	if tr := c.transport(); tr != nil {
		if err := tr.CloseConn(); err != nil {
			slog.Debug("fatal teardown close conn", "cause", cause, "error", err)
		}
	}
	slog.Info("session torn down", "cause", cause, "session", c.SessionID())
}

// handleDict 处理 DICT 帧（zstd_dict 能力；服务端在 HELLO_ACK 后立即下发）：
// 注册字典到 core 进程级单例（encoder pool / decoder 重建）并标记可用——
// 此后 SendBatch 对 > 512B 的 batch 选用 COMPRESSION_ZSTD_DICT。
// 后续 DICT 帧（字典轮换为演进项）按"最后写入者生效"覆盖。
func (c *CoreClient) handleDict(payload []byte) {
	// 协商校验：未协商 zstd_dict 而收到 DICT = 对端越权，拒绝处理
	// （防恶意服务端在未协商通道注入字典消耗 CPU/内存）。
	if !slices.Contains(c.SelectedCapabilities(), core.CapZstdDict) {
		slog.Warn("unsolicited DICT frame (zstd_dict not negotiated); ignoring")
		return
	}
	var d core.ZstdDict
	if err := core.Decode(payload, &d); err != nil {
		slog.Warn("invalid DICT frame; ignoring", "error", err)
		return
	}
	// 尺寸上限（与服务端 Policy 同值）：防恶意服务端连发大字典
	// 翻搅注册表（sha256+拷贝+解码器构造的 CPU 放大）。
	if len(d.GetDict()) > core.MaxZstdDictBytes {
		slog.Warn("DICT exceeds size limit; ignoring", "dict_id", d.GetDictId(),
			"bytes", len(d.GetDict()), "limit", core.MaxZstdDictBytes)
		return
	}
	codec, err := core.RegisterZstdDict(d.GetDictId(), d.GetDict())
	if err != nil {
		slog.Warn("failed to activate zstd dict; ignoring", "dict_id", d.GetDictId(), "error", err)
		return
	}
	c.zdict.Store(codec)
	slog.Info("zstd dictionary activated", "dict_id", d.GetDictId(), "bytes", len(d.GetDict()))
}

// handlePing 回 PONG。
func (c *CoreClient) handlePing(ctx context.Context, payload []byte) {
	var ping core.PingMsg
	if err := core.Decode(payload, &ping); err != nil {
		// 畸形心跳此前静默吞错：连接最终以「心跳无响应 → 读超时断连」收场，
		// 日志零根因线索（v1 binding 实际踩过的心跳排障坑）。
		slog.Debug("invalid ping payload; not ponging", "error", err)
		return
	}
	pong := &core.PongMsg{TimeUnixNs: ping.GetTimeUnixNs(), Nonce: ping.GetNonce(), Status: "ok"}
	p, err := core.Encode(pong)
	if err != nil {
		slog.Debug("encode pong failed", "error", err)
		return
	}
	if err := c.transport().WriteFrame(ctx, core.TypePong, p); err != nil {
		slog.Debug("write pong failed", "error", err)
	}
}

// HeartbeatLoop 周期发送 PING（v1/ntls 双 binding 均注入；维持两侧 control
// 读循环的 DefaultReadTimeout 刷新——QUIC 传输层 keepalive 不产生应用层帧）。
func (c *CoreClient) HeartbeatLoop(ctx context.Context) {
	interval := 30 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ping := &core.PingMsg{TimeUnixNs: time.Now().UnixNano()}
			p, err := core.Encode(ping)
			if err != nil {
				continue
			}
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := c.transport().WriteFrame(wctx, core.TypePing, p); err != nil {
				cancel()
				slog.Debug("heartbeat write failed; exiting", "error", err)
				return
			}
			cancel()
		}
	}
}

// dispatchRedirect 异步调用 redirect handler（单飞行 + 30s 超时 + panic 防护）。
func (c *CoreClient) dispatchRedirect(payload []byte) {
	var h func(context.Context, []byte)
	if p := c.redirectHandler.Load(); p != nil {
		h = *p
	}
	if h == nil {
		return
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	if !c.redirectInflight.CompareAndSwap(false, true) {
		slog.Debug("redirect handler in flight; dropping duplicate")
		return
	}
	go func() {
		defer c.redirectInflight.Store(false)
		defer func() {
			if r := recover(); r != nil {
				slog.Warn("redirect handler panicked", "panic", r)
			}
		}()
		parent := c.lifecycleCtx
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, 30*time.Second)
		defer cancel()
		h(ctx, cp)
	}()
}

// ackReapInterval 是客户端 RESULT 超时扫描间隔（AckTimeout 的实际驱动——
// 此前 ReapExpired 无生产调用方，AckTimeout 是死配置）。
const ackReapInterval = 30 * time.Second

// AckReaperLoop 周期扫描超时 slot：标记失败 + 通知回调（level="timeout"）+
// 唤醒 drain。不回补 credit（模型 B：返还权威在服务端；服务端 reaper 保证
// 最终 RESULT(released)+CREDIT——连接存活期间该回收只是迟到而非缺席）。
// 由 StartLifecycle 作为独立 goroutine 启动（与心跳并列）。
func (c *CoreClient) AckReaperLoop(ctx context.Context) {
	ticker := time.NewTicker(ackReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l := c.ledger.Load()
			if l == nil {
				continue
			}
			for _, s := range l.ReapExpired(time.Now()) {
				slog.Warn("batch result timed out", "seq", s.Seq, "age", time.Since(s.SentAt).Round(time.Second))
				c.dispatchResult(resultNotify{seq: s.Seq, level: "timeout", code: core.CodeInternal})
			}
			c.notifyDrainIfEmpty()
		}
	}
}

// isTemporaryError 报告可恢复临时 I/O 错误。
func isTemporaryError(err error) bool {
	var ne interface{ Temporary() bool }
	if errors.As(err, &ne) {
		return ne.Temporary()
	}
	return false
}

// CommandHandler 是命令执行回调：实现执行命令并返回结果码/消息（协议层
// 自动回 COMMAND_ACK）。RESTART 类自重启命令应在回调内先完成落盘等准备，
// 再派生脱离会话的重启动作并返回 ACCEPTED——ACK 必须先于进程退出发出。
type CommandHandler func(ctx context.Context, cmd *corepb.ControlCommand) (corepb.CommandAckCode, string)

// SetCommandHandler 注册命令执行回调（capability: control_commands 协商
// 选定后，server 的 COMMAND 帧将触发；nil = 忽略命令帧，保持旧版兼容）。
// 回调以独立 goroutine 运行（panic 防护 + 5min 超时），不阻塞 control loop。
func (c *CoreClient) SetCommandHandler(h CommandHandler) {
	if h == nil {
		c.commandHandler.Store((*CommandHandler)(nil))
		return
	}
	c.commandHandler.Store(&h)
}

// maxCommandIDLen 是 command_id 的字节上限（服务端生成器为 ULID 类短标识；
// 超限 id 属恶意帧——seenCommands 环形窗口 256 × 无上限长度可驻留 GB 级内存）。
const maxCommandIDLen = 128

// maxCommandHandlers 是命令回调的并发执行槽数（恶意/被攻陷服务端的命令洪水
// 防线：无界 spawn + 5min ctx 存活可堆出百万级 goroutine）。满槽直接回
// COMMAND_ACK(failed)——服务端 SendCommand 立即失败而非干等 30s 超时。
const maxCommandHandlers = 8

// dispatchCommand 解码命令帧并异步执行，执行完成后自动回 COMMAND_ACK。
// 命令按 command_id 幂等：同一 ID 的重复帧由 inFlight 去重（重发窗口内）。
func (c *CoreClient) dispatchCommand(ctx context.Context, payload []byte) {
	h := c.commandHandler.Load()
	if h == nil || *h == nil {
		slog.Debug("command received but no handler registered; ignoring")
		return
	}
	var cmd corepb.ControlCommand
	if err := core.Decode(payload, &cmd); err != nil {
		slog.Warn("decode command failed", "error", err)
		return
	}
	// 协商校验（与 handleDict 对称的纵深防御）：未协商 control_commands 而收到
	// COMMAND = 对端越权，拒绝处理（命令方向是可信服务端，但两侧校验不对称
	// 会削弱防线——review F30 裁决）。
	if !slices.Contains(c.SelectedCapabilities(), core.CapControlCommands) {
		slog.Warn("unsolicited COMMAND frame (control_commands not negotiated); ignoring")
		return
	}
	if cmd.CommandId == "" {
		slog.Warn("command without id; ignoring")
		return
	}
	if len(cmd.CommandId) > maxCommandIDLen {
		slog.Warn("command id exceeds length limit; ignoring", "len", len(cmd.CommandId))
		return
	}
	// 幂等簿记：记录已见 command_id（有界防膨胀）。满时环形淘汰最旧条目——
	// 整体清空会把刚插入的 ID 一并遗忘，服务端重发窗口内的重复命令将重复执行
	// （RESTART 类有实际危害），恰好击穿本机制唯一的防御目的。
	if c.markSeenCommand(cmd.CommandId) {
		slog.Warn("duplicate command id; ignoring", "command_id", cmd.CommandId)
		return
	}

	handler := *h
	select {
	case c.commandSlots <- struct{}{}:
		go func() {
			defer func() { <-c.commandSlots }()
			defer func() {
				if r := recover(); r != nil {
					slog.Warn("command handler panicked", "command_id", cmd.CommandId, "panic", r)
					c.sendCommandAck(cmd.CommandId, corepb.CommandAckCode_COMMAND_ACK_CODE_FAILED, "handler panicked")
				}
			}()
			wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
			defer cancel()
			code, msg := handler(wctx, &cmd)
			c.sendCommandAck(cmd.CommandId, code, msg)
		}()
	default:
		slog.Warn("command handler slots full; rejecting", "command_id", cmd.CommandId)
		c.sendCommandAck(cmd.CommandId, corepb.CommandAckCode_COMMAND_ACK_CODE_FAILED, "command concurrency limit")
	}
}

// maxSeenCommands 是命令幂等窗口容量（重发窗口远小于此界）。
const maxSeenCommands = 256

// markSeenCommand 登记命令 ID 并报告是否重复（true=重复，调用方忽略该命令）。
// 容量满时按到达序环形淘汰最旧条目：刚插入的 ID 必须仍在窗口内——
// clear-on-full 会让重发窗口内的最新命令重复执行。
func (c *CoreClient) markSeenCommand(commandId string) bool {
	c.seenCmdMu.Lock()
	defer c.seenCmdMu.Unlock()
	if c.seenCommands == nil {
		c.seenCommands = make(map[string]struct{}, 64)
	}
	if _, dup := c.seenCommands[commandId]; dup {
		return true
	}
	c.seenCommands[commandId] = struct{}{}
	c.seenCmdOrder = append(c.seenCmdOrder, commandId)
	if len(c.seenCmdOrder) > maxSeenCommands {
		oldest := c.seenCmdOrder[0]
		c.seenCmdOrder = c.seenCmdOrder[1:]
		delete(c.seenCommands, oldest)
	}
	return false
}

// sendCommandAck 回传命令应答（control stream 串行锁复用）。
func (c *CoreClient) sendCommandAck(commandId string, code corepb.CommandAckCode, msg string) {
	ack := &corepb.ControlCommandAck{CommandId: commandId, Code: code, Message: msg}
	p, err := core.Encode(ack)
	if err != nil {
		slog.Warn("encode command ack failed", "error", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlWriteTimeout)
	defer cancel()
	// 与 handlePing 同路径：CoreClient 内部直写 transport（controlMu 串行
	// 由 v1 包装层对外的 WriteFrame 负责，core 内部各帧由 control stream
	// 单读单写模型天然串行）。
	if err := c.transport().WriteFrame(ctx, core.TypeCommandAck, p); err != nil {
		slog.Warn("write command ack failed", "error", err)
	}
}
