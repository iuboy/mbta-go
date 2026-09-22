package protocol

// client_control.go：客户端 control loop（RESULT/CREDIT/PING/PONG/CLOSE/REDIRECT/
// ABORT/COMMAND）+ 结果回调 worker + 心跳（仅 TCP binding）。

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
		f, err := c.tr.ReadFrame(ctx)
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
				slog.Warn("server aborted", "code", core.CodeName(a.GetCode()), "detail", a.GetDetail())
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
	l := c.ledger.Load()
	if l == nil {
		return
	}
	l.Terminal(r.GetRefSeq()) // RESULT 不隐含返还 credit（模型 B：返还经 CREDIT）
	c.notifyDrainIfEmpty()
	c.dispatchResult(resultNotify{
		seq: r.GetRefSeq(), level: r.GetLevel().String(), code: r.GetCode(), correlation: r.GetCorrelation(),
	})
	if r.GetLevel() == corepb.ResultLevel_RESULT_LEVEL_REJECTED ||
		r.GetLevel() == corepb.ResultLevel_RESULT_LEVEL_RELEASED {
		c.metrics.SinkFailures().Inc()
	}
}

// handleCredit 处理 CREDIT 增量。校验规则（r3 §6.3）：
// 双零 delta 忽略；任一维为 0 且另一维 >0 = 协议违规（功能性冻结）→ ABORT；
// 负值/回绕/超钳制由账本钳制消化（非致命）。
func (c *CoreClient) handleCredit(payload []byte) {
	var cr core.Credit
	if err := core.Decode(payload, &cr); err != nil {
		slog.Debug("invalid credit payload", "error", err)
		return
	}
	if cr.GetBatches() == 0 || cr.GetBytes() == 0 {
		slog.Warn("invalid CREDIT (single-zero dimension); aborting",
			"batches", cr.GetBatches(), "bytes", cr.GetBytes())
		c.fatalTeardown("credit protocol violation")
		return
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
	if c.tr != nil {
		if err := c.tr.CloseConn(); err != nil {
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
		return
	}
	pong := &core.PongMsg{TimeUnixNs: ping.GetTimeUnixNs(), Nonce: ping.GetNonce(), Status: "ok"}
	p, err := core.Encode(pong)
	if err != nil {
		return
	}
	if err := c.tr.WriteFrame(ctx, core.TypePong, p); err != nil {
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
			if err := c.tr.WriteFrame(wctx, core.TypePing, p); err != nil {
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
	if cmd.CommandId == "" {
		slog.Warn("command without id; ignoring")
		return
	}
	// 幂等：记录已见 command_id（有界防膨胀；成功命令会从服务端移除，重发
	// 窗口有限，256 条环形足够）。
	c.seenCmdMu.Lock()
	if c.seenCommands == nil {
		c.seenCommands = make(map[string]struct{}, 64)
	}
	if _, dup := c.seenCommands[cmd.CommandId]; dup {
		c.seenCmdMu.Unlock()
		slog.Warn("duplicate command id; ignoring", "command_id", cmd.CommandId)
		return
	}
	c.seenCommands[cmd.CommandId] = struct{}{}
	if len(c.seenCommands) > 256 {
		// 简单防膨胀：超过上限清空（重发窗口远小于此界）。
		c.seenCommands = make(map[string]struct{}, 64)
	}
	c.seenCmdMu.Unlock()

	handler := *h
	go func() {
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
}

// sendCommandAck 回传命令应答（control stream 串行锁复用）。
func (c *CoreClient) sendCommandAck(commandId string, code corepb.CommandAckCode, msg string) {
	ack := &corepb.ControlCommandAck{CommandId: commandId, Code: code, Message: msg}
	p, err := core.Encode(ack)
	if err != nil {
		slog.Warn("encode command ack failed", "error", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// 与 handlePing 同路径：CoreClient 内部直写 transport（controlMu 串行
	// 由 v1 包装层对外的 WriteFrame 负责，core 内部各帧由 control stream
	// 单读单写模型天然串行）。
	if err := c.tr.WriteFrame(ctx, core.TypeCommandAck, p); err != nil {
		slog.Warn("write command ack failed", "error", err)
	}
}
