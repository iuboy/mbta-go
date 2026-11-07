// command_registry.go：运维命令通道的会话注册表与应答等待。
//
// 服务端按 agentID 寻址已认证连接下发 COMMAND 帧（0x23）；agent 回
// COMMAND_ACK（0x24）后 resolve 该命令的 pending channel。注册表由
// ServerConfig.Commands 注入（nil = 命令能力整体关闭），跨连接共享，
// 所有方法线程安全。
//
// 寻址语义：同一 agentID 重复连接（重连竞态）以最后一次注册为准——旧连接
// 在 DISCONNECTED 清理时仅当仍指向自己才移除，避免误删新连接。
package protocol

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// 命令应答等待的默认超时。命令执行（配置应用/服务重启）在 agent 侧异步
// 完成时应先回 ACCEPTED；超过此窗口未收到任何 ACK 视为失败。
const DefaultCommandAckTimeout = 30 * time.Second

// ErrCommand 发送失败的可判定错误族（errors.Is）。
var (
	ErrAgentNotConnected = errors.New("agent not connected")
	ErrAgentNoCapability = errors.New("agent did not negotiate control_commands")
	ErrCommandTimeout    = errors.New("command ack timeout")
	ErrCommandRejected   = errors.New("command rejected by agent")
	ErrCommandFailed     = errors.New("command failed on agent")
)

// CommandRegistry 维护 agentID → 活动连接的映射，并提供命令下发 + ACK 等待。
type CommandRegistry struct {
	mu      sync.RWMutex
	byAgent map[string]*CoreHandler
	// pending 的 key 是 (agentID, commandId) 复合键：CommandId 是调用方生成的
	// 幂等键，作用域是单个 agent——全局键会让对 agentA/B 并发下发的同 ID 命令
	// 互相覆盖 pending 条目，A 的 ACK resolve 到 B 的等待者（审查 F7 裁决）。
	pending  map[string]chan *corepb.ControlCommandAck
	timeouts func() time.Duration // ACK 等待窗口（可测；nil = DefaultCommandAckTimeout）
}

// NewCommandRegistry 创建空注册表。
func NewCommandRegistry() *CommandRegistry {
	return &CommandRegistry{
		byAgent:  make(map[string]*CoreHandler),
		pending:  make(map[string]chan *corepb.ControlCommandAck),
		timeouts: func() time.Duration { return DefaultCommandAckTimeout },
	}
}

func (r *CommandRegistry) register(agentID string, h *CoreHandler) {
	if r == nil || agentID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byAgent[agentID] = h
}

func (r *CommandRegistry) unregister(agentID string, h *CoreHandler) {
	if r == nil || agentID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// 仅当仍指向自己才移除：重连竞态下新连接可能已覆盖。
	if cur, ok := r.byAgent[agentID]; ok && cur == h {
		delete(r.byAgent, agentID)
	}
}

func (r *CommandRegistry) get(agentID string) (*CoreHandler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.byAgent[agentID]
	return h, ok
}

// pendingKey 构造 pending 表的 (agentID, commandId) 复合键。
func pendingKey(agentID, commandID string) string {
	return agentID + "\x1f" + commandID
}

// resolve 唤醒指定 agent 等待中的 ACK 等待者；无人等待则丢弃。
// agentID 来自回传 ACK 的连接（handler 自身），与服务端下发时的寻址维度一致。
func (r *CommandRegistry) resolve(agentID string, ack *corepb.ControlCommandAck) {
	if r == nil || ack == nil || ack.CommandId == "" {
		return
	}
	key := pendingKey(agentID, ack.CommandId)
	r.mu.Lock()
	ch, ok := r.pending[key]
	if ok {
		delete(r.pending, key)
	}
	r.mu.Unlock()
	if ok {
		ch <- ack
		close(ch)
	}
}

// SendCommand 向指定 agent 下发命令并等待 ACK（同步语义，含超时）。
// 返回 agent 的应答；REJECTED/FAILED 转为 *AckError（errors.Is 命中
// ErrCommandRejected/ErrCommandFailed，errors.As 可取完整应答）。
func (r *CommandRegistry) SendCommand(ctx context.Context, agentID string, cmd *corepb.ControlCommand) (*corepb.ControlCommandAck, error) {
	if r == nil {
		return nil, ErrAgentNotConnected
	}
	if cmd == nil || cmd.CommandId == "" {
		return nil, errors.New("command_id is required (idempotency key)")
	}
	h, ok := r.get(agentID)
	if !ok {
		return nil, ErrAgentNotConnected
	}
	if !h.hasCapability(core.CapControlCommands) {
		return nil, ErrAgentNoCapability
	}

	timeout := DefaultCommandAckTimeout
	if r.timeouts != nil {
		timeout = r.timeouts()
	}
	key := pendingKey(agentID, cmd.CommandId)
	ackCh := make(chan *corepb.ControlCommandAck, 1)
	r.mu.Lock()
	r.pending[key] = ackCh
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		// 指向检查（与 unregister 同模式）：同 (agentID, commandId) 的并发发送
		// 会覆盖 pending——迟到退出者只清理仍属于自己的条目，后到等待者的
		// ACK 路由不被误删。
		if cur, ok := r.pending[key]; ok && cur == ackCh {
			delete(r.pending, key)
		}
		r.mu.Unlock()
	}()

	if err := h.sendCommand(cmd); err != nil {
		return nil, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case ack := <-ackCh:
		switch ack.Code {
		case corepb.CommandAckCode_COMMAND_ACK_CODE_APPLIED,
			corepb.CommandAckCode_COMMAND_ACK_CODE_ACCEPTED:
			return ack, nil
		case corepb.CommandAckCode_COMMAND_ACK_CODE_REJECTED:
			return ack, &AckError{Ack: ack, err: ErrCommandRejected}
		default:
			return ack, &AckError{Ack: ack, err: ErrCommandFailed}
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, ErrCommandTimeout
	}
}

// AckError 携带 agent 应答细节的命令失败：errors.Is 命中对应哨兵
// （ErrCommandRejected/ErrCommandFailed），errors.As 可取完整应答。
type AckError struct {
	Ack *corepb.ControlCommandAck
	err error
}

// Error 返回命令失败的描述：类别（rejected/failed）加 agent 应答消息。
func (e *AckError) Error() string {
	code := "command failed"
	if errors.Is(e.err, ErrCommandRejected) {
		code = "command rejected"
	}
	msg := ""
	if e.Ack != nil {
		msg = ": " + e.Ack.Message
	}
	return code + msg
}

// Is 报告是否命中错误哨兵（供 errors.Is 判别，实现见 Unwrap）。
func (e *AckError) Is(target error) bool { return target == e.err }

// Unwrap 返回内部哨兵错误（ErrCommandRejected/ErrCommandFailed）。
func (e *AckError) Unwrap() error { return e.err }
