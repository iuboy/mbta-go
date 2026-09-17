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

	core "github.com/iuboy/mbta-go/core"
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
	mu       sync.RWMutex
	byAgent  map[string]*CoreHandler
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

// resolve 唤醒等待中的 ACK 等待者；无人等待则丢弃。
func (r *CommandRegistry) resolve(ack *corepb.ControlCommandAck) {
	if r == nil || ack == nil || ack.CommandId == "" {
		return
	}
	r.mu.Lock()
	ch, ok := r.pending[ack.CommandId]
	if ok {
		delete(r.pending, ack.CommandId)
	}
	r.mu.Unlock()
	if ok {
		ch <- ack
		close(ch)
	}
}

// SendCommand 向指定 agent 下发命令并等待 ACK（同步语义，含超时）。
// 返回 agent 的应答；REJECTED/FAILED 转为可判定错误（AckError）。
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
	ackCh := make(chan *corepb.ControlCommandAck, 1)
	r.mu.Lock()
	r.pending[cmd.CommandId] = ackCh
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.pending, cmd.CommandId)
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
			return ack, ErrCommandRejected
		default:
			return ack, ErrCommandFailed
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, ErrCommandTimeout
	}
}

// AckError 携带 agent 应答细节的命令失败（errors.As 可取）。
type AckError struct {
	Ack *corepb.ControlCommandAck
}

func (e *AckError) Error() string {
	if e.Ack == nil {
		return "command ack error"
	}
	return "command " + e.Ack.CommandId + ": " + e.Ack.Message
}
