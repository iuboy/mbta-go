package conformance

// command_test.go：运维命令通道 wire 级一致性（spec §8.2 control_commands）。
//
//   - 协商选中：握手后 agent 注册进 CommandRegistry，SendCommand → COMMAND 帧
//     下发 → COMMAND_ACK 回传 resolve → 调用方拿到应答；
//   - 未协商 MUST NOT 下发：能力未选中时 agent 不注册，SendCommand 立即
//     ErrAgentNotConnected（facade 再导出哨兵，errors.Is 判别）；
//   - 恶意/故障 agent 回 REJECTED → AckError（errors.Is ErrCommandRejected）。

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// cmdCaps 是启用命令通道所需的双侧能力。
var cmdCaps = []string{core.CapControlCommands, core.CapTraceContext}

// startCmdEnv 建立协商了 control_commands 的握手环境（注册表注入服务端）。
func startCmdEnv(t *testing.T, reg *protocol.CommandRegistry, clientCaps []string) *testEnv {
	t.Helper()
	cfg := envConfig{
		serverCaps: cmdCaps,
		clientCaps: clientCaps,
		commands:   reg,
	}
	return startEnv(t, cfg)
}

// TestCommand_WireRoundTrip 验证协商选中后的完整往返：SendCommand 下发
// COMMAND（command_id 原样），测试注入 COMMAND_ACK 后调用方同步拿到应答。
func TestCommand_WireRoundTrip(t *testing.T) {
	reg := protocol.NewCommandRegistry()
	env := startCmdEnv(t, reg, cmdCaps)

	type res struct {
		ack *corepb.ControlCommandAck
		err error
	}
	ch := make(chan res, 1)
	go func() {
		ack, err := reg.SendCommand(context.Background(), env.cfg.agentID,
			&corepb.ControlCommand{CommandId: "cmd-0001", Payload: []byte(`{"action":"reload"}`)})
		ch <- res{ack, err}
	}()

	f := AwaitFrame(t, env.tr.Sent, core.TypeCommand, 5*time.Second)
	var sentCmd corepb.ControlCommand
	if err := core.Decode(f.Payload, &sentCmd); err != nil {
		t.Fatalf("decode command: %v", err)
	}
	if sentCmd.GetCommandId() != "cmd-0001" {
		t.Fatalf("command_id = %q, want cmd-0001", sentCmd.GetCommandId())
	}

	// 模拟 agent 回 ACK（连接寻址按 agentID——controlLoop resolveAck 用本连接 agent）。
	ackPayload, err := core.Encode(&corepb.ControlCommandAck{
		CommandId: "cmd-0001", Code: corepb.CommandAckCode_COMMAND_ACK_CODE_APPLIED, Message: "reloaded",
	})
	if err != nil {
		t.Fatalf("encode ack: %v", err)
	}
	env.tr.ControlIn <- MakeFrame(core.TypeCommandAck, ackPayload)

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("SendCommand: %v", r.err)
		}
		if r.ack.GetCode() != corepb.CommandAckCode_COMMAND_ACK_CODE_APPLIED {
			t.Errorf("ack code = %v, want APPLIED", r.ack.GetCode())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for SendCommand return")
	}
}

// TestCommand_NotNegotiatedNotRegistered 验证「未协商 control_commands 时
// MUST NOT 下发」：能力未选中 → agent 不注册 → SendCommand 立即
// ErrAgentNotConnected（而非发帧后干等 30s 超时）。
func TestCommand_NotNegotiatedNotRegistered(t *testing.T) {
	reg := protocol.NewCommandRegistry()
	// 客户端只带 trace_context：交集不含 control_commands。
	env := startCmdEnv(t, reg, []string{core.CapTraceContext})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err := reg.SendCommand(ctx, env.cfg.agentID, &corepb.ControlCommand{CommandId: "cmd-x"})
	if !errors.Is(err, protocol.ErrAgentNotConnected) {
		t.Fatalf("SendCommand err = %v, want ErrAgentNotConnected", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("SendCommand took %v, want immediate（未注册即刻失败而非等 ACK 超时）", elapsed)
	}
	// 无 COMMAND 帧潜行。
	if f, ok := NextFrame(env.tr.Sent, 100*time.Millisecond); ok && f.Header.Type == core.TypeCommand {
		t.Error("COMMAND frame sent for agent without control_commands capability")
	}
}

// TestCommand_AgentRejectedAckError 验证 agent 回 REJECTED 时 SendCommand
// 返回 AckError（errors.Is 命中 ErrCommandRejected，errors.As 可取应答细节）。
func TestCommand_AgentRejectedAckError(t *testing.T) {
	reg := protocol.NewCommandRegistry()
	env := startCmdEnv(t, reg, cmdCaps)

	type res struct {
		ack *corepb.ControlCommandAck
		err error
	}
	ch := make(chan res, 1)
	go func() {
		ack, err := reg.SendCommand(context.Background(), env.cfg.agentID,
			&corepb.ControlCommand{CommandId: "cmd-0002"})
		ch <- res{ack, err}
	}()
	f := AwaitFrame(t, env.tr.Sent, core.TypeCommand, 5*time.Second)
	var sentCmd corepb.ControlCommand
	if err := core.Decode(f.Payload, &sentCmd); err != nil {
		t.Fatalf("decode command: %v", err)
	}

	ackPayload, err := core.Encode(&corepb.ControlCommandAck{
		CommandId: sentCmd.GetCommandId(), Code: corepb.CommandAckCode_COMMAND_ACK_CODE_REJECTED, Message: "not now",
	})
	if err != nil {
		t.Fatalf("encode ack: %v", err)
	}
	env.tr.ControlIn <- MakeFrame(core.TypeCommandAck, ackPayload)

	select {
	case r := <-ch:
		var ackErr *protocol.AckError
		if !errors.As(r.err, &ackErr) || !errors.Is(r.err, protocol.ErrCommandRejected) {
			t.Fatalf("SendCommand err = %v, want AckError wrapping ErrCommandRejected", r.err)
		}
		if ackErr.Ack.GetMessage() != "not now" {
			t.Errorf("ack message = %q, want %q", ackErr.Ack.GetMessage(), "not now")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for SendCommand return")
	}
}

// ACK 超时路径（ErrCommandTimeout）由 internal/protocol/command_registry_test.go
// 以注入 timeouts 窗口覆盖（50ms 收敛），此处不重复拉长套件时长。
