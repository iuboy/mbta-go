package protocol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// pending 键按 (agentID, commandId) 隔离的回归（审查 F7）：跨 agent 并发下发
// 同 CommandId 时，A 的等待者不得被 B 的 ACK 唤醒（此前 pending 以 CommandId
// 为全局键，第二个 SendCommand 覆盖第一条目、ACK 串线）。
func TestRegistry_SendCommand_PerAgentPendingKeys(t *testing.T) {
	r := NewCommandRegistry()
	r.timeouts = func() time.Duration { return 5 * time.Second } // 覆盖负例等待窗口
	ft := &fakeCommandTransport{written: make(chan core.Frame, 8)}
	mkHandler := func() *CoreHandler {
		h := &CoreHandler{tr: ft}
		h.negCaps.Store([]string{core.CapControlCommands})
		return h
	}
	h1, h2 := mkHandler(), mkHandler()
	r.register("a1", h1)
	r.register("a2", h2)
	defer r.unregister("a1", h1)
	defer r.unregister("a2", h2)

	res1 := make(chan error, 1)
	go func() {
		_, err := r.SendCommand(context.Background(), "a1",
			&corepb.ControlCommand{CommandId: "same-id"})
		res1 <- err
	}()

	// 等待 a1 的 COMMAND 帧写出（pending 已登记）。
	select {
	case <-ft.written:
	case <-time.After(2 * time.Second):
		t.Fatal("COMMAND frame not written")
	}

	// a2 对同 ID 命令的 ACK 不得唤醒 a1 的等待者。
	r.resolve("a2", &corepb.ControlCommandAck{
		CommandId: "same-id", Code: corepb.CommandAckCode_COMMAND_ACK_CODE_APPLIED})
	select {
	case err := <-res1:
		t.Fatalf("a1 waiter resolved by a2's ack: err=%v (cross-agent regression)", err)
	case <-time.After(50 * time.Millisecond):
	}

	// 自身 agent 的 ACK 正常唤醒。
	r.resolve("a1", &corepb.ControlCommandAck{
		CommandId: "same-id", Code: corepb.CommandAckCode_COMMAND_ACK_CODE_APPLIED})
	select {
	case err := <-res1:
		if err != nil {
			t.Fatalf("own ack should succeed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a1 waiter not resolved by own ack")
	}
}

// AckError 契约回归（审查 F11）：FAILED/REJECTED 返回 *AckError——errors.Is
// 命中哨兵之外，errors.As 必须能取到完整应答（此前 AckError 零构造点，
// 文档承诺的 errors.As 契约从未成立）。
func TestRegistry_SendCommand_FailedAckCarriesAckError(t *testing.T) {
	r := newTestRegistry()
	ft := &fakeCommandTransport{written: make(chan core.Frame, 8)}
	h := &CoreHandler{tr: ft}
	h.negCaps.Store([]string{core.CapControlCommands})
	r.register("a1", h)
	defer r.unregister("a1", h)

	errCh := make(chan error, 1)
	go func() {
		_, err := r.SendCommand(context.Background(), "a1",
			&corepb.ControlCommand{CommandId: "c-err"})
		errCh <- err
	}()

	select {
	case fr := <-ft.written:
		var sent corepb.ControlCommand
		_ = core.Decode(fr.Payload, &sent)
		r.resolve("a1", &corepb.ControlCommandAck{
			CommandId: sent.CommandId,
			Code:      corepb.CommandAckCode_COMMAND_ACK_CODE_REJECTED,
			Message:   "disk full",
		})
	case <-time.After(2 * time.Second):
		t.Fatal("frame not written")
	}

	err := <-errCh
	if !errors.Is(err, ErrCommandRejected) {
		t.Fatalf("err = %v, want errors.Is ErrCommandRejected", err)
	}
	var ackErr *AckError
	if !errors.As(err, &ackErr) || ackErr.Ack == nil || ackErr.Ack.Message != "disk full" {
		t.Fatalf("errors.As(*AckError) failed or payload wrong: %#v", ackErr)
	}
}
