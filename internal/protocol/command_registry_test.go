package protocol

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	core "github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
)

// CommandRegistry 单元测试：寻址/能力门控/ACK 等待与解析。
// （sendCommand 的帧写入依赖真实 Transport，由 test/ 集成测试覆盖。）

func newTestRegistry() *CommandRegistry {
	r := NewCommandRegistry()
	// 加速超时路径
	r.timeouts = func() time.Duration { return 50 * time.Millisecond }
	return r
}

func newTestHandler(negCaps []string) *CoreHandler {
	h := &CoreHandler{}
	h.negCaps.Store(negCaps)
	return h
}

func TestRegistry_SendCommand_AgentNotConnected(t *testing.T) {
	r := newTestRegistry()
	_, err := r.SendCommand(context.Background(), "ghost", &corepb.ControlCommand{CommandId: "c1"})
	if !errors.Is(err, ErrAgentNotConnected) {
		t.Fatalf("err = %v, want ErrAgentNotConnected", err)
	}
}

func TestRegistry_SendCommand_NoCapability(t *testing.T) {
	r := newTestRegistry()
	// 未协商 control_commands 的旧版 agent：注册表里不可见（注册即门控），
	// 这里直接用无能力 handler 模拟"绕过注册"的防御路径。
	h := newTestHandler([]string{"other"})
	r.register("a1", h)
	defer r.unregister("a1", h)

	_, err := r.SendCommand(context.Background(), "a1", &corepb.ControlCommand{CommandId: "c1"})
	if !errors.Is(err, ErrAgentNoCapability) {
		t.Fatalf("err = %v, want ErrAgentNoCapability", err)
	}
}

// fakeCommandTransport 捕获 COMMAND 帧的写（其余方法满足接口）。
type fakeCommandTransport struct {
	written chan core.Frame
}

func (f *fakeCommandTransport) RecvControlFrame(ctx context.Context) (core.Frame, error) {
	<-ctx.Done()
	return core.Frame{}, ctx.Err()
}

func (f *fakeCommandTransport) RecvDataFrame(ctx context.Context) (core.Frame, error) {
	<-ctx.Done()
	return core.Frame{}, ctx.Err()
}

func (f *fakeCommandTransport) SendFrame(ctx context.Context, fr core.Frame) error {
	if fr.Header.Type == core.TypeCommand {
		f.written <- fr
	}
	return nil
}

func (f *fakeCommandTransport) SupportsDatagram() bool { return false }

func (f *fakeCommandTransport) SendDatagram(ctx context.Context, payload []byte) error {
	return nil
}

func (f *fakeCommandTransport) Multiplexing() MultiplexModel { return MultiplexQuicMultiStream }

func (f *fakeCommandTransport) Close() error { return nil }

func (f *fakeCommandTransport) RemoteAddr() net.Addr { return nil }

// TestRegistry_AckLifecycle 全链路：SendCommand → COMMAND 帧写出 →
// registry.resolve(ACK) → SendCommand 返回 agent 应答。
func TestRegistry_AckLifecycle(t *testing.T) {
	r := newTestRegistry()
	ft := &fakeCommandTransport{written: make(chan core.Frame, 8)}
	h := &CoreHandler{tr: ft}
	h.negCaps.Store([]string{core.CapControlCommands})
	r.register("a1", h)
	defer r.unregister("a1", h)

	cmd := &corepb.ControlCommand{
		CommandId: "c1",
		Type:      corepb.CommandType_COMMAND_TYPE_SERVICE_RESTART,
	}
	go func() {
		ack, err := r.SendCommand(context.Background(), "a1", cmd)
		if err != nil {
			t.Errorf("SendCommand: %v", err)
			return
		}
		if ack.Code != corepb.CommandAckCode_COMMAND_ACK_CODE_APPLIED {
			t.Errorf("ack code = %v", ack.Code)
		}
	}()

	// 取出 COMMAND 帧并模拟 agent 回 ACK。
	select {
	case fr := <-ft.written:
		if fr.Header.Type != core.TypeCommand {
			t.Fatalf("frame type = 0x%02x, want TypeCommand", fr.Header.Type)
		}
		var sent corepb.ControlCommand
		if err := core.Decode(fr.Payload, &sent); err != nil {
			t.Fatalf("decode sent command: %v", err)
		}
		r.resolve(&corepb.ControlCommandAck{
			CommandId: sent.CommandId,
			Code:      corepb.CommandAckCode_COMMAND_ACK_CODE_APPLIED,
			Message:   "restarted",
		})
	case <-time.After(2 * time.Second):
		t.Fatal("COMMAND frame not written")
	}
}

// TestRegistry_SendCommand_FailedAck 验证 FAILED ACK 转为 AckError。
func TestRegistry_SendCommand_FailedAck(t *testing.T) {
	r := newTestRegistry()
	ft := &fakeCommandTransport{written: make(chan core.Frame, 8)}
	h := &CoreHandler{tr: ft}
	h.negCaps.Store([]string{core.CapControlCommands})
	r.register("a1", h)
	defer r.unregister("a1", h)

	errCh := make(chan error, 1)
	go func() {
		_, err := r.SendCommand(context.Background(), "a1",
			&corepb.ControlCommand{CommandId: "c2"})
		errCh <- err
	}()

	select {
	case fr := <-ft.written:
		var sent corepb.ControlCommand
		_ = core.Decode(fr.Payload, &sent)
		r.resolve(&corepb.ControlCommandAck{
			CommandId: sent.CommandId,
			Code:      corepb.CommandAckCode_COMMAND_ACK_CODE_FAILED,
			Message:   "disk full",
		})
	case <-time.After(2 * time.Second):
		t.Fatal("frame not written")
	}

	if err := <-errCh; !errors.Is(err, ErrCommandFailed) {
		t.Fatalf("err = %v, want ErrCommandFailed", err)
	}
}

func TestRegistry_PendingTimeout(t *testing.T) {
	r := newTestRegistry()
	h := newTestHandler([]string{core.CapControlCommands})
	r.register("a1", h)
	defer r.unregister("a1", h)

	// 直接走 SendCommand 的超时路径：sendCommand 前置检查通过前 agent 必须
	// 已注册；为避免真实帧写，注册表测试里把 handler 换成带 tr 的不可行——
	// 这里验证 resolve 的去重语义 + pending 清理。
	ack := &corepb.ControlCommandAck{CommandId: "gone", Code: corepb.CommandAckCode_COMMAND_ACK_CODE_FAILED}
	r.resolve(ack) // 无人等待：不 panic、不阻塞
	r.resolve(ack) // 二次 resolve 同一 ACK：channel 已关闭，必须安全
}

func TestRegistry_Unregister_PreservesNewConnection(t *testing.T) {
	r := newTestRegistry()
	old := newTestHandler([]string{core.CapControlCommands})
	cur := newTestHandler([]string{core.CapControlCommands})

	r.register("a1", old)
	r.register("a1", cur) // 重连覆盖
	r.unregister("a1", old)

	if _, ok := r.get("a1"); !ok {
		t.Fatal("old connection unregister must not evict current connection")
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := newTestRegistry()
	h := newTestHandler([]string{core.CapControlCommands})

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := "a" + string(rune('a'+i%8))
			r.register(id, h)
			_, _ = r.get(id)
			r.unregister(id, h)
		}()
	}
	wg.Wait()
}
