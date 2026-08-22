// Package conformance 提供 MBTA 协议核心（r3）的传输无关一致性测试。
//
// 用 FakeTransport 注入 protocol.CoreHandler，验证握手（1-RTT ECDH + token_proof）、
// Envelope/密钥日程、credit（模型 B）、集合制去重、sink 契约与 CLOSE/ABORT 语义
// 不依赖真实 QUIC/TCP binding。v1/ntls 各自只保留 binding 特有测试。
package conformance

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// FakeTransport 是 protocol.Transport 的内存实现，用于测试 CoreHandler。
//
//   - ControlIn / DataIn：测试向其写入帧（模拟 client→server；CoreHandler 经
//     RecvControlFrame / RecvDataFrame 消费）；
//   - Sent：CoreHandler 经 SendFrame 写出的帧（HELLO_ACK/RESULT/CREDIT/ABORT 等），
//     按 core.IsControlType 路由（r3 服务端应答帧全部落在 control 域）。
type FakeTransport struct {
	ControlIn chan core.Frame
	DataIn    chan core.Frame
	Sent      chan core.Frame

	mu     sync.Mutex
	closed bool
}

// NewFakeTransport 创建 FakeTransport（模拟单连接可靠传输）。
func NewFakeTransport() *FakeTransport {
	return &FakeTransport{
		ControlIn: make(chan core.Frame, 16),
		DataIn:    make(chan core.Frame, 64),
		Sent:      make(chan core.Frame, 128),
	}
}

func (t *FakeTransport) RecvControlFrame(ctx context.Context) (core.Frame, error) {
	select {
	case f, ok := <-t.ControlIn:
		if !ok {
			return core.Frame{}, io.EOF
		}
		return f, nil
	case <-ctx.Done():
		return core.Frame{}, ctx.Err()
	}
}

func (t *FakeTransport) RecvDataFrame(ctx context.Context) (core.Frame, error) {
	select {
	case f, ok := <-t.DataIn:
		if !ok {
			return core.Frame{}, io.EOF
		}
		return f, nil
	case <-ctx.Done():
		return core.Frame{}, ctx.Err()
	}
}

// SendFrame 写出一帧。r3 帧路由按 type 高位通道域（core.IsControlType）——
// 服务端应答帧（HELLO_ACK/RESULT/CREDIT/ABORT/CLOSE）全为 control 域，统一送 Sent。
func (t *FakeTransport) SendFrame(ctx context.Context, f core.Frame) error {
	return t.sendOnChannel(ctx, t.Sent, f)
}

// sendOnChannel 在 closed-check 后向 ch 发送帧。
//
// Sent 不随 Close 关闭（关闭与协议层并发发送构成 data race）；关闭后置 closed
// 标志使后续发送立即返回 ErrClosedPipe，ctx 取消兜底阻塞发送。
func (t *FakeTransport) sendOnChannel(ctx context.Context, ch chan<- core.Frame, f core.Frame) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return io.ErrClosedPipe
	}
	t.mu.Unlock()
	select {
	case ch <- f:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *FakeTransport) SupportsDatagram() bool { return false }

func (t *FakeTransport) SendDatagram(ctx context.Context, payload []byte) error {
	_ = ctx
	_ = payload
	return protocol.ErrDatagramUnsupported
}

// Multiplexing 返回 TCP 单连接模型（CoreHandler 据此选择更小的批并发信号量）。
func (t *FakeTransport) Multiplexing() protocol.MultiplexModel {
	return protocol.MultiplexTCPSingleConn
}

// RemoteAddr 满足 protocol.Transport 接口；FakeTransport 无真实对端，返回 nil。
func (t *FakeTransport) RemoteAddr() net.Addr { return nil }

// Close 幂等关闭。关闭 ControlIn/DataIn 使阻塞的 RecvControlFrame/RecvDataFrame
// 收到 io.EOF（接收方与 close 并发是安全的）。Sent 不关闭：协议层 goroutine
// 可能仍在并发发送（close vs send 是 data race）；已缓冲的帧仍可被测试读取。
func (t *FakeTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	close(t.ControlIn)
	close(t.DataIn)
	return nil
}

// ===== 测试 helpers =====

// MakeFrame 构造一个写入 ControlIn/DataIn 的帧（r3 flags 全保留恒 0）。
func MakeFrame(typ uint8, payload []byte) core.Frame {
	return core.Frame{
		Header:  core.Header{Type: typ, Flags: 0, Length: uint64(len(payload))},
		Payload: payload,
	}
}

// Fatalf 接口与 testing.T/TF 的 Fatalf 兼容（避免测试 helper 绑死 *testing.T）。
type Fatalf interface {
	Fatalf(format string, args ...any)
}

// ReadFrame 从 Sent 通道读一帧（10s 上限）；channel 已排空关闭时 Fatal。
func ReadFrame(t Fatalf, ch chan core.Frame) core.Frame {
	select {
	case f, ok := <-ch:
		if !ok {
			t.Fatalf("frame channel closed before a frame arrived")
			return core.Frame{}
		}
		return f
	case <-time.After(10 * time.Second):
		t.Fatalf("timeout waiting for frame")
		return core.Frame{}
	}
}

// NextFrame 非致命版：timeout 内读到返回帧与 true；超时返回 false（不 Fatal，
// 供「断言不出现」类测试使用）。
func NextFrame(ch chan core.Frame, timeout time.Duration) (core.Frame, bool) {
	select {
	case f, ok := <-ch:
		if !ok {
			return core.Frame{}, false
		}
		return f, true
	case <-time.After(timeout):
		return core.Frame{}, false
	}
}

// AwaitFrame 轮询 Sent 直到出现指定 type 的帧（跳过其他帧），超时 Fatal。
func AwaitFrame(t Fatalf, ch chan core.Frame, typ uint8, timeout time.Duration) core.Frame {
	deadline := time.After(timeout)
	for {
		select {
		case f, ok := <-ch:
			if !ok {
				t.Fatalf("frame channel closed while waiting for type 0x%02x", typ)
				return core.Frame{}
			}
			if f.Header.Type == typ {
				return f
			}
		case <-deadline:
			t.Fatalf("timeout waiting for frame type 0x%02x", typ)
			return core.Frame{}
		}
	}
}

// AwaitResult 等待 ref_seq 匹配的 RESULT 帧（跳过 CREDIT 等无关帧），超时 Fatal。
func AwaitResult(t Fatalf, ch chan core.Frame, refSeq uint64, timeout time.Duration) *core.Result {
	f := AwaitFrame(t, ch, core.TypeResult, timeout)
	var r core.Result
	if err := core.Decode(f.Payload, &r); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if r.GetRefSeq() != refSeq {
		t.Fatalf("result ref_seq = %d, want %d", r.GetRefSeq(), refSeq)
	}
	return &r
}

// AwaitCredit 等待下一帧 CREDIT，超时 Fatal。
func AwaitCredit(t Fatalf, ch chan core.Frame, timeout time.Duration) *core.Credit {
	f := AwaitFrame(t, ch, core.TypeCredit, timeout)
	var c core.Credit
	if err := core.Decode(f.Payload, &c); err != nil {
		t.Fatalf("decode credit: %v", err)
	}
	return &c
}
