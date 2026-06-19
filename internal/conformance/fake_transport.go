// Package conformance 提供 MBTA 协议核心的传输无关一致性测试。
//
// 用 FakeTransport 注入 protocol.CoreHandler，验证握手/envelope/投递/capability 语义
// 不依赖真实 QUIC/TCP binding。v1/ntls 各自只保留 binding 特有测试。
package conformance

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// FakeTransport 是 protocol.Transport 的内存实现，用于测试 CoreHandler。
//
//   - ControlIn / DataIn：测试向其写入帧，模拟 client→server（CoreHandler 经 RecvControlFrame/RecvDataFrame 读取）；
//   - Sent：CoreHandler 经 SendFrame 写出的帧（HELLO_ACK/AUTH_OK/ACK/NACK/WINDOW 等），测试读取验证。
type FakeTransport struct {
	ControlIn chan core.Frame
	DataIn    chan core.Frame
	Sent      chan core.Frame

	datagram bool
	mu       sync.Mutex
	closed   bool
}

// NewFakeTransport 创建 FakeTransport。datagram 控制是否模拟不可靠通道（QUIC）。
func NewFakeTransport(datagram bool) *FakeTransport {
	return &FakeTransport{
		ControlIn: make(chan core.Frame, 16),
		DataIn:    make(chan core.Frame, 64),
		Sent:      make(chan core.Frame, 64),
		datagram:  datagram,
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

func (t *FakeTransport) SendFrame(ctx context.Context, f core.Frame) error {
	select {
	case t.Sent <- f:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *FakeTransport) SupportsDatagram() bool { return t.datagram }

func (t *FakeTransport) SendDatagram(ctx context.Context, payload []byte) error {
	_ = ctx
	_ = payload
	return protocol.ErrDatagramUnsupported
}

func (t *FakeTransport) Multiplexing() protocol.MultiplexModel {
	return protocol.MultiplexTCPSingleConn
}

func (t *FakeTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}

// ===== 测试 helpers =====

// MakeFrame 构造一个帧（测试写入 ControlIn/DataIn）。
func MakeFrame(typ uint8, flags byte, channel uint8, payload []byte) core.Frame {
	return core.Frame{
		Header: core.Header{
			Version:   core.Version,
			Flags:     flags,
			Type:      typ,
			ChannelID: channel,
			Length:    uint32(len(payload)),
		},
		Payload: payload,
	}
}

// ReadFrame 从 Sent 通道读一帧（带超时），失败 t.Fatal。
func ReadFrame(t interface{ Fatalf(string, ...any) }, ch chan core.Frame) core.Frame {
	select {
	case f := <-ch:
		return f
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for frame")
		return core.Frame{}
	}
}
