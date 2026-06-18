package ntls

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/protocol"
)

// tcpTransport 把单条 TCP（TLCP）连接适配为 protocol.Transport（server 端）。
//
// 模型（core spec §10 / MultiplexTCPSingleConn）：单连接上 control 帧（HELLO/AUTH/PING/CLOSE）
// 与 data 帧（BATCH/DATAGRAM）按 ChannelID 分流到两个逻辑通道，供 CoreHandler 的
// control loop 与 data loop 分别消费。写侧 writeMu 串行化（同连接帧不交错）。
//
// TCP 不支持不可靠通道：SupportsDatagram()=false，lossy signal 由 CoreHandler 回退 BATCH。
type tcpTransport struct {
	conn    net.Conn
	writeMu sync.Mutex // 同连接写串行化

	controlCh chan core.Frame // control 帧（ChannelControl）
	dataCh    chan core.Frame // data 帧（BATCH/DATAGRAM）

	closeMu sync.Mutex
	closed  bool
}

// newTCPTransport 包装一条已握手的 TLCP 连接，启动读循环分发帧。
func newTCPTransport(conn net.Conn) *tcpTransport {
	t := &tcpTransport{
		conn:      conn,
		controlCh: make(chan core.Frame, 16),
		dataCh:    make(chan core.Frame, 64),
	}
	go t.readLoop()
	return t
}

// readLoop 单连接读帧 → 按 ChannelID 分发。
func (t *tcpTransport) readLoop() {
	for {
		f, err := core.Read(t.conn, core.DefaultLimits())
		if err != nil {
			close(t.controlCh)
			close(t.dataCh)
			return
		}
		if f.Header.ChannelID == core.ChannelControl {
			t.controlCh <- f
		} else {
			t.dataCh <- f
		}
	}
}

// RecvControlFrame 从 control 逻辑通道读。
func (t *tcpTransport) RecvControlFrame(ctx context.Context) (core.Frame, error) {
	select {
	case f, ok := <-t.controlCh:
		if !ok {
			return core.Frame{}, io.EOF
		}
		return f, nil
	case <-ctx.Done():
		return core.Frame{}, ctx.Err()
	}
}

// RecvDataFrame 从 data 逻辑通道读。
func (t *tcpTransport) RecvDataFrame(ctx context.Context) (core.Frame, error) {
	select {
	case f, ok := <-t.dataCh:
		if !ok {
			return core.Frame{}, io.EOF
		}
		return f, nil
	case <-ctx.Done():
		return core.Frame{}, ctx.Err()
	}
}

// SendFrame 写帧（按 ChannelID 写单连接，writeMu 串行化）。
func (t *tcpTransport) SendFrame(ctx context.Context, f core.Frame) error {
	_ = ctx
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return core.Write(t.conn, f.Header.Version, f.Header.Type, f.Header.Flags, f.Header.ChannelID, f.Payload)
}

// SupportsDatagram：TCP 无不可靠通道。
func (t *tcpTransport) SupportsDatagram() bool { return false }

// SendDatagram：TCP 不支持，返回 ErrDatagramUnsupported（CoreHandler 据此回退 BATCH）。
func (t *tcpTransport) SendDatagram(ctx context.Context, payload []byte) error {
	_ = ctx
	_ = payload
	return protocol.ErrDatagramUnsupported
}

// Multiplexing：TCP 单连接帧多路复用。
func (t *tcpTransport) Multiplexing() protocol.MultiplexModel {
	return protocol.MultiplexTCPSingleConn
}

// Close 关闭连接。
func (t *tcpTransport) Close() error {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	return t.conn.Close()
}
