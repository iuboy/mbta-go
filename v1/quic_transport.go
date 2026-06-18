package v1

import (
	"context"
	"io"
	"sync"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/protocol"
	"github.com/quic-go/quic-go"
)

// quicTransport 把 v1.Conn（QUIC）适配为 protocol.Transport（server 端）。
//
// 模型（core spec §10 / MultiplexQuicMultiStream）：
//   - 第一个 AcceptStream = control stream（构造时 accept）；
//   - 后续 AcceptStream = data streams，后台 goroutine 聚合其帧到 RecvDataFrame；
//   - server 发送均走 control stream（ACK/NACK/WINDOW/THROTTLE/PONG/AUTH_OK 等）；
//   - DATAGRAM 通道走 QUIC DATAGRAM（需 quic.Config.EnableDatagrams=true）。
type quicTransport struct {
	conn       *Conn
	controlStr *quic.Stream
	controlMu  sync.Mutex // control stream 写串行化

	dataCh  chan core.Frame // 聚合 data stream 帧
	dataErr chan error      // data accept 循环错误
	closeMu sync.Mutex
	closed  bool
}

// newQuicTransport accept 第一个 stream 作为 control stream，启动 data accept 循环。
func newQuicTransport(conn *Conn) (*quicTransport, error) {
	s, role, err := conn.AcceptStream(context.Background())
	if err != nil {
		return nil, core.WrapError(core.NumStream, core.CodeStream, "accept control stream", err)
	}
	if role != core.StreamRoleControl {
		_ = s.Close()
		return nil, core.NewError(core.NumProtocol, core.CodeProtocol, "first stream must be control")
	}
	t := &quicTransport{
		conn:       conn,
		controlStr: s,
		dataCh:     make(chan core.Frame, 64),
		dataErr:    make(chan error, 1),
	}
	go t.acceptDataStreams()
	return t, nil
}

func (t *quicTransport) acceptDataStreams() {
	for {
		s, _, err := t.conn.AcceptStream(context.Background())
		if err != nil {
			t.dataErr <- err
			close(t.dataCh)
			return
		}
		go t.readDataStream(s)
	}
}

func (t *quicTransport) readDataStream(s *quic.Stream) {
	defer s.Close()
	for {
		f, err := core.Read(s, core.DefaultLimits())
		if err != nil {
			return
		}
		t.dataCh <- f // 背压：ch 满则阻塞，天然限流
	}
}

// RecvControlFrame 读 control stream 下一帧。
func (t *quicTransport) RecvControlFrame(ctx context.Context) (core.Frame, error) {
	// control stream 读是单 goroutine（CoreHandler control loop），无需 ctx 感知读（关闭时 stream EOF）。
	_ = ctx
	return core.Read(t.controlStr, core.DefaultLimits())
}

// RecvDataFrame 从聚合 data channel 读下一帧。
func (t *quicTransport) RecvDataFrame(ctx context.Context) (core.Frame, error) {
	select {
	case f, ok := <-t.dataCh:
		if !ok {
			err := io.EOF
			select {
			case e := <-t.dataErr:
				if e != nil {
					err = e
				}
			default:
			}
			return core.Frame{}, err
		}
		return f, nil
	case <-ctx.Done():
		return core.Frame{}, ctx.Err()
	}
}

// SendFrame 写帧（server 端均走 control stream，按 ChannelID=0）。
func (t *quicTransport) SendFrame(ctx context.Context, f core.Frame) error {
	_ = ctx
	t.controlMu.Lock()
	defer t.controlMu.Unlock()
	return core.Write(t.controlStr, f.Header.Version, f.Header.Type, f.Header.Flags, f.Header.ChannelID, f.Payload)
}

// SupportsDatagram 报告是否支持 QUIC DATAGRAM（需 EnableDatagrams）。
func (t *quicTransport) SupportsDatagram() bool { return true }

// SendDatagram 走 QUIC DATAGRAM 不可靠通道。
func (t *quicTransport) SendDatagram(ctx context.Context, payload []byte) error {
	_ = ctx
	if err := t.conn.QC.SendDatagram(payload); err != nil {
		return core.WrapError(core.NumStream, core.CodeStream, "send datagram", err)
	}
	return nil
}

// Multiplexing 报告多路复用模型。
func (t *quicTransport) Multiplexing() protocol.MultiplexModel {
	return protocol.MultiplexQuicMultiStream
}

// Close 关闭传输。
func (t *quicTransport) Close() error {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	return t.conn.CloseWithError(0, "done")
}
