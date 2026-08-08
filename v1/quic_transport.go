package v1

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/protocol"
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
	done    chan struct{}   // 关闭信号：通知所有 readDataStream 退出，避免向 closed dataCh 发送 panic
	closeMu sync.Mutex
	closed  bool
	wg      sync.WaitGroup // 追踪活跃的 readDataStream goroutine，保证 dataCh 关闭前全部退出
}

// newQuicTransport accept 第一个 stream 作为 control stream，启动 data accept 循环；失败时关闭底层 QUIC 连接。
func newQuicTransport(conn *Conn) (*quicTransport, error) {
	s, role, err := conn.AcceptStream(context.Background())
	if err != nil {
		_ = conn.CloseWithError(0, "accept control stream failed")
		return nil, core.WrapError(core.ErrCodeStream, "accept control stream", err)
	}
	if role != core.StreamRoleControl {
		_ = s.Close()
		_ = conn.CloseWithError(0, "first stream not control")
		return nil, core.NewError(core.ErrCodeProtocol, "first stream must be control")
	}
	t := &quicTransport{
		conn:       conn,
		controlStr: s,
		dataCh:     make(chan core.Frame, 64),
		dataErr:    make(chan error, 1),
		done:       make(chan struct{}),
	}
	go t.acceptDataStreams()
	return t, nil
}

func (t *quicTransport) acceptDataStreams() {
	for {
		s, _, err := t.conn.AcceptStream(context.Background())
		if err != nil {
			// 先发关闭信号，让所有 readDataStream 退出（避免向即将 close 的 dataCh 发送 panic）。
			t.closeMu.Lock()
			if !t.closed {
				t.closed = true
				close(t.done)
			}
			t.closeMu.Unlock()
			// 等待所有 readDataStream goroutine 彻底退出后，再安全关闭 dataCh。
			t.wg.Wait()
			select {
			case t.dataErr <- err:
			default:
			}
			close(t.dataCh)
			return
		}
		t.wg.Add(1)
		go t.readDataStream(s)
	}
}

func (t *quicTransport) readDataStream(s *quic.Stream) {
	defer func() {
		s.Close()
		t.wg.Done()
	}()
	for {
		f, err := core.Read(s, core.DefaultLimits())
		if err != nil {
			return
		}
		select {
		case t.dataCh <- f: // 背压：ch 满则阻塞，天然限流
		case <-t.done: // Close/accept 失败时退出，避免向 closed channel 发送 panic
			return
		}
	}
}

// RecvControlFrame 读 control stream 下一帧，受调用方 ctx 约束。
// 通过 SetReadDeadline 让 ctx.Deadline()/取消中断阻塞读（模式对称于 writeFrameCtx 写路径）。
func (t *quicTransport) RecvControlFrame(ctx context.Context) (core.Frame, error) {
	if err := ctx.Err(); err != nil {
		return core.Frame{}, err
	}
	// ctx 无 deadline 时设默认上限，避免对端静默断开时读永久阻塞（goroutine 泄漏）。
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(controlReadDefaultTimeout)
	}
	if err := t.controlStr.SetReadDeadline(dl); err != nil {
		return core.Frame{}, core.WrapError(core.ErrCodeStream, "set control read deadline", err)
	}
	defer func() { _ = t.controlStr.SetReadDeadline(time.Time{}) }()
	// 二次检查 ctx 取消：缩小 ctx.Err() 与 SetReadDeadline 之间的 TOCTOU 窗口。
	if err := ctx.Err(); err != nil {
		return core.Frame{}, err
	}
	f, err := core.Read(t.controlStr, core.DefaultLimits())
	if err != nil {
		// ctx 取消与 SetReadDeadline 超时都会让 Read 返回错误；区分 ctx 取消以便上层处理。
		if ctx.Err() != nil {
			return core.Frame{}, ctx.Err()
		}
		return core.Frame{}, err
	}
	return f, nil
}

// controlReadDefaultTimeout 是 control stream 读在 ctx 无 deadline 时的默认上限，
// 防止对端静默断开（中间防火墙丢包）导致 goroutine 永久阻塞。
const controlReadDefaultTimeout = 5 * time.Minute

// RecvDataFrame 从聚合 data channel 读下一帧。
// dataCh 关闭时阻塞读 dataErr 拿真实错误（cap=1 非阻塞发送可能丢错误，空则返回 io.EOF）。
func (t *quicTransport) RecvDataFrame(ctx context.Context) (core.Frame, error) {
	select {
	case f, ok := <-t.dataCh:
		if !ok {
			// dataCh 关闭：读 dataErr 拿真实错误，空则返回 io.EOF。
			select {
			case e := <-t.dataErr:
				if e != nil {
					return core.Frame{}, e
				}
			case <-ctx.Done():
				return core.Frame{}, ctx.Err()
			default:
				return core.Frame{}, io.EOF
			}
			return core.Frame{}, io.EOF
		}
		return f, nil
	case <-ctx.Done():
		return core.Frame{}, ctx.Err()
	}
}

// SendFrame 写帧（server 端走 control stream，ChannelID=0）。
// 通过 SetWriteDeadline 实现 ctx 感知写（QUIC 流控背压下 Write 阻塞需可被 ctx 取消）。
func (t *quicTransport) SendFrame(ctx context.Context, f core.Frame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(30 * time.Second)
	}
	t.controlMu.Lock()
	defer t.controlMu.Unlock()
	if err := t.controlStr.SetWriteDeadline(dl); err != nil {
		return core.WrapError(core.ErrCodeStream, "set control write deadline", err)
	}
	defer func() { _ = t.controlStr.SetWriteDeadline(time.Time{}) }()
	return core.Write(t.controlStr, f.Header.Version, f.Header.Type, f.Header.Flags, f.Header.ChannelID, f.Payload)
}

// SupportsDatagram 报告是否支持 QUIC DATAGRAM（检查连接实际是否启用 datagram 扩展，不硬编码 true）。
func (t *quicTransport) SupportsDatagram() bool {
	// 防御：连接尚未完全建立时返回 false（QC 可能在握手完成前为 nil）。
	if t.conn == nil || t.conn.QC == nil {
		return false
	}
	// SupportsDatagrams 是 {Local, Remote} 结构体：本端 + 对端都必须启用。
	ds := t.conn.QC.ConnectionState().SupportsDatagrams
	return ds.Local && ds.Remote
}

// SendDatagram 走 QUIC DATAGRAM 不可靠通道。
func (t *quicTransport) SendDatagram(ctx context.Context, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// nil guard：连接尚未完全建立时 QC 为 nil（与 SupportsDatagram 防御一致）。
	if t.conn == nil || t.conn.QC == nil {
		return core.NewError(core.ErrCodeStream, "QUIC connection not established")
	}
	if err := t.conn.QC.SendDatagram(payload); err != nil {
		return core.WrapError(core.ErrCodeStream, "send datagram", err)
	}
	return nil
}

// Multiplexing 报告多路复用模型。
func (t *quicTransport) Multiplexing() protocol.MultiplexModel {
	return protocol.MultiplexQuicMultiStream
}

// RemoteAddr 返回 QUIC 对端地址。连接尚未建立或已关闭时返回 nil。
func (t *quicTransport) RemoteAddr() net.Addr {
	if t.conn == nil {
		return nil
	}
	return t.conn.RemoteAddr
}

// Close 关闭传输。
func (t *quicTransport) Close() error {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	close(t.done) // 通知所有 readDataStream goroutine 退出，避免 goroutine 泄漏
	return t.conn.CloseWithError(0, "done")
}
