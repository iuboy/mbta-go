package ntls

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// tcpTransport 把单条 TCP（TLCP）连接适配为 protocol.Transport（server 端）。
//
// 模型（core spec §10 / MultiplexTCPSingleConn）：单连接上 control 帧（HELLO/AUTH/PING/CLOSE）
// 与 data 帧（BATCH/DATAGRAM）按 ChannelID 分流到两个逻辑通道，供 CoreHandler 的
// control loop 与 data loop 分别消费。写侧 writeSem 串行化（同连接帧不交错）。
//
// TCP 不支持不可靠通道：SupportsDatagram()=false，lossy signal 由 CoreHandler 回退 BATCH。
type tcpTransport struct {
	conn     net.Conn
	writeSem chan struct{} // 容量 1 的信号量，替代 sync.Mutex 支持 ctx 取消

	controlCh chan core.Frame // control 帧（ChannelControl）
	dataCh    chan core.Frame // data 帧（BATCH/DATAGRAM）
	done      chan struct{}   // Close 时关闭，唤醒阻塞在 channel 发送的 readLoop

	closeMu sync.Mutex
	closed  bool
}

// newTCPTransport 包装一条已握手的 TLCP 连接，启动读循环分发帧。
func newTCPTransport(conn net.Conn) *tcpTransport {
	// writeSem 初始持有 1 个 token（空闲），后续 SendFrame 通过 select 获取。
	sem := make(chan struct{}, 1)
	sem <- struct{}{}
	t := &tcpTransport{
		conn:      conn,
		writeSem:  sem,
		controlCh: make(chan core.Frame, 16),
		dataCh:    make(chan core.Frame, 64),
		done:      make(chan struct{}),
	}
	go t.readLoop()
	return t
}

// readLoop 单连接读帧 → 按 ChannelID 分发。
// 发送经 select+done：消费者退出时 Close 关闭 done（同时关 conn 让 core.Read 返回 err）唤醒发送，避免 goroutine 泄漏（tcp-binding §3.3）。
func (t *tcpTransport) readLoop() {
	// defer close 让消费者收到 io.EOF 而非永久挂起。
	defer func() {
		close(t.controlCh)
		close(t.dataCh)
	}()
	for {
		f, err := core.Read(t.conn, core.DefaultLimits())
		if err != nil {
			return
		}
		ch := t.dataCh
		if f.Header.ChannelID == core.ChannelControl {
			ch = t.controlCh
		}
		select {
		case ch <- f:
		case <-t.done:
			return
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

// SendFrame 写帧（按 ChannelID 写单连接，writeSem 串行化）。
// writeSem 为容量 1 信号量，select 监听 ctx.Done() 使写锁等待可取消（sync.Mutex 阻塞不可取消，慢速对端致泄漏）。
func (t *tcpTransport) SendFrame(ctx context.Context, f core.Frame) error {
	// 获取写信号量（或响应 ctx 取消）。
	select {
	case <-t.writeSem:
		// 获取到 token，继续写操作
	case <-ctx.Done():
		return ctx.Err()
	}
	// 归还 token（等价于解锁）。
	defer func() { t.writeSem <- struct{}{} }()
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

// RemoteAddr 返回 TCP 对端地址。连接已关闭时返回 nil。
func (t *tcpTransport) RemoteAddr() net.Addr {
	if t.conn == nil {
		return nil
	}
	return t.conn.RemoteAddr()
}

// Close 关闭连接，等待 in-flight 写操作完成后再关闭底层 TCP 连接，
// 避免活跃的 core.Write 被 conn.Close() 中断产生 io.ErrClosedPipe。
func (t *tcpTransport) Close() error {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	close(t.done) // 唤醒可能阻塞在 channel 发送的 readLoop

	// drain writeSem（5s 超时防写端卡死），不归还 token 以阻止 write-after-close。
	select {
	case <-t.writeSem:
		// token 已 drain，保持持有——不归还，阻止新写操作。
	case <-time.After(5 * time.Second):
		// 超时兜底：写端可能卡在慢速对端，不无限等待。
	}
	return t.conn.Close()
}
