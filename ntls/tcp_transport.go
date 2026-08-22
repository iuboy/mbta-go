package ntls

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// tcpTransport 把单条 TCP（TLCP）连接适配为 protocol.Transport（server 端）。
//
// 模型（r3 / MultiplexTCPSingleConn）：单连接上 control 帧（HELLO/PING/CLOSE 等）
// 与 data 帧（BATCH/DGRAM）按 type 高位通道域分流到两个逻辑通道，供 CoreHandler 的
// control loop 与 data loop 分别消费。写侧 writeSem 串行化（同连接帧不交错）。
//
// TCP 不支持不可靠通道：SupportsDatagram()=false，DGRAM 帧走可靠 BATCH 路径。
type tcpTransport struct {
	conn     net.Conn
	maxFrame uint64        // 帧上限（policy.MaxFrameBytes；0=默认 16MB）
	writeSem chan struct{} // 容量 1 的信号量，替代 sync.Mutex 支持 ctx 取消
	authed   atomic.Bool   // HELLO_ACK 后置位（protocol.AuthMarker）：读 deadline 从 pre-auth 短超时切到空闲超时

	controlCh chan core.Frame // control 帧（type 高位=0）
	dataCh    chan core.Frame // data 帧（BATCH/DATAGRAM）
	done      chan struct{}   // Close 时关闭，唤醒阻塞在 channel 发送的 readLoop

	closeMu sync.Mutex
	closed  bool
}

// tcpPreAuthReadTimeout 是认证前每帧读取的 deadline。TCP 层没有空闲超时、OS
// keepalive 只能杀死死链路（活着的静默对端会 ACK 探测包）——认证前（未通过
// challenge-response）的静默对端可无限占用 connSem 并发槽位（DoS）。此超时把
// 钉死窗口收敛为有界；认证后切换到 core.DefaultReadTimeout（心跳 30s 维持）。
// 测试可缩短（包内 var）。
var tcpPreAuthReadTimeout = 30 * time.Second

// newTCPTransport 包装一条已握手的 TLCP 连接，启动读循环分发帧。
func newTCPTransport(conn net.Conn, maxFrame uint64) *tcpTransport {
	// writeSem 初始持有 1 个 token（空闲），后续 SendFrame 通过 select 获取。
	sem := make(chan struct{}, 1)
	sem <- struct{}{}
	t := &tcpTransport{
		conn:      conn,
		maxFrame:  maxFrame,
		writeSem:  sem,
		controlCh: make(chan core.Frame, 16),
		dataCh:    make(chan core.Frame, 64),
		done:      make(chan struct{}),
	}
	go t.readLoop()
	return t
}

// limits 返回帧上限（0=默认）。
func (t *tcpTransport) limits() core.FrameLimits {
	if t.maxFrame == 0 {
		return core.DefaultLimits()
	}
	return core.FrameLimits{MaxFrameBytes: t.maxFrame}
}

// readLoop 单连接读帧 → 按 type 高位通道域分发（control/data）。
// 发送经 select+done：消费者退出时 Close 关闭 done（同时关 conn 让 core.Read 返回 err）唤醒发送，避免 goroutine 泄漏（tcp-binding §3.3）。
func (t *tcpTransport) readLoop() {
	// defer close 让消费者收到 io.EOF 而非永久挂起。
	defer func() {
		close(t.controlCh)
		close(t.dataCh)
	}()
	for {
		// 每帧读取前设 deadline：认证前用短超时（防未认证连接钉死 connSem 槽位），
		// 认证后用空闲超时（与 QUIC control 读对齐，心跳 30s 维持活性）。
		timeout := core.DefaultReadTimeout
		if !t.authed.Load() {
			timeout = tcpPreAuthReadTimeout
		}
		if err := t.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return
		}
		f, err := core.Read(t.conn, t.limits())
		if err != nil {
			return
		}
		ch := t.dataCh
		if core.IsControlType(f.Header.Type) {
			ch = t.controlCh
		}
		select {
		case ch <- f:
		case <-t.done:
			return
		}
	}
}

// MarkAuthed 实现 protocol.AuthMarker：HELLO_ACK 后由协议层调用，切换读超时档位。
func (t *tcpTransport) MarkAuthed() { t.authed.Store(true) }

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

// SendFrame 写帧到单连接（writeSem 串行化，帧 type 的通道域不影响写路径——
// TCP 单连接上 control/data 帧交替写入同一流）。
// writeSem 为容量 1 信号量，select 监听 ctx.Done() 使写锁等待可取消（sync.Mutex 阻塞不可取消，慢速对端致泄漏）。
// 写操作设 SetWriteDeadline：ctx 有 Deadline 用之，否则用 core.DefaultWriteTimeout（30s），
// 防止半开对端让写永久阻塞（sink worker 的 durable RESULT 尤其受影响）。
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
	// 设写 deadline：与 ntlsClientTransport.WriteFrame 对称。
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(core.DefaultWriteTimeout)
	}
	if err := t.conn.SetWriteDeadline(dl); err != nil {
		return core.WrapError(core.ErrCodeStream, "set write deadline", err)
	}
	defer func() { _ = t.conn.SetWriteDeadline(time.Time{}) }()
	if err := core.Write(t.conn, f.Header.Type, 0, f.Payload); err != nil {
		// 写失败（含部分写/短写）时拆除连接：流上残留半帧会让后续帧全部错位
		// （流去同步），故障表现远离根因；关 conn 迫使 readLoop 出错、Handle 返回。
		_ = t.conn.Close()
		return err
	}
	return nil
}

// SupportsDatagram：TCP 无不可靠通道。
func (t *tcpTransport) SupportsDatagram() bool { return false }

// SendDatagram：接口占位——服务端不发送 DGRAM（DGRAM 只进不出），无生产调用方。
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
