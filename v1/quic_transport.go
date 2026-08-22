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
	maxFrame   uint64 // 帧上限（policy.MaxFrameBytes；0=默认 16MB）

	controlMu sync.Mutex // control stream 写串行化

	dataCh  chan core.Frame // 聚合 data stream 帧
	dataErr chan error      // data accept 循环错误
	done    chan struct{}   // 关闭信号：通知所有 readDataStream 退出，避免向 closed dataCh 发送 panic
	closeMu sync.Mutex
	closed  bool
	wg      sync.WaitGroup // 追踪活跃的 readDataStream goroutine，保证 dataCh 关闭前全部退出
}

// firstStreamTimeout 是等待客户端打开第一个（control）stream 的上限。
// 认证前连接未通过 challenge-response：QUIC 层握手完成后保持静默的对端（仅靠
// 连接层保活）可无限占用 connSem 并发槽位（DoS）。此超时把认证前的钉死窗口
// 收敛为有界。测试可缩短（包内 var）。
var firstStreamTimeout = 30 * time.Second

// newQuicTransport accept 第一个 stream 作为 control stream，启动 data accept 循环；失败时关闭底层 QUIC 连接。
//
// ctx 用于约束首个 stream 的等待（见 firstStreamTimeout）：此前用 context.Background()
// 完全无界，是未认证连接钉死槽位的根因。
func newQuicTransport(ctx context.Context, conn *Conn, maxFrame uint64) (*quicTransport, error) {
	firstStreamCtx, cancel := context.WithTimeout(ctx, firstStreamTimeout)
	defer cancel()
	s, role, err := conn.AcceptStream(firstStreamCtx)
	if err != nil {
		_ = conn.Close()
		return nil, core.WrapError(core.ErrCodeStream, "accept control stream", err)
	}
	if role != core.StreamRoleControl {
		_ = s.Close()
		_ = conn.Close()
		return nil, core.NewError(core.ErrCodeProtocol, "first stream must be control")
	}
	t := &quicTransport{
		conn:       conn,
		controlStr: s,
		maxFrame:   maxFrame,
		dataCh:     make(chan core.Frame, 64),
		dataErr:    make(chan error, 1),
		done:       make(chan struct{}),
	}
	go t.acceptDataStreams(ctx)
	if t.SupportsDatagram() {
		t.wg.Add(1)
		go func() { defer t.wg.Done(); t.receiveDatagrams() }()
	}
	return t, nil
}

// acceptDataStreams 聚合后续 data stream 的帧。ctx 为连接生命周期 context：
// 取消时 AcceptStream 返回错误，走统一的关闭清理路径（避免 goroutine 滞留到
// QUIC 空闲超时）。
func (t *quicTransport) acceptDataStreams(ctx context.Context) {
	for {
		s, _, err := t.conn.AcceptStream(ctx)
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

// receiveDatagrams 把 QUIC DATAGRAM（RFC 9221）注入 data 通道：载荷是完整的
// DGRAM 帧（TypeDgram + Envelope——type 高位域使协议层 RecvDataFrame 无差别消费，
// 与 TCP binding 的单连接 demux 对称）。不可靠语义天然允许在通道关闭竞态下丢弃。
func (t *quicTransport) receiveDatagrams() {
	for {
		data, err := t.conn.QC.ReceiveDatagram(context.Background())
		if err != nil {
			return // 连接关闭/扩展未启用：退出（无清理义务，dataCh 由 acceptDataStreams 管）
		}
		// DATAGRAM 载荷 = Envelope（帧类型由通道语义隐含为 TypeDgram）；
		// 构造完整帧使协议层 dataLoop 的 type switch 命中 TypeDgram 分支。
		f := core.Frame{Header: core.Header{Type: core.TypeDgram, Length: uint64(len(data))}, Payload: data}
		select {
		case t.dataCh <- f:
		case <-t.done:
			return
		}
	}
}

func (t *quicTransport) readDataStream(s *quic.Stream) {
	defer func() {
		s.Close()
		t.wg.Done()
	}()
	for {
		f, err := core.Read(s, t.limits())
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

// limits 返回帧上限（0=默认）。
func (t *quicTransport) limits() core.FrameLimits {
	if t.maxFrame == 0 {
		return core.DefaultLimits()
	}
	return core.FrameLimits{MaxFrameBytes: t.maxFrame}
}

// RecvControlFrame 读 control stream 下一帧，受调用方 ctx 约束。
// 委托 core.ReadFrameCtx：deadline 转换 + ctx.Done watcher（取消能立即唤醒阻塞读，
// 此前入口一次性转换导致取消后最长滞留 DefaultReadTimeout=5 分钟，服务端停机时
// handler goroutine 连同 connSem 槽位滞留）。
func (t *quicTransport) RecvControlFrame(ctx context.Context) (core.Frame, error) {
	if err := ctx.Err(); err != nil {
		return core.Frame{}, err
	}
	return core.ReadFrameCtxLimit(ctx, t.controlStr, t.limits())
}

// control stream 读超时统一用 core.DefaultReadTimeout。

// RecvDataFrame 从聚合 data channel 读下一帧。
// dataCh 关闭时非阻塞读 dataErr 拿真实错误（cap=1 非阻塞发送可能丢错误，空则返回 io.EOF）。
func (t *quicTransport) RecvDataFrame(ctx context.Context) (core.Frame, error) {
	select {
	case f, ok := <-t.dataCh:
		if !ok {
			// dataCh 关闭：非阻塞读 dataErr，空则 io.EOF。
			select {
			case e := <-t.dataErr:
				if e != nil {
					return core.Frame{}, e
				}
			case <-ctx.Done():
				return core.Frame{}, ctx.Err()
			default:
			}
			return core.Frame{}, io.EOF
		}
		return f, nil
	case <-ctx.Done():
		return core.Frame{}, ctx.Err()
	}
}

// SendFrame 写帧（server 端应答帧均为 control 域，走 control stream）。
// 通过 SetWriteDeadline 实现 ctx 感知写（QUIC 流控背压下 Write 阻塞需可被 ctx 取消）。
// 写失败（含部分写/短写）时拆除连接：流上残留半帧会让后续帧全部错位（流去同步），
// 故障表现远离根因；CloseWithError 迫使读侧出错、Handle 返回、槽位释放。
func (t *quicTransport) SendFrame(ctx context.Context, f core.Frame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(core.DefaultWriteTimeout)
	}
	t.controlMu.Lock()
	defer t.controlMu.Unlock()
	if err := t.controlStr.SetWriteDeadline(dl); err != nil {
		return core.WrapError(core.ErrCodeStream, "set control write deadline", err)
	}
	defer func() { _ = t.controlStr.SetWriteDeadline(time.Time{}) }()
	if err := core.Write(t.controlStr, f.Header.Type, 0, f.Payload); err != nil {
		_ = t.conn.Close()
		return err
	}
	return nil
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
	// error code 0 = "no error" 会误导对端；用 1（internal error）+ 明确 reason。
	return t.conn.Close()
}
