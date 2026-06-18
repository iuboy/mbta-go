package ntls

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/protocol"
)

// Client 是 MBTA-NTLS 客户端：单 TCP（TLCP）连接上多路复用 control/data 帧。
//
// Phase 2 重构后，Client 是一个薄包装：协议逻辑（状态机/握手/ACK/drain/heartbeat）
// 全部委托给 protocol.CoreClient，自身仅保留传输适配（ntlsClientTransport）。
//
// 可靠投递语义：仅在内存追踪已发送未 ACK 的 batch。进程崩溃/重连后未 ACK 的
// batch 会丢失——持久化与重发由调用方负责。
type Client struct {
	core *protocol.CoreClient // 共享协议核心
	cfg  ClientConfig         // ntls 专属配置（Server/Credentials，供 Dial 用）
	conn net.Conn             // 单 TCP（TLCP）连接
	mu   sync.Mutex           // 保护 conn 字段的读写（Connect 设置 / Close 读取）
}

// ntlsClientTransport 实现 protocol.ClientTransport，封装单 TCP 连接的读写。
//
// writeMu 串行化所有写（HELLO/AUTH/BATCH/PING/PONG/CLOSE），替代 v1 的
// controlMu + picker。ctx 仅对 data 通道设 SetWriteDeadline（control 用 Background）。
type ntlsClientTransport struct {
	conn    net.Conn
	writeMu sync.Mutex
}

func (t *ntlsClientTransport) ReadFrame() (core.Frame, error) {
	return core.Read(t.conn, core.DefaultLimits())
}

// WriteFrame 写一帧。data 通道（ChannelData）受 ctx 约束（设 SetWriteDeadline），
// control 通道（ChannelControl）调用方传 context.Background() 不受超时约束。
func (t *ntlsClientTransport) WriteFrame(ctx context.Context, typ uint8, flags, channel uint8, payload []byte) error {
	if channel == core.ChannelData {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	// data 帧且 ctx 带 Deadline：设 SetWriteDeadline 实现写超时。
	// writeMu 保证同一时刻只有一个写者，deadline 不会被并发覆盖。
	if channel == core.ChannelData {
		if dl, ok := ctx.Deadline(); ok {
			_ = t.conn.SetWriteDeadline(dl)
			defer func() { _ = t.conn.SetWriteDeadline(time.Time{}) }()
		}
	}
	return core.Write(t.conn, core.Version, typ, flags, channel, payload)
}

func (t *ntlsClientTransport) CloseConn() error {
	return t.conn.Close()
}

// NewClient 创建一个 MBTA-NTLS 客户端。
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Server == "" {
		return nil, core.NewError(core.NumCredential, core.CodeCredential, "server address required")
	}
	cc := protocol.NewCoreClient(nil, protocol.CoreClientConfig{
		AgentID:      cfg.AgentID,
		Hostname:     cfg.Hostname,
		Token:        cfg.Token,
		Capabilities: cfg.Capabilities,
	})
	// ntls 单连接无 SetAuthed 门禁，onAuthed 留空。
	cc.SetReadControlLoop(cc.ReadControlLoop)
	cc.SetHeartbeatLoop(cc.HeartbeatLoop)
	return &Client{core: cc, cfg: cfg}, nil
}

// Connect 拨号并完成 HELLO/AUTH 握手。
//
// ctx 仅控制握手阶段（Dial、HELLO/AUTH）的超时与取消。握手成功后，后台 goroutine
// 运行在独立的 lifecycle ctx 上，不随 ctx 取消而退出；client 生命周期由 Close() 终结。
func (c *Client) Connect(ctx context.Context) error {
	if err := c.core.SmTransitionConnecting(); err != nil {
		return err
	}

	conn, err := Dial(ctx, &c.cfg)
	if err != nil {
		return core.WrapError(core.NumTransport, core.CodeTransport, "dial", err)
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	tr := &ntlsClientTransport{conn: conn}
	c.core.SetTransport(tr)

	// ntls 单 TCP 连接：无独立 control stream，但状态机仍要求
	// Connecting -> ControlStreamOpen -> HelloSent 路径。
	if err := c.core.SmTransition(core.StateControlStreamOpen); err != nil {
		return err
	}

	if err := c.core.SendHello(); err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "hello", err)
	}
	helloAck, err := c.core.RecvHelloAck()
	if err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "hello_ack", err)
	}

	c.core.SetSessionID(helloAck.GetSessionId())
	if err := c.core.SmTransition(core.StateHelloAcked); err != nil {
		return err
	}

	if w := helloAck.GetInitialWindow(); w != nil {
		c.core.UpdateWindow(int(w.GetMaxInflightBatches()), int(w.GetMaxInflightEvents()), w.GetMaxInflightBytes())
	}
	if helloAck.GetHeartbeatIntervalSec() > 0 {
		c.core.SetHeartbeatInterval(time.Duration(helloAck.GetHeartbeatIntervalSec()) * time.Second)
	} else {
		c.core.SetHeartbeatInterval(30 * time.Second)
	}

	if err := c.core.SendAuth(); err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "auth", err)
	}
	if err := c.core.RecvAuthResult(); err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "auth_result", err)
	}

	c.core.StartLifecycle()
	return nil
}

// SendBatch 通过 MBTA-NTLS 协议发送一个 SignalBatch。
// 委托给 CoreClient.SendBatch。
func (c *Client) SendBatch(ctx context.Context, signalBatch *core.SignalBatch, tag, source string) (string, error) {
	return c.core.SendBatch(ctx, signalBatch, tag, source)
}

// SetACKHandler 注册服务端 ACK 回调。
func (c *Client) SetACKHandler(h func(chunkID, ackMode string)) {
	c.core.SetACKHandler(h)
}

// Close 优雅关闭：发 CLOSE 帧、drain pending ACK、关闭连接。
func (c *Client) Close() error {
	return c.core.Close()
}

// State 返回当前连接状态。
func (c *Client) State() core.State {
	return c.core.State()
}

// SessionID 返回会话 ID。
func (c *Client) SessionID() string {
	return c.core.SessionID()
}
