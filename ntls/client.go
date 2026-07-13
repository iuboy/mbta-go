package ntls

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/binding"
	"github.com/iuboy/mbta-go/internal/protocol"
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
		return nil, core.NewError(core.NumConfig, core.CodeConfig, "server address required")
	}
	cc := protocol.NewCoreClient(nil, protocol.CoreClientConfig{
		AgentID:      cfg.AgentID,
		Hostname:     cfg.Hostname,
		Token:        cfg.Token,
		Capabilities: cfg.Capabilities,
		// binding 默认算法（spec §8.3：跟随传输 binding 合规语境）。
		// ntls 走 TCP + TLCP/RFC8998 → 国密密码套件；codec/compression 用协议 baseline 默认。
		DefaultCodec:       corepb.Codec_CODEC_PROTO,
		DefaultCipherSuite: corepb.CipherSuite_CIPHER_SUITE_GM,
		DefaultCompression: corepb.Compression_COMPRESSION_ZSTD,
		Metrics:            cfg.Metrics,
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
	// 防重复 Connect：已连接/连接中时拒绝，避免旧连接泄漏（fd 泄漏 + transport 覆盖）。
	c.mu.Lock()
	if c.conn != nil {
		c.mu.Unlock()
		return core.NewError(core.NumSession, core.CodeSession, "already connected")
	}
	c.mu.Unlock()

	tr := &ntlsClientTransport{}
	err := binding.Handshake(ctx, c.core,
		// dial: 建立 TCP（TLCP/TLS1.3）连接
		func(ctx context.Context) error {
			conn, err := Dial(ctx, &c.cfg)
			if err != nil {
				return core.WrapError(core.NumTransport, core.CodeTransport, "dial", err)
			}
			c.mu.Lock()
			c.conn = conn
			tr.conn = conn
			c.mu.Unlock()
			return nil
		},
		// setupTransport: 单 TCP 连接，无独立 control stream，仅设置 transport
		func(ctx context.Context, cc *protocol.CoreClient) error {
			cc.SetTransport(tr)
			return nil
		},
		// postAuth: ntls 无 post-auth 工作
		nil,
	)
	// 握手失败兜底：binding.Handshake 的 defer 已调用 cc.Close() 关闭 transport（含
	// tr.conn），此处仅清理 c.conn 引用，不二次 Close（避免 net.Conn 双重关闭；
	// 某些 TLCP wrapper 非幂等）。同步把 tr.conn 置 nil 防止悬挂引用。
	if err != nil {
		c.mu.Lock()
		c.conn = nil
		tr.conn = nil
		c.mu.Unlock()
	}
	return err
}

// SendBatch 通过 MBTA-NTLS 协议发送一个 SignalBatch。
// 委托给 CoreClient.SendBatch。opts 携带 per-call 发送选项（如 core.WithTraceContext）。
func (c *Client) SendBatch(ctx context.Context, signalBatch *core.SignalBatch, tag, source string, opts ...core.SendOption) (string, error) {
	return c.core.SendBatch(ctx, signalBatch, tag, source, opts...)
}

// SetACKHandler 注册服务端 ACK 回调。
func (c *Client) SetACKHandler(h func(chunkID, ackMode string)) {
	c.core.SetACKHandler(h)
}

// SetRedirectHandler 注册服务端 TypeRedirect（S→C 集群重定向到 leader）回调。
func (c *Client) SetRedirectHandler(h func(payload []byte)) {
	c.core.SetRedirectHandler(h)
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
