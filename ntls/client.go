package ntls

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/binding"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// Client 是 MBTA-NTLS 客户端：单 TCP（TLCP）连接上多路复用 control/data 帧。
// 协议逻辑（状态机/握手/ACK/drain/heartbeat）全部委托给 protocol.CoreClient，
// 自身仅保留传输适配（ntlsClientTransport）。
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

func (t *ntlsClientTransport) ReadFrame(ctx context.Context) (core.Frame, error) {
	// ctx 感知读：通过 SetReadDeadline 让 ctx 取消/超时能中断阻塞读，
	// 避免对端静默断开（TCP 无 RST，仅静默丢包）时 control loop 永久阻塞。
	if err := ctx.Err(); err != nil {
		return core.Frame{}, err
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(ntlsReadDefaultTimeout)
	}
	if err := t.conn.SetReadDeadline(dl); err != nil {
		return core.Frame{}, core.WrapError(core.ErrCodeStream, "set read deadline", err)
	}
	defer func() { _ = t.conn.SetReadDeadline(time.Time{}) }()
	f, err := core.Read(t.conn, core.DefaultLimits())
	if err != nil && ctx.Err() != nil {
		return core.Frame{}, ctx.Err()
	}
	return f, err
}

// ntlsReadDefaultTimeout 是 NTLS control 读在 ctx 无 deadline 时的默认上限。
const ntlsReadDefaultTimeout = 5 * time.Minute

// WriteFrame 写一帧。data 和 control 通道均受 ctx 约束（设 SetWriteDeadline），
// 防止慢速/无响应对端导致写永久阻塞（goroutine 泄漏）。
func (t *ntlsClientTransport) WriteFrame(ctx context.Context, typ uint8, flags, channel uint8, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	// 设写 deadline：ctx 有 Deadline 用之，否则设默认上限（30s）防背压永久阻塞。
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(ntlsWriteDefaultTimeout)
	}
	if err := t.conn.SetWriteDeadline(dl); err != nil {
		return core.WrapError(core.ErrCodeStream, "set write deadline", err)
	}
	defer func() { _ = t.conn.SetWriteDeadline(time.Time{}) }()
	return core.Write(t.conn, core.Version, typ, flags, channel, payload)
}

// ntlsWriteDefaultTimeout 是 ctx 无 deadline 时客户端写的默认上限。
const ntlsWriteDefaultTimeout = 30 * time.Second

func (t *ntlsClientTransport) CloseConn() error {
	return t.conn.Close()
}

func NewClient(cfg ClientConfig) (*Client, error) {
	// fail-fast：构造期校验必填字段与格式，避免拖到 Connect 的 dial 层才报错。
	if cfg.AgentID == "" {
		return nil, core.NewError(core.ErrCodeConfig, "AgentID required")
	}
	if cfg.Token == "" {
		return nil, core.NewError(core.ErrCodeConfig, "Token required")
	}
	if err := core.ValidateHostPort(cfg.Server); err != nil {
		return nil, core.WrapError(core.ErrCodeConfig, "Server", err)
	}
	if unknown := core.FilterUnknownStable(cfg.Capabilities); len(unknown) > 0 {
		return nil, core.NewError(core.ErrCodeProtocol, fmt.Sprintf("unknown stable capabilities: %v", unknown))
	}
	cc := protocol.NewCoreClient(nil, protocol.CoreClientConfig{
		AgentID:      cfg.AgentID,
		Hostname:     cfg.Hostname,
		Token:        cfg.Token,
		Capabilities: cfg.Capabilities,
		OS:           cfg.OS,
		AgentVersion: cfg.AgentVersion,
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
		return core.NewError(core.ErrCodeSession, "already connected")
	}
	c.mu.Unlock()

	tr := &ntlsClientTransport{}
	// connSet 标记本协程是否实际设置了 c.conn：并发 Connect 时失败协程只关自己的连接。
	var connSet bool
	err := binding.Handshake(ctx, c.core,
		// dial: 建立 TCP（TLCP/TLS1.3）连接
		func(ctx context.Context) error {
			conn, err := Dial(ctx, &c.cfg)
			if err != nil {
				return core.WrapError(core.ErrCodeTransport, "dial", err)
			}
			// dial 回调内二次检查：消除入口 c.conn==nil 检查与赋值之间的 TOCTOU 窗口。
			c.mu.Lock()
			if c.conn != nil {
				// 另一个并发 Connect 已设置连接，关闭当前 conn 避免泄漏。
				c.mu.Unlock()
				_ = conn.Close()
				return core.NewError(core.ErrCodeSession, "already connected (race)")
			}
			c.conn = conn
			tr.conn = conn
			connSet = true
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
	// 握手失败：cc.Close() 仅在 transport 已注册时关闭连接，dial 成功但 setupTransport 失败时需在此显式关闭（仅关本协程设置的连接）。
	if err != nil {
		c.mu.Lock()
		if connSet {
			_ = c.conn.Close()
			c.conn = nil
		}
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

func (c *Client) State() core.State {
	return c.core.State()
}

func (c *Client) SessionID() string {
	return c.core.SessionID()
}
