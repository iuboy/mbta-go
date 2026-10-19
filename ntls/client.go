package ntls

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/binding"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// Client 是 MBTA-NTLS 客户端：单 TCP（TLCP）连接上多路复用 control/data 帧。
// 协议逻辑（状态机/握手/RESULT/drain/心跳）全部委托给 protocol.CoreClient，
// 自身仅保留传输适配（ntlsClientTransport）。
//
// 可靠投递语义：credit 账本仅在内存追踪已发送未终态的 batch。进程崩溃/重连后
// 未终态的 batch 会丢失——持久化与重发由调用方负责。
type Client struct {
	core *protocol.CoreClient // 共享协议核心
	cfg  ClientConfig         // ntls 专属配置（Server/Credentials，供 Dial 用）
	conn net.Conn             // 单 TCP（TLCP）连接
	mu   sync.Mutex           // 保护 conn 字段的读写（Connect 设置 / Close 读取）
}

// ntlsClientTransport 实现 protocol.ClientTransport，封装单 TCP 连接的读写。
//
// writeSem（容量 1 信号量）串行化所有写（HELLO/BATCH/PING/CLOSE），替代 v1 的
// controlMu + picker。与 sync.Mutex 的区别：获取可被 ctx 取消——慢速对端 + Mutex
// 会把等待方钉死在锁上（与服务端 tcpTransport 的选择对称）。
type ntlsClientTransport struct {
	frameLimit atomic.Uint64 // 协商帧上限（0=默认 16MB）
	conn       net.Conn
	writeSem   chan struct{} // 初始持有 1 token；Close 后不归还以阻止 write-after-close
	closed     atomic.Bool
}

// newNTLSClientTransport 初始化写信号量。
func newNTLSClientTransport() *ntlsClientTransport {
	sem := make(chan struct{}, 1)
	sem <- struct{}{}
	return &ntlsClientTransport{writeSem: sem}
}

// SetFrameLimit 注入协商帧上限（HELLO_ACK 后由协议层调用）。
func (t *ntlsClientTransport) SetFrameLimit(maxBytes uint64) { t.frameLimit.Store(maxBytes) }

func (t *ntlsClientTransport) ReadFrame(ctx context.Context) (core.Frame, error) {
	fl := t.frameLimit.Load()
	if fl == 0 {
		return core.ReadFrameCtx(ctx, t.conn)
	}
	return core.ReadFrameCtxLimit(ctx, t.conn, core.FrameLimits{MaxFrameBytes: fl})
}

// 读超时统一用 core.DefaultReadTimeout。

// WriteFrame 写一帧（control/data 帧均写单连接，type 通道域只影响对端分流）。
// 受 ctx 约束（设 SetWriteDeadline + 写锁等待可取消），防止慢速/无响应对端导致
// 写永久阻塞（goroutine 泄漏）。
func (t *ntlsClientTransport) WriteFrame(ctx context.Context, typ uint8, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// 获取写信号量（或响应 ctx 取消；CloseConn 已关闭时立即失败）。
	select {
	case <-t.writeSem:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() {
		if !t.closed.Load() {
			t.writeSem <- struct{}{} // 归还 token（CloseConn 已 drain 则不再归还）
		}
	}()
	if t.closed.Load() {
		return core.NewError(core.ErrCodeStream, "transport closed")
	}
	// 设写 deadline：ctx 有 Deadline 用之，否则设默认上限（30s）防背压永久阻塞。
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(core.DefaultWriteTimeout)
	}
	if err := t.conn.SetWriteDeadline(dl); err != nil {
		return core.WrapError(core.ErrCodeStream, "set write deadline", err)
	}
	defer func() { _ = t.conn.SetWriteDeadline(time.Time{}) }()
	return core.Write(t.conn, typ, 0, payload)
}

// 写超时统一用 core.DefaultWriteTimeout。

func (t *ntlsClientTransport) CloseConn() error {
	// drain 写信号量（5s 超时兜底）并不归还：阻止后续 WriteFrame 在关闭后挂起或
	// 对已关 conn 写（与服务端 tcpTransport.Close 对称）。
	if t.closed.CompareAndSwap(false, true) {
		select {
		case <-t.writeSem:
		case <-time.After(5 * time.Second):
		}
	}
	return t.conn.Close()
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if err := core.ValidateHostPort(cfg.Server); err != nil {
		return nil, core.WrapError(core.ErrCodeConfig, "Server", err)
	}
	// ntls 特有校验（NewClient 构造期 fail-fast）：
	// TLCP 双 SM2 凭证一致性；TLS1.3 单证书同填一致性。
	if cfg.Credentials != nil {
		if cfg.Credentials.TLSMode {
			if err := validateTLS13Creds(cfg.Credentials); err != nil {
				return nil, err
			}
		} else {
			if err := validateDualSM2Creds(cfg.Credentials); err != nil {
				return nil, err
			}
		}
	}
	// ntls binding 默认国密 profile（SM2+HKDF-SM3+SM4-GCM）。
	if cfg.Profile == corepb.Profile_PROFILE_UNSPECIFIED {
		cfg.Profile = corepb.Profile_PROFILE_GM
	}
	// 公共校验 + CoreClient 构造委托 binding.NewClientCore（v1/ntls 共享）。
	cc, err := binding.NewClientCore(binding.ClientCoreConfig{
		AgentID:      cfg.AgentID,
		Meta:         cfg.Meta,
		Token:        cfg.Token,
		Capabilities: cfg.Capabilities,
		Profile:      cfg.Profile,
		Metrics:      cfg.Metrics,
		DrainTimeout: cfg.DrainTimeout,
	})
	if err != nil {
		return nil, err
	}
	// 注入应用层心跳（v1/ntls 双 binding 均注入）：读侧空闲超时依赖
	// PING/PONG 维持活性——QUIC 传输层 keepalive 不产生 MBTA 应用层帧，
	// 同样需要（见 v1/client.go NewClient 注释的实测复盘）。
	cc.SetHeartbeatLoop(cc.HeartbeatLoop)
	return &Client{core: cc, cfg: cfg}, nil
}

// Connect 拨号并完成 HELLO 握手（1-RTT）。
//
// ctx 仅控制握手阶段（Dial、HELLO）的超时与取消。握手成功后，后台 goroutine
// 运行在独立的 lifecycle ctx 上，不随 ctx 取消而退出；client 生命周期由 Close() 终结。
func (c *Client) Connect(ctx context.Context) error {
	// 防重复 Connect：已连接/连接中时拒绝，避免旧连接泄漏（fd 泄漏 + transport 覆盖）。
	// Client 单次使用：Close 后（c.conn 不清，状态机已 CLOSED）或握手失败清理后，
	// 重连须新建实例——按状态区分报错，避免对已关闭实例报误导性的 "already connected"。
	// 例外：dial 阶段失败已回退 Idle，同实例重试放行（见 binding.Handshake）。
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil || c.core.IsClosed() {
		if c.core.IsClosed() {
			return core.NewError(core.ErrCodeSession,
				"client closed or previous connect failed; Client is single-use, create a new instance")
		}
		return core.NewError(core.ErrCodeSession, "already connected")
	}

	tr := newNTLSClientTransport()
	// connSet 标记本协程是否实际设置了 c.conn：并发 Connect 时失败协程只关自己的连接。
	var connSet bool
	err := binding.Handshake(ctx, c.core,
		// dial: 建立 TCP（TLCP/TLS1.3）连接
		func(ctx context.Context) error {
			conn, err := Dial(ctx, &c.cfg)
			if err != nil {
				return err // Dial 已 wrap ErrCodeTransport + 具体原因
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
		// setupTransport: 单 TCP 连接，无独立 control stream，仅注入 transport
		func(ctx context.Context) error {
			c.core.SetTransport(tr)
			return nil
		},
		// postAuth: ntls 无 post-auth 工作
		nil,
	)
	// 握手失败清理：binding.Handshake 内部已调 cc.Close()（关 transport + 取消 lifecycle
	// + 等 goroutine），此处清理外层 ntls.Client 的 c.conn 引用（置 nil 防 use-after-close）
	// 并兜底关 conn（幂等，可能已被 cc.Close 关闭）。ntls client transport 自身不开 goroutine。
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

// SendBatch 通过 MBTA-NTLS 协议发送一个 SignalBatch，返回分配的 seq。
// 委托给 CoreClient.SendBatch。opts 携带 per-call 发送选项（如 core.WithTraceContext）。
func (c *Client) SendBatch(ctx context.Context, signalBatch *core.SignalBatch, opts ...core.SendOption) (uint64, error) {
	return c.core.SendBatch(ctx, signalBatch, opts...)
}

// SendDatagram 在 TCP binding 上必然降级：传输无不可靠通道（SupportsDatagram=false），
// 委托 CoreClient.SendDatagram 自动走可靠 SendBatch 路径（返回 seq、消耗 credit）。
// 保持与 v1 binding 同形 API 面，调用方代码无需按 binding 分支。
func (c *Client) SendDatagram(ctx context.Context, signalBatch *core.SignalBatch, opts ...core.SendOption) (uint64, error) {
	return c.core.SendDatagram(ctx, signalBatch, opts...)
}

// SetResultHandler 注册结果回调：服务端 RESULT（accepted/durable/rejected/released）
// 终态时调用，参数为 (seq, level, code, correlation)。
func (c *Client) SetResultHandler(h func(seq uint64, level string, code uint32, correlation string)) {
	c.core.SetResultHandler(h)
}

// SetRedirectHandler 注册服务端 REDIRECT（S→C 集群重定向到 leader）回调。
func (c *Client) SetRedirectHandler(h func(context.Context, []byte)) {
	c.core.SetRedirectHandler(h)
}

// Close 优雅关闭：发 CLOSE 帧、drain pending 结果、关闭连接。
func (c *Client) Close() error {
	return c.core.Close()
}

func (c *Client) State() core.State {
	return c.core.State()
}

func (c *Client) SessionID() string {
	return c.core.SessionID()
}

// SelectedCapabilities 返回握手协商选定的能力集（握手前为 nil）。
func (c *Client) SelectedCapabilities() []string {
	return c.core.SelectedCapabilities()
}
