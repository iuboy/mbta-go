package mbta

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/iuboy/mbta-go/core"
	ntls "github.com/iuboy/mbta-go/ntls"
	v1 "github.com/iuboy/mbta-go/v1"
)

// ClientOption 配置 [Client]（函数式选项）。
type ClientOption func(*ClientConfig) error

// Client 是单版本 MBTA 客户端。各版本（v1、ntls）是完全独立的协议，版本间
// 不做自动回退；需要多版本时分别创建 Client 实例。
type Client struct {
	cfg    ClientConfig
	client versionedClient
	mu     sync.RWMutex
}

// ResultHandler 在服务端对某批次发送 RESULT 终态时被调用：
// accepted / durable / rejected / released。seq 与 SendBatch 返回值对应；
// rejected 时 code 为错误码注册表数字，correlation 透传发送选项携带的关联标识。
type ResultHandler func(seq uint64, level string, code uint32, correlation string)

// RedirectHandler 在服务端发送 REDIRECT 帧（S→C 集群重定向到 HA leader）时被调用。
// payload 由应用层定义（如 JSON {leaderAddr, leaderId}）。
//
// ctx 带 30 秒超时；handler 在内部 IO/锁操作中应检查 ctx.Done() 并及时退出，
// 否则超时后 goroutine 泄漏（Go runtime 无法杀死阻塞的 goroutine）。
type RedirectHandler func(ctx context.Context, payload []byte)

// versionedClient 以统一接口包装版本专属客户端（facade 方法直接透传）。
type versionedClient interface {
	Connect(ctx context.Context) error
	SendBatch(ctx context.Context, batch *core.SignalBatch, opts ...core.SendOption) (uint64, error)
	SendDatagram(ctx context.Context, batch *core.SignalBatch, opts ...core.SendOption) (uint64, error)
	Close() error
	State() string
	SetResultHandler(handler ResultHandler)
	SetRedirectHandler(handler RedirectHandler)
}

// ClientConfig 是客户端配置。
type ClientConfig struct {
	// 协议版本：Version1 / VersionNTLS 之一，必填。
	// 类型化为 ProtocolVersion，调用方传常量减少拼写错误（initClient 仍运行时分派）。
	Version ProtocolVersion

	// 连接设置。
	Server  string
	AgentID string
	Token   string // 认证 token（不上 wire，仅参与 token_proof HMAC）

	// Meta 写入 HELLO.meta（hostname/os/agent_version 等，供服务端 OnSession 读取，可选）。
	Meta map[string]string

	// Capabilities 是客户端能力（与服务端 policy 协商取交集；未知能力 fail-fast）。
	Capabilities []string

	// DrainTimeout 限制 Close 时等待未终态 batch 的最长时间（可选）。0=用各版本
	// 默认（30s）。缩短可减小「发完即 Close」的等待窗口；未终态的 batch 会丢
	// （调用方负责重发）。
	DrainTimeout time.Duration

	// 版本专属配置。
	V1Creds   *v1.ClientCredentials
	NTLSCreds *ntls.ClientCredentials

	// Metrics 可选的可观测性接口（nil=NoOp）。客户端侧指标（BatchesSent/BatchLatency）。
	Metrics core.Metrics
}

// NewClient 创建单版本 MBTA 客户端（仅构造不连接；连接用 [Client.Connect]
// 或 [Dial]）。客户端严格按配置指定的版本连接。
func NewClient(opts ...ClientOption) (*Client, error) {
	cfg := &ClientConfig{
		Version: Version1, // Default to v1
	}

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, core.WrapError(core.ErrCodeConfig, "client option", err)
		}
	}

	// Validate version：ProtocolVersion 类型已在编译期约束为合法常量之一，
	// 这里只兜底零值（用户未设置 Version）。
	if cfg.Version == "" {
		return nil, core.NewError(core.ErrCodeConfig, "version is required")
	}

	if cfg.AgentID == "" {
		return nil, core.NewError(core.ErrCodeConfig, "AgentID is required")
	}
	if cfg.Server == "" {
		return nil, core.NewError(core.ErrCodeConfig, "Server address is required")
	}

	// 防御性拷贝 Meta/Capabilities：cfg 以值拷贝进 Client，但 map/slice 仍与
	// 调用方共享底层数据——NewClient 之后调用方修改 map（哪怕只是加一个键）会
	// 与握手读取构成数据竞态（审查 F11 裁决）。
	meta, caps := cfg.Meta, cfg.Capabilities
	cfg.Meta = nil
	cfg.Capabilities = nil
	c := &Client{cfg: *cfg}
	if len(meta) > 0 {
		m := make(map[string]string, len(meta))
		for k, v := range meta {
			m[k] = v
		}
		c.cfg.Meta = m
	}
	if len(caps) > 0 {
		c.cfg.Capabilities = append([]string(nil), caps...)
	}

	// 构造版本专属客户端。
	client, err := c.initClient()
	if err != nil {
		return nil, err
	}
	c.client = client

	return c, nil
}

// Dial 创建 Client 并完成连接，返回可直接使用的客户端——[NewClient] + Connect
// 的便捷组合。
//
// 简单用法：
//
//	client, err := mbta.Dial(ctx, "localhost:7400", "my-agent", "secret-token",
//	    "v1",
//	    mbta.WithV1Credentials(v1.ClientCredentials{CAFile: "ca.pem"}),
//	)
//	if err != nil { ... }
//	defer client.Close()
//
//	// client 已连接，可直接 SendBatch
func Dial(ctx context.Context, server, agentID, token string, version ProtocolVersion, opts ...ClientOption) (*Client, error) {
	allOpts := append([]ClientOption{
		WithServer(server),
		WithAgent(agentID, token),
		WithVersion(version),
	}, opts...)

	client, err := NewClient(allOpts...)
	if err != nil {
		// NewClient 失败几乎都是配置错误（ErrCodeConfig）——原样透传，
		// 包成 ErrCodeTransport 会让按错误码分类的调用方把配置错误当网络抖动重试。
		if core.CodeNumOf(err) == core.ErrCodeConfig.Num {
			return nil, err
		}
		return nil, core.WrapError(core.ErrCodeTransport, "dial create", err)
	}

	if err := client.Connect(ctx); err != nil {
		if closeErr := client.Close(); closeErr != nil {
			slog.Debug("cleanup close after failed connect", "error", closeErr)
		}
		return nil, core.WrapError(core.ErrCodeTransport, "dial connect", err)
	}

	return client, nil
}

// initClient 按配置版本构造专属客户端。
func (c *Client) initClient() (versionedClient, error) {
	switch c.cfg.Version {
	case Version1:
		return c.initV1Client()
	case VersionNTLS:
		return c.initNTLSClient()
	default:
		return nil, core.NewError(core.ErrCodeConfig, fmt.Sprintf("unsupported version: %s", c.cfg.Version))
	}
}

// Connect 用配置的版本建立连接。
//
// 持锁跨越整个网络握手（QUIC 拨号 + 1-RTT 握手，可达 ctx 超时上限，默认 30s）：
// 期间并发的 Close/SendBatch/State 全部阻塞直至握手结束——串行化是有意为之
// （防重连竞态与 use-after-close），需要快速中断请取消 ctx（review F10 裁决：
// 文档化延迟量级，不改锁语义）。
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client == nil {
		return core.NewError(core.ErrCodeSession, "client has been closed (cannot reconnect after Close)")
	}

	slog.Info("connecting", "version", c.cfg.Version, "server", c.cfg.Server)

	if err := c.client.Connect(ctx); err != nil {
		slog.Error("connection failed", "version", c.cfg.Version, "error", err)
		return err
	}

	slog.Info("connected", "version", c.cfg.Version)
	return nil
}

// SendBatch 通过活动连接发送 batch，返回协议分配的 seq（供 ResultHandler 对账）。
// opts 携带 per-call 选项（如 WithTraceContext），不传则与旧行为一致。
// RLock 保护防止与 Close 竞态（Close 的 Lock 等待 RLock 释放，保证串行化）。
func (c *Client) SendBatch(ctx context.Context, batch *core.SignalBatch, opts ...core.SendOption) (uint64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return 0, core.NewError(core.ErrCodeSession, "not connected (call Connect first)")
	}

	return c.client.SendBatch(ctx, batch, opts...)
}

// SendDatagram 以不可靠通道发送 batch（at-most-once，豁免 credit），返回分配的 seq。
// 需协商 datagram 能力且传输支持（QUIC DATAGRAM，两侧启用扩展）；任一不满足时
// 降级为可靠 SendBatch 路径（消耗 credit、有 RESULT 反馈）——调用方无需感知 binding
// 差异。RLock 保护同 SendBatch。
func (c *Client) SendDatagram(ctx context.Context, batch *core.SignalBatch, opts ...core.SendOption) (uint64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return 0, core.NewError(core.ErrCodeSession, "not connected (call Connect first)")
	}

	return c.client.SendDatagram(ctx, batch, opts...)
}

// Close 关闭客户端并释放全部资源。Close 后不可重连（Connect 返回错误）。
//
// token 生命周期：Go string 不可变，库不做内存清零（清零副本不触及堆上其他
// 引用，制造虚假安全感——review F9 裁决）。token 的唯一防线是熵强度
// （core spec §163：≥128bit 随机）；连接关闭后网络面即收敛。
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client != nil {
		err := c.client.Close()
		// 置 nil 防止 use-after-close。
		c.client = nil
		return err
	}
	return nil
}

// State 返回当前连接状态（idle/handshaking/ready/closed，见 [core.State]）。
// Close 后返回 idle。
func (c *Client) State() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.client == nil {
		return core.StateIdle.String()
	}
	return c.client.State()
}

// SetResultHandler 注册服务端 RESULT 通知回调。服务端对某批次上报终态时，
// 以 (seq, level, code, correlation) 调用 handler。
//
// 回调内不得调用 Close：结果回调经 ackQueue 串行 worker 执行，Close 会等待
// lifecycle goroutine 退出预算（review F26 裁决：契约文档化）。
//
// 用 Lock（非 RLock）：SetResultHandler 修改 handler 状态，需防并发 Set（RLock 仅防与 Close 的并发）。
// Close 后调用：既不报错也不生效（内层实例已终结，回调永远不会触发）——
// 告警提示，避免「注册成功」的错觉（审查 F8 裁决）。
func (c *Client) SetResultHandler(handler ResultHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client == nil {
		slog.Warn("SetResultHandler on closed client; handler will never fire")
		return
	}
	c.client.SetResultHandler(handler)
}

// SetRedirectHandler 注册 REDIRECT 通知回调（S→C 集群重定向到 HA leader）。
// handler 收到原始帧 payload，由应用层自行解码。
// 锁语义与 Close 后行为同 [Client.SetResultHandler]（用 Lock 保护）。
func (c *Client) SetRedirectHandler(handler RedirectHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client == nil {
		slog.Warn("SetRedirectHandler on closed client; handler will never fire")
		return
	}
	c.client.SetRedirectHandler(handler)
}

// ActiveVersion 返回配置的协议版本。
func (c *Client) ActiveVersion() ProtocolVersion {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.Version
}

// initV1Client 构造 v1 客户端包装。
// 注意：与 initNTLSClient 是并行字段拷贝——新增共享配置字段时两处必须同步
// （Commands 曾在 server 侧漏抄，见审查 F1）。
func (c *Client) initV1Client() (versionedClient, error) {
	if c.cfg.V1Creds == nil {
		return nil, core.NewError(core.ErrCodeCredential, "v1 credentials not provided")
	}
	// profile 由版本映射推导（v1=intl）；版本与 profile 正交，显式需求走 v1 包直连。
	profile, err := ProfileFor(c.cfg.Version)
	if err != nil {
		return nil, err
	}

	cfg := v1.ClientConfig{
		Transport: v1.QUICClientConfig{
			Server:      c.cfg.Server,
			Credentials: c.cfg.V1Creds,
		},
		AgentID:      c.cfg.AgentID,
		Token:        c.cfg.Token,
		Meta:         c.cfg.Meta,
		Capabilities: c.cfg.Capabilities,
		Profile:      profile,
		Metrics:      c.cfg.Metrics,
		DrainTimeout: c.cfg.DrainTimeout,
	}

	client, err := v1.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	return &versionWrapper[*v1.Client]{client: client}, nil
}

// initNTLSClient 初始化 NTLS（TCP + TLCP）客户端。
// 与 initV1Client 并行拷贝——同步义务见彼处注释。
func (c *Client) initNTLSClient() (versionedClient, error) {
	// fail-fast：NewClient 时校验凭证非空。
	if c.cfg.NTLSCreds == nil {
		return nil, core.NewError(core.ErrCodeCredential, "ntls credentials not provided")
	}
	profile := NTLSProfileFor(c.cfg.NTLSCreds.Mode)
	cfg := ntls.ClientConfig{
		Server:       c.cfg.Server,
		Credentials:  c.cfg.NTLSCreds,
		AgentID:      c.cfg.AgentID,
		Token:        c.cfg.Token,
		Meta:         c.cfg.Meta,
		Capabilities: c.cfg.Capabilities,
		Profile:      profile,
		Metrics:      c.cfg.Metrics,
		DrainTimeout: c.cfg.DrainTimeout,
	}
	client, err := ntls.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &versionWrapper[*ntls.Client]{client: client}, nil
}

// versionedCore 是两个 binding 客户端的共同方法集（versionWrapper 泛型约束；
// v1.Client 与 ntls.Client 以指针接收者满足）。ResultHandler/RedirectHandler
// 在 facade 是定义类型，约束里用底层函数签名（方法集匹配要求参数类型精确一致）。
type versionedCore[C any] interface {
	Connect(ctx context.Context) error
	SendBatch(ctx context.Context, batch *core.SignalBatch, opts ...core.SendOption) (uint64, error)
	SendDatagram(ctx context.Context, batch *core.SignalBatch, opts ...core.SendOption) (uint64, error)
	Close() error
	State() core.State
	SetResultHandler(handler func(seq uint64, level string, code uint32, correlation string))
	SetRedirectHandler(handler func(ctx context.Context, payload []byte))
}

// versionWrapper 把任一 binding 客户端适配为 versionedClient——此前 v1/ntls
// 两个 wrapper 是逐字等价的 8 方法对（40 行纯维护税，review F14 裁决泛型化）。
type versionWrapper[C versionedCore[C]] struct {
	client C
}

func (w *versionWrapper[C]) Connect(ctx context.Context) error { return w.client.Connect(ctx) }
func (w *versionWrapper[C]) SendBatch(ctx context.Context, batch *core.SignalBatch, opts ...core.SendOption) (uint64, error) {
	return w.client.SendBatch(ctx, batch, opts...)
}
func (w *versionWrapper[C]) SendDatagram(ctx context.Context, batch *core.SignalBatch, opts ...core.SendOption) (uint64, error) {
	return w.client.SendDatagram(ctx, batch, opts...)
}
func (w *versionWrapper[C]) Close() error  { return w.client.Close() }
func (w *versionWrapper[C]) State() string { return w.client.State().String() }
func (w *versionWrapper[C]) SetResultHandler(handler ResultHandler) {
	w.client.SetResultHandler(handler)
}
func (w *versionWrapper[C]) SetRedirectHandler(handler RedirectHandler) {
	w.client.SetRedirectHandler(handler)
}

// —— 客户端选项（函数式选项模式）——

// WithVersion 设置协议版本。version 是 ProtocolVersion 类型（typed string），
// 调用方须传 Version1/VersionNTLS 常量之一；从 string 构造时用 [ParseVersion] 转换。
func WithVersion(version ProtocolVersion) ClientOption {
	return func(cc *ClientConfig) error {
		cc.Version = version
		return nil
	}
}

// WithServer 设置服务端地址（host:port）。
func WithServer(server string) ClientOption {
	return func(cc *ClientConfig) error {
		cc.Server = server
		return nil
	}
}

// WithAgent 设置 agent 身份（agentID + token）。
// 旧签名的 hostname 参数并入 WithAgentMeta 的通用元数据面（HELLO.meta map）。
func WithAgent(agentID, token string) ClientOption {
	return func(cc *ClientConfig) error {
		cc.AgentID = agentID
		cc.Token = token
		return nil
	}
}

// WithAgentMeta 设置 HELLO 元数据表（hostname/os/agent_version 等）。
// 整表替换（非合并）：调用方对 map 拥有完整控制权，避免部分更新的歧义。
func WithAgentMeta(meta map[string]string) ClientOption {
	return func(cc *ClientConfig) error {
		cc.Meta = meta
		return nil
	}
}

// WithCapabilities 设置客户端能力（与服务端 policy 协商取交集；
// 未知能力在 NewClient 构造期 fail-fast）。
func WithCapabilities(caps []string) ClientOption {
	return func(cc *ClientConfig) error {
		cc.Capabilities = caps
		return nil
	}
}

// WithV1Credentials 配置 v1（QUIC + TLS 1.3）的客户端凭证。
func WithV1Credentials(creds v1.ClientCredentials) ClientOption {
	return func(cc *ClientConfig) error {
		cc.V1Creds = &creds
		return nil
	}
}

// WithNTLSCredentials 配置 ntls（TCP + TLCP/TLS1.3）的客户端凭证。
func WithNTLSCredentials(cfg ntls.ClientCredentials) ClientOption {
	return func(cc *ClientConfig) error {
		cc.NTLSCreds = &cfg
		return nil
	}
}

// WithClientMetrics 配置客户端侧指标收集器（BatchesSent/BatchLatency）。
// 可选；nil 用 NoOp 收集器。
// 注：客户端 option 保留 Client 前缀以与服务端 WithMetrics 区分（同包同名冲突）。
func WithClientMetrics(metrics core.Metrics) ClientOption {
	return func(cc *ClientConfig) error {
		cc.Metrics = metrics
		return nil
	}
}

// WithDrainTimeout 设置 Close 时等待未终态 batch 的最长时间（可选，0=默认 30s）。
// 缩短可减小「发完即 Close」的等待窗口；未终态的 batch 会丢（调用方负责重发）。
func WithDrainTimeout(d time.Duration) ClientOption {
	return func(cc *ClientConfig) error {
		if d < 0 {
			return core.NewError(core.ErrCodeConfig, "drain timeout must not be negative")
		}
		cc.DrainTimeout = d
		return nil
	}
}
