package binding

import (
	"context"
	"fmt"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// ClientCoreConfig 是各 binding 共享的客户端公共配置（v1/ntls 去重）。
// binding 特有字段（如 ntls 双 SM2 凭证）由各 binding 自行校验。
type ClientCoreConfig struct {
	AgentID      string
	Hostname     string
	Token        string
	Capabilities []string
	OS           string
	AgentVersion string
	Metrics      core.Metrics
	DrainTimeout time.Duration
}

// NewClientCore 校验公共必填字段并构造 CoreClient（v1/ntls NewClient 共享）。
// defaultCipherSuite 由调用方按 binding 语境传入（v1=INTL, ntls=GM）。
// 调用方负责 binding 特有校验（在调用前完成），本函数只做公共部分。
func NewClientCore(cfg ClientCoreConfig, defaultCipherSuite corepb.CipherSuite) (*protocol.CoreClient, error) {
	if cfg.AgentID == "" {
		return nil, core.NewError(core.ErrCodeConfig, "AgentID required")
	}
	if cfg.Token == "" {
		return nil, core.NewError(core.ErrCodeConfig, "Token required")
	}
	if unknown := core.FilterUnknownStable(cfg.Capabilities); len(unknown) > 0 {
		return nil, core.NewError(core.ErrCodeProtocol, fmt.Sprintf("unknown stable capabilities: %v", unknown))
	}
	cc := protocol.NewCoreClient(nil, protocol.CoreClientConfig{
		AgentID:            cfg.AgentID,
		Hostname:           cfg.Hostname,
		Token:              cfg.Token,
		Capabilities:       cfg.Capabilities,
		OS:                 cfg.OS,
		AgentVersion:       cfg.AgentVersion,
		DefaultCodec:       corepb.Codec_CODEC_PROTO,
		DefaultCipherSuite: defaultCipherSuite,
		DefaultCompression: corepb.Compression_COMPRESSION_ZSTD,
		Metrics:            cfg.Metrics,
		DrainTimeout:       cfg.DrainTimeout,
	})
	cc.SetReadControlLoop(cc.ReadControlLoop)
	cc.SetHeartbeatLoop(cc.HeartbeatLoop)
	return cc, nil
}

// Handshake 编排客户端握手流程（HELLO → HELLO_ACK → AUTH → AUTH_RESULT → StartLifecycle）。
// 消除 v1/ntls 的 ~40 行重复。
//
// cc 由调用方在 NewClient 时创建并注入（保持 CoreClient 生命周期归调用方）。
// 调用方提供：
//   - dial: 建立传输连接
//   - setupTransport: 在 Dial 成功后、握手前设置 transport（v1 在此 OpenControlStream + SetOnAuthed）
//   - postAuth: 可选，StartLifecycle 后执行（v1 在此 openDataStream）；nil 跳过
//
// DefaultHeartbeatInterval 是服务端未指定心跳间隔时的回退值。
const DefaultHeartbeatInterval = 30 * time.Second

func Handshake(ctx context.Context, cc *protocol.CoreClient, dial func(context.Context) error,
	setupTransport func(context.Context, *protocol.CoreClient) error, postAuth func(context.Context) error) error {
	if err := cc.SmTransition(core.StateConnecting); err != nil {
		return err
	}

	if err := dial(ctx); err != nil {
		return err // dial 回调（v1/ntls）已 wrap ErrCodeTransport + 具体原因，再包一层产生冗余链
	}

	// 握手任一步骤失败：清理已建立的连接（cc.Close 幂等，会取消 lifecycle、关闭 transport、
	// 等待 goroutine 退出），避免连接/goroutine 泄漏。
	handshakeOK := false
	defer func() {
		if !handshakeOK {
			_ = cc.Close()
		}
	}()

	if err := setupTransport(ctx, cc); err != nil {
		return err
	}

	if err := cc.SmTransition(core.StateControlStreamOpen); err != nil {
		return err
	}

	if err := cc.SendHello(ctx); err != nil {
		return core.WrapError(core.ErrCodeHandshake, "hello", err)
	}
	helloAck, err := cc.RecvHelloAck(ctx)
	if err != nil {
		return core.WrapError(core.ErrCodeHandshake, "hello_ack", err)
	}

	cc.SetSessionID(helloAck.GetSessionId())
	if err := cc.SmTransition(core.StateHelloAcked); err != nil {
		return err
	}
	if w := helloAck.GetInitialWindow(); w != nil {
		cc.UpdateWindow(int(w.GetMaxInflightBatches()), int(w.GetMaxInflightEvents()), w.GetMaxInflightBytes())
	}
	if helloAck.GetHeartbeatIntervalSec() > 0 {
		cc.SetHeartbeatInterval(time.Duration(helloAck.GetHeartbeatIntervalSec()) * time.Second)
	} else {
		cc.SetHeartbeatInterval(DefaultHeartbeatInterval)
	}

	if err := cc.SendAuth(ctx); err != nil {
		return core.WrapError(core.ErrCodeHandshake, "auth", err)
	}
	if err := cc.RecvAuthResult(ctx); err != nil {
		return core.WrapError(core.ErrCodeHandshake, "auth_result", err)
	}

	// 先执行 postAuth（如 openDataStream），成功后再启动 lifecycle goroutine。
	// 避免 postAuth 失败时已启动的 4 个 goroutine 无限运行（goroutine 泄漏）。
	if postAuth != nil {
		if err := postAuth(ctx); err != nil {
			return err
		}
	}
	cc.StartLifecycle()
	handshakeOK = true
	return nil
}
