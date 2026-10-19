package binding

// client.go：binding 层客户端共享逻辑。

import (
	"context"
	"fmt"
	"time"

	"github.com/iuboy/mbta-go/core"
	corepb "github.com/iuboy/mbta-go/corepb"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// ClientCoreConfig 是各 binding 共享的客户端公共配置。
type ClientCoreConfig struct {
	AgentID      string
	Meta         map[string]string
	Token        string
	Capabilities []string
	Profile      corepb.Profile
	Metrics      core.Metrics
	DrainTimeout time.Duration
}

// NewClientCore 校验必填字段并构造 CoreClient。
func NewClientCore(cfg ClientCoreConfig) (*protocol.CoreClient, error) {
	if cfg.AgentID == "" {
		return nil, core.NewError(core.ErrCodeConfig, "AgentID required")
	}
	if cfg.Token == "" {
		return nil, core.NewError(core.ErrCodeConfig, "Token required")
	}
	if cfg.Profile != corepb.Profile_PROFILE_INTL && cfg.Profile != corepb.Profile_PROFILE_GM {
		return nil, core.NewError(core.ErrCodeConfig, "Profile must be intl or gm")
	}
	if unknown := core.FilterUnknownCaps(cfg.Capabilities); len(unknown) > 0 {
		return nil, core.NewError(core.ErrCodeProtocol, fmt.Sprintf("unknown capabilities: %v", unknown))
	}
	cc := protocol.NewCoreClient(nil, protocol.CoreClientConfig{
		AgentID:      cfg.AgentID,
		Meta:         cfg.Meta,
		Token:        cfg.Token,
		Capabilities: cfg.Capabilities,
		Profile:      cfg.Profile,
		Metrics:      cfg.Metrics,
		DrainTimeout: cfg.DrainTimeout,
	})
	cc.SetReadControlLoop(cc.ReadControlLoop)
	return cc, nil
}

// Handshake 编排客户端握手（HELLO → HELLO_ACK → StartLifecycle）。
// postAuth 可选（v1 的 openDataStream 等；StartLifecycle 前执行，防 goroutine 泄漏）。
func Handshake(ctx context.Context, cc *protocol.CoreClient,
	dial func(context.Context) error, setupTransport func(context.Context) error,
	postAuth func(context.Context) error) error {
	// Idle→Ready 由 cc.Handshake 内部完成，此处不预转（预转会使握手尾部
	// READY→READY 非法，客户端全链路不可用）。
	if err := dial(ctx); err != nil {
		// dial 失败时状态从未离开 Idle（Idle→Ready 由 cc.Handshake 内部完成），
		// 直接返回即可重试。
		return err
	}
	handshakeOK := false
	defer func() {
		if !handshakeOK {
			_ = cc.Close()
		}
	}()
	if err := setupTransport(ctx); err != nil {
		return err
	}
	if err := cc.Handshake(ctx); err != nil {
		return err
	}
	if postAuth != nil {
		if err := postAuth(ctx); err != nil {
			return err
		}
	}
	cc.StartLifecycle()
	handshakeOK = true
	return nil
}
