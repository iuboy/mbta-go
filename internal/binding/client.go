package binding

import (
	"context"
	"time"

	"github.com/iuboy/mbta-go/core"
	"github.com/iuboy/mbta-go/internal/protocol"
)

// Handshake 编排客户端握手流程（HELLO → HELLO_ACK → AUTH → AUTH_RESULT → StartLifecycle）。
// 消除 v1/ntls 的 ~40 行重复。
//
// cc 由调用方在 NewClient 时创建并注入（保持 CoreClient 生命周期归调用方）。
// 调用方提供：
//   - dial: 建立传输连接
//   - setupTransport: 在 Dial 成功后、握手前设置 transport（v1 在此 OpenControlStream + SetOnAuthed）
//   - postAuth: 可选，StartLifecycle 后执行（v1 在此 openDataStreams）；nil 跳过
func Handshake(
	ctx context.Context,
	cc *protocol.CoreClient,
	dial func(context.Context) error,
	setupTransport func(context.Context, *protocol.CoreClient) error,
	postAuth func(context.Context) error,
) error {
	if err := cc.SmTransitionConnecting(); err != nil {
		return err
	}

	if err := dial(ctx); err != nil {
		return core.WrapError(core.NumTransport, core.CodeTransport, "dial", err)
	}

	if err := setupTransport(ctx, cc); err != nil {
		return err
	}

	if err := cc.SmTransition(core.StateControlStreamOpen); err != nil {
		return err
	}

	if err := cc.SendHello(); err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "hello", err)
	}
	helloAck, err := cc.RecvHelloAck()
	if err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "hello_ack", err)
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
		cc.SetHeartbeatInterval(30 * time.Second)
	}

	if err := cc.SendAuth(); err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "auth", err)
	}
	if err := cc.RecvAuthResult(); err != nil {
		return core.WrapError(core.NumHandshake, core.CodeHandshake, "auth_result", err)
	}

	cc.StartLifecycle()

	if postAuth != nil {
		if err := postAuth(ctx); err != nil {
			return err
		}
	}
	return nil
}
