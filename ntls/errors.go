package ntls

import "github.com/iuboy/mbta-go/core"

var (
	// ErrNotReady 表示客户端未就绪。
	ErrNotReady = core.NewError(core.NumSession, core.CodeSession, "client not ready, call Connect first")

	// ErrWindowFull 表示流控窗口已满，无法发送。
	ErrWindowFull = core.NewError(core.NumWindowFull, core.CodeWindowFull, "window full, cannot send batch")

	// ErrThrottled 表示客户端被限流。
	ErrThrottled = core.NewError(core.NumThrottle, core.CodeThrottle, "throttled")
)
