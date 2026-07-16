package protocol

import "log/slog"

// SetRedirectHandler registers a callback invoked when the server sends a
// TypeRedirect frame (S→C cluster redirect). The callback receives the raw
// frame payload; the application decodes it (e.g. JSON {leaderAddr, leaderId}).
// At most one handler is active; a later call replaces the prior one.
//
// Used by HA follower replicas to redirect agents to the elected leader.
func (c *CoreClient) SetRedirectHandler(h func(payload []byte)) {
	c.redirectHandler.Store(&h)
}

func (c *CoreClient) loadRedirectHandler() func(payload []byte) {
	if p := c.redirectHandler.Load(); p != nil {
		return *p
	}
	return nil
}

// dispatchRedirect 在独立 goroutine 中调用注册的 redirect handler。
//
// 旧实现同步调用，会在 readControlLoop goroutine 中阻塞所有后续 ACK/NACK/
// WINDOW/THROTTLE/PING/CLOSE 处理（handler 由应用层注册，库无法控制其耗时）。
// 改为异步执行避免控制帧处理被卡住。payload 是只读字节切片，并发安全。
// nil handler 表示客户端忽略 redirect 帧（旧版客户端无此特性）。
func (c *CoreClient) dispatchRedirect(payload []byte) {
	h := c.loadRedirectHandler()
	if h == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Warn("redirect handler panicked", "error", r)
			}
		}()
		h(payload)
	}()
}
