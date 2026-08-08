package protocol

import (
	"context"
	"log/slog"
	"time"
)

// redirectHandlerTimeout 是应用层 redirect handler 的最大执行时间。
// 超时后 outer goroutine 退出并释放 redirectInflight，但 inner goroutine
// 无法被 Go runtime 杀死——handler 应监听 ctx.Done() 并及时退出。
const redirectHandlerTimeout = 30 * time.Second

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
// 同步调用会有缺陷：会在 readControlLoop goroutine 中阻塞所有后续 ACK/NACK/
// WINDOW/THROTTLE/PING/CLOSE 处理（handler 由应用层注册，库无法控制其耗时）。
// 异步执行避免控制帧处理被卡住。
//
// 并发保护：
//   - payload 做防御性拷贝：当前所有内置 transport 均通过 core.Read 分配新切片，
//     但未来若引入 buffer pool 或第三方实现复用读取缓冲区，直接传切片引用会导致
//     goroutine 中的 handler 与网络读取层发生数据竞争。
//   - redirectInflight 原子标志：保证同一时间最多一个 redirect handler goroutine
//     在执行，防止恶意/有缺陷的服务端高频重定向耗尽 goroutine 资源。
func (c *CoreClient) dispatchRedirect(payload []byte) {
	h := c.loadRedirectHandler()
	if h == nil {
		return
	}
	// 防御性拷贝：避免 handler goroutine 与 transport 读取层共享底层数组。
	cp := make([]byte, len(payload))
	copy(cp, payload)

	// 若已有 redirect handler 在运行，跳过本次（防止 goroutine 爆炸）。
	if !c.redirectInflight.CompareAndSwap(false, true) {
		slog.Debug("redirect handler already in flight, dropping duplicate redirect")
		return
	}

	go func() {
		defer c.redirectInflight.Store(false)
		defer func() {
			if r := recover(); r != nil {
				slog.Warn("redirect handler panicked", "error", r)
			}
		}()
		// 带超时执行：防止应用层 handler 永久阻塞导致 goroutine 泄漏 + redirectInflight
		// 永久置位（后续所有 redirect 静默丢弃）。
		// 超时后 inner goroutine 无法被杀死，但传入 cancelable ctx 使 handler
		// 有机会监听取消并主动退出。
		ctx, cancel := context.WithTimeout(context.Background(), redirectHandlerTimeout)
		defer cancel()
		done := make(chan struct{})
		go func() {
			// handler 应在内部操作中检查 ctx.Done()，而非忽略 ctx。
			// 为兼容现有 func([]byte) 签名，handler 无法直接接收 ctx——
			// 但 ctx 的 cancel 会在超时后触发，handler 若通过其他方式感知连接关闭
			// （如共享 ctx 传播）可提前退出。
			h(cp)
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			slog.Warn("redirect handler timed out, inner goroutine may leak if handler blocks",
				"timeout", redirectHandlerTimeout)
		}
	}()
}
