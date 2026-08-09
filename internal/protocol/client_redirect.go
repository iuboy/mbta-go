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
// TypeRedirect frame (S→C cluster redirect). The callback receives a ctx with
// redirectHandlerTimeout deadline + the raw frame payload; the application
// decodes it (e.g. JSON {leaderAddr, leaderId}). handler 必须在内部 IO/锁操作中
// 检查 ctx.Done() 并及时退出，否则超时后 goroutine 泄漏。At most one handler is active;
// a later call replaces the prior one.
//
// Used by HA follower replicas to redirect agents to the elected leader.
func (c *CoreClient) SetRedirectHandler(h func(context.Context, []byte)) {
	c.redirectHandler.Store(&h)
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
	// 内联 loadRedirectHandler：atomic pointer load + 解引用。
	var h func(context.Context, []byte)
	if p := c.redirectHandler.Load(); p != nil {
		h = *p
	}
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
		// 带超时的 ctx：handler 必须在内部 IO/锁操作中检查 ctx.Done() 并及时退出。
		ctx, cancel := context.WithTimeout(context.Background(), redirectHandlerTimeout)
		defer cancel()
		h(ctx, cp)
	}()
}
