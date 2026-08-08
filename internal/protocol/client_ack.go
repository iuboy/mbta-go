package protocol

import (
	"context"
	"log/slog"
	"time"
)

// SetACKHandler registers a callback invoked when the server acknowledges a batch.
func (c *CoreClient) SetACKHandler(h func(chunkID, ackMode string)) {
	c.ackHandler.Store(&h)
}

func (c *CoreClient) loadACKHandler() func(chunkID, ackMode string) {
	if p := c.ackHandler.Load(); p != nil {
		return *p
	}
	return nil
}

// dispatchACK 入队用户 ACK/NACK 回调异步执行。永不阻塞：队列满时丢弃回调（warn）。
// 仅回调通知丢失——AckTracker 在 handleAck/handleNack 同步释放 slot，
// ackReaper 仍会回收未 ACK batch 的 inflight 配额。
func (c *CoreClient) dispatchACK(chunkID, mode string) {
	select {
	case c.ackQueue <- ackTask{chunkID: chunkID, mode: mode}:
	default:
		slog.Warn("ack callback queue full, dropping callback",
			"chunk", chunkID, "mode", mode)
	}
}

// runACKWorker 消费 ackTask 并在单 goroutine 上调用已注册 handler，保持 ACK 到达顺序。
// 关闭时先排空队列（带超时保护），使已入队回调仍能投递，但不会因 handler 阻塞而永久挂起。
func (c *CoreClient) runACKWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			// 排空队列时加超时：用户 handler 可能阻塞，不能让 drain 永久挂住
			// 否则 ackWorkerDone 不关闭 → waitGoroutines 超时 + goroutine 永久泄漏。
			drainDeadline := time.NewTimer(5 * time.Second)
			defer drainDeadline.Stop()
		drain:
			for {
				select {
				case t := <-c.ackQueue:
					c.invokeACKHandler(t)
				case <-drainDeadline.C:
					if q := len(c.ackQueue); q > 0 {
						slog.Warn("ACK worker drain timed out, dropping callbacks", "pending", q)
					}
					break drain
				default:
					break drain
				}
			}
			return
		case t := <-c.ackQueue:
			c.invokeACKHandler(t)
		}
	}
}

// invokeACKHandler 每次新鲜加载 handler，使 SetACKHandler 更新立即生效。
func (c *CoreClient) invokeACKHandler(t ackTask) {
	if h := c.loadACKHandler(); h != nil {
		h(t.chunkID, t.mode)
	}
}

// ackReaper 周期回收超时未 ACK 的 batch 的 inflight 配额（30s ticker）。
// 防止对端永不 ACK 时 inflight 永久占用窗口。同时为序号跨度检查兜底：回收队头
// 超时 slot 后 oldestSeq 前移，解除 CanSend 的队头阻塞。
func (c *CoreClient) ackReaper(ctx context.Context) {
	const reaperInterval = 30 * time.Second
	ticker := time.NewTicker(reaperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			// ReapExpired 在 tracker.mu 下批量扫描固定 AckRingSize 个 slot，
			// 回收 deadline 过期的 slot 并重算 oldestSeq。每个回收的 slot 已扣减聚合计数。
			for _, slot := range c.tracker.ReapExpired(now) {
				slog.Warn("reaped expired unacked batch",
					"seq", slot.Seq, "age", now.Sub(slot.SentAt).Round(time.Second))
				c.notifyDrainIfEmpty()
			}
		}
	}
}

// notifyDrainIfEmpty 在 drain 状态且 tracker 归零时通知 close 的 drain 循环。
// 非阻塞：drainCh 容量 1，重复通知无妨。
func (c *CoreClient) notifyDrainIfEmpty() {
	if c.tracker.Empty() {
		select {
		case c.drainCh <- struct{}{}:
		default:
		}
	}
}

// countPendingAcks 返回当前待 ACK 的 batch 数（用于 close 日志）。
func (c *CoreClient) countPendingAcks() int {
	return c.tracker.PendingCount()
}
