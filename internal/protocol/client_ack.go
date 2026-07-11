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
// 仅回调通知丢失——pendingAcks/inflight 在 handleAck/handleNack 同步更新，
// ackReaper 仍会回收未 ACK batch 的 inflight。
func (c *CoreClient) dispatchACK(chunkID, mode string) {
	select {
	case c.ackQueue <- ackTask{chunkID: chunkID, mode: mode}:
	default:
		slog.Warn("ack callback queue full, dropping callback",
			"chunk", chunkID, "mode", mode)
	}
}

// runACKWorker 消费 ackTask 并在单 goroutine 上调用已注册 handler，保持 ACK 到达顺序。
// 关闭时先排空队列，使已入队回调仍能投递。
func (c *CoreClient) runACKWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case t := <-c.ackQueue:
					c.invokeACKHandler(t)
				default:
					return
				}
			}
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
// 防止对端永不 ACK 时 inflight 永久占用窗口。
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
			c.pendingAcks.Range(func(key, val any) bool {
				pb, ok := val.(*pendingBatch)
				if !ok {
					return true
				}
				if now.After(pb.Deadline) {
					// 用 LoadAndDelete 原子 claim：避免与 handleAck/Nack 的 LoadAndDelete 竞争，
					// 否则两条路径都执行清理会导致 pendingCount 双减（无下溢保护）和 inflight 双扣。
					if _, loaded := c.pendingAcks.LoadAndDelete(key); loaded {
						c.pendingCount.Add(-1)
						c.inflight.Remove(pb.Events, pb.Bytes)
						slog.Warn("reaped expired unacked batch",
							"chunk", key, "seq", pb.Seq, "age", now.Sub(pb.SentAt).Round(time.Second))
						c.notifyDrainIfEmpty()
					}
				}
				return true
			})
		}
	}
}

// notifyDrainIfEmpty 在 drain 状态且 pendingAcks 归零时通知 close 的 drain 循环。
// 非阻塞：drainCh 容量 1，重复通知无妨。
func (c *CoreClient) notifyDrainIfEmpty() {
	if c.pendingCount.Load() == 0 {
		select {
		case c.drainCh <- struct{}{}:
		default:
		}
	}
}

// countPendingAcks 返回当前待 ACK 的 batch 数（用于 close 日志）。
func (c *CoreClient) countPendingAcks() int {
	return int(c.pendingCount.Load())
}
