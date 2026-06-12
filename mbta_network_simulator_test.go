package mbta_test

import (
	"math/rand"
	"net"
	"sync"
	"time"
)

// LimitedPacketConn 包装 net.PacketConn，注入网络损伤：
//   - 带宽限制（令牌桶算法）
//   - 固定延迟 + 随机抖动
//   - 随机丢包
//   - 间歇性断连
//
// 通过 quic.Transport{Conn: limitedConn} 透明注入到 QUIC 层。
type LimitedPacketConn struct {
	inner net.PacketConn // 真实 UDP 连接

	mu           sync.Mutex
	bandwidth    int64         // 字节/秒，0 表示不限
	latency      time.Duration // 固定单向延迟
	jitter       time.Duration // 抖动范围 ±jitter
	lossRate     float64       // 丢包率 0.0~1.0
	disconnected bool          // 断连开关

	// 令牌桶状态
	tokens     int64     // 当前可用令牌（字节数）
	lastRefill time.Time // 上次补充令牌的时间
	maxTokens  int64     // 令牌桶容量

	rng *rand.Rand // 每连接独立的随机数生成器，避免全局锁
}

// NewLimitedPacketConn 创建网络模拟 PacketConn
func NewLimitedPacketConn(inner net.PacketConn) *LimitedPacketConn {
	now := time.Now()
	return &LimitedPacketConn{
		inner:        inner,
		bandwidth:    0, // 默认不限速
		latency:      0,
		jitter:       0,
		lossRate:     0,
		disconnected: false,
		tokens:       0,
		lastRefill:   now,
		maxTokens:    0,
		rng:          rand.New(rand.NewSource(now.UnixNano())),
	}
}

// SetBandwidth 设置带宽限制（字节/秒），0 表示不限
func (c *LimitedPacketConn) SetBandwidth(bps int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.bandwidth = bps
	if bps > 0 {
		// 令牌桶容量 = 1 秒的带宽，允许短时突发
		c.maxTokens = bps
		if c.tokens > c.maxTokens {
			c.tokens = c.maxTokens
		}
	}
}

// SetLatency 设置固定单向延迟
func (c *LimitedPacketConn) SetLatency(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.latency = d
}

// SetJitter 设置抖动范围（延迟在 [latency-jitter, latency+jitter] 范围内波动）
func (c *LimitedPacketConn) SetJitter(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.jitter = d
}

// SetLossRate 设置丢包率（0.0~1.0）
func (c *LimitedPacketConn) SetLossRate(rate float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lossRate = rate
}

// SetDisconnected 设置断连状态
// true: ReadFrom 静默丢弃包（黑洞），WriteTo 静默丢弃
// false: 恢复正常
func (c *LimitedPacketConn) SetDisconnected(disconnected bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.disconnected = disconnected
}

// Reset 清除所有网络损伤设置，恢复到正常状态
func (c *LimitedPacketConn) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bandwidth = 0
	c.latency = 0
	c.jitter = 0
	c.lossRate = 0
	c.disconnected = false
	c.tokens = 0
	c.maxTokens = 0
}

// ReadFrom 读取数据包，注入延迟和丢包
// 断连时静默丢弃包（黑洞模式），而非返回 error，避免 QUIC Transport 关闭
func (c *LimitedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		// 先从底层读取
		n, addr, err = c.inner.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}

		c.mu.Lock()
		disconnected := c.disconnected
		lossRate := c.lossRate
		delay := c.latency
		jitter := c.jitter
		c.mu.Unlock()

		// 断连状态：静默丢弃包（黑洞），模拟网络中断
		// 不返回 error — QUIC 会通过重传自行恢复
		if disconnected {
			continue // 丢弃，继续读下一个包
		}

		// 随机丢包：静默丢弃，继续读下一个
		if lossRate > 0 && c.rng.Float64() < lossRate {
			continue
		}

		// 注入延迟（+ 抖动）
		if delay > 0 {
			actualDelay := delay
			if jitter > 0 {
				// [-jitter, +jitter] 范围的随机偏移
				actualDelay += time.Duration(c.rng.Int63n(int64(2*jitter))) - jitter
				if actualDelay < 0 {
					actualDelay = 0
				}
			}
			time.Sleep(actualDelay)
		}

		return n, addr, nil
	}
}

// WriteTo 写入数据包，应用带宽限制和延迟
func (c *LimitedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	disconnected := c.disconnected
	c.mu.Unlock()

	// 断连状态：静默丢弃
	if disconnected {
		return len(p), nil
	}

	// 带宽限制（令牌桶）
	c.mu.Lock()
	bw := c.bandwidth
	c.mu.Unlock()

	if bw > 0 {
		c.waitTokens(len(p), bw)
	}

	return c.inner.WriteTo(p, addr)
}

// waitTokens 等待足够的令牌可用（令牌桶算法）
func (c *LimitedPacketConn) waitTokens(bytes int, bandwidth int64) {
	c.mu.Lock()
	now := time.Now()

	// 补充令牌：自上次 refill 以来的时间 × 带宽
	elapsed := now.Sub(c.lastRefill).Seconds()
	refill := int64(elapsed * float64(bandwidth))
	c.tokens += refill
	if c.tokens > c.maxTokens {
		c.tokens = c.maxTokens
	}
	c.lastRefill = now

	// 消耗令牌
	need := int64(bytes)
	if c.tokens >= need {
		c.tokens -= need
		c.mu.Unlock()
		return
	}

	// 令牌不足 — 计算需要等待的时间
	deficit := need - c.tokens
	c.tokens = 0
	c.mu.Unlock()

	// 等待 deficit 字节的令牌生成
	waitSec := float64(deficit) / float64(bandwidth)
	time.Sleep(time.Duration(waitSec * float64(time.Second)))
}

// LocalAddr 返回本地地址
func (c *LimitedPacketConn) LocalAddr() net.Addr {
	return c.inner.LocalAddr()
}

// Close 关闭连接
func (c *LimitedPacketConn) Close() error {
	return c.inner.Close()
}

// SetDeadline 设置截止时间
func (c *LimitedPacketConn) SetDeadline(t time.Time) error {
	return c.inner.SetDeadline(t)
}

// SetReadDeadline 设置读取截止时间
func (c *LimitedPacketConn) SetReadDeadline(t time.Time) error {
	return c.inner.SetReadDeadline(t)
}

// SetWriteDeadline 设置写入截止时间
func (c *LimitedPacketConn) SetWriteDeadline(t time.Time) error {
	return c.inner.SetWriteDeadline(t)
}
