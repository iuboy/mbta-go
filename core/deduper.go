package core

// deduper.go：应用层关联去重器（CorrelationDeduper）。
//
// 用途：跨连接 at-least-once 边界的应用层闭环（spec"部署模型与投递语义"节）。
// batch 在连接 1 上 accepted 未 durable → 连接死亡 → 客户端在连接 2 以新 seq
// 重发——任何 seq/epoch 设计都无法跨连接关联，标准做法是 sink 实现者按
// Batch.Meta.Correlation 幂等（Kafka consumer、Fluentd chunk dedup 同款）。
// 本类型提供进程级 LRU + 可选 TTL 的一行式实现：
//
//	d := core.NewCorrelationDeduper(65536, time.Hour)
//	func(ctx, ev, done) {
//	    if d.Dedup(ev.Meta.Correlation) { process(ev) }  // true=首次
//	    done(core.Outcome{Level: core.OutcomeDurable})    // 重复也确认（已处理过）
//	}
//
// 空 correlation 视为"不去重"（恒放行）——correlation 是可选字段，
// 未携带者的去重责任在应用自身。

import (
	"container/list"
	"sync"
	"time"
)

// CorrelationDeduper 是进程级 LRU 关联去重器（并发安全）。
type CorrelationDeduper struct {
	mu    sync.Mutex
	cap   int
	ttl   time.Duration
	seen  map[string]time.Time
	order list.List // key 到达序（队首最旧，容量淘汰）
}

// NewCorrelationDeduper 创建去重器。capacity ≤0 取 65536；ttl ≤0 表示不过期
// （仅容量淘汰）。
func NewCorrelationDeduper(capacity int, ttl time.Duration) *CorrelationDeduper {
	if capacity <= 0 {
		capacity = 65536
	}
	return &CorrelationDeduper{cap: capacity, ttl: ttl, seen: make(map[string]time.Time, 1024)}
}

// Dedup 报告 key 是否首次出现：首次返回 true（放行）并登记；重复或已过期被
// 淘汰后重新出现也返回 true。空 key 恒 true（不去重语义）。
func (d *CorrelationDeduper) Dedup(key string) bool {
	if key == "" {
		return true
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if ts, ok := d.seen[key]; ok {
		if d.ttl <= 0 || now.Sub(ts) < d.ttl {
			return false // 窗口内重复
		}
		delete(d.seen, key) // 过期：视作首次
		for e := d.order.Front(); e != nil; e = e.Next() {
			if e.Value.(string) == key {
				d.order.Remove(e)
				break
			}
		}
	}
	d.seen[key] = now
	d.order.PushBack(key)
	for len(d.seen) > d.cap {
		front := d.order.Front()
		if front == nil {
			break
		}
		delete(d.seen, front.Value.(string))
		d.order.Remove(front)
	}
	return true
}

// Seen 报告 key 是否在窗口内（不登记）。
func (d *CorrelationDeduper) Seen(key string) bool {
	if key == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	ts, ok := d.seen[key]
	if !ok {
		return false
	}
	return d.ttl <= 0 || time.Since(ts) < d.ttl
}

// Len 返回当前登记数。
func (d *CorrelationDeduper) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}
