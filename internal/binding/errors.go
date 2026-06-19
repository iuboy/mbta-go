// Package binding 收敛 v1（QUIC）/ ntls（TCP+TLCP）binding 的共享骨架：
// accept 循环、握手编排。各 binding 仅实现传输工厂接口。
package binding

// DefaultMaxConcurrentConns 是未配置时的并发连接上限（H-3）。
const DefaultMaxConcurrentConns = 10000
