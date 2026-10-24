// Package binding 是 v1/ntls 两个顶层 binding 的共享服务端外壳与客户端握手
// 编排：泛型 Server（accept 循环骨架 + 三态状态机）、AcceptLoop/handleConn、
// Handshake/ClientCoreConfig。
//
// DefaultMaxConcurrentConns（并发连接上限默认值，H-3 裁决）定义在 server.go。
package binding
