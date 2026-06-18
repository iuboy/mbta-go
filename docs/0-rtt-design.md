# 0-RTT（early_data）实现状态

**状态：已实现（QUIC binding 支持；TCP binding 不支持）**

## 为何 TCP 不支持

Go `crypto/tls` 的 TLS 1.3 实现：

- ✅ session resumption（ClientSessionCache → 1-RTT resumption）
- ❌ 0-RTT application data（tls.Conn 在握手后才暴露 Write；无 early data API）

要实现 TCP 0-RTT data 需：

1. 第三方 TLS 库（如 `refraction-networking/utls`）——引入非标准依赖
2. 或自定义 TLS 0-RTT 层——复杂

协议规范将 `early_data` 限定为仅 QUIC。

