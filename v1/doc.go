// Package v1 实现 MBTA v1（ALPN mbta/1）over QUIC + TLS 1.3 的传输 binding。
//
// v1 是薄 transport binding：协议逻辑（握手/envelope/投递/流控/ACK/drain/heartbeat）
// 全部委托给 internal/protocol.CoreClient/CoreHandler，本包仅实现 QUIC 传输适配——
// QUIC 多流（control stream + N 并发 data stream）、0-RTT early_data（DialEarly）、
// stream picker（single/hash 负载分发）。
//
// 国际密码套件（AES-256-GCM + HMAC-SHA256）。所有协议语义共享 core 包。
// 详见 docs/mbta-core-spec.md。
package v1
