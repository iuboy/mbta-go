// Package v1 实现 MBTA v1（ALPN mbta/1）over QUIC + TLS 1.3 的传输 binding。
//
// v1 是薄 transport binding：协议逻辑（1-RTT 握手/Envelope/RESULT+CREDIT/drain）
// 全部委托给 internal/protocol.CoreClient/CoreHandler，本包仅实现 QUIC 传输适配——
// QUIC 多流（control stream + 单 data stream）+ QUIC DATAGRAM 不可靠通道。
// 帧路由按 type 高位通道域（core.IsControlType/IsDataType）。
//
// 默认 profile 为国际密码组合（X25519+HKDF-SHA256+AES-256-GCM）。
// 详见 docs/v2-design.md。
package v1
