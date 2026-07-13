// Package core 实现 MBTA 协议的核心原语：与传输无关的协议层基础组件。
//
// core 是 v1（QUIC）/ ntls（TCP+TLCP）等所有 binding 共享的协议地基，不依赖任何
// 具体传输。binding 层（internal/protocol 的 CoreHandler/CoreClient）在 core 之上编排
// 协议状态机，仅自身实现传输适配。
//
// 主要组件：
//   - 帧（frame.go）：MBTA wire 帧格式、Flags/FlowClass、Read/Write 与校验。
//   - SecureEnvelope（envelope.go）：HMAC 验签 + AEAD 加密 + 压缩的载荷封装（双轨密码套件）。
//   - 消息（message.go）：corepb 控制面/数据面消息类型别名与校验（ValidateHello/Auth/Batch）。
//   - SignalCodec（codec.go）：proto/cbor/json 信号批次编解码注册表，capability 驱动协商。
//   - capability（capability.go）：stable/deprecated/experimental 能力注册与 Negotiate 协商。
//   - session（session.go）：会话状态机、NegotiateResult、SessionStore（0-RTT 恢复）。
//   - auth（auth.go）：challenge-response 认证、SessionKeys 派生。
//   - delivery（delivery.go）：ReplayCache 重放去重、SeqGenerator 序号生成。
//   - flow（flow.go）：Inflight/Window 流控、ThrottleState 节流状态。
//   - metrics（metrics.go）：协议层可观测性抽象（Counter/Gauge/Histogram + NoOp 回退）。
//   - errors（errors.go）：结构化 Error（numCode/code/msg），错误码范围见 spec §13。
//   - ulid（ulid.go）：全局唯一 ChunkID（ULID 16B，并发安全单调熵）。
//
// 除非另有说明，core 中的 wire 常量（消息类型、Flags、CipherSuite 等）发布后不可改
// （core spec §1.4）。详见 docs/mbta-core-spec.md。
package core
