// Package core 实现 MBTA 协议的核心原语（r3 重设计）：与传输无关的协议层基础组件。
//
// 主要组件：
//   - 帧（frame.go）：[type][flags][varint len] wire 帧格式；type 高位为通道域。
//   - 密钥日程（keyschedule.go）：ECDH + transcript 绑定 + HKDF split；密钥永不上 wire。
//   - Envelope（envelope.go）：compress-then-encrypt、确定性 nonce、AD 绑定全部明文元数据。
//   - 消息（message.go）：控制面消息校验（ValidateHello/HelloAck）。
//   - credit（credit.go）：客户端 CreditLedger（模型 B 账本）+ 服务端 CreditManager
//     （准入/去重/额度守恒的单一真相：low 前缀集合 + 终态环 + SettleGrant 令牌）。
//   - session（session.go）：客户端 4 态 / 服务端 3 态状态机。
//   - session_event（session_event.go）：会话生命周期回调（OnSession/SessionEvent）。
//   - policy（policy.go）：服务端策略与协商（capabilities 交集、limits、ack_mode、初始 credit）。
//   - sink（sink.go）：注册式投递契约（SinkOptions + BatchHandler + done(Outcome)）。
//   - auth（auth.go）：TokenValidator（ResolveToken 必选）+ token_proof 验证。
//   - cipher（cipher.go）：profile 密码组合（intl/gm）。
//   - codec（codec*.go）：SignalBatch 编解码（proto 默认 / cbor；解码侧条数/深度上限）。
//   - signal（signal.go）：七类信号数据模型（log/gauge/counter/histogram/summary/
//     span/profile，对齐 OTLP——spec 附录 B 的 signal_type 注册表）与逐字段校验。
//   - metrics（metrics.go）：MBTAMetrics/Metrics 可观测性接口（prometheus 实现）。
//   - validation（validation.go）：不可信输入防线（长度/控制字符/host:port 校验、
//     SanitizeForLog——spec §11.3）。
//   - errors（errors.go）：数字错误码注册表（wire 只传数字；append-only）。
//   - types（types.go）：帧类型注册表（append-only）与通道域判定。
//   - send_option（send_option.go）：SendBatch 的 per-call 发送选项（trace 上下文等）。
//   - dedup（deduper.go）：CorrelationDeduper（跨连接 at-least-once 边界的应用层幂等）。
//   - ulid（ulid.go）：会话 ID 生成。
package core
