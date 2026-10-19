// Package core 实现 MBTA 协议的核心原语（r3 重设计）：与传输无关的协议层基础组件。
//
// 主要组件：
//   - 帧（frame.go）：[type][flags][varint len] wire 帧格式；type 高位为通道域。
//   - 密钥日程（keyschedule.go）：ECDH + transcript 绑定 + HKDF split；密钥永不上 wire。
//   - Envelope（envelope.go）：compress-then-encrypt、确定性 nonce、AD 绑定全部明文元数据。
//   - 消息（message.go）：控制面消息校验（ValidateHello/HelloAck）。
//   - credit（credit.go）：客户端 CreditLedger（模型 B）+ 服务端 AdmissionWindow（集合制窗口+终态环）。
//   - session（session.go）：客户端 4 态 / 服务端 3 态状态机。
//   - auth（auth.go）：TokenValidator（ResolveToken 必选）+ token_proof 验证。
//   - cipher（cipher.go）：profile 密码组合（intl/gm）。
//   - codec（codec*.go）：SignalBatch 编解码（proto 默认 / cbor）。
//   - errors（errors.go）：数字错误码注册表（wire 只传数字；append-only）。
//   - ulid（ulid.go）：会话 ID 生成。
package core
