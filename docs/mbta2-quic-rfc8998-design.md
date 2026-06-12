# MBTA/2 设计

## 1. 定位

`mbta/2` 是 MBTA 的 QUIC 国密传输入口，ALPN 固定为 `mbta/2`。它复用 MBTA 的 SignalBatch、BATCH、ACK、NACK、PARTIAL_ACK、WINDOW、THROTTLE、spool 和 OTLP 映射语义，区别在于传输层使用 RFC 8998 TLS 1.3 国密套件。

`mbta/2` 不替代 `mbta/1`。两者可以在同一 QUIC 监听端口上通过 ALPN 区分。

## 2. 协议入口

| 项           | 值                          |
| ------------ | --------------------------- |
| ALPN         | `mbta/2`                    |
| 帧版本       | `0x02`                      |
| 传输         | QUIC + RFC 8998 TLS 1.3     |
| 默认安全模型 | `gm_transport` + `hmac_sm3` |
| Payload      | SignalBatch                 |

## 3. 传输安全

`mbta/2` 的传输层必须满足 RFC 8998 国密 TLS 1.3 语义：

- TLS cipher suite 使用 SM4-GCM + SM3。
- Transcript hash 使用 SM3。
- Key schedule 使用 HKDF-SM3。
- 证书和签名路径支持 SM2。
- QUIC packet protection 使用与 TLS exporter 一致的国密密钥派生。

实现不得仅通过普通 Go `crypto/tls` cipher suite ID 模拟 RFC 8998。只有当 QUIC TLS handshake、packet protection、header protection、key update 和 resumption 均按 RFC 8998 路径实现时，才能声明支持 `mbta/2`。

## 4. 应用层安全

`mbta/2` 的默认应用层安全能力为：

- BATCH 仍使用 SecureEnvelope。
- HMAC 默认使用 HMAC-SM3。
- 应用层 SM4-GCM 不默认启用。

原因是传输层已经提供 SM4-GCM 机密性。应用层 SM4-GCM 只用于端到端 payload 加密、服务端 TLS 终止后仍需保持密文、或多租户隔离要求明确的场景。

## 5. 复用语义

`mbta/2` 复用以下 `mbta/1` 语义：

- SignalBatch。
- Resource / Scope / Signal records。
- `signal_type="log"`、`gauge`、`counter`、`histogram`、`summary`、`span`。
- HELLO / HELLO_ACK capability 协商。
- AUTH / AUTH_OK / AUTH_FAIL。
- BATCH / ACK / NACK / PARTIAL_ACK。
- WINDOW / THROTTLE。
- PING / PONG / CLOSE。
- Spool 删除规则。
- Durable ACK 语义。
- OTLP Logs / Metrics / Traces 映射。

## 6. 差异语义

| 维度             | `mbta/1`                       | `mbta/2`         |
| ---------------- | ------------------------------ | ---------------- |
| ALPN             | `mbta/1`                       | `mbta/2`         |
| 帧版本           | `0x01`                         | `0x02`           |
| TLS              | 标准 TLS 1.3                   | RFC 8998 TLS 1.3 |
| 传输层 AEAD      | Go/quic-go 支持的 TLS 1.3 AEAD | SM4-GCM          |
| 传输层 hash      | 标准 TLS 1.3 hash              | SM3              |
| 应用层 HMAC 默认 | HMAC-SHA256 或协商能力         | HMAC-SM3         |
| 应用层 SM4-GCM   | capability 启用                | 可选，不默认启用 |

## 7. Capability

`mbta/2` 必须声明：

```json
{
  "transport_profile": "gm_rfc8998_quic",
  "secure_envelope": true,
  "hmac": ["sm3"],
  "payload": ["signal_batch_v1"]
}
```

可选能力：

- `app_encryption_sm4_gcm`
- `sm2_cert_auth`
- `multi_data_stream`
- `partial_ack`
- `durable_ack`

## 8. 验收标准

`mbta/2` 发布前必须通过：

- ALPN `mbta/2` 协商测试。
- RFC 8998 TLS 1.3 handshake 测试。
- QUIC packet protection 国密路径测试。
- SM2 证书链验证测试。
- HMAC-SM3 SecureEnvelope 测试。
- SignalBatch 端到端投递测试。
- ACK / NACK / PARTIAL_ACK / Durable ACK 测试。
- OTLP Logs / Metrics / Traces 映射测试。
- 与 `mbta/1` 共端口 ALPN 分流测试。

## 9. 禁止项

- 禁止把 `mbta/2` 降级为标准 TLS 1.3。
- 禁止用普通 TLS cipher suite 配置假装 RFC 8998 QUIC。
- 禁止在 `mbta/2` 中接受 `mbta/1` 帧版本。
- 禁止将 `mbta/2` 的应用层 SM4-GCM 设为默认强制能力。
