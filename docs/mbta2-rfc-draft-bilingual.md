# MBTA/2 Protocol Specification / MBTA/2 协议规范

> ⚠️ **SUPERSEDED（部分）：** 权威基准见 [mbta-core-spec.md](./mbta-core-spec.md) r2，QUIC 传输规范见 [mbta-quic-binding.md](./mbta-quic-binding.md)。`mbta/2`（QUIC+RFC8998 国密）依赖无独立 RFC 的国密 QUIC 实现，可用性待生态成熟（见 core §10）。冲突处以 core 为准。

Category: Internet-Draft / 互联网草案  
Version: 1.0  
ALPN: `mbta/2`  
Frame Version: `0x02`

## 1. Status of This Memo / 本备忘录状态

This document is an Internet-Draft style specification for MBTA/2, the QUIC + RFC 8998 TLS 1.3 transport profile for MBTA. It defines the transport-security differences from MBTA/1 while reusing MBTA SignalBatch and delivery semantics.

本文档是 MBTA/2 的互联网草案风格规范。MBTA/2 是 MBTA 的 QUIC + RFC 8998 TLS 1.3 传输 profile。本文档定义其相对 MBTA/1 的传输安全差异，同时复用 MBTA SignalBatch 和投递语义。

## 2. Abstract / 摘要

MBTA/2 carries MBTA telemetry signals over QUIC with RFC 8998 TLS 1.3 national cryptographic algorithms. It uses ALPN `mbta/2`, frame version `0x02`, SignalBatch payloads, and SecureEnvelope with HMAC-SM3 by default.

MBTA/2 通过使用 RFC 8998 TLS 1.3 国密算法的 QUIC 传输 MBTA 遥测信号。它使用 ALPN `mbta/2`、帧版本 `0x02`、SignalBatch payload，并默认使用 HMAC-SM3 的 SecureEnvelope。

## 3. Conventions and Terminology / 约定与术语

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" are normative.

关键词 MUST、MUST NOT、SHOULD、SHOULD NOT、MAY 表示规范性要求。

## 4. Protocol Identification / 协议标识

| Field / 字段                    | Value / 值                  |
| ------------------------------- | --------------------------- |
| ALPN                            | `mbta/2`                    |
| Transport / 传输                | QUIC + RFC 8998 TLS 1.3     |
| Frame Version / 帧版本          | `0x02`                      |
| Payload / 负载                  | SignalBatch                 |
| Default Security / 默认安全模型 | `gm_transport` + `hmac_sm3` |

Endpoints MUST negotiate ALPN `mbta/2`. MBTA/2 endpoints MUST NOT accept frame version `0x01` as MBTA/2 traffic.

端点 MUST 协商 ALPN `mbta/2`。MBTA/2 端点 MUST NOT 将帧版本 `0x01` 作为 MBTA/2 流量接受。

## 5. Transport Security / 传输安全

MBTA/2 MUST implement the RFC 8998 TLS 1.3 national cryptographic profile for QUIC. A conforming implementation MUST provide:

MBTA/2 MUST 为 QUIC 实现 RFC 8998 TLS 1.3 国密 profile。符合规范的实现 MUST 提供：

- SM4-GCM based TLS cipher suites / 基于 SM4-GCM 的 TLS cipher suite。
- SM3 transcript hash / SM3 transcript hash。
- HKDF-SM3 key schedule / HKDF-SM3 密钥派生。
- SM2 certificate and signature support / SM2 证书和签名支持。
- QUIC packet protection derived from the RFC 8998 TLS handshake / 从 RFC 8998 TLS 握手派生的 QUIC packet protection。
- Header protection, key update, and resumption consistent with the selected national cryptographic profile / 与所选国密 profile 一致的 header protection、key update 和 resumption。

An implementation MUST NOT claim MBTA/2 support by only configuring cipher suite identifiers in a standard TLS stack.

实现 MUST NOT 仅通过在标准 TLS 栈中配置 cipher suite 标识来声明支持 MBTA/2。

## 6. Reused MBTA Semantics / 复用的 MBTA 语义

MBTA/2 reuses the following MBTA semantics:

MBTA/2 复用以下 MBTA 语义：

- SignalBatch, Resource, Scope, and signal records / SignalBatch、Resource、Scope 和 signal records。
- `log`, `gauge`, `counter`, `histogram`, `summary`, and `span` signal types / 六类 signal type。
- HELLO, HELLO_ACK, AUTH, AUTH_OK, AUTH_FAIL。
- BATCH, ACK, NACK, PARTIAL_ACK。
- WINDOW, THROTTLE。
- PING, PONG, CLOSE。
- Spool and Durable ACK deletion rules / Spool 和 Durable ACK 删除规则。
- OTLP Logs, Metrics, and Traces mapping / OTLP Logs、Metrics 和 Traces 映射。

## 7. Application Security / 应用层安全

BATCH messages SHOULD use SecureEnvelope. HMAC-SM3 MUST be supported and SHOULD be the default HMAC algorithm.

BATCH 消息 SHOULD 使用 SecureEnvelope。HMAC-SM3 MUST 被支持，并且 SHOULD 作为默认 HMAC 算法。

Application-layer SM4-GCM MAY be negotiated for end-to-end payload encryption. It MUST NOT be mandatory by default because the transport layer already provides SM4-GCM confidentiality.

应用层 SM4-GCM MAY 通过协商启用，用于端到端 payload 加密。由于传输层已经提供 SM4-GCM 机密性，它 MUST NOT 默认强制启用。

## 8. Capability Advertisement / 能力声明

MBTA/2 HELLO MUST declare the transport profile:

MBTA/2 HELLO MUST 声明传输 profile：

```json
{
  "transport_profile": "gm_rfc8998_quic",
  "secure_envelope": true,
  "hmac": ["sm3"],
  "payload": ["signal_batch_v1"]
}
```

Optional capabilities MAY include:

可选能力 MAY 包括：

- `app_encryption_sm4_gcm`
- `sm2_cert_auth`
- `multi_data_stream`
- `partial_ack`
- `durable_ack`

## 9. Wire Format / 线格式

MBTA/2 uses the same 16-byte MBTA frame header as MBTA/1, with `Version=0x02`.

MBTA/2 使用与 MBTA/1 相同的 16 字节 MBTA 帧头，但 `Version=0x02`。

```text
Offset  Size  Field
0       4     Magic = "MBTA"
4       1     Version = 0x02
5       1     Flags
6       2     Type, big-endian uint16
8       4     Length, big-endian uint32
12      4     CRC32(payload), IEEE CRC32
```

## 10. Interoperability with MBTA/1 / 与 MBTA/1 的互操作

MBTA/1 and MBTA/2 MAY share a QUIC listening port. The selected protocol MUST be determined by ALPN. A server MUST NOT silently downgrade MBTA/2 to MBTA/1.

MBTA/1 和 MBTA/2 MAY 共用一个 QUIC 监听端口。选定协议 MUST 由 ALPN 决定。Server MUST NOT 将 MBTA/2 静默降级为 MBTA/1。

## 11. Security Considerations / 安全考虑

Implementations MUST validate SM2 certificate chains, enforce RFC 8998 handshake semantics, reject downgrade attempts, verify SecureEnvelope HMAC, and protect against replay and oversized payloads.

实现 MUST 验证 SM2 证书链、强制 RFC 8998 握手语义、拒绝降级尝试、校验 SecureEnvelope HMAC，并防护重放和超大 payload。

## 12. Registry / 注册表

The ALPN identifier for this protocol is `mbta/2`. The frame version is `0x02`.

本协议的 ALPN 标识为 `mbta/2`。帧版本为 `0x02`。

## 13. Conformance / 一致性

An implementation conforms to MBTA/2 only if it implements RFC 8998 QUIC transport semantics, uses ALPN `mbta/2`, emits frame version `0x02`, and satisfies all reused MBTA SignalBatch, delivery, and SecureEnvelope requirements.

实现只有实现 RFC 8998 QUIC 传输语义、使用 ALPN `mbta/2`、发出帧版本 `0x02`，并满足所有复用的 MBTA SignalBatch、投递和 SecureEnvelope 要求，才符合 MBTA/2。
