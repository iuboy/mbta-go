# MBTA-NTLS/1 Protocol Specification / MBTA-NTLS/1 协议规范

> ⚠️ **SUPERSEDED（部分）：** 本文件为 `mbta-ntls/1` 早期草案（16B 帧 + JSON envelope）。
> 权威基准见 [mbta-core-spec.md](./mbta-core-spec.md) r2，TCP 传输规范见 [mbta-tcp-binding.md](./mbta-tcp-binding.md)。
> 冲突处（帧格式、envelope、消息类型编号）**以 core / 新 binding 为准**。保留作历史参考。

Category: Internet-Draft / 互联网草案  
Version: 1.0  
Protocol Name: `mbta-ntls/1`  
Frame Version: `0x01`

## 1. Status of This Memo / 本备忘录状态

This document is an Internet-Draft style specification for MBTA-NTLS/1, the TCP + NTLS/TLCP transport profile for MBTA. It defines a TCP byte-stream binding for MBTA frames and reuses MBTA SignalBatch and delivery semantics.

本文档是 MBTA-NTLS/1 的互联网草案风格规范。MBTA-NTLS/1 是 MBTA 的 TCP + NTLS/TLCP 传输 profile。它定义 MBTA 帧在 TCP 字节流上的绑定，并复用 MBTA SignalBatch 和投递语义。

## 2. Abstract / 摘要

MBTA-NTLS/1 transports MBTA telemetry signals over TCP protected by NTLS/TLCP. It uses independent TCP listener ports, MBTA framed messages, explicit channel metadata, SignalBatch payloads, and SecureEnvelope with HMAC-SM3 by default.

MBTA-NTLS/1 在 NTLS/TLCP 保护的 TCP 连接上传输 MBTA 遥测信号。它使用独立 TCP 监听端口、MBTA 帧消息、显式 channel 元数据、SignalBatch payload，并默认使用 HMAC-SM3 的 SecureEnvelope。

## 3. Conventions and Terminology / 约定与术语

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" are normative.

关键词 MUST、MUST NOT、SHOULD、SHOULD NOT、MAY 表示规范性要求。

## 4. Protocol Identification / 协议标识

| Field / 字段                    | Value / 值                                 |
| ------------------------------- | ------------------------------------------ |
| Protocol Name / 协议名          | `mbta-ntls/1`                              |
| Transport / 传输                | TCP + NTLS/TLCP                            |
| Frame Version / 帧版本          | `0x01`                                     |
| Payload / 负载                  | SignalBatch                                |
| Default Security / 默认安全模型 | `gm_transport` + `hmac_sm3`                |
| Port Strategy / 端口策略        | Dedicated TCP listener / 独立 TCP 监听端口 |

MBTA-NTLS/1 MUST NOT be multiplexed with QUIC on the same listener by protocol sniffing.

MBTA-NTLS/1 MUST NOT 通过协议嗅探与 QUIC 混用同一个监听入口。

## 5. Transport Binding / 传输绑定

A TCP connection MUST complete NTLS/TLCP handshake before any MBTA frame is accepted. A Server MUST reject BATCH before transport security and application authentication complete.

TCP 连接 MUST 先完成 NTLS/TLCP 握手，才能接收 MBTA 帧。Server MUST 拒绝传输安全和应用认证完成前的 BATCH。

Because TCP does not provide QUIC streams, MBTA-NTLS/1 MUST define explicit channel metadata. A channel descriptor contains:

由于 TCP 不提供 QUIC stream，MBTA-NTLS/1 MUST 定义显式 channel 元数据。channel 描述符包含：

```json
{
  "channel_id": 1,
  "channel_type": "control"
}
```

At least one control channel MUST exist per connection. Data channels MAY be multiplexed over the same TCP connection or carried by additional TCP connections if negotiated.

每条连接 MUST 至少有一个 control channel。data channel MAY 在同一 TCP 连接上复用，也 MAY 在协商后使用额外 TCP 连接承载。

## 6. Frame Format / 帧格式

MBTA-NTLS/1 uses the 16-byte MBTA frame header with `Version=0x01`.

MBTA-NTLS/1 使用 16 字节 MBTA 帧头，`Version=0x01`。

```text
Offset  Size  Field
0       4     Magic = "MBTA"
4       1     Version = 0x01
5       1     Flags
6       2     Type, big-endian uint16
8       4     Length, big-endian uint32
12      4     CRC32(payload), IEEE CRC32
```

Receivers MUST handle TCP fragmentation, coalescing, short reads, half-open connections, oversized lengths, and CRC mismatches.

接收端 MUST 处理 TCP 拆包、粘包、短读、半开连接、超大 length 和 CRC 不匹配。

## 7. Reused MBTA Semantics / 复用的 MBTA 语义

MBTA-NTLS/1 reuses:

MBTA-NTLS/1 复用：

- SignalBatch, Resource, Scope, and signal records / SignalBatch、Resource、Scope 和 signal records。
- `log`, `gauge`, `counter`, `histogram`, `summary`, and `span` signal types / 六类 signal type。
- HELLO, HELLO_ACK, AUTH, AUTH_OK, AUTH_FAIL。
- BATCH, ACK, NACK, PARTIAL_ACK。
- WINDOW, THROTTLE。
- PING, PONG, CLOSE。
- Spool and Durable ACK deletion rules / Spool 和 Durable ACK 删除规则。
- OTLP Logs, Metrics, and Traces mapping / OTLP Logs、Metrics 和 Traces 映射。

## 8. Application Security / 应用层安全

BATCH messages SHOULD use SecureEnvelope. HMAC-SM3 MUST be supported and SHOULD be the default HMAC algorithm. Application-layer SM4-GCM MAY be negotiated for end-to-end payload encryption.

BATCH 消息 SHOULD 使用 SecureEnvelope。HMAC-SM3 MUST 被支持，并且 SHOULD 作为默认 HMAC 算法。应用层 SM4-GCM MAY 通过协商启用，用于端到端 payload 加密。

## 9. Capability Advertisement / 能力声明

MBTA-NTLS/1 HELLO MUST declare:

MBTA-NTLS/1 HELLO MUST 声明：

```json
{
  "transport_profile": "ntls_tlcp_tcp",
  "secure_envelope": true,
  "hmac": ["sm3"],
  "payload": ["signal_batch_v1"]
}
```

Optional capabilities MAY include:

可选能力 MAY 包括：

- `app_encryption_sm4_gcm`
- `sm2_cert_auth`
- `multi_channel`
- `multi_connection`
- `partial_ack`
- `durable_ack`

## 10. Delivery and Flow Control / 投递与流控

TCP reliability MUST NOT be treated as Durable ACK. Durable ACK is returned only after server-side durable storage or reliable queue insertion.

TCP 可靠性 MUST NOT 被视为 Durable ACK。Durable ACK 只能在服务端持久化或写入可靠队列后返回。

WINDOW and THROTTLE semantics are the same as MBTA/1. Agents MUST account for TCP connection-level head-of-line blocking when applying flow control.

WINDOW 和 THROTTLE 语义与 MBTA/1 相同。Agent 应用流控时 MUST 考虑 TCP 连接级队头阻塞。

## 11. Security Considerations / 安全考虑

Implementations MUST validate NTLS/TLCP certificates, reject MBTA frames before secure transport completion, enforce payload limits, verify SecureEnvelope HMAC, and protect against replay.

实现 MUST 验证 NTLS/TLCP 证书、拒绝安全传输完成前的 MBTA 帧、强制 payload 限制、校验 SecureEnvelope HMAC，并防护重放。

Implementations MUST NOT mix QUIC and TCP traffic on the same listener by unreliable protocol detection.

实现 MUST NOT 通过不可靠协议检测在同一监听入口混合 QUIC 和 TCP 流量。

## 12. Registry / 注册表

The protocol name is `mbta-ntls/1`. The frame version is `0x01`.

协议名为 `mbta-ntls/1`。帧版本为 `0x01`。

## 13. Conformance / 一致性

An implementation conforms to MBTA-NTLS/1 only if it implements TCP + NTLS/TLCP transport security, explicit channel handling, MBTA frame parsing, SignalBatch payloads, SecureEnvelope, delivery acknowledgement rules, and flow-control behavior specified here.

实现只有实现本文规定的 TCP + NTLS/TLCP 传输安全、显式 channel 处理、MBTA 帧解析、SignalBatch payload、SecureEnvelope、投递确认规则和流控行为，才符合 MBTA-NTLS/1。
