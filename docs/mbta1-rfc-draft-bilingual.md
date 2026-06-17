# MBTA/1 Protocol Specification / MBTA/1 协议规范

> ⚠️ **SUPERSEDED（部分）：** 本文件为 `mbta/1` 早期草案（16B 帧 + JSON envelope）。
> 权威基准见 [mbta-core-spec.md](./mbta-core-spec.md) r2（8B 帧 / proto envelope / 双投递通道等），
> QUIC 传输规范见 [mbta-quic-binding.md](./mbta-quic-binding.md)。
> 本文与 core r2 冲突处（帧格式、envelope、消息类型编号、投递语义）**以 core / 新 binding 为准**。保留作历史参考。

Category: Internet-Draft / 互联网草案  
Version: 1.0  
ALPN: `mbta/1`  
Frame Version: `0x01`

## 1. Status of This Memo / 本备忘录状态

This document is an Internet-Draft style specification for MBTA/1, the QUIC + TLS 1.3 transport profile for the Mebsuta telemetry forwarding protocol. It is a draft used to align implementation and conformance tests.

本文档是 MBTA/1 的互联网草案风格规范。MBTA/1 是 Mebsuta 遥测转发协议的 QUIC + TLS 1.3 传输 profile。本文档用于对齐实现和一致性测试。

## 2. Abstract / 摘要

MBTA/1 transports telemetry signals from Agents to Servers over QUIC with mandatory TLS 1.3. It defines framing, session negotiation, authentication, SecureEnvelope processing, SignalBatch payloads, delivery acknowledgements, flow control, and OTLP-compatible signal mapping.

MBTA/1 通过强制 TLS 1.3 的 QUIC 连接，将遥测信号从 Agent 转发到 Server。协议定义帧格式、会话协商、认证、SecureEnvelope 处理、SignalBatch payload、投递确认、流控以及与 OTLP 兼容的信号映射。

## 3. Conventions and Terminology / 约定与术语

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" are to be interpreted as normative requirements.

关键词 MUST、MUST NOT、SHOULD、SHOULD NOT、MAY 表示规范性要求。

| Term / 术语    | Meaning / 含义                                                                                                                       |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Agent          | The endpoint that collects and sends telemetry signals. / 采集并发送遥测信号的一端。                                                 |
| Server         | The endpoint that receives, validates, acknowledges, and routes telemetry signals. / 接收、校验、确认并路由遥测信号的一端。          |
| SignalBatch    | A batch payload containing resource, scope, and signal records. / 包含 resource、scope 和 signal records 的批次 payload。            |
| SecureEnvelope | The application-layer envelope for encoding, compression, encryption, and authentication. / 承载编码、压缩、加密和认证的应用层信封。 |
| Durable ACK    | An acknowledgement returned after durable storage or reliable queue insertion. / 服务端持久化或写入可靠队列后返回的确认。            |

## 4. Protocol Identification / 协议标识

An MBTA/1 endpoint MUST use ALPN `mbta/1`. The MBTA frame version MUST be `0x01`.

MBTA/1 端点 MUST 使用 ALPN `mbta/1`。MBTA 帧版本 MUST 为 `0x01`。

| Field / 字段                    | Value / 值                  |
| ------------------------------- | --------------------------- |
| ALPN                            | `mbta/1`                    |
| Transport / 传输                | QUIC + TLS 1.3              |
| Frame Version / 帧版本          | `0x01`                      |
| Payload / 负载                  | SignalBatch                 |
| Default Security / 默认安全模型 | `standard` or `gm_envelope` |

## 5. Transport / 传输层

MBTA/1 MUST run over QUIC with TLS 1.3. The client MUST validate the server certificate and SNI unless explicitly configured for a development environment. Production deployments MUST NOT enable insecure certificate verification.

MBTA/1 MUST 运行在 QUIC + TLS 1.3 之上。客户端 MUST 验证服务端证书和 SNI，除非显式配置为开发环境。生产部署 MUST NOT 启用不安全证书验证。

MBTA/1 defines two stream roles:

MBTA/1 定义两类 stream：

| Stream / 流    | Direction / 方向                                     | Purpose / 用途                                   |
| -------------- | ---------------------------------------------------- | ------------------------------------------------ |
| Control Stream | Bidirectional, opened by Agent / 双向，由 Agent 打开 | HELLO, AUTH, WINDOW, THROTTLE, PING, PONG, CLOSE |
| Data Stream    | Bidirectional, opened by Agent / 双向，由 Agent 打开 | BATCH and ACK/NACK/PARTIAL_ACK                   |

The first bidirectional stream opened by the Agent MUST be treated as the Control Stream. A Server MUST reject Data Streams before authentication completes.

Agent 打开的第一条双向 stream MUST 作为 Control Stream。认证完成前，Server MUST 拒绝 Data Stream。

## 6. Frame Format / 帧格式

All MBTA messages MUST be encoded as a 16-byte header followed by a payload.

所有 MBTA 消息 MUST 编码为 16 字节帧头加 payload。

```text
Offset  Size  Field
0       4     Magic = "MBTA"
4       1     Version = 0x01
5       1     Flags
6       2     Type, big-endian uint16
8       4     Length, big-endian uint32
12      4     CRC32(payload), IEEE CRC32
```

Receivers MUST reject invalid magic, unsupported version, oversized payloads, short reads, and CRC mismatches.

接收端 MUST 拒绝非法 magic、不支持的版本、超大 payload、短读和 CRC 不匹配。

## 7. Message Types / 消息类型

| Type / 类型 | Direction / 方向     | Meaning / 含义                                                            |
| ----------- | -------------------- | ------------------------------------------------------------------------- |
| HELLO       | Agent -> Server      | Version and capability negotiation / 版本和能力协商                       |
| HELLO_ACK   | Server -> Agent      | Selected capabilities and connection parameters / 选定能力和连接参数      |
| AUTH        | Agent -> Server      | Authentication request / 认证请求                                         |
| AUTH_OK     | Server -> Agent      | Authentication success / 认证成功                                         |
| AUTH_FAIL   | Server -> Agent      | Authentication failure / 认证失败                                         |
| BATCH       | Agent -> Server      | SignalBatch transfer / SignalBatch 传输                                   |
| ACK         | Server -> Agent      | Whole-batch acknowledgement / 整批确认                                    |
| NACK        | Server -> Agent      | Whole-batch rejection / 整批拒绝                                          |
| PARTIAL_ACK | Server -> Agent      | Partial success and per-signal failure details / 部分成功和逐信号失败详情 |
| WINDOW      | Server -> Agent      | Flow-control window update / 流控窗口更新                                 |
| THROTTLE    | Server -> Agent      | Rate throttling instruction / 速率节流指令                                |
| PING / PONG | Bidirectional / 双向 | Health check / 健康检查                                                   |
| CLOSE       | Bidirectional / 双向 | Graceful close / 优雅关闭                                                 |
| ERROR       | Bidirectional / 双向 | Protocol error / 协议错误                                                 |

## 8. Session and Authentication / 会话与认证

An Agent MUST complete HELLO/HELLO_ACK and AUTH/AUTH_OK before sending BATCH. A Server MUST reject BATCH messages before authentication completes.

Agent MUST 在发送 BATCH 前完成 HELLO/HELLO_ACK 和 AUTH/AUTH_OK。Server MUST 拒绝认证完成前的 BATCH。

HELLO MUST declare supported capabilities. HELLO_ACK MUST select the active capabilities. Unsupported or unselected capabilities MUST NOT be used on the connection.

HELLO MUST 声明支持的能力。HELLO_ACK MUST 选择连接启用的能力。未支持或未选定的能力 MUST NOT 在连接上使用。

## 9. SignalBatch Payload / SignalBatch 负载

BATCH payload MUST be a SignalBatch. Event-array payloads are not valid MBTA/1 conformance inputs.

BATCH payload MUST 为 SignalBatch。事件数组 payload 不是合法的 MBTA/1 一致性输入。

```json
{
  "schema_url": "https://mebsuta.io/schemas/mbta/signal-batch/v1",
  "resource": {},
  "scope": {},
  "signals": []
}
```

Each signal record MUST include `signal_type`. Logs MUST use `signal_type="log"`; an empty string MUST NOT represent a log.

每条 signal record MUST 包含 `signal_type`。日志 MUST 使用 `signal_type="log"`；空字符串 MUST NOT 表示日志。

Supported signal types are `log`, `gauge`, `counter`, `histogram`, `summary`, and `span`.

支持的 signal type 为 `log`、`gauge`、`counter`、`histogram`、`summary`、`span`。

## 10. SecureEnvelope / 安全信封

BATCH SHOULD be carried in SecureEnvelope. SecureEnvelope processing order is:

BATCH SHOULD 使用 SecureEnvelope 承载。SecureEnvelope 处理顺序为：

1. Canonical JSON encoding / 规范 JSON 编码。
2. Optional compression / 可选压缩。
3. Optional encryption / 可选加密。
4. HMAC generation / 生成 HMAC。
5. Envelope serialization / 序列化 envelope。

Receivers MUST verify HMAC before decrypting or decoding the business object. SM4-GCM nonce values MUST be explicit and MUST NOT be reused with the same key.

接收端 MUST 在解密或解析业务对象前验证 HMAC。SM4-GCM nonce MUST 显式传输，并且在同一密钥下 MUST NOT 复用。

## 11. Delivery Semantics / 投递语义

Each BATCH MUST include `seq` and `chunk_id`. `seq` is monotonic within an Agent session. `chunk_id` MUST be globally unique enough for deduplication and replay protection.

每个 BATCH MUST 包含 `seq` 和 `chunk_id`。`seq` 在 Agent 会话内单调递增。`chunk_id` MUST 具备足够全局唯一性，用于去重和抗重放。

If `durable_required=true`, an Agent MUST delete local spool records only after receiving Durable ACK. NACK, timeout, and connection loss MUST NOT delete pending spool data.

当 `durable_required=true` 时，Agent MUST 只在收到 Durable ACK 后删除本地 spool 记录。NACK、超时和连接中断 MUST NOT 删除待确认 spool 数据。

PARTIAL_ACK MUST identify failed signals by `event_id` or signal index.

PARTIAL_ACK MUST 通过 `event_id` 或 signal index 定位失败信号。

## 12. Flow Control / 流控

WINDOW defines the accepted inflight capacity. THROTTLE defines a temporary rate limit. Agents MUST obey both MBTA flow-control messages and QUIC transport flow control.

WINDOW 定义允许的 inflight 容量。THROTTLE 定义临时速率限制。Agent MUST 同时遵守 MBTA 流控消息和 QUIC 传输层流控。

## 13. OTLP Mapping / OTLP 映射

Servers MUST preserve enough data to map MBTA SignalBatch to OTLP Logs, Metrics, and Traces.

Server MUST 保留足够信息，将 MBTA SignalBatch 映射为 OTLP Logs、Metrics 和 Traces。

| MBTA / MBTA 字段          | OTLP / OTLP 字段     |
| ------------------------- | -------------------- |
| `resource`                | Resource             |
| `scope`                   | InstrumentationScope |
| `signal_type="log"`       | Logs LogRecord       |
| `signal_type="gauge"`     | Metrics Gauge        |
| `signal_type="counter"`   | Metrics Sum          |
| `signal_type="histogram"` | Metrics Histogram    |
| `signal_type="summary"`   | Metrics Summary      |
| `signal_type="span"`      | Traces Span          |

## 14. Security Considerations / 安全考虑

Implementations MUST enforce TLS 1.3, certificate validation, payload size limits, HMAC verification, replay detection, and spool deletion rules. Production configurations MUST NOT allow insecure TLS verification.

实现 MUST 强制 TLS 1.3、证书验证、payload 大小限制、HMAC 校验、重放检测和 spool 删除规则。生产配置 MUST NOT 允许不安全 TLS 验证。

## 15. Registry / 注册表

The ALPN identifier for this protocol is `mbta/1`. The frame version is `0x01`.

本协议的 ALPN 标识为 `mbta/1`。帧版本为 `0x01`。

## 16. Conformance / 一致性

An implementation conforms to MBTA/1 only if it implements the mandatory transport, frame, session, SignalBatch, SecureEnvelope, delivery, flow-control, and OTLP mapping requirements in this document.

实现只有满足本文档中强制规定的传输、帧、会话、SignalBatch、SecureEnvelope、投递、流控和 OTLP 映射要求，才符合 MBTA/1。
