# MBTA v1 设计

## 1. 定位

MBTA v1 是用于 Agent 向 Server 转发遥测信号的可靠传输协议。帧头 `Version` 固定为 `0x01`，QUIC ALPN 固定为 `mbta/1`。本版文档作为 MBTA v1 冻结规范的起点。

MBTA 不重复发明遥测数据模型。v1 的 payload 模型吸收 OpenTelemetry 的核心分层：`Resource` + `InstrumentationScope` + signal records。MBTA 负责 Agent 场景下的 QUIC 连接、认证、可靠投递、spool、ACK、流控和国密 envelope；Server 侧必须能够把 MBTA signal 无损映射为 OTLP Logs / Metrics / Traces。

v1 的核心目标：

- 基于 QUIC 提供可靠、有序、多流、加密传输。
- 强制使用 TLS 1.3 作为传输层安全基础。
- 通过能力协商独立启用压缩、HMAC、国密应用层能力、部分成功、流控和 OTLP-like SignalBatch 等功能。
- 使用 SecureEnvelope 统一描述编码、压缩、加密和认证顺序。
- 明确定义 ACK、NACK、PARTIAL_ACK，支持可靠转发和精确重试。
- 通过 WINDOW 和 THROTTLE 控制慢消费者、服务端过载和客户端内存占用。
- 统一传输日志、指标和 trace，不为不同信号类型新增独立消息类型。

## 2. 协议入口

| 入口 | 帧版本 | 传输 | 默认安全模型 | 状态 |
|------|--------|------|--------------|------|
| `mbta/1` | `0x01` | QUIC + 标准 TLS 1.3 | `standard` 或 `gm_envelope` | v1 入口 |

约束：

- MBTA v1 不包含 RFC 8998 QUIC 国密传输。
- MBTA v1 不包含 TCP + NTLS/TLCP。
- 应用层国密能力通过 SecureEnvelope 表达，不改变 QUIC 传输层。

## 3. 分层模型

MBTA v1 分为以下协议层：

1. Transport：QUIC + TLS 1.3 + ALPN。
2. Framing：16 字节 MBTA 帧头、payload 长度、类型和 CRC32。
3. Session：HELLO / HELLO_ACK，完成版本确认、能力协商和连接参数下发。
4. Authentication：AUTH / AUTH_OK / AUTH_FAIL，支持 Token、mTLS 绑定和 SM2 证书能力。
5. Security Envelope：统一编码、压缩、加密、HMAC。
6. Signal Model：Resource、Scope、LogRecord、MetricPoint 和 SpanRecord。
7. Delivery：BATCH、ACK、NACK、PARTIAL_ACK、seq、chunk_id。
8. Flow Control：WINDOW、THROTTLE。
9. Health and Close：PING、PONG、CLOSE。
10. Operations：错误码、限制、指标、审计和演进策略。

实现层建议保持同样边界：

```text
internal/mbta/
  frame/
  message/
  transport/
  session/
  envelope/
  security/
  delivery/
  flow/
  spool/
  server/
  client/
  conformance/
```

## 4. 传输与 Stream

MBTA v1 使用标准 QUIC + TLS 1.3：

- 服务端必须提供证书。
- 客户端默认必须验证服务端证书链和 SNI / ServerName。
- `tls_insecure_skip_verify` 只允许开发或测试环境使用，生产配置必须拒绝或显式告警。
- 0-RTT 不允许发送 AUTH 或 BATCH。

Stream 模型：

| Stream | 类型 | 发起方 | 用途 |
|--------|------|--------|------|
| Control Stream | bidirectional | Agent | HELLO、AUTH、WINDOW、THROTTLE、PING/PONG、CLOSE |
| Data Stream | bidirectional | Agent | BATCH 及对应 ACK/NACK/PARTIAL_ACK |

规则：

- 第一个由 Agent 打开的双向 stream 作为 Control Stream。
- HELLO / AUTH 完成前，服务端只接受控制消息。
- 未认证连接打开 Data Stream 时，服务端返回或触发 `ERR_AUTH_REQUIRED`。
- v1 基础实现可以只支持一个 Data Stream，多 Data Stream 需要 capability 协商。

## 5. 帧与消息

所有 MBTA 消息使用 16 字节帧头：

```text
Offset  Size  Field
0       4     Magic = "MBTA"
4       1     Version = 0x01
5       1     Flags
6       2     Type
8       4     Length
12      4     CRC32(payload)
```

核心消息类型：

| 类型 | 方向 | 用途 |
|------|------|------|
| HELLO / HELLO_ACK | Agent <-> Server | 版本确认和能力协商 |
| AUTH / AUTH_OK / AUTH_FAIL | Agent <-> Server | 应用层认证 |
| BATCH | Agent -> Server | 批量事件传输 |
| ACK / NACK / PARTIAL_ACK | Server -> Agent | 投递结果 |
| WINDOW / THROTTLE | Server -> Agent | 流控和节流 |
| PING / PONG | 双向 | 健康检查 |
| CLOSE | 双向 | 优雅关闭 |
| ERROR | 双向 | 协议错误 |

## 6. OTLP-like SignalBatch

BATCH payload 必须使用 `SignalBatch`，不使用单纯事件数组作为规范格式。

SignalBatch 结构：

```json
{
  "schema_url": "https://mebsuta.io/schemas/mbta/signal-batch/v1",
  "resource": {},
  "scope": {},
  "signals": []
}
```

字段语义：

| 字段 | 含义 |
|------|------|
| `schema_url` | payload schema 标识，便于版本识别和 OTLP 映射 |
| `resource` | 产生信号的实体属性，如 host、service、agent、tenant |
| `scope` | 采集器或插件信息，如 name、version、collector_id |
| `signals` | 同一 resource/scope 下的遥测记录数组 |

Signal record 使用统一外壳：

```json
{
  "signal_type": "log",
  "event_id": "evt-...",
  "time_unix_ms": 1710000000000,
  "observed_time_unix_ms": 1710000000100,
  "trace_id": "",
  "span_id": "",
  "attributes": {},
  "body": "message",
  "severity_number": 9,
  "severity_text": "info"
}
```

`signal_type` 是必填字段。日志必须使用 `"log"`，不再用空字符串表示日志。

支持的 signal_type：

| signal_type | 说明 | OTLP 映射 |
|-------------|------|-----------|
| `log` | 日志或普通事件 | Logs LogRecord |
| `gauge` | 瞬时指标 | Metrics Gauge |
| `counter` | 单调或非单调计数 | Metrics Sum |
| `histogram` | 直方图 | Metrics Histogram |
| `summary` | 摘要指标 | Metrics Summary |
| `span` | trace span | Traces Span |

日志字段：

| 字段 | 含义 |
|------|------|
| `body` | 日志 body，允许 string、number、bool、map、array、null |
| `severity_number` | 与 OpenTelemetry Logs severity number 对齐 |
| `severity_text` | 原始级别文本 |
| `trace_id` / `span_id` | 与 trace 关联 |

指标字段：

```json
{
  "signal_type": "gauge",
  "metric_name": "cpu_usage",
  "metric_fields": {"used": 42.5, "idle": 57.5},
  "unit": "%",
  "temporality": "unspecified",
  "is_monotonic": false,
  "attributes": {"cpu": "cpu0"}
}
```

指标规则：

- `metric_name` 对所有指标信号必填。
- `metric_fields` 至少包含一个数值字段。
- `counter` 应声明 `temporality` 和 `is_monotonic`。
- `histogram` 使用 `buckets`、`counts`、`sum`、`count` 表达；简单采集器也可以用 `metric_fields` 保存派生数值。
- 指标也可以保留 `body` 作为人类可读文本，但 Server 不应依赖解析 `body` 得到指标值。

Span 字段：

| 字段 | 含义 |
|------|------|
| `trace_id` | trace 标识 |
| `span_id` | span 标识 |
| `parent_span_id` | 父 span 标识 |
| `name` | span 名称 |
| `kind` | client、server、producer、consumer、internal |
| `start_time_unix_ms` | 开始时间 |
| `end_time_unix_ms` | 结束时间 |
| `status_code` / `status_message` | span 状态 |

Resource 和 Scope 复用规则：

- 同一 BATCH 内共有属性必须放在 `resource` 或 `scope`，避免每条 signal 重复。
- 每条 signal 的 `attributes` 只放该 signal 独有维度。
- Server 接收后必须能无损映射到内部 `event.Event`，并能进一步转换为 OTLP。

## 7. SecureEnvelope

SecureEnvelope 是压缩、加密和 HMAC 的唯一承载点，避免安全处理分散到业务结构中。

发送顺序：

1. 业务对象 JSON canonical encoding。
2. 可选压缩。
3. 可选加密。
4. 计算 HMAC。
5. 封装 SecureEnvelope。

接收顺序：

1. 解析 SecureEnvelope。
2. 校验算法和 capability。
3. 校验 HMAC。
4. 可选解密。
5. 可选解压。
6. 解析 SignalBatch。

应用层国密能力：

- HMAC-SM3：用于 batch 级语义绑定、审计和重放检测。
- SM4-GCM：用于可选端到端 payload 加密，nonce 必须显式生成并随 envelope 传输。
- SM2 证书认证：作为应用层身份能力，不替代 QUIC TLS 1.3 的传输层安全。

## 8. 可靠性与流控

可靠性语义：

- `seq` 是 Agent 会话内单调递增的批次序号。
- `chunk_id` 是全局唯一批次 ID，用于去重、重试和抗重放。
- ACK 表示批次接收成功；Durable ACK 表示服务端已持久化或写入可靠队列。
- NACK 表示批次失败并携带原因。
- PARTIAL_ACK 表示批次部分成功，客户端需要按失败项重试。失败项必须支持按 `event_id` 或 signal index 定位。

Spool 删除规则：

- `durable_required=true` 时，客户端只能在收到 Durable ACK 后删除本地 spool。
- 非 durable 模式下，普通 ACK 可触发删除。
- NACK、超时、连接中断不得删除待确认数据。

流控语义：

- WINDOW 下发服务端可接受的 inflight 限额。
- THROTTLE 下发临时节流策略。
- WINDOW 负责容量边界，THROTTLE 负责速率调整。

## 9. OTLP 映射

MBTA Server 必须提供清晰的 OTLP 映射边界：

| MBTA | OTLP |
|------|------|
| `SignalBatch.resource` | Resource |
| `SignalBatch.scope` | InstrumentationScope |
| `signal_type="log"` | Logs LogRecord |
| `body` | LogRecord Body |
| `severity_number` / `severity_text` | LogRecord severity |
| `trace_id` / `span_id` | LogRecord trace correlation |
| `signal_type="gauge"` | Metrics Gauge data point |
| `signal_type="counter"` | Metrics Sum data point |
| `signal_type="histogram"` | Metrics Histogram data point |
| `signal_type="summary"` | Metrics Summary data point |
| `signal_type="span"` | Traces Span |
| `attributes` | record or data point attributes |

MBTA 的 ACK、NACK、PARTIAL_ACK、spool、WINDOW、THROTTLE 和 SecureEnvelope 不映射为 OTLP 数据模型字段，它们属于 MBTA 传输控制语义。

## 10. 协议冻结规则

- 本文档定义 MBTA v1 冻结规范。
- 新字段必须可忽略，并保持默认语义。
- 新 capability 必须通过 HELLO / HELLO_ACK 协商。
- 帧格式、状态机、传输安全模型或安全语义发生不可协商的变化时，必须引入新 ALPN 或新版本。
- v1 不把应用层 SM2/SM3/SM4 等同于最终合规结论；合规取决于密码产品、证书体系、密钥管理、部署场景和测评结论。
