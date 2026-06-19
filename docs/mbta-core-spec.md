# MBTA Core Protocol Specification

**Status:** Frozen baseline / 冻结基准
**Revision:** r2 (2026-06)
**Authority:** 所有传输 binding（QUIC / TCP+TLS1.3 / TCP+TLCP）与密码套件文档是本规范的实例，与本文件冲突时以本文件为准。
**Scope:** 线上字节格式与语义状态机。性能、内存、并发模型属实现范畴，不在此规定。

---

## 0. 概述

MBTA 是 Agent → Server 的遥测信号传输协议，对齐 OpenTelemetry 数据模型（OTLP）。

默认值服务主力部署（服务器/云端/边缘 agent）；受限场景（嵌入式）与高阶场景通过 capability 协商偏移。国际与国密算法在协议每一层对称（§8）。线格式、字段号、enum 取值、默认值不可逆，capability 与新消息类型可演化（§1.3、§1.4）。session 与传输 4-tuple 解耦（§9.1）。

---

## 1. 协议标识与版本治理

### 1.1 标识

| 字段          | 值                          |
| ------------- | --------------------------- |
| Protocol Name | `MBTA`                      |
| Frame Magic   | `"MBTA"` (4 字节 ASCII)     |
| Frame Version | `0x01`                      |
| 默认 Payload  | SignalBatch（OTLP-aligned） |

### 1.2 ALPN 与 Capability 的分工

**ALPN 仅在线格式不兼容时升级**（帧格式、状态机、安全语义的根本性变更）。特性集的演进走 **Capability 协商**，不动 ALPN。多数演进只动 capability，降低升级摩擦。

传输 profile 通过 ALPN 区分（绑定不同传输/安全栈）：

| ALPN          | 传输 × 密码                             | 状态                             |
| ------------- | --------------------------------------- | -------------------------------- |
| `mbta/1`      | QUIC + TLS 1.3（国际）                  | 可用                             |
| `mbta/2`      | QUIC + RFC 8998（国密 over QUIC）       | 计划中                           |
| `mbta-tls/1`  | TCP + TLS 1.3（国际）                   | **本规范要求补齐**（见 §10）     |
| `mbta-ntls/1` | TCP + TLCP（国密）                      | 可用                             |
| `mbta-wt/1`   | WebTransport over HTTP/3（浏览器/边缘） | **候选 binding，预留**（见 §10） |

> 传输与密码独立组合（见 §10）。`mbta-tls/1` 与 `mbta-ntls/1` 共用 TCP framing，仅 TLS 握手层不同。

### 1.3 Capability 生命周期

每个 capability 必须标记生命周期阶段，规范层定义其协商失败语义：

| 阶段         | 命名      | 语义                     |
| ------------ | --------- | ------------------------ |
| experimental | `x-` 前缀 | 可改可删，不计入一致性   |
| stable       | 正式名    | 语义冻结，进入一致性要求 |
| deprecated   | `dep-`    | 仍支持，新实现不应选择   |
| removed      | —         | MUST 拒绝                |

**失败语义：** 未识别的 experimental capability 静默忽略；未识别的 stable capability 返回协议错误。

### 1.4 字段号与 enum 演化

采用二进制 schema 编码（Protobuf，见 §6）：

- 字段号永不复用：删除的字段号永久 reserved。
- enum 值只追加不复用：`Codec`/`Compression`/`CipherSuite`/`DeliveryMode`/`ErrorNum` 等枚举不回收旧值。
- 新字段必须有安全的默认零值。

---

## 2. 帧格式（Frame Format）

所有 MBTA 消息以定长前缀 + 变长长度 + 载荷编码。

### 2.1 帧布局

```
Offset  Size    Field
0       4       Magic = "MBTA"
4       1       Version = 0x01
5       1       Flags
6       1       Type            (uint8)
7       1       ChannelID       (uint8)
8       varint  Length          (1–4 字节，payload 字节数)
# (无 CRC — 完整性由 AEAD + HMAC 保证)
…       Length  Payload
```

其中 `v` 为 varint `Length` 占用字节数。

### 2.2 接收端校验（MUST）

接收端 MUST 拒绝：

1. Magic ≠ "MBTA"；
2. Version ≠ 0x01；
3. 保留 Flags 位（见 §3）被置位；
4. Length 超过协商的 `max_frame_payload_bytes`；
5. 未读取完整的 Payload。

当 Header 已读但 Payload 读取失败时，接收端 MUST 排空（drain）声明的剩余字节，以维持帧边界对齐。

---

## 3. Flags 位语义

Flags 为 8 位，从 LSB 编号：

| Bit | 掩码   | 名称        | v1 状态 | 语义                                                                             |
| --- | ------ | ----------- | ------- | -------------------------------------------------------------------------------- |
| 0   | `0x01` | Envelope    | ✅ 启用  | Payload 是 SecureEnvelope                                                        |
| 1   | `0x02` | Control     | ✅ 启用  | 控制面消息                                                                       |
| 2   | `0x04` | Data        | ✅ 启用  | 数据面消息                                                                       |
| 3   | `0x08` | MoreFollows | ✅ 启用  | 本帧是逻辑多片消息的一片，后续还有；末片清零                                     |
| 4   | `0x10` | Reserved    | 预留    | MUST NOT set（v2 扩展预留，原 NoCRC 已移除）                                     |
| 5   | `0x20` | Coalesced   | ✅ 启用  | Payload 是多条同类型小消息的合并打包                                             |
| 6–7 | `0xC0` | FlowClass   | ✅ 启用  | 流类别（见 §9.3）：00=normal, 01=control-be, 10=critical, 11=reserved(MUST 拒绝) |

### 3.1 约束

1. FlowClass=`11`：返回协议错误并关闭连接。扩展走 capability/版本协商。
2. 位组合：
   - `Control` 与 `Data` 互斥（`Flags & 0x06` 不可同时为 0 或同时非 0）；
   - `MoreFollows` 与 `Coalesced` 互斥。
3. `MoreFollows`、`Coalesced`、特定 `FlowClass` 需先通过 capability 协商（`more_follows` / `coalesce_control` / `flow_class`）；未协商而置位则拒绝。

> **FlowClass 与 DeliveryMode 是两个正交维度**：FlowClass（本节）表达**优先级/类别**；DeliveryMode（见 §11.4）表达**投递可靠性**（reliable/lossy）。两者独立，不互相占用位。

### 3.2 Coalesced Payload 子格式

```
coalesced_payload = uint8(count) + count × { uint16(inner_len) + inner_payload }
```

仅允许**同 Type** 的控制消息合并（如多个 ACK）。

---

## 4. 消息类型（Message Types）

`Type` 字段（uint8）取值：

| 值  | 类型        | 方向 | 说明                                                         |
| --- | ----------- | ---- | ------------------------------------------------------------ |
| 1   | HELLO       | C→S  | 版本与能力协商                                               |
| 2   | HELLO_ACK   | S→C  | 选定能力与连接参数                                           |
| 3   | AUTH        | C→S  | 认证请求                                                     |
| 4   | AUTH_OK     | S→C  | 认证成功                                                     |
| 5   | AUTH_FAIL   | S→C  | 认证失败                                                     |
| 6   | BATCH       | C→S  | SignalBatch 传输（可靠）                                     |
| 7   | DATAGRAM    | C→S  | 不可靠信号传输（见 §11.4，capability `unreliable_datagram`） |
| 8   | ACK         | S→C  | 整批确认                                                     |
| 9   | NACK        | S→C  | 整批拒绝                                                     |
| 10  | PARTIAL_ACK | S→C  | 部分成功 + 逐项失败                                          |
| 11  | WINDOW      | S→C  | 流控窗口                                                     |
| 12  | THROTTLE    | S→C  | 速率节流                                                     |
| 13  | PING        | 双向 | 健康探测                                                     |
| 14  | PONG        | 双向 | 健康响应（可携带自省信息）                                   |
| 15  | CLOSE       | 双向 | 优雅关闭                                                     |
| 16  | ERROR       | 双向 | 协议错误                                                     |

> 值 6（BATCH）与 7（DATAGRAM）区别仅在**投递语义**：BATCH 走可靠流 + ACK + spool；DATAGRAM 走 QUIC DATAGRAM（RFC 9221）或等价不可靠通道，无 ACK、无重传、无 spool。见 §11.4。

17–255 保留给未来扩展；新类型 MUST 通过 capability 协商，未协商的未知类型 MUST 拒绝。

### 4.1 消息载荷编码

所有消息的 Payload 按连接协商的 **Codec（§6.3）** 编码为对应的 message 结构（即控制面与数据面统一编码，不另设定长二进制控制帧格式）。具体 message schema（字段号、类型）由 proto 定义维护，本规范仅约束字段**语义**。

- `Flags.Envelope=1` 时，Payload 是 SecureEnvelope，业务对象在其内（见 §5）；
- `Flags.Envelope=0` 时，Payload 是裸 message 编码（如部分轻量控制帧可选，由实现决定）；
- 失败项定位（PARTIAL_ACK）通过 `event_id` 或 signal index；大 batch 的失败项**可**编码为 bitmap 以紧凑表达，具体由 schema 决定。

> **编码约定：** 所有字符串字段（agent_id、reason、attributes 文本值等）MUST 为 **UTF-8**；多字节整数用**大端序**；Length 为无符号 varint。

---

## 5. SecureEnvelope

SecureEnvelope 承载压缩、加密、认证，使安全处理集中在一处。

### 5.1 处理顺序

**发送（Build）：**
1. 业务对象按选定 Codec 编码；
2. 可选压缩；
3. 可选加密；
4. 计算 HMAC；
5. 序列化 envelope。

**接收（Open）：**
1. 解析 envelope；
2. 校验算法与 capability；
3. 校验 HMAC（在解密/解码之前）；
4. 可选解密；
5. 可选解压；
6. 按选定 Codec 解码。

HMAC 校验失败丢弃该 envelope。DATAGRAM 的完整性由传输层 AEAD 保证，HMAC 失败仅丢弃该 datagram，不触发重传。

### 5.2 Envelope 字段（schema 纲要）

envelope 的字段用二进制 schema（见 §6）编码。关键字段（语义，非语言绑定）：

| 字段               | 类型      | 说明                                                          |
| ------------------ | --------- | ------------------------------------------------------------- |
| envelope_version   | uint      | wire 格式版本                                                 |
| message_type       | enum      | batch / datagram                                              |
| session_id         | bytes     | 会话标识                                                      |
| key_id             | bytes     | 密钥标识                                                      |
| seq                | uint64    | 会话内单调递增（仅 reliable BATCH）                           |
| chunk_id           | bytes(16) | **ULID**，全局唯一 + 时序（仅 reliable BATCH；datagram 可选） |
| created_at_unix_ms | int64     | 创建时间                                                      |
| codec              | enum      | 见 §6                                                         |
| compression        | enum      | 见 §7                                                         |
| cipher_suite       | enum      | 见 §8                                                         |
| delivery_mode      | enum      | reliable / lossy（见 §11.4）                                  |
| nonce              | bytes     | 显式 nonce，**同密钥下禁止复用**                              |
| payload            | bytes     | 加密/压缩后的载荷（**原生 bytes，无 base64**）                |
| mac                | bytes     | HMAC 输出（**原生 bytes**）                                   |

### 5.3 HMAC 签名输入

HMAC 签名输入为 envelope 序列化字节的规范形式（canonical wire bytes）。确定性编码（§6）保证同一 envelope 跨实现逐字节一致，HMAC 可验证。签名输入用 canonical wire bytes，不用手工拼接字符串。

### 5.4 抗重放

- `chunk_id` 为 ULID，全局唯一；
- `nonce` 在同密钥下不复用；
- 服务端维护去重缓存（dedup cache），其作用域与持久化由投递语义 capability 决定（见 §11）。

---

## 6. 数据模型与 Codec

### 6.1 数据模型：OTLP-aligned SignalBatch

MBTA 不重复发明遥测数据模型，对齐 OpenTelemetry 分层：`Resource` + `InstrumentationScope` + signal records。

```
SignalBatch = schema_url + resource + scope + signals[]
signal = signal_type + event_id + time + attributes + [body | metric_fields | span_fields | profile_payload]
signal_type ∈ {log, gauge, counter, histogram, summary, span, profile}
```

Server 侧 MUST 能无损映射到 OTLP（Logs / Metrics / Traces / **Profiles**，映射表见附录 B）。`signal_type` 必填；日志 MUST 用 `"log"`，空字符串非法。

### 6.2 Signal 类型语义

| signal_type | 说明                                     | OTLP 映射                            |
| ----------- | ---------------------------------------- | ------------------------------------ |
| `log`       | 日志/事件                                | Logs LogRecord                       |
| `gauge`     | 瞬时指标                                 | Metrics Gauge                        |
| `counter`   | 单调/非单调计数                          | Metrics Sum                          |
| `histogram` | 直方图，支持 **exponential bucket** 表达 | Metrics Histogram                    |
| `summary`   | 摘要                                     | Metrics Summary                      |
| `span`      | trace span                               | Traces Span                          |
| `profile`   | 持续性能采样 profile                     | **Profiles Profile**（OTLP v1.3.0+） |

**histogram exponential bucket：** `histogram` signal 可声明 `aggregation=explicit | exponential`。exponential 模式对齐 OTel Exponential Histogram（更高分辨率、更低成本），字段含 `scale`、`offset`、`positive_buckets`、`negative_buckets`、`sum`、`count`、`min`/`max`。

**profile signal：** 携带采样类型（cpu / heap / mutex / goroutine 等）、profile 字节载荷，以及与 trace/log/metric 的**双向关联字段**（`profile_id`、`trace_id`、`span_id`、`log_record_ref`），对齐 OTel Profiles 跨信号关联目标。

### 6.3 Codec 枚举（wire 值）

| Codec    | 取值    | 适用                                                       |
| -------- | ------- | ---------------------------------------------------------- |
| Protobuf | `proto` | baseline 默认：确定性编码、跨语言、OTLP 互通 |
| CBOR     | `cbor`  | constrained 场景：自描述、紧凑，受限环境友好         |
| JSON     | `json`  | 仅调试，非生产推荐                                |

Codec 由 HELLO 协商；未协商的 codec 拒绝。

**选择优先级**（双方都支持多个时）：`proto > cbor > json`。仅当双方都不支持 proto 但都支持 cbor 或 json 时才降级。

**CBOR / JSON 映射约定**：proto 经 AnyValue oneof 表达动态类型（attributes/body 的 string/int64/float64/bool/bytes）；CBOR 与 JSON 直接序列化 SignalBatch（map / any 原生），无需 AnyValue oneof。跨 codec 类型语义差异：
- CBOR：小正整数按 RFC 8949 编码为无符号，解码端可能得到 uint64 而非 int64；数值语义无损。
- JSON：数字统一为 float64，整数 attributes 经 JSON 往返后可能丢失 int 精度（>2^53）；`[]byte` 走 base64。故 JSON 仅用于调试。

---

## 7. 压缩（Compression）

压缩算法在 envelope `compression` 字段声明，per-envelope。协商通过 capability。

| Compression | 适用                                                                            |
| ----------- | ------------------------------------------------------------------------------- |
| `zstd`      | **baseline 默认**：通用最优比率/速度；可选 trained dictionary（`dict_id` 协商） |
| `lz4`       | constrained / 低延迟：最低 CPU 与延迟                                           |
| `none`      | 小载荷（压缩负收益）、DATAGRAM 实时信号、或已下层压缩                           |
| `gzip`      | 兼容兜底（legacy / OTLP 互操作）                                                |

发送端可依据载荷特征自适应选择（从已协商集合内），写入 per-envelope 字段。接收端 MUST 按字段值解压，拒绝未协商算法。

**安全约束：** 接收端 MUST 强制解压上限（`max_decompressed_size`），防御高比率压缩的放大攻击。该上限不大于 `max_batch_bytes`。

---

## 8. 密码套件

国际与国密在每一层对称。传输层算法由 binding 决定（§10），应用层算法由 `cipher_suite` 字段声明。

### 8.1 算法对称表

| 层            | 国际                           | 国密                                                         |
| ------------- | ------------------------------ | ------------------------------------------------------------ |
| 传输 TLS      | TLS 1.3                        | TLCP（GB/T 38636-2020）/ RFC 8998（IETF，TLS 1.3 + SM 套件） |
| HMAC          | HMAC-SHA-256                   | HMAC-SM3                                                     |
| envelope AEAD | AES-256-GCM                    | SM4-GCM                                                      |
| 证书签名      | ECDSA-P256 / Ed25519 / RSA-PSS | SM2                                                          |

### 8.2 Cipher Suite 抽象

`cipher_suite` 是一组联动算法（HMAC + AEAD + Sign），不混搭：

| CipherSuite        | HMAC    | AEAD        | Sign          |
| ------------------ | ------- | ----------- | ------------- |
| `intl`（国际套件） | SHA-256 | AES-256-GCM | ECDSA/Ed25519 |
| `gm`（国密套件）   | SM3     | SM4-GCM     | SM2           |

HELLO 协商选套件；实现按套件选择算法。

### 8.3 默认值规则

默认套件跟随传输 binding：

- TLS 1.3 binding → `intl`（HMAC-SHA-256 / AES-256-GCM）；
- TLCP / RFC 8998 binding → `gm`（HMAC-SM3 / SM4-GCM）。

### 8.4 AEAD 约束

- nonce 显式随 envelope 传输；
- 同密钥下 nonce 不复用；
- 密文格式：`nonce || ciphertext || tag`。

---

## 9. Session、流控与网络

### 9.1 Session 与传输 tuple 解耦

**SessionID 是逻辑身份，独立于任何传输 4-tuple。** 协议状态（认证态、窗口、inflight）绑定到 SessionID，不绑定到网络连接。

此设计同时服务：
- 嵌入式/移动场景：NAT 重绑定、IP 切换导致连接频繁断；
- QUIC：连接迁移（连接 IP 变化而连接不断）；
- 未来：传输替换、多路径（MP-QUIC）。

断连后，客户端以同一 SessionID 重连，服务端恢复/关联会话状态；spool 中待确认数据重发（见 §11）。

### 9.2 流控

| 消息     | 语义                                                     |
| -------- | -------------------------------------------------------- |
| WINDOW   | 服务端下发的 inflight 容量上限（批数 / 事件数 / 字节数） |
| THROTTLE | 临时速率节流（`retry_delay_ms`）                         |

WINDOW 管容量边界，THROTTLE 管速率调整。客户端 MUST 同时遵守 MBTA 流控与底层传输流控（如 QUIC flow control / TCP）。WINDOW 取值变化时才发送，避免同值重复下发。

> **DATAGRAM 通道不纳入 WINDOW inflight 计数**：不可靠投递无 inflight 待确认语义，仅受传输层（QUIC DATAGRAM 拥塞反馈）速率约束。

### 9.3 FlowClass 与网络层协作

FlowClass（Flags bit 6–7）标识消息类别：`normal` / `control-be`（尽力而为控制）/ `critical`（关键路径，如安全审计 trace）。

**IPv6 协作（SHOULD，仅 IPv6）：** 当传输为 IPv6 时，实现 SHOULD 将 FlowClass 映射到 IPv6 Flow Label（20-bit）与 DSCP，使网络中间设备可做差异化转发。**IPv4 部署无此映射**——IPv4 无 Flow Label，且 DSCP 在公网常被清洗。此映射为可选增强，不影响 IPv4 部署的任何行为。

### 9.4 PMTU

IPv6 中间设备不分片（依赖源端 PMTUD）。协议**不依赖网络分片**：

- 超过 `max_batch_bytes` 的逻辑 BATCH 必须通过 `MoreFollows` 分片（§3）；
- 实现宜采用保守的默认 MTU（如 1280，IPv6 最小 MTU），PMTU 探测为可选（capability `pmtu_probe`），因 ICMP 常被防火墙丢弃，探测可能黑洞。

### 9.5 会话建立与协商（握手协议）

会话按以下顺序建立。**认证完成前，服务端 MUST 拒绝 BATCH/DATAGRAM。**

```
Agent                          Server
  | --- HELLO ------------------> |   (1) 身份 + 能力宣告
  | <-- HELLO_ACK --------------- |   (2) 选定能力 + 参数 + 挑战
  | --- AUTH --------------------> |   (3) 凭据 + 应答挑战
  | <-- AUTH_OK / AUTH_FAIL ------ |   (4) 会话密钥 / 失败
  | --- BATCH/DATAGRAM ---------> |   (5) 认证后允许
```

**(1) HELLO（C→S）字段语义：**
- `agent_id` / `hostname` / `instance_id` / `agent_version`：Agent 身份与实现信息；
- `frame_version`：帧版本（=0x01）；
- `capabilities`：能力宣告集——支持的 codec / compression / cipher_suite / delivery_mode 子集，以及各附录 C capability（客户端视角"我能做"）；
- `resource_class` / `mem_limit_kb`（可选）：受限场景触发服务端降级（§12）。

**(2) HELLO_ACK（S→C）字段语义：**
- `session_id` / `server_id`：会话逻辑身份（独立于 tuple，见 §9.1）；
- `selected_capabilities`：从客户端宣告集中**选定的公共子集**（自动降级，见 §12.1）；
- 选定 codec / compression / cipher_suite（随 binding 合规语境，§8.3）；
- `limits`：`max_frame_payload_bytes` / `max_batch_bytes` / `max_batch_events` / `max_event_bytes`；
- `initial_window`：初始流控窗口（§9.2）；
- `heartbeat_interval_sec`：心跳间隔；
- `challenge_nonce`：服务端生成的一次性挑战，供 AUTH 应答。

**(3) AUTH（C→S）字段语义：**
- 凭据按选定 cipher_suite 与部署：`token`（静态令牌）/ mTLS 证书 / SM2 证书（`sm2_cert_auth`）；
- `auth_nonce`：客户端基于 `challenge_nonce` 计算的应答（challenge-response），防重放；
- `session_id`：绑定本次认证到 HELLO_ACK 会话。

**(4) AUTH_OK / AUTH_FAIL：**
- `AUTH_OK`：下发会话密钥 `key_id` + `HMACKey` +（若协商）`SM4Key`/`AESKey`，`expires_at`；密钥随会话，连接关闭清零；
- `AUTH_FAIL`：`code` / `reason` / `retryable`；retryable 时回传**新** `challenge_nonce`，客户端 MUST 用新挑战重算后重试（旧挑战一次性）。

**前置条件（MUST）：** HELLO/HELLO_ACK 与 AUTH/AUTH_OK 均完成后，方可发送 BATCH/DATAGRAM；未认证连接发送数据帧 MUST 返回 `ERR_AUTH_REQUIRED`。

### 9.6 优雅关闭

`CLOSE`（双向可发起）启动优雅关闭协议：

1. 发起方停止接受/发送**新** BATCH/DATAGRAM；
2. **drain inflight**：等待所有已发 BATCH 的 ACK/NACK，或达到 `close_timeout`；
3. drain 完成（或超时）后，关闭底层传输；
4. 超时强关时，未确认的 reliable BATCH **保留在 spool**（不删除），待以同一 SessionID 重连后重发（§11.5）；
5. 对端收到 CLOSE 后，对称执行 drain。

`close_timeout` 由 HELLO_ACK 协商或用默认值。`critical` FlowClass 的在途信号应优先在 timeout 内确认。

---

## 10. 传输 Binding

传输与密码独立组合：

```
传输轴:  QUIC | TCP | WebTransport(HTTP/3)
密码轴:  TLS1.3(国际) | TLCP(国密) | RFC8998(国密-over-QUIC) | PQC-hybrid(未来)
```

| 组合                     | 状态                                              |
| ------------------------ | ------------------------------------------------- |
| QUIC + TLS 1.3           | ✅（`mbta/1`）                                     |
| QUIC + RFC 8998          | 计划中（`mbta/2`）                                 |
| TCP + TLCP               | ✅（`mbta-ntls/1`）                                |
| TCP + TLS 1.3            | ✅（`mbta-tls/1`）                                 |
| WebTransport over HTTP/3 | 候选 binding，预留（`mbta-wt/1`）                 |

### 10.1 TCP Binding 的 Channel 语义

TCP 无 QUIC stream，binding 须显式定义 channel：帧头 `ChannelID` 字段（§2）承载 channel 标识。每连接至少一个 control channel；多 data channel 通过 capability `multi_channel` 协商。

### 10.2 传输抽象

协议核心（状态机 / SignalBatch / 投递 / 流控 / spool）与具体传输解耦。新传输（QUIC v2 / MP-QUIC / WebTransport / 路径感知网络）作为新 binding 接入，核心不变。binding 声明其支持的投递模式（是否支持 `unreliable_datagram`，见 §11.4）。

### 10.3 Binding 文档规范要求

每个传输 binding 文档 MUST 定义以下内容，缺一不可；未定义项视为该 binding 不支持：

| 项                     | 要求                                                                                                                  |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------- |
| ALPN 与标识            | binding 对应的 ALPN、Frame Version、密码轴取值                                                                        |
| 握手映射               | TLS/TLCP/等握手如何完成；HELLO/HELLO_ACK 起始时机（握手后或 0-RTT 内）                                                |
| Stream / Channel 映射  | control/data 如何映射到传输多路复用单元（QUIC stream / TCP channel/帧多路复用）；`ChannelID` 字段语义                 |
| 不可靠通道             | 是否支持 `unreliable_datagram`（§11.4）；支持则说明映射（如 QUIC DATAGRAM），不支持则 DATAGRAM 退化为 reliable 或拒绝 |
| 帧分片/粘包处理        | 字节流类 binding（TCP）MUST 说明拆包/粘包/半开/短读防护；数据报类 binding（QUIC）说明帧与 datagram 边界关系           |
| FlowClass 网络协作     | 是否/如何映射 IPv6 Flow Label 与 DSCP（§9.3）                                                                         |
| 支持的 capability 子集 | 该 binding 启用/禁用哪些 core capability（如 `multi_channel`、`pmtu_probe`）                                          |
| 与 core 的差异边界     | 显式列出与 core 默认行为的任何偏离（无偏离则声明"完全遵循 core"）                                                     |
| 一致性测试要求         | 该 binding 特有的一致性项（如 TCP 拆包测试、QUIC 连接迁移测试）                                                       |

凡 binding 文档与 core 冲突，**以 core 为准**。binding 仅在 core 允许的"传输相关开放点"上做具体化。


---

## 11. 角色与投递语义

### 11.1 角色

- **baseline（默认）**：单向 hub-spoke（Agent → Server）。这是遥测的现实拓扑，状态机最小。
- **advanced（capability `symmetric_role`）**：对等角色（initiator/responder，mutual auth）。为 IPv6 可寻址下的反向推送、联邦聚合预留。baseline 客户端无需实现。

### 11.2 投递标识

| 字段       | 语义                                                                            |
| ---------- | ------------------------------------------------------------------------------- |
| `seq`      | Agent 会话内单调递增的批次序号（仅 reliable BATCH）                             |
| `chunk_id` | **ULID(16 字节)**，全局唯一 + 时序，用于去重、重试、抗重放（仅 reliable BATCH） |

PARTIAL_ACK MUST 通过 `event_id` 或 signal index 定位失败项，支持逐项重试。

### 11.3 Reliable 投递保证（BATCH，capability）

| 模式                                                       | 语义                                     | 去重缓存                     |
| ---------------------------------------------------------- | ---------------------------------------- | ---------------------------- |
| **at-least-once**（baseline 默认）                         | 崩溃/断连重发，可能重复投递              | per-connection，轻量         |
| **effectively-once**（capability `durable_ack` + `dedup`） | 服务端持久化去重表（带 TTL），跨重连命中 | 持久化，TTL 窗口内不重复投递 |

**选择理由：** effectively-once 依赖 `chunk_id` 全局唯一性，故与 ULID 决策绑定。轻量部署（海量嵌入式 Agent）可退回 at-least-once，不为每个轻量连接维护持久化表——下游按幂等处理。

### 11.4 Unreliable 投递（DATAGRAM，capability `unreliable_datagram`）

| 维度                 | BATCH（reliable）                | DATAGRAM（lossy）                             |
| -------------------- | -------------------------------- | --------------------------------------------- |
| DeliveryMode         | `reliable`                       | `lossy`                                       |
| 投递保证             | at-least-once / effectively-once | **at-most-once**（尽最大努力，不重传）        |
| ACK/NACK             | 有                               | **无**                                        |
| spool 持久化         | 有（崩溃重发）                   | **无**                                        |
| seq / chunk_id       | 必填                             | 可选（仅作采样/关联，不参与去重）             |
| 纳入 WINDOW inflight | 是                               | **否**（仅受传输层拥塞约束）                  |
| 传输通道             | QUIC stream / TCP                | **QUIC DATAGRAM（RFC 9221）**或等价不可靠通道 |
| 失败处理             | NACK / 重试                      | 静默丢弃（HMAC 失败亦丢弃，不重传）           |

**适用判断：** signal 声明 `durability=lossy` 且 binding 支持 DATAGRAM 时，走 DATAGRAM；否则回退 reliable BATCH。`critical` FlowClass 的信号 MUST 走 reliable，禁用 lossy。

### 11.5 Spool 与删除规则

客户端发送前持久化（spool）待确认数据，ACK 后删除（仅 reliable BATCH）：

- `durable_required=true` 时，仅在收到 Durable ACK 后删除；
- 非 durable 模式，普通 ACK 触发删除；
- **NACK / 超时 / 连接中断 MUST NOT 删除**待确认数据；
- 重连后按 `seq` 升序重发 PendingBatches；
- **DATAGRAM 不入 spool**，无删除语义。

### 11.6 0-RTT 投递（capability `early_data`，仅 QUIC binding）

**语义：** `early_data` capability **仅 QUIC binding 支持**（`mbta/1`）。

QUIC 原生支持 0-RTT：客户端在握手完成前发送已 spooled 的 reliable BATCH（早期数据）。

**TCP binding 不支持 0-RTT data**（`mbta-tls/1` / `mbta-ntls/1`）——TCP binding 的传输层不支持握手前 application data。

**抗重放约束（MUST）：**
- 0-RTT 早期数据 MUST 携带 `chunk_id`（ULID）；服务端 MUST 经去重缓存校验，重放的 0-RTT BATCH 命中则丢弃并回 ACK（effectively-once 场景）或拒绝（at-least-once 场景按部署策略）；
- **AUTH MUST NOT 走 0-RTT**（认证凭据不可重放暴露）；0-RTT 仅限已认证会话的 resumption；
- 服务端可按部署策略限制 0-RTT 批量上限（`max_early_data_bytes`），缩小重放影响面。

**适用判断：** 客户端声明 capability `early_data` 且 binding 为 QUIC（`SupportsDatagram()==true`）时启用；TCP binding 不响应此 capability。

---

## 12. 场景分层与定位

默认服务主力部署。受限与高阶场景通过协商偏移，**不改默认值**。

| 维度                | baseline（默认）       | constrained（嵌入式降级）                                                  | advanced（高阶增强）                   |
| ------------------- | ---------------------- | -------------------------------------------------------------------------- | -------------------------------------- |
| Codec               | proto                  | cbor                                                                       | —                                      |
| 压缩                | zstd                   | lz4 / none                                                                 | —                                      |
| 传输                | QUIC+TLS1.3 / TCP+TLCP | 同左（多走 TCP）                                                           | MP-QUIC / WebTransport / PQC binding   |
| 投递                | at-least-once          | 同左                                                                       | effectively-once / unreliable_datagram |
| 角色                | 单向                   | 同左                                                                       | 对称 / 联邦                            |
| PMTU                | 安全默认 1280          | 固定保守值                                                                 | 探测 + jumbo                           |
| FlowClass→FlowLabel | SHOULD（IPv6）         | 不启用                                                                     | 启用                                   |
| 资源能力            | —                      | `resource_class=embedded` 触发服务端降级（更小 batch / 关压缩 / 拉长心跳） | —                                      |

**协商方向：** 能力弱的一端（嵌入式）主动声明可用子集，向 baseline 降级；服务端不下调自身默认。一个只实现 constrained 子集的客户端与全 baseline 服务端对接时，自动降级到公共子集互通。

---

## 13. 错误码

错误码携带数字码（NumCode）+ 字符串码，可程序化匹配。

| 范围      | 类别                      |
| --------- | ------------------------- |
| 1000–1099 | 配置                      |
| 2000–2099 | 传输                      |
| 3000–3099 | 协议                      |
| 4000–4099 | 数据                      |
| 5000–5099 | 流控                      |
| 6000–6099 | 存储                      |
| 7000–7099 | 版本                      |
| 8000–8099 | 安全                      |
| 9000–9999 | 实验/私有（不计入一致性） |

数字码语义一旦发布不可改（只能 deprecated）；字符串码与数字码的稳定映射由实现 schema 维护并随版本冻结。完整错误码表（含具体 NumCode 常量与字符串码）由参考实现的 schema 定义维护。

---

## 14. 安全考虑

1. **传输安全**：MUST 强制 TLS 1.3 / TLCP；生产 MUST NOT 关闭证书验证。
2. **完整性**：SecureEnvelope HMAC MUST 在解密/解码前验证；DATAGRAM 的完整性由传输层 AEAD 保证，HMAC 失败静默丢弃。
3. **重放**：`chunk_id` ULID + nonce + 去重缓存协同抗重放（仅 reliable BATCH；DATAGRAM at-most-once，重放影响有限）。
4. **放大攻击**：解压上限、payload 上限 MUST 强制。
5. **后量子（PQC）迁移（具体化）：** NIST 已于 2024-08 固化三大 PQC 标准——**FIPS 203 (ML-KEM)**、**FIPS 204 (ML-DSA)**、**FIPS 205 (SLH-DSA)**。
   - 传输 binding 的密钥交换应支持 **ML-KEM (FIPS 203) 混合密钥交换**（经典 ECDH/SM2 + ML-KEM），ML-KEM 为近乎 ECDH 的 drop-in 替换；
   - 签名支持 **ML-DSA (FIPS 204)** 作为 ECDSA/SM2 的未来选项；
   - cipher suite 抽象保持可扩展，PQC 套件作为新 enum 值追加（遵循 §1.4），不替换现有国际/国密套件；
   - PQC-hybrid 作为新传输密码轴取值（§10），通过 capability 协商，不影响既有部署。
6. **隐私**：IPv6 真实地址 + 高基数遥测可能形成设备指纹。协议支持轮换 AgentID / 临时凭证（IPv6 隐私扩展的对偶），稳定标识与跨会话不可关联标识分离；敏感字段 SHOULD 不入默认遥测。

---

## 15. 一致性要求

实现符合 MBTA Core 当且仅当实现：

1. 帧格式（§2）、Flags（§3）、消息类型（§4）；
2. SecureEnvelope 处理顺序与 HMAC 校验（§5）；
3. SignalBatch 数据模型与至少一个 Codec（§6）；
4. 至少一套完整 CipherSuite（国际或国密，§8）；
5. Session 与 tuple 解耦（§9.1）；
6. HELLO/AUTH 状态机与 BATCH/ACK/NACK/PARTIAL_ACK 投递（§4、§11）；
7. WINDOW/THROTTLE 流控（§9.2）；
8. OTLP Logs/Metrics/Traces/Profiles 映射能力（附录 B）；
9. 错误码与失败语义（§13）。

**DATAGRAM（不可靠投递）为可选 capability**，不实现仍合规。**一个只实现 constrained 子集（CBOR + lz4 + at-least-once + 单向）的嵌入式实现是合规的**，只要它与 baseline 服务端协商降级互通。

---

## 附录 A：相关文档

| 文档                            | 角色                                                                                       |
| ------------------------------- | ------------------------------------------------------------------------------------------ |
| **mbta-core-spec.md（本文件）** | 所有 binding 的共同核心                                                                    |
| mbta-core-spec-diagrams.md      | 图表与字段参考（帧/状态机/时序图/capability registry/OTLP 映射）                           |
| mbta-tcp-binding.md             | `mbta-tls/1`（TCP+TLS1.3）、`mbta-ntls/1`（TCP+TLCP）binding 规范，须与 §10 对齐           |
| mbta-quic-binding.md（待编写）  | `mbta/1`（QUIC+TLS1.3）、`mbta/2`（QUIC+RFC8998）、`mbta-wt/1`（WebTransport）binding 规范 |
| performance-optimization.md     | Go 参考实现的性能与架构笔记                                                                |
| 0-rtt-design.md                 | `early_data`（0-RTT）实现状态                                                              |

binding 文档与本规范冲突时，以本规范为准。

---

## 附录 B：OTLP 映射

| MBTA                                                | OTLP                                 |
| --------------------------------------------------- | ------------------------------------ |
| `SignalBatch.resource`                              | Resource                             |
| `SignalBatch.scope`                                 | InstrumentationScope                 |
| `signal_type="log"`                                 | Logs LogRecord                       |
| `signal_type="gauge"`                               | Metrics Gauge                        |
| `signal_type="counter"`                             | Metrics Sum                          |
| `signal_type="histogram"`（explicit / exponential） | Metrics Histogram                    |
| `signal_type="summary"`                             | Metrics Summary                      |
| `signal_type="span"`                                | Traces Span                          |
| `signal_type="profile"`                             | **Profiles Profile**（OTLP v1.3.0+） |
| `attributes`                                        | record/data point attributes         |

ACK/NACK/PARTIAL_ACK/DATAGRAM/spool/WINDOW/THROTTLE/SecureEnvelope 属 MBTA 传输控制语义，不映射为 OTLP 数据模型字段。

---

## 附录 C：Capability Registry

集中登记本规范定义的全部 capability 及其生命周期阶段（阶段语义见 §1.3）。未登记的 capability 使用 `x-` experimental 前缀。登记值一旦标 stable，名称与语义冻结。

### C.1 投递与可靠性

| Capability            | 阶段   | 语义                                           | 引用          |
| --------------------- | ------ | ---------------------------------------------- | ------------- |
| `partial_ack`         | stable | 支持逐项部分确认                               | §11.2         |
| `durable_ack`         | stable | 支持 Durable ACK（持久化后确认）               | §11.3 / §11.5 |
| `dedup`               | stable | 服务端持久化跨重连去重（effectively-once）     | §11.3         |
| `unreliable_datagram` | stable | 支持不可靠 DATAGRAM 投递通道                   | §11.4         |
| `early_data`          | stable | 支持 0-RTT 早期数据投递（**仅 QUIC binding**） | §11.6         |

### C.2 传输与通道

| Capability       | 阶段   | 语义                                                 | 引用  |
| ---------------- | ------ | ---------------------------------------------------- | ----- |
| `multi_channel`  | stable | TCP binding 多 data channel                          | §10.1 |
| `pmtu_probe`     | stable | 启用 PMTU 主动探测                                   | §9.4  |
| `flow_class`     | stable | 启用 FlowClass 差异化（含 IPv6 FlowLabel/DSCP 映射） | §9.3  |
| `symmetric_role` | stable | 对等角色（initiator/responder，mutual auth）         | §11.1 |

### C.3 帧与编码

| Capability         | 阶段   | 语义                             | 引用 |
| ------------------ | ------ | -------------------------------- | ---- |
| `more_follows`     | stable | 启用逻辑多片消息分帧             | §3   |
| `coalesce_control` | stable | 启用控制帧合并打包               | §3   |
| `flow_class`       | stable | Flags FlowClass 位有效（同 C.2） | §3   |

### C.4 数据与算法

| Capability                                  | 阶段   | 语义                                    | 引用 |
| ------------------------------------------- | ------ | --------------------------------------- | ---- |
| `comp_zstd` / `comp_lz4` / `comp_gzip`      | stable | 压缩算法支持（按需协商子集）            | §7   |
| `codec_proto` / `codec_cbor` / `codec_json` | stable | Codec 支持                              | §6.3 |
| `cs_intl` / `cs_gm`                         | stable | 国际 / 国密密码套件支持（至少其一必备） | §8   |
| `histogram_exponential`                     | stable | histogram 支持 exponential bucket 表达  | §6.2 |

### C.5 实验性（示例，非穷尽）

| Capability       | 阶段         | 语义                             |
| ---------------- | ------------ | -------------------------------- |
| `x-pqc-hybrid`   | experimental | PQC 混合传输密钥交换（ML-KEM）   |
| `x-mpquic`       | experimental | Multipath QUIC binding           |
| `x-webtransport` | experimental | WebTransport over HTTP/3 binding |

> 实验性 capability 可随时变更或删除，不计入一致性。转为 stable 前不得用于生产互通。
