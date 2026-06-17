# MBTA Core Protocol Specification

**Status:** Frozen baseline / 冻结基准
**Revision:** r2 (2026-06) — 吸收前沿能力（profile signal、unreliable datagram、PQC 固化标准）、补齐 OTLP 对齐缺口、明确嵌入式/CoAP 定位
**Document Authority:** 本文件是 MBTA 协议的**权威核心规范**。所有传输 profile（QUIC / TCP+TLS1.3 / TCP+TLCP）与密码套件文档都是本规范的 **binding 实例**，不得与本文件冲突。
**Scope:** 本规范仅描述**线上字节格式**与**语义状态机**。它**与实现语言无关**：不假设 GC、不假设特定并发原语、不假设特定内存模型。任何"如何实现得快"的内容仅出现在文末非规范性（informative）的实现指南附录。

---

## 0. 设计原则

MBTA 是 Agent → Server 的遥测信号传输协议，对齐 OpenTelemetry 数据模型（OTLP）。本规范由四条正交原则约束，任何设计决策不得违反：

| 原则 | 含义 |
|------|------|
| **场景中立** | 默认值服务主力部署（服务器/云端/边缘 agent）；受限场景（嵌入式）与高阶场景（未来网络）通过**协商偏移**适配，不定义默认 |
| **密码双轨** | 国际与国密在协议每一层（传输 / HMAC / 加密 / 签名）**对称一等**；传输与密码拆成正交两维 |
| **长寿演化** | 把不可逆决策（线格式、字段号、enum 取值、默认值）与可演化决策（capability、新消息类型）分离；session 与传输 tuple 解耦 |
| **实现中立** | 协议只规定字节与语义；内存管理、并发模型、分配策略由实现自决 |

判别铁律：**协议规范 = 线上字节 + 语义状态机。一旦涉及"如何实现"，即离开协议范畴。**

---

## 1. 协议标识与版本治理

### 1.1 标识

| 字段 | 值 |
|------|----|
| Protocol Name | `MBTA` |
| Frame Magic | `"MBTA"` (4 字节 ASCII) |
| Frame Version | `0x01` |
| 默认 Payload | SignalBatch（OTLP-aligned） |

### 1.2 ALPN 与 Capability 的分工

**ALPN 仅在线格式不兼容时升级**（帧格式、状态机、安全语义的根本性变更）。特性集的演进走 **Capability 协商**，不动 ALPN。多数演进只动 capability，降低升级摩擦。

传输 profile 通过 ALPN 区分（绑定不同传输/安全栈）：

| ALPN | 传输 × 密码 | 状态 |
|------|-------------|------|
| `mbta/1` | QUIC + TLS 1.3（国际） | 可用 |
| `mbta/2` | QUIC + RFC 8998（国密 over QUIC） | 计划中 |
| `mbta-tls/1` | TCP + TLS 1.3（国际） | **本规范要求补齐**（见 §10） |
| `mbta-ntls/1` | TCP + TLCP（国密） | 可用 |
| `mbta-wt/1` | WebTransport over HTTP/3（浏览器/边缘） | **候选 binding，预留**（见 §10） |

> 传输与密码是正交两维（见 §10）。`mbta-tls/1` 与 `mbta-ntls/1` 共用 TCP framing，仅 TLS 握手层不同。

### 1.3 Capability 生命周期纪律

每个 capability 必须标记生命周期阶段，规范层定义其协商失败语义：

| 阶段 | 命名 | 语义 |
|------|------|------|
| experimental | `x-` 前缀 | 可改可删，不计入一致性 |
| stable | 正式名 | 语义冻结，进入一致性要求 |
| deprecated | `dep-` | 仍支持，新实现不应选择 |
| removed | — | MUST 拒绝 |

**失败语义：** 未识别的 experimental capability 静默忽略；未识别的 **stable** capability MUST 报协议错误（防止"加能力被老对端静默吞掉"）。

### 1.4 字段号与 enum 演化纪律

采用二进制 schema 编码（Protobuf，见 §6）后，以下为规范性铁律：

- **字段号永不复用**：删除的字段号永久 reserved。
- **enum 值只追加不复用**：`Codec`/`Compression`/`CipherSuite`/`DeliveryMode`/`ErrorNum` 等枚举永不回收旧值。
- **新字段必须有安全的默认零值**（前向/后向兼容）。

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
8+v     0/2     CRC16           (仅当 Flags.NoCRC = 0 时存在)
…       Length  Payload
```

其中 `v` 为 varint `Length` 占用字节数。

### 2.2 设计理由（规范性）

- **定长前缀 8 字节**：Magic + Version + Flags + Type + ChannelID 恰为一个机器字，字段自然对齐，任意实现可用单次内存访问完成头部解析。
- **4 字节 Magic**："MBTA" 全名提供高辨识度，接收端可从损坏的字节流中重新同步（误匹配概率远低于 2 字节魔数）。
- **Type 为 uint8**：消息类型空间 < 256，紧凑且足够。
- **Length 为 varint**：小载荷仅占 1 字节，兼顾窄带场景与大载荷（支持 jumbogram，上限 2⁶³−1）。
- **CRC16 可选**：当传输层已提供 AEAD 完整性（TLS 1.3 / TLCP）时，CRC 冗余，默认置 `NoCRC=1` 省略；仅在裸字节流 / 调试链路下使用。CRC 覆盖 Payload 字节，**大端序**编码。注意：单一 Length 字段，禁止冗余/过度指定的长度字段（避免差分解析漏洞）。

### 2.3 接收端校验（MUST）

接收端 MUST 拒绝：

1. Magic ≠ "MBTA"；
2. Version ≠ 0x01；
3. 保留 Flags 位（见 §3）被置位；
4. Length 超过协商的 `max_frame_payload_bytes`；
5. CRC16 不匹配（当存在时）；
6. 未读取完整的 Payload。

当 Header 已读但 Payload 读取失败时，接收端 MUST 排空（drain）声明的剩余字节，以维持帧边界对齐。

---

## 3. Flags 位语义

Flags 为 8 位，从 LSB 编号：

| Bit | 掩码 | 名称 | v1 状态 | 语义 |
|-----|------|------|---------|------|
| 0   | `0x01` | Envelope | ✅ 启用 | Payload 是 SecureEnvelope |
| 1   | `0x02` | Control | ✅ 启用 | 控制面消息 |
| 2   | `0x04` | Data | ✅ 启用 | 数据面消息 |
| 3   | `0x08` | MoreFollows | ✅ 启用 | 本帧是逻辑多片消息的一片，后续还有；末片清零 |
| 4   | `0x10` | NoCRC | ✅ 启用 | 置位=省略 CRC16（默认置位，依赖 AEAD） |
| 5   | `0x20` | Coalesced | ✅ 启用 | Payload 是多条同类型小消息的合并打包 |
| 6–7 | `0xC0` | FlowClass | ✅ 启用 | 流类别（见 §9.3）：00=normal, 01=control-be, 10=critical, 11=reserved(MUST 拒绝) |

### 3.1 硬规则（规范性）

1. **保留/未定义位 MUST 拒绝**：接收端遇到 FlowClass=`11` 置位时，返回协议错误并关闭连接。**不允许静默忽略**——扩展只能走 capability/版本协商。
2. **位组合约束**（MUST）：
   - `Control` 与 `Data` 互斥（`Flags & 0x06` 不可同时为 0 或同时非 0）；
   - `NoCRC=0`（携带 CRC）仅在传输层无 AEAD 时允许；AEAD 传输下 MUST 置 `NoCRC=1`；
   - `MoreFollows` 与 `Coalesced` 互斥（合并帧不再分片）。
3. **启用前置条件**：`MoreFollows`、`Coalesced`、特定 `FlowClass` 需通过 capability 协商（`more_follows` / `coalesce_control` / `flow_class`）后才允许使用；未协商而置位 → 拒绝。

> **FlowClass 与 DeliveryMode 是两个正交维度**：FlowClass（本节）表达**优先级/类别**；DeliveryMode（见 §11.4）表达**投递可靠性**（reliable/lossy）。两者独立，不互相占用位。

### 3.2 Coalesced Payload 子格式

```
coalesced_payload = uint8(count) + count × { uint16(inner_len) + inner_payload }
```

仅允许**同 Type** 的控制消息合并（如多个 ACK）。

---

## 4. 消息类型（Message Types）

`Type` 字段（uint8）取值：

| 值 | 类型 | 方向 | 说明 |
|----|------|------|------|
| 1  | HELLO | C→S | 版本与能力协商 |
| 2  | HELLO_ACK | S→C | 选定能力与连接参数 |
| 3  | AUTH | C→S | 认证请求 |
| 4  | AUTH_OK | S→C | 认证成功 |
| 5  | AUTH_FAIL | S→C | 认证失败 |
| 6  | BATCH | C→S | SignalBatch 传输（可靠） |
| 7  | DATAGRAM | C→S | 不可靠信号传输（见 §11.4，capability `unreliable_datagram`） |
| 8  | ACK | S→C | 整批确认 |
| 9  | NACK | S→C | 整批拒绝 |
| 10 | PARTIAL_ACK | S→C | 部分成功 + 逐项失败 |
| 11 | WINDOW | S→C | 流控窗口 |
| 12 | THROTTLE | S→C | 速率节流 |
| 13 | PING | 双向 | 健康探测 |
| 14 | PONG | 双向 | 健康响应（可携带自省信息） |
| 15 | CLOSE | 双向 | 优雅关闭 |
| 16 | ERROR | 双向 | 协议错误 |

> 值 6（BATCH）与 7（DATAGRAM）区别仅在**投递语义**：BATCH 走可靠流 + ACK + spool；DATAGRAM 走 QUIC DATAGRAM（RFC 9221）或等价不可靠通道，无 ACK、无重传、无 spool。见 §11.4。

17–255 保留给未来扩展；新类型 MUST 通过 capability 协商，未协商的未知类型 MUST 拒绝。

### 4.1 消息载荷编码

所有消息的 Payload 按连接协商的 **Codec（§6.3）** 编码为对应的 message 结构（即控制面与数据面统一编码，不另设定长二进制控制帧格式）。具体 message schema（字段号、类型）由 proto 定义维护，本规范仅约束字段**语义**。

- `Flags.Envelope=1` 时，Payload 是 SecureEnvelope，业务对象在其内（见 §5）；
- `Flags.Envelope=0` 时，Payload 是裸 message 编码（如部分轻量控制帧可选，由实现决定）；
- 失败项定位（PARTIAL_ACK）通过 `event_id` 或 signal index；大 batch 的失败项**可**编码为 bitmap 以紧凑表达，具体由 schema 决定。

> **编码约定：** 所有字符串字段（agent_id、reason、attributes 文本值等）MUST 为 **UTF-8**；多字节整数（CRC16 等）用**大端序**；Length 为无符号 varint。

---

## 5. SecureEnvelope

SecureEnvelope 是压缩、加密、认证的唯一承载点，避免安全处理分散到业务结构。

### 5.1 处理顺序

**发送（Build）：**
1. 业务对象按选定 Codec 规范编码；
2. 可选压缩；
3. 可选加密；
4. 计算 HMAC；
5. 序列化 envelope。

**接收（Open）：**
1. 解析 envelope；
2. 校验算法与 capability；
3. **校验 HMAC**（在解密/解码业务对象之前）；
4. 可选解密；
5. 可选解压；
6. 按选定 Codec 解码。

接收端 MUST 在解密或解码业务对象前验证 HMAC。

> **注：** DATAGRAM（不可靠）消息的完整性由传输层（QUIC DATAGRAM 的 AEAD）保证；其 SecureEnvelope 处理同上，但 HMAC 校验失败时仅丢弃该 datagram，不触发重传。

### 5.2 Envelope 字段（schema 纲要）

envelope 的字段用二进制 schema（见 §6）编码。关键字段（语义，非语言绑定）：

| 字段 | 类型 | 说明 |
|------|------|------|
| envelope_version | uint | wire 格式版本 |
| message_type | enum | batch / datagram |
| session_id | bytes | 会话标识 |
| key_id | bytes | 密钥标识 |
| seq | uint64 | 会话内单调递增（仅 reliable BATCH） |
| chunk_id | bytes(16) | **ULID**，全局唯一 + 时序（仅 reliable BATCH；datagram 可选） |
| created_at_unix_ms | int64 | 创建时间 |
| codec | enum | 见 §6 |
| compression | enum | 见 §7 |
| cipher_suite | enum | 见 §8 |
| delivery_mode | enum | reliable / lossy（见 §11.4） |
| nonce | bytes | 显式 nonce，**同密钥下禁止复用** |
| payload | bytes | 加密/压缩后的载荷（**原生 bytes，无 base64**） |
| mac | bytes | HMAC 输出（**原生 bytes**） |

### 5.3 HMAC 签名输入

HMAC 的签名输入为 envelope 序列化字节的**规范确定形式**（canonical wire bytes）。确定性编码（§6）保证同一 envelope 在任何实现下序列化结果逐字节一致，从而 HMAC 跨实现可验证。**禁止**用手工拼接的字符串作签名输入。

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

Server 侧 MUST 能无损映射到 OTLP（Logs / Metrics / Traces / **Profiles**，映射表见附录 C）。`signal_type` 必填；日志 MUST 用 `"log"`，空字符串非法。

### 6.2 Signal 类型语义

| signal_type | 说明 | OTLP 映射 |
|-------------|------|-----------|
| `log` | 日志/事件 | Logs LogRecord |
| `gauge` | 瞬时指标 | Metrics Gauge |
| `counter` | 单调/非单调计数 | Metrics Sum |
| `histogram` | 直方图，支持 **exponential bucket** 表达 | Metrics Histogram |
| `summary` | 摘要 | Metrics Summary |
| `span` | trace span | Traces Span |
| `profile` | 持续性能采样 profile | **Profiles Profile**（OTLP v1.3.0+） |

**histogram exponential bucket：** `histogram` signal 可声明 `aggregation=explicit | exponential`。exponential 模式对齐 OTel Exponential Histogram（更高分辨率、更低成本），字段含 `scale`、`offset`、`positive_buckets`、`negative_buckets`、`sum`、`count`、`min`/`max`。

**profile signal：** 携带采样类型（cpu / heap / mutex / goroutine 等）、profile 字节载荷，以及与 trace/log/metric 的**双向关联字段**（`profile_id`、`trace_id`、`span_id`、`log_record_ref`），对齐 OTel Profiles 跨信号关联目标。

> **生态状态注记（2026-06）：** OpenTelemetry 已于 2026-05-21 通过 **CNCF 毕业**（graduation），成为 vendor-neutral 的事实观测标准——这强化了 MBTA 对齐 OTLP 数据模型的战略正确性。`profile` 信号对应 OTLP Profiles（OTLP v1.3.0+ 引入，截至 Collector v1.49.0 / OTLP v1.9.0 仍在 **Alpha** 阶段，未 stable）。因此本规范在协议层**预留** `profile` signal_type 与映射，实现侧稳定性随 OTel Profiles 成熟度演进，二者解耦。

### 6.3 Codec 枚举（wire 值）

| Codec | 取值 | 适用 |
|-------|------|------|
| Protobuf | `proto` | **baseline 默认**：主力场景，确定性编码、跨语言、OTLP 互通 |
| CBOR | `cbor` | constrained 场景：自描述、紧凑、流式，受限环境友好 |
| JSON | `json` | 仅调试/人类可读，非生产推荐 |

**协议层选择 Protobuf 作默认的规范性理由**（实现中立）：
- MAC 跨实现确定性（wire-stable）；
- 跨语言代码生成（多语言互通）；
- wire 比 JSON 紧凑；
- 与 OTLP schema 直接互通。

> 任何具体实现的内存/CPU 表现属实现范畴，不作为协议层论证。

Codec 由 HELLO 协商；未协商的 codec MUST 拒绝。

---

## 7. 压缩（Compression）

压缩算法在 envelope `compression` 字段声明，per-envelope。协商通过 capability。

| Compression | 适用 |
|-------------|------|
| `zstd` | **baseline 默认**：通用最优比率/速度；可选 trained dictionary（`dict_id` 协商） |
| `lz4` | constrained / 低延迟：最低 CPU 与延迟 |
| `none` | 小载荷（压缩负收益）、DATAGRAM 实时信号、或已下层压缩 |
| `gzip` | 兼容兜底（legacy / OTLP 互操作） |

> 依据 OpenTelemetry Collector 社区收敛实践：zstd 为通用默认，lz4 为低延迟选项，gzip 为 legacy（OTel Collector issue #9128 maintainer 基准实测 lz4 在遥测场景优于 gzip）。本规范与此选型一致。

发送端可依据载荷特征自适应选择（从已协商集合内），写入 per-envelope 字段。接收端 MUST 按字段值解压，拒绝未协商算法。

**安全约束：** 接收端 MUST 强制解压上限（`max_decompressed_size`），防御高比率压缩的放大攻击。该上限不大于 `max_batch_bytes`。

---

## 8. 密码套件（双轨对称）

国际与国密在每一层对称一等。传输层算法由传输 binding 决定（§10），应用层算法由 `cipher_suite` 字段声明。

### 8.1 算法对称表

| 层 | 国际 | 国密 |
|----|------|------|
| 传输 TLS | TLS 1.3 | TLCP（GB/T 38636-2020）/ RFC 8998（IETF，TLS 1.3 + SM 套件） |
| HMAC | HMAC-SHA-256 | HMAC-SM3 |
| envelope AEAD | AES-256-GCM | SM4-GCM |
| 证书签名 | ECDSA-P256 / Ed25519 / RSA-PSS | SM2 |

### 8.2 Cipher Suite 抽象

`cipher_suite` 是**一组联动算法**（HMAC + AEAD + Sign），而非散装单算法，避免混搭带来的合规语义模糊：

| CipherSuite | HMAC | AEAD | Sign |
|-------------|------|------|------|
| `intl`（国际套件） | SHA-256 | AES-256-GCM | ECDSA/Ed25519 |
| `gm`（国密套件） | SM3 | SM4-GCM | SM2 |

HELLO 协商选**套件**；实现按套件选择算法，热路径无逐消息分支。

### 8.3 默认值规则（规范性）

**默认套件跟随传输 binding 的合规语境**，协议层不定全局默认：

- 选 TLS 1.3 binding → 默认 `intl`（HMAC-SHA-256 / AES-256-GCM）；
- 选 TLCP / RFC 8998 binding → 默认 `gm`（HMAC-SM3 / SM4-GCM）。

**对称命名**：capability 与枚举值成对平级（`hmac_sha256`/`hmac_sm3`、`enc_aes_gcm`/`enc_sm4_gcm`、`tls13`/`tlcp`/`rfc8998`），无主次前缀。任一套件缺失即视为不合规。

### 8.4 AEAD 加密约束

- nonce 显式随 envelope 传输（`nonce` 字段）；
- **同密钥下 nonce 禁止复用**；
- 密文格式：`nonce || ciphertext || tag`。

---

## 9. Session、流控与网络

### 9.1 Session 与传输 tuple 解耦（核心）

**SessionID 是逻辑身份，独立于任何传输 4-tuple。** 协议状态（认证态、窗口、inflight）绑定到 SessionID，不绑定到网络连接。

此设计同时服务：
- 嵌入式/移动场景：NAT 重绑定、IP 切换导致连接频繁断；
- QUIC：连接迁移（连接 IP 变化而连接不断）；
- 未来：传输替换、多路径（MP-QUIC）。

断连后，客户端以同一 SessionID 重连，服务端恢复/关联会话状态；spool 中待确认数据重发（见 §11）。

### 9.2 流控

| 消息 | 语义 |
|------|------|
| WINDOW | 服务端下发的 inflight 容量上限（批数 / 事件数 / 字节数） |
| THROTTLE | 临时速率节流（`retry_delay_ms`） |

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
- `capabilities`：能力宣告集——支持的 codec / compression / cipher_suite / delivery_mode 子集，以及各 §附录 E capability（客户端视角"我能做"）；
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

## 10. 传输 Binding（正交两维）

传输协议与密码套件是**正交两维**，合法组合全部一等：

```
传输轴:  QUIC | TCP | WebTransport(HTTP/3)
密码轴:  TLS1.3(国际) | TLCP(国密) | RFC8998(国密-over-QUIC) | PQC-hybrid(未来)
```

| 组合 | 状态 |
|------|------|
| QUIC + TLS 1.3 | ✅（`mbta/1`） |
| QUIC + RFC 8998 | 计划中（`mbta/2`）；国密 over QUIC 尚无独立 RFC，依赖实现（Tongsuo 等实验性） |
| TCP + TLCP | ✅（`mbta-ntls/1`） |
| TCP + TLS 1.3 | **本规范要求补齐**（`mbta-tls/1`），补齐国际 over TCP 对称性 |
| WebTransport over HTTP/3 | **候选 binding，预留**（`mbta-wt/1`） |

**补齐 `mbta-tls/1` 的理由（对称性）：** QUIC/UDP 受限、且不需要国密合规的场景（国际部署、海外工业、非国密合规环境）当前无入口。补齐后矩阵对称，国际不被挤掉。

**WebTransport binding（预留）：** WebTransport over HTTP/3（IETF draft）支持双向流、单向流与不可靠 datagram，且具备浏览器 API（W3C）。该 binding 打开 MBTA 的**浏览器/边缘场景**（前端 RUM、边缘 agent 直接上报）。当前仅作候选预留，不在冻结版实现——正交传输抽象已支持未来新增 binding。

> **传输标准状态注记（2026-06）：**
> - **QUIC v2（RFC 9369）** 已发布（2023），与 v1 功能等价，旨在对抗协议僵化（ossification），但部署仍有限。MBTA 不锁死 QUIC 版本。
> - **Multipath QUIC** 仍为 IETF draft（`draft-ietf-quic-multipath-21`），未成 RFC；3GPP TS 23.288 已为 5G/ATSSS 引用。MBTA 的 session/tuple 解耦（§9.1）与 effectively-once 去重（§11.3）为 MP-QUIC 冗余路径重包预留地基。
> - **国密 over QUIC** 仍**无统一国际/国家标准**（RFC 8998 仅覆盖 TLS 1.3，TLCP=GB/T 38636-2020 是独立协议栈），仅有 Tongsuo/BabaSSL 等实验性实现。此现状印证 `mbta/2` 推迟、优先 TCP+TLCP（`mbta-ntls/1`）的现实正确性。

### 10.1 TCP Binding 的 Channel 语义

TCP 无 QUIC stream，binding 须显式定义 channel：帧头 `ChannelID` 字段（§2）承载 channel 标识。每连接至少一个 control channel；多 data channel 通过 capability `multi_channel` 协商。

### 10.2 传输抽象（规范性）

协议核心（状态机 / SignalBatch / 投递 / 流控 / spool）**不假设某一种传输的存在**。新传输（QUIC v2 / MP-QUIC / WebTransport / 路径感知网络）作为新 binding 接入，核心不变。binding 须声明其支持的投递模式（是否支持 `unreliable_datagram`，见 §11.4）。

### 10.3 Binding 文档规范要求（规范性）

每个传输 binding 文档 MUST 定义以下内容，缺一不可；未定义项视为该 binding 不支持：

| 项 | 要求 |
|----|------|
| ALPN 与标识 | binding 对应的 ALPN、Frame Version、密码轴取值 |
| 握手映射 | TLS/TLCP/等握手如何完成；HELLO/HELLO_ACK 起始时机（握手后或 0-RTT 内） |
| Stream / Channel 映射 | control/data 如何映射到传输多路复用单元（QUIC stream / TCP channel/帧多路复用）；`ChannelID` 字段语义 |
| 不可靠通道 | 是否支持 `unreliable_datagram`（§11.4）；支持则说明映射（如 QUIC DATAGRAM），不支持则 DATAGRAM 退化为 reliable 或拒绝 |
| 帧分片/粘包处理 | 字节流类 binding（TCP）MUST 说明拆包/粘包/半开/短读防护；数据报类 binding（QUIC）说明帧与 datagram 边界关系 |
| FlowClass 网络协作 | 是否/如何映射 IPv6 Flow Label 与 DSCP（§9.3） |
| 支持的 capability 子集 | 该 binding 启用/禁用哪些 core capability（如 `multi_channel`、`pmtu_probe`） |
| 与 core 的差异边界 | 显式列出与 core 默认行为的任何偏离（无偏离则声明"完全遵循 core"） |
| 一致性测试要求 | 该 binding 特有的一致性项（如 TCP 拆包测试、QUIC 连接迁移测试） |

凡 binding 文档与 core 冲突，**以 core 为准**。binding 仅在 core 允许的"传输相关开放点"上做具体化。


---

## 11. 角色与投递语义

### 11.1 角色

- **baseline（默认）**：单向 hub-spoke（Agent → Server）。这是遥测的现实拓扑，状态机最小。
- **advanced（capability `symmetric_role`）**：对等角色（initiator/responder，mutual auth）。为 IPv6 可寻址下的反向推送、联邦聚合预留。baseline 客户端无需实现。

### 11.2 投递标识

| 字段 | 语义 |
|------|------|
| `seq` | Agent 会话内单调递增的批次序号（仅 reliable BATCH） |
| `chunk_id` | **ULID(16 字节)**，全局唯一 + 时序，用于去重、重试、抗重放（仅 reliable BATCH） |

PARTIAL_ACK MUST 通过 `event_id` 或 signal index 定位失败项，支持逐项重试。

### 11.3 Reliable 投递保证（BATCH，capability）

| 模式 | 语义 | 去重缓存 |
|------|------|----------|
| **at-least-once**（baseline 默认） | 崩溃/断连重发，可能重复投递 | per-connection，轻量 |
| **effectively-once**（capability `durable_ack` + `dedup`） | 服务端持久化去重表（带 TTL），跨重连命中 | 持久化，TTL 窗口内不重复投递 |

**选择理由：** effectively-once 依赖 `chunk_id` 全局唯一性，故与 ULID 决策绑定。轻量部署（海量嵌入式 Agent）可退回 at-least-once，不为每个轻量连接维护持久化表——下游按幂等处理。

### 11.4 Unreliable 投递（DATAGRAM，capability `unreliable_datagram`）

**动机（吸收 RFC 9221）：** 实时/高频低价值信号（实时仪表盘、每秒指标）中，**陈旧数据无价值，重传反而有害**。对这类信号，可靠重传是错误的保障模型。

| 维度 | BATCH（reliable） | DATAGRAM（lossy） |
|------|-------------------|-------------------|
| DeliveryMode | `reliable` | `lossy` |
| 投递保证 | at-least-once / effectively-once | **at-most-once**（尽最大努力，不重传） |
| ACK/NACK | 有 | **无** |
| spool 持久化 | 有（崩溃重发） | **无** |
| seq / chunk_id | 必填 | 可选（仅作采样/关联，不参与去重） |
| 纳入 WINDOW inflight | 是 | **否**（仅受传输层拥塞约束） |
| 传输通道 | QUIC stream / TCP | **QUIC DATAGRAM（RFC 9221）**或等价不可靠通道 |
| 失败处理 | NACK / 重试 | 静默丢弃（HMAC 失败亦丢弃，不重传） |

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

QUIC 原生支持 0-RTT：客户端在握手完成前发送已 spooled 的 reliable BATCH（早期数据），降低握手 RTT 占比——这对"每天醒一次"的电池/嵌入式场景与跨地域高延迟场景能耗与延迟收益显著。

**TCP binding 不支持**（`mbta-tls/1` / `mbta-ntls/1`）：
- Go `crypto/tls` 不暴露 0-RTT application data API（`tls.Conn.Write` 在握手后）；
- TLCP（pollux-go/tlcp）无 0-RTT data 语义；
- TCP binding 使用 TLS session resumption（`ClientSessionCache`）降低 resumption 握手开销（1-RTT），但**不发送 0-RTT data**。
- 这与 §11.4 `SupportsDatagram=false`（TCP 无不可靠通道）一致：TCP binding 的传输层不支持握手前 application data。

**抗重放约束（MUST）：**
- 0-RTT 早期数据 MUST 携带 `chunk_id`（ULID）；服务端 MUST 经去重缓存校验，重放的 0-RTT BATCH 命中则丢弃并回 ACK（effectively-once 场景）或拒绝（at-least-once 场景按部署策略）；
- **AUTH MUST NOT 走 0-RTT**（认证凭据不可重放暴露）；0-RTT 仅限已认证会话的 resumption；
- 服务端可按部署策略限制 0-RTT 批量上限（`max_early_data_bytes`），缩小重放影响面。

**适用判断：** 客户端声明 capability `early_data` 且 binding 为 QUIC（`SupportsDatagram()==true`）时启用；TCP binding 不响应此 capability。

---

## 12. 场景分层与定位

## 12. 场景分层与定位

### 12.1 场景分层（Capability 协商偏移）

默认服务主力部署。受限与高阶场景通过协商偏移，**不改默认值**。

| 维度 | baseline（默认） | constrained（嵌入式降级） | advanced（高阶增强） |
|------|------------------|---------------------------|----------------------|
| Codec | proto | cbor | — |
| 压缩 | zstd | lz4 / none | — |
| 传输 | QUIC+TLS1.3 / TCP+TLCP | 同左（多走 TCP） | MP-QUIC / WebTransport / PQC binding |
| 投递 | at-least-once | 同左 | effectively-once / unreliable_datagram |
| 角色 | 单向 | 同左 | 对称 / 联邦 |
| PMTU | 安全默认 1280 | 固定保守值 | 探测 + jumbo |
| FlowClass→FlowLabel | SHOULD（IPv6） | 不启用 | 启用 |
| 资源能力 | — | `resource_class=embedded` 触发服务端降级（更小 batch / 关压缩 / 拉长心跳） | — |

**协商方向：** 能力弱的一端（嵌入式）主动声明可用子集，向 baseline 降级；服务端不下调自身默认。一个只实现 constrained 子集的客户端与全 baseline 服务端对接时，自动降级到公共子集互通。

### 12.2 与 CoAP / LwM2M 的定位边界

嵌入式/受限设备领域已有成熟国际标准 **CoAP（RFC 7252）+ LwM2M**（DTLS 安全、低开销、RESTful 资源模型、设备管理）。MBTA **不与之正面竞争**，定位明确分工：

| 维度 | CoAP / LwM2M | MBTA constrained |
|------|--------------|------------------|
| 核心模型 | RESTful 资源 / 设备管理（OTA、配置、传感器读数） | OTLP 语义遥测聚合传输（resource/scope/signal） |
| 数据模型 | 资源树 | SignalBatch → OTLP |
| 强项 | 设备管理、UDP/DTLS、MCU 友好 | 可靠/不可靠双通道投递、流控、国密、OTLP 互通 |
| 典型设备 | 真·MCU 传感器（NB-IoT、LoRa） | 有 IP 栈 + 需 OTLP 语义 + 资源受限的**网关级**设备 |

**结论：**
1. MBTA constrained profile 的适用边界是"**有 IP 栈、需 OTLP 语义、资源受限**"的网关/边缘级设备，而非真·MCU 传感器；
2. 真·MCU 传感器场景宜用 CoAP/LwM2M 采集，在网关处转换为 MBTA 上行；
3. MBTA 不重复 CoAP 的设备管理能力（OTA/配置），仅做遥测聚合传输。

此边界澄清使 constrained profile 聚焦其真实价值，避免在嵌入式领域重复造轮子。

---

## 13. 错误码

错误码携带数字码（NumCode）+ 字符串码，可程序化匹配。

| 范围 | 类别 |
|------|------|
| 1000–1099 | 配置 |
| 2000–2099 | 传输 |
| 3000–3099 | 协议 |
| 4000–4099 | 数据 |
| 5000–5099 | 流控 |
| 6000–6099 | 存储 |
| 7000–7099 | 版本 |
| 8000–8099 | 安全 |
| 9000–9999 | 实验/私有（不计入一致性） |

**纪律：** 数字码语义一旦发布不可改（只能 deprecated）；字符串码与数字码的稳定映射由实现 schema 维护并随版本冻结，二者一旦发布不可改语义。完整错误码表（含具体 NumCode 常量与字符串码）由参考实现的 schema 定义维护，不在此重复列举。

---

## 14. 安全考虑

1. **传输安全**：MUST 强制 TLS 1.3 / TLCP；生产 MUST NOT 关闭证书验证。
2. **完整性**：SecureEnvelope HMAC MUST 在解密/解码前验证；DATAGRAM 的完整性由传输层 AEAD 保证，HMAC 失败静默丢弃。
3. **重放**：`chunk_id` ULID + nonce + 去重缓存协同抗重放（仅 reliable BATCH；DATAGRAM at-most-once，重放影响有限）。
4. **放大攻击**：解压上限、payload 上限 MUST 强制。
5. **后量子（PQC）迁移（具体化）：** NIST 已于 2024-08 固化三大 PQC 标准——**FIPS 203 (ML-KEM)**、**FIPS 204 (ML-DSA)**、**FIPS 205 (SLH-DSA)**。
   - 传输 binding 的密钥交换应支持 **ML-KEM (FIPS 203) 混合密钥交换**（经典 ECDH/SM2 + ML-KEM），ML-KEM 为近乎 ECDH 的 drop-in 替换；
   - 签名支持 **ML-DSA (FIPS 204)** 作为 ECDSA/SM2 的未来选项；
   - cipher suite 抽象保持可扩展，PQC 套件作为新 enum 值追加（遵循 §1.4 只追加纪律），不替换现有国际/国密套件；
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
8. OTLP Logs/Metrics/Traces/Profiles 映射能力（附录 C）；
9. 错误码与失败语义（§13）。

**DATAGRAM（不可靠投递）为可选 capability**，不实现仍合规。**一个只实现 constrained 子集（CBOR + lz4 + at-least-once + 单向）的嵌入式实现是合规的**，只要它与 baseline 服务端协商降级互通。

---

## 附录 A（informative）：实现指南

本附录**非规范性**，描述"如何实现得高效"，与语言无关，不构成一致性要求。

1. **定长对齐的帧头便于一次内存访问解析**：8 字节定长前缀、自然对齐的字段布局，使任意实现可用单次内存访问读取头部，无需逐字节解析。
2. **二进制 schema 编码（proto）比动态文本解析更紧凑、字段访问更直接**：定长记录优于指针间接，利于缓存与批量处理。
3. **实现宜复用编解码缓冲区**以减少动态分配；具体策略（对象池、slab 等）由实现自决。
4. **高并发下，热点结构可分区（sharded）以降低争用**；并发原语由实现选择。
5. **写路径宜支持多帧合并（coalesce）与 gather write**，减少系统调用与缓冲区拷贝。
6. **HMAC 宜直接作用于序列化字节**（§5.3），避免额外拼接。
7. **DATAGRAM 实现宜复用传输层不可靠通道**（QUIC DATAGRAM），避免在可靠流上模拟不可靠语义。
8. **自省**：PONG / HELLO_ACK 可携带实现的能力矩阵、版本、负载水位，供对端自适应（如观测到对端 `degraded` 时主动降速）。

> 以上均非协议要求。一个不照做的实现仍合规——仅可能性能不同。任何具体语言（含 Go 参考实现）的优化细节应记录于该实现的文档，不写入本规范。

---

## 附录 B：与现有文档的关系

| 文档 | 角色 |
|------|------|
| **mbta-core-spec.md（本文件）** | 权威冻结基准，所有 binding 的共同核心 |
| mbta1-rfc-draft-bilingual.md | `mbta/1`（QUIC+TLS1.3）binding 规范，须与 §10 对齐 |
| mbta-ntls1-rfc-draft-bilingual.md | `mbta-ntls/1`（TCP+TLCP）binding 规范，须与 §10 对齐 |
| mbta2-rfc-draft-bilingual.md | `mbta/2`（QUIC+RFC8998）binding 规范 |
| **mbta-tls/1（待起草）** | TCP+TLS1.3 binding，补齐 §10 对称性 |
| **mbta-wt/1（预留）** | WebTransport over HTTP/3 binding，浏览器/边缘场景 |
| performance-optimization.md | **Go 参考实现**的性能笔记，实现特定，非协议要求 |
| mbta1-architecture-diagrams.md | 架构图（实现层） |

凡 binding 文档与本规范冲突，**以本规范为准**。

---

## 附录 C：OTLP 映射

| MBTA | OTLP |
|------|------|
| `SignalBatch.resource` | Resource |
| `SignalBatch.scope` | InstrumentationScope |
| `signal_type="log"` | Logs LogRecord |
| `signal_type="gauge"` | Metrics Gauge |
| `signal_type="counter"` | Metrics Sum |
| `signal_type="histogram"`（explicit / exponential） | Metrics Histogram |
| `signal_type="summary"` | Metrics Summary |
| `signal_type="span"` | Traces Span |
| `signal_type="profile"` | **Profiles Profile**（OTLP v1.3.0+） |
| `attributes` | record/data point attributes |

ACK/NACK/PARTIAL_ACK/DATAGRAM/spool/WINDOW/THROTTLE/SecureEnvelope 属 MBTA 传输控制语义，不映射为 OTLP 数据模型字段。

---

## 附录 D：r2 修订摘要（2026-06）

**功能吸收：**
- §6 / 附录 C：新增 `profile` signal_type（对齐 OTLP v1.3.0+ 第四信号）；histogram 支持 exponential bucket 表达。修复 OTLP 对齐缺口。
- §4 / §11.4：新增 DATAGRAM 消息类型与 `unreliable_datagram` capability（吸收 RFC 9221 不可靠数据报），建立 reliable/lossy 双投递通道。
- §10：新增 WebTransport（`mbta-wt/1`）候选 binding 与 PQC-hybrid 密码轴。
- §14：PQC 迁移路径具体化为 FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)。
- §12.2：新增与 CoAP/LwM2M 的定位边界澄清。
- 压缩选型与 OTel Collector 社区收敛实践对齐（§7）。

**遗漏补全：**
- §4.1：明确控制/数据消息统一按 Codec 编码，PARTIAL_ACK 失败项可用 bitmap。
- §11.6：新增 0-RTT 投递（`early_data`）语义与抗重放约束；明确标注**仅 QUIC binding**支持（TCP binding 受 Go crypto/tls 限制不支持 0-RTT data）。
- §13：修正错误码映射的自指承诺（改由实现 schema 维护）。
- 附录 E：新增 Capability Registry（集中登记全部 capability + 生命周期阶段）。

**二轮遗漏补全：**
- §9.5：新增会话建立与协商握手协议（HELLO/HELLO_ACK/AUTH/AUTH_OK 字段语义、顺序、前置条件）。
- §9.6：新增优雅关闭 drain 语义（停新→drain inflight→超时强关→spool 保留）。
- §2 / §4.1：补充 CRC16 大端序、字符串 UTF-8、varint 无符号等编码约定。
- §10.3：新增 Binding 文档规范要求（元规范，约束各 binding 文档必须定义的 9 项内容）。

**2026-06 生态快照（用于校准前瞻性判断）：**

| 项 | 状态（2026-06） | 对 MBTA 的影响 |
|----|-----------------|----------------|
| OpenTelemetry | **CNCF 毕业**（2026-05-21） | 强化 OTLP 对齐战略 |
| OTLP 协议 | v1.9.0（Collector v1.49.0） | proto codec 选型稳固 |
| OTLP Profiles | **Alpha**（未 stable） | `profile` signal_type 协议层预留，实现侧解耦 |
| QUIC v2 | RFC 9369，部署有限 | 不锁 QUIC 版本 |
| Multipath QUIC | draft-ietf-quic-multipath-21，未 RFC | session 解耦 + effectively-once 已铺地基 |
| 国密 over QUIC | 无统一标准，仅实验实现 | 印证推迟 `mbta/2`、优先 TCP+TLCP 正确 |
| NIST PQC | FIPS 203/204/205 已固化（2024-08） | PQC 迁移路径可具体承诺 |
| Exponential Histogram | OTel 稳定特性 | histogram signal 字段表达支持 |

---

## 附录 E：Capability Registry（规范性）

本附录集中登记本规范定义的全部 capability 及其生命周期阶段（阶段语义见 §1.3）。未登记的 capability MUST 使用 `x-` experimental 前缀。登记值一旦标 stable，名称与语义冻结（遵循 §1.4 只追加纪律）。

### E.1 投递与可靠性

| Capability | 阶段 | 语义 | 引用 |
|------------|------|------|------|
| `partial_ack` | stable | 支持逐项部分确认 | §11.2 |
| `durable_ack` | stable | 支持 Durable ACK（持久化后确认） | §11.3 / §11.5 |
| `dedup` | stable | 服务端持久化跨重连去重（effectively-once） | §11.3 |
| `unreliable_datagram` | stable | 支持不可靠 DATAGRAM 投递通道 | §11.4 |
| `early_data` | stable | 支持 0-RTT 早期数据投递（**仅 QUIC binding**） | §11.6 |

### E.2 传输与通道

| Capability | 阶段 | 语义 | 引用 |
|------------|------|------|------|
| `multi_channel` | stable | TCP binding 多 data channel | §10.1 |
| `pmtu_probe` | stable | 启用 PMTU 主动探测 | §9.4 |
| `flow_class` | stable | 启用 FlowClass 差异化（含 IPv6 FlowLabel/DSCP 映射） | §9.3 |
| `symmetric_role` | stable | 对等角色（initiator/responder，mutual auth） | §11.1 |

### E.3 帧与编码

| Capability | 阶段 | 语义 | 引用 |
|------------|------|------|------|
| `more_follows` | stable | 启用逻辑多片消息分帧 | §3 |
| `coalesce_control` | stable | 启用控制帧合并打包 | §3 |
| `flow_class` | stable | Flags FlowClass 位有效（同 E.2） | §3 |

### E.4 数据与算法

| Capability | 阶段 | 语义 | 引用 |
|------------|------|------|------|
| `comp_zstd` / `comp_lz4` / `comp_gzip` | stable | 压缩算法支持（按需协商子集） | §7 |
| `codec_proto` / `codec_cbor` / `codec_json` | stable | Codec 支持 | §6.3 |
| `cs_intl` / `cs_gm` | stable | 国际 / 国密密码套件支持（至少其一必备） | §8 |
| `histogram_exponential` | stable | histogram 支持 exponential bucket 表达 | §6.2 |

### E.5 实验性（示例，非穷尽）

| Capability | 阶段 | 语义 |
|------------|------|------|
| `x-pqc-hybrid` | experimental | PQC 混合传输密钥交换（ML-KEM） |
| `x-mpquic` | experimental | Multipath QUIC binding |
| `x-webtransport` | experimental | WebTransport over HTTP/3 binding |

> 实验性 capability 可随时变更或删除，不计入一致性。转为 stable 前不得用于生产互通。


