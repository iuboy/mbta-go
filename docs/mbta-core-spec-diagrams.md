# MBTA Core Protocol r2 — 图表与字段参考

> 配合 [mbta-core-spec.md](./mbta-core-spec.md) r2 使用。所有字段值、偏移、枚举均以 core spec r2 为准。

---

## 1. 帧格式（Frame Wire Format）

### 1.1 帧布局（§2）

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Magic "MBTA"                         |  Offset 0, 4B
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Flags     |     Type      |  ChannelID   |  Offset 4, 4B
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Length (varint, 1–5B)             | ...   |  Offset 8
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              CRC16 (optional, Flags.NoCRC=0)          |       |  仅当 NoCRC=0
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                          Payload                              ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| 字段 | 偏移 | 大小 | 说明 |
|------|------|------|------|
| Magic | 0 | 4B | 固定 `"MBTA"`（0x4D425441） |
| Version | 4 | 1B | 固定 `0x01` |
| Flags | 5 | 1B | 见 §2 |
| Type | 6 | 1B | uint8，消息类型（§3） |
| ChannelID | 7 | 1B | 0=control, ≥1=data |
| Length | 8 | varint | payload 字节数（LEB128，1–5B） |
| CRC16 | 8+v | 0/2B | IEEE CRC-16/CCITT-FALSE，大端（仅 NoCRC=0 时存在） |
| Payload | 8+v(+2) | Length | 消息内容 |

**最小帧**：9B（8B 定长前缀 + 1B varint Length=0 + 无 CRC + 空 payload）。

### 1.2 Flags 位定义（§3）

```
  Bit 7  6  5  4  3  2  1  0
     ┌──┬──┬──┬──┬──┬──┬──┬──┐
     │FC1│FC0│ Co│ NC│ MF│ D │ C │ En│
     └──┴──┴──┴──┴──┴──┴──┴──┘
      FlowClass   │    │   │   │   │
      (2 bit)     │    │   │   │   │
                 Coal  NoCRC MF  Dat Ctl Env
```

| Bit | 掩码 | 名称 | 说明 |
|-----|------|------|------|
| 0 | 0x01 | Envelope | payload 是 SecureEnvelope |
| 1 | 0x02 | Control | 控制面消息 |
| 2 | 0x04 | Data | 数据面消息（与 Control 互斥） |
| 3 | 0x08 | MoreFollows | 逻辑多片消息（§3） |
| 4 | 0x10 | NoCRC | 置位=省略 CRC16（AEAD 下默认置位） |
| 5 | 0x20 | Coalesced | 多条同类型小消息合并打包 |
| 6–7 | 0xC0 | FlowClass | 00=normal, 01=best-effort, 10=critical, 11=reserved(MUST 拒绝) |

**校验规则**：Control ∧ Data 互斥；MoreFollows ∧ Coalesced 互斥；FlowClass=3 MUST 拒绝。

---

## 2. 消息类型（§4）

```
 ┌─────────────────────────────────────────────────────────┐
 │                    MBTA 消息类型                          │
 ├──────────────┬──────┬───────────────────────────────────┤
 │ Type (uint8) │ 方向  │ 用途                               │
 ├──────────────┼──────┼───────────────────────────────────┤
 │  1  HELLO    │ C→S  │ 版本与能力协商                     │
 │  2  HELLO_ACK│ S→C  │ 选定能力 + 连接参数 + challenge    │
 │  3  AUTH     │ C→S  │ 认证请求（challenge-response）     │
 │  4  AUTH_OK  │ S→C  │ 认证成功 + 会话密钥 + ticket       │
 │  5  AUTH_FAIL│ S→C  │ 认证失败 + 新 challenge            │
 ├──────────────┼──────┼───────────────────────────────────┤
 │  6  BATCH    │ C→S  │ reliable batch（at-least-once）   │
 │  7  DATAGRAM │ C→S  │ unreliable datagram（at-most-once）│
 │  8  ACK      │ S→C  │ 整批确认                           │
 │  9  NACK     │ S→C  │ 整批拒绝                           │
 │ 10  PARTIAL  │ S→C  │ 部分成功 + 逐项失败               │
 ├──────────────┼──────┼───────────────────────────────────┤
 │ 11  WINDOW   │ S→C  │ 流控窗口                           │
 │ 12  THROTTLE │ S→C  │ 速率节流                           │
 ├──────────────┼──────┼───────────────────────────────────┤
 │ 13  PING     │ 双向  │ 健康探测                           │
 │ 14  PONG     │ 双向  │ 健康响应                           │
 │ 15  CLOSE    │ 双向  │ 优雅关闭 + drain timeout          │
 │ 16  ERROR    │ 双向  │ 协议错误                           │
 └──────────────┴──────┴───────────────────────────────────┘
 17–255 保留（新类型 MUST 通过 capability 协商）
```

---

## 3. SecureEnvelope（§5）

### 3.1 字段表（corepb.SecureEnvelope）

| 字段号 | 字段 | 类型 | 说明 |
|--------|------|------|------|
| 1 | envelope_version | uint32 | =1 |
| 2 | message_type | enum | BATCH=1 / DATAGRAM=2 |
| 3 | session_id | bytes | 会话标识 |
| 4 | key_id | bytes | 密钥标识 |
| 5 | seq | uint64 | 会话内单调递增（仅 reliable） |
| 6 | chunk_id | bytes(16) | ULID，全局唯一+时序 |
| 7 | created_at_unix_ms | int64 | 创建时间 |
| 8 | codec | enum | PROTO=1 / CBOR=2 / JSON=3 |
| 9 | compression | enum | ZSTD=1 / LZ4=2 / NONE=3 / GZIP=4 |
| 10 | cipher_suite | enum | INTL=1 / GM=2 |
| 11 | delivery_mode | enum | RELIABLE=1 / LOSSY=2 |
| 12 | nonce | bytes | 显式 nonce，同密钥禁止复用 |
| 13 | payload | bytes | 加密+压缩后载荷（原生 bytes，无 base64） |
| 14 | mac | bytes | HMAC 输出（原生 bytes） |

### 3.2 处理顺序（§5.1）

```
 发送 (Build):
 ┌─────────────┐    ┌──────────┐    ┌──────────┐    ┌─────┐    ┌────────┐
 │ Codec 编码  │───▶│ 压缩     │───▶│ AEAD 加密│───▶│ HMAC│───▶│ 序列化 │
 │(proto/cbor) │    │(zstd/lz4)│    │(AES/SM4) │    │     │    │        │
 └─────────────┘    └──────────┘    └──────────┘    └─────┘    └────────┘
                                                       │
                            HMAC 输入 = proto.Marshal(env_mac=∅)
                            (Deterministic: true)

 接收 (Open):
 ┌────────┐    ┌─────┐    ┌──────────┐    ┌──────────┐    ┌─────────────┐
 │ 解析   │───▶│ HMAC│───▶│ AEAD 解密│───▶│ 解压      │───▶│ Codec 解码  │
 │envelope│    │校验 │    │          │    │          │    │             │
 └────────┘    └─────┘    └──────────┘    └──────────┘    └─────────────┘
                │
          MUST 在解密/解码前校验
```

---

## 4. 密码套件双轨（§8）

```
 ┌─────────────────────────────────────────────────────────┐
 │                CipherSuite 正交对称                      │
 │                                                         │
 │  ┌──────────┐  ┌────────────┐  ┌──────────┐            │
 │  │   层     │  │  国际 intl │  │  国密 gm  │            │
 │  ├──────────┼──┼────────────┼──┼──────────┤            │
 │  │ 传输 TLS │  │  TLS 1.3   │  │ TLCP/RFC8998│          │
 │  │ HMAC     │  │ SHA-256    │  │ SM3       │            │
 │  │ AEAD     │  │ AES-256-GCM│  │ SM4-GCM   │            │
 │  │ 签名     │  │ ECDSA/Ed25519│ │ SM2       │           │
 │  └──────────┘  └────────────┘  └──────────┘            │
 │                                                         │
 │  默认跟随 binding: TLS1.3→intl, TLCP/RFC8998→gm        │
 └─────────────────────────────────────────────────────────┘
```

---

## 5. 状态机

### 5.1 Server 状态机（§9.5）

```
                  ┌──────────┐
                  │ Accepted │ ← 初始
                  └────┬─────┘
                       │ Transition
                  ┌────▼──────────┐
                  │ ControlWait   │
                  └────┬──────────┘
              收到 HELLO │
                  ┌────▼──────────┐
                  │ HelloReceived │
                  └────┬──────────┘
              发 HELLO_ACK │
                  ┌────▼──────────┐
                  │  AuthWait     │
                  └────┬──────────┘
              AUTH_OK │  AUTH_FAIL → 回 AuthWait（新 challenge）
                  ┌────▼──────────┐
                  │    Ready      │ ← dataLoop 启动（或 earlyData 时更早）
                  └────┬──────────┘
              CLOSE │
                  ┌────▼──────────┐
                  │   Draining    │ ← drain inflight（close_timeout）
                  └────┬──────────┘
                       │
                  ┌────▼─────┐
                  │  Closed  │
                  └──────────┘
```

### 5.2 Client 状态机

```
 Disconnected → Connecting → ControlStreamOpen → HelloSent
      → HelloAcked → AuthSent → Ready → Draining → Closed
```

### 5.3 握手时序图（§9.5）

```
 Agent                                Server
   │                                    │
   │ ──────── QUIC/TCP 握手 ──────────▶ │
   │                                    │
   │ ──────── HELLO ──────────────────▶ │  (capabilities + session_ticket?)
   │ ◀──────── HELLO_ACK ───────────── │  (selected caps + challenge + limits)
   │                                    │
   │ ──────── AUTH ──────────────────▶ │  (token + challenge-response)
   │ ◀──────── AUTH_OK ────────────── │  (keys + session_ticket)
   │                                    │
   │ ════════ Ready ═══════════════════ │
   │                                    │
   │ ──────── BATCH ─────────────────▶ │  (envelope: compress→encrypt→HMAC)
   │ ◀──────── ACK ────────────────── │
   │                                    │
   │ ──────── DATAGRAM (0-RTT) ──────▶ │  (unreliable, 仅 QUIC)
   │           (无 ACK)                 │
   │                                    │
   │ ──────── CLOSE ─────────────────▶ │  (drain timeout)
   │ ◀──────── drain complete ──────── │
   │                                    │
```

---

## 6. 投递通道（§11）

```
 ┌─────────────────────────────────────────────────────┐
 │                  Client SendBatch                   │
 │                                                     │
 │  ┌──────────┐  reliability?  ┌────────────────────┐ │
 │  │ signal   │────────────────│ durability=lossy?  │ │
 │  │ batch    │                │  + SupportsDatagram│ │
 │  └──────────┘                └──────┬────────┬────┘ │
 │                               YES   │        │ NO   │
 │                              ┌──────▼──┐ ┌───▼────┐ │
 │                              │ DATAGRAM│ │ BATCH  │ │
 │                              │(lossy)  │ │(reliab)│ │
 │                              └────┬────┘ └───┬────┘ │
 │                                   │          │      │
 │  ┌────────────────────────────────┘          │      │
 │  │ NO ACK    NO spool   NO retry             │      │
 │  │ at-most-once                               │      │
 │  │                                           │      │
 │  │                              ACK + spool + retry │
 │  │                              at-least-once       │
 └──┼──────────────────────────────────────────┼──────┘
    │                                          │
    ▼                                          ▼
 ┌──────────┐                          ┌──────────────┐
 │ Server   │                          │ Server       │
 │ process  │                          │ processBatch │
 │Datagram  │                          │ VerifyMAC →  │
 │(尽力投递) │                          │ Open → route │
 │          │                          │ → ACK/NACK   │
 └──────────┘                          └──────────────┘
```

### 0-RTT early_data（仅 QUIC binding，§11.6）

```
 首次连接：Dial → 握手 → AUTH_OK（颁发 MBTA ticket + TLS 自动存 session ticket）

 resumption（0-RTT）：
   client DialEarly（TLS ticket → 0-RTT）
     │
     ├── HELLO（session_ticket → CoreHandler 恢复 keys + earlyData=true）
     │
     ├── dataLoop 立即启动（HELLO 后，非 AUTH 后）
     │
     ├── 0-RTT BATCH（resumption keys）──▶ processBatch → ACK
     │   （AUTH 前发送，dedup 保护）
     │
     └── AUTH（full auth，§11.6: AUTH MUST NOT 走 0-RTT）
```

---

## 7. 架构（§10 binding 正交）

```
 ┌─────────────────────────────────────────────────────────┐
 │                    MBTA Core Spec r2                    │
 ├─────────────────────────────────────────────────────────┤
 │                                                         │
 │  ┌─────────────────────────────────────────────────┐   │
 │  │              protocol/CoreHandler                 │   │
 │  │  (传输无关：握手 / envelope / 投递 / 流控 / ACK)   │   │
 │  │                                                   │   │
 │  │  Transport interface                              │   │
 │  │  ├── RecvControlFrame / RecvDataFrame             │   │
 │  │  ├── SendFrame                                    │   │
 │  │  ├── SupportsDatagram / SendDatagram              │   │
 │  │  └── Multiplexing()                               │   │
 │  └───────────────────┬───────────────────────────────┘   │
 │                      │                                   │
 │     ┌────────────────┼────────────────┐                 │
 │     │                │                │                 │
 │  ┌──▼───┐     ┌──────▼─────┐   ┌─────▼──────┐          │
 │  │ v1   │     │   ntls     │   │   ntls     │          │
 │  │ QUIC │     │ TCP+TLCP   │   │ TCP+TLS1.3 │          │
 │  │      │     │ mbta-ntls/1│   │ mbta-tls/1 │          │
 │  │ Data │     │  Data ◐    │   │  Data ◐    │          │
 │  │ DG ✓ │     │  DG ✗     │   │  DG ✗     │          │
 │  │0RTT✓ │     │ 0RTT ✗    │   │ 0RTT ✗    │          │
 │  └──────┘     └────────────┘   └────────────┘          │
 │                                                         │
 │  core (wire + envelope + cipher + capability + session) │
 │  corepb (proto 生成: envelope + signal + control)       │
 │  spool (at-least-once 持久化)                           │
 └─────────────────────────────────────────────────────────┘

 DG = SupportsDatagram    0RTT = early_data capability
 ◐ = session resumption（1-RTT，非 0-RTT data）
```

---

## 8. Capability Registry（附录 E）

| Capability | 阶段 | 仅 QUIC? | 引用 |
|------------|------|----------|------|
| `partial_ack` | stable | 否 | §11.2 |
| `durable_ack` | stable | 否 | §11.3 |
| `dedup` | stable | 否 | §11.3 |
| `unreliable_datagram` | stable | **仅 QUIC** | §11.4 |
| `early_data` | stable | **仅 QUIC** | §11.6 |
| `multi_channel` | stable | 否 | §10.1 |
| `pmtu_probe` | stable | 否 | §9.4 |
| `flow_class` | stable | 否 | §9.3 |
| `symmetric_role` | stable | 否 | §11.1 |
| `more_follows` | stable | 否 | §3 |
| `coalesce_control` | stable | 否 | §3 |
| `comp_zstd` / `comp_lz4` / `comp_gzip` | stable | 否 | §7 |
| `codec_proto` / `codec_cbor` / `codec_json` | stable | 否 | §6 |
| `cs_intl` / `cs_gm` | stable | 否 | §8 |
| `histogram_exponential` | stable | 否 | §6.2 |

---

## 9. OTLP 映射（附录 C）

```
 MBTA SignalBatch                    OTLP
 ┌──────────────────┐               ┌──────────────────┐
 │ resource         │ ────────────▶ │ Resource         │
 │ scope            │ ────────────▶ │ InstrumentationScope│
 │ signals[]        │               │                  │
 │  ├ log           │ ────────────▶ │ Logs LogRecord   │
 │  ├ gauge         │ ────────────▶ │ Metrics Gauge    │
 │  ├ counter       │ ────────────▶ │ Metrics Sum      │
 │  ├ histogram     │ ────────────▶ │ Metrics Histogram│
 │  ├ summary       │ ────────────▶ │ Metrics Summary  │
 │  ├ span          │ ────────────▶ │ Traces Span      │
 │  └ profile       │ ────────────▶ │ Profiles (v1.3+) │
 └──────────────────┘               └──────────────────┘

 ACK/NACK/DATAGRAM/WINDOW/THROTTLE/SecureEnvelope → 不映射（MBTA 传输控制语义）
```

---

## 10. 错误码范围

```
 1000–1099  配置      5000–5099  流控
 2000–2099  传输      6000–6099  存储
 3000–3099  协议      7000–7099  版本
 4000–4099  数据      8000–8099  安全
                        9000–9999  实验/私有（不计入一致性）
```
