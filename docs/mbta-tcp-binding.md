# MBTA TCP Binding Specification

**Status:** Frozen baseline / 冻结基准
**Revision:** r2 (2026-06)
**Authority:** 本文件是 MBTA **TCP 传输 binding** 规范，覆盖两个 ALPN：

| ALPN | 传输 × 密码 | 状态 |
|------|-------------|------|
| `mbta-tls/1` | TCP + TLS 1.3（国际） | **本规范定义（补齐对称性）** |
| `mbta-ntls/1` | TCP + TLCP（国密，GB/T 38636-2020） | 本规范定义 |

**Scope:** 本 binding 遵循 [mbta-core-spec.md](./mbta-core-spec.md) r2 全部核心语义。两者共用 TCP framing，**唯一差异是 TLS 握手层**（传输×密码正交两维，见 core §10）。凡本文件未定义处，以 core 为准。

---

## 1. 协议标识

| 字段 | `mbta-tls/1` | `mbta-ntls/1` |
|------|--------------|---------------|
| ALPN | `mbta-tls/1` | `mbta-ntls/1` |
| 传输 | TCP | TCP |
| 密码轴 | TLS 1.3（国际） | TLCP（国密） |
| Frame Version | `0x01` | `0x01` |
| 默认 CipherSuite | `intl`（SHA-256 / AES-256-GCM） | `gm`（SM3 / SM4-GCM） |
| 端口 | 独立 TCP 监听端口 | 独立 TCP 监听端口 |

> TCP binding 使用**独立 TCP 端口**，MUST NOT 与 QUIC 在同一监听入口混合（不可靠协议嗅探）。

---

## 2. 握手映射

```
TCP 连接建立
   │
   ├──[mbta-tls/1]──> TLS 1.3 握手（X.509 / SNI 验证）
   ├──[mbta-ntls/1]─> TLCP 握手（SM2 双证书：签名证书 + 加密证书）
   │
   ▼
MBTA framed stream（HELLO/HELLO_ACK/AUTH/...）
```

- **MUST** 先完成 TLS/TLCP 握手，才能接收任何 MBTA 帧；握手未完成收到帧 MUST 拒绝；
- 服务端 MUST 验证证书；生产 MUST NOT 关闭证书验证（core §14.1）；
- `mbta-ntls/1` 的 TLCP 使用 SM2 双证书（签名 + 加密），由 GB/T 38636-2020 定义；
- HELLO/HELLO_ACK 在**握手完成后**发送；本 binding **不支持 0-RTT**（TCP+TLS 无 0-RTT 语义），故不启用 capability `early_data`。

---

## 3. 帧与 Stream/Channel 映射

### 3.1 帧格式

完全遵循 core §2（8B `"MBTA"` 定长前缀 + varint Length + 可选 CRC16 + Payload）。本 binding 无增改。

### 3.2 Channel 语义（TCP 无 QUIC stream）

TCP 是单字节流，无原生多路复用。本 binding 用帧头 `ChannelID` 字段（core §2）显式定义 channel：

- 每连接 MUST 至少一个 **control channel**（`channel_id=0`），承载 HELLO/AUTH/WINDOW/THROTTLE/PING/PONG/CLOSE/ERROR；
- **data channel**（`channel_id≥1`）承载 BATCH/ACK/NACK/PARTIAL_ACK；
- 基础实现可只用单连接单 data channel（`channel_id=1`）；多 data channel 通过 capability `multi_channel`（core 附录 E）协商启用；
- 所有帧在同 TCP 连接交替传输；**写侧 MUST 串行化**（同一连接的帧不得交错），由实现用单写锁保证。

### 3.3 拆包/粘包/半开/短读防护（MUST）

TCP 是连续字节流，接收端 MUST：

1. 按 varint `Length` 精确读取 payload；
2. 拒绝超限 Length（> `max_frame_payload_bytes`）；
3. 处理短读（payload 未读完时 drain 剩余声明字节，维持帧边界，core §2.3）；
4. 处理半开连接（对端 RST/FIN 异常）；
5. 校验 CRC16（当 `NoCRC=0`；AEAD 传输下默认 `NoCRC=1`）。

---

## 4. 不可靠通道（DATAGRAM）

**本 binding 不支持 `unreliable_datagram`。** TCP 是可靠字节流，无原生不可靠通道。

- 客户端声明 `durability=lossy` 的 signal 在 TCP binding 下 **退化为 reliable BATCH**（走 `channel_id≥1`，正常 ACK/spool）；
- 服务端不接受 DATAGRAM 消息类型（core §4 type=7）在此 binding 上的使用；
- 实时/不可靠投递需求须使用 QUIC binding（见 [mbta-quic-binding.md](./mbta-quic-binding.md)）。

---

## 5. FlowClass 与网络协作

- `mbta-tls/1` / `mbta-ntls/1` 走 TCP over IPv4/IPv6；
- **IPv4**：无 Flow Label；DSCP 在公网常被清洗，FlowClass→DSCP 映射无效，不影响行为；
- **IPv6**：SHOULD 将 FlowClass 映射到 IPv6 Flow Label + DSCP（core §9.3），属可选增强；
- TCP 自身的 NODELAY（禁用 Nagle）SHOULD 开启，降低小帧延迟。

---

## 6. 支持的 Capability 子集

| Capability | 本 binding | 说明 |
|------------|-----------|------|
| `partial_ack` / `durable_ack` / `dedup` | ✅ | 投递语义与传输无关 |
| `unreliable_datagram` | ❌ | TCP 无不可靠通道 |
| `early_data` | ❌ | TCP+TLS 无 0-RTT |
| `multi_channel` | ✅（协商） | 帧多路复用多 data channel |
| `pmtu_probe` | ✅（协商） | ICMP 易黑洞，默认固定 1280 |
| `flow_class` | ✅ | IPv6 下映射 Flow Label |
| `symmetric_role` | ✅ | core §11.1 |
| `more_follows` / `coalesce_control` | ✅ | core §3 |

---

## 7. 与 core 的差异边界

本 binding **完全遵循 core**，仅在以下传输相关开放点具体化：

1. **握手段**：强制 TLS 1.3 或 TLCP（core §10 允许的密码轴取值）；
2. **多路复用**：用 `ChannelID` 帧字段而非 QUIC stream（core §10.1）；
3. **不可靠通道**：不支持（core 允许 binding 声明不支持，§10.2）；
4. **0-RTT**：不支持。

其余（帧格式、SecureEnvelope、SignalBatch、投递语义、流控、spool、密码套件协商、capability 生命周期）与 core 完全一致。

---

## 8. 一致性测试要求（本 binding 特有）

实现 MUST 通过：

- TLS 1.3 / TLCP 握手测试（含双证书验证）；
- TCP 拆包/粘包/短读/半开连接测试；
- 超大 Length、CRC16 错误防护测试；
- channel 多路复用（control + data 帧交替，不交错）；
- 写侧串行化（并发发送者帧不交错）；
- HELLO/AUTH/BATCH/ACK/NACK/PARTIAL_ACK/WINDOW/THROTTLE 端到端；
- spool 崩溃恢复 + 重连重发（core §11.5）；
- OTLP Logs/Metrics/Traces/Profiles 映射（core 附录 C）。

---

## 9. 两个 ALPN 的选择指引

| 部署需求 | 选择 |
|----------|------|
| 国际合规、海外、非国密要求 | `mbta-tls/1`（TCP+TLS1.3） |
| 国密合规（金融/政务/关基） | `mbta-ntls/1`（TCP+TLCP） |
| UDP/QUIC 受限网络 | TCP 系列（二者皆可，按合规选） |
| 需要多流低延迟、连接迁移、不可靠投递 | 用 QUIC binding，非本文件 |
