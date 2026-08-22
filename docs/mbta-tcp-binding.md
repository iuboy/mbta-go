# MBTA TCP Binding 规范（r3）

**状态：** 实施规格（r3，2026-08）
**权威性：** 本文件是 MBTA **TCP 传输 binding** 规范，遵循 [mbta-core-spec.md](./mbta-core-spec.md) r3；未定义处以 core 为准。参考实现：`ntls/` 包（`transport.go`、`tcp_transport.go`、`client.go`）。

**覆盖 ALPN：**

| ALPN | 传输 × 密码 | 状态 |
|------|-------------|------|
| `mbta-ntls/1` | TCP + TLCP（国密，GB/T 38636-2020） | 本规范定义 |
| `mbta-tls/1` | TCP + TLS 1.3（国际） | 本规范定义 |

两个 ALPN 共用同一 TCP framing 与协议语义，差异仅在 TLS 握手层（§2）。r3 为原地破坏性重构，ALPN 标识不变（core §0.1）。

---

## 1. 协议标识

| 字段 | `mbta-ntls/1` | `mbta-tls/1` |
|------|---------------|--------------|
| ALPN | `mbta-ntls/1` | `mbta-tls/1` |
| 传输 | TCP（独立监听端口） | TCP（独立监听端口） |
| 密码轴 | TLCP（SM2 双证书） | TLS 1.3（单证书，MinVersion = 1.3） |
| 应用层 profile 默认 | `gm`（SM2 + HKDF-SM3 + SM4-GCM） | `gm`（参考实现 binding 级默认；实际以 HELLO 声明为准，见 §9.4） |
| 帧格式 | core §1（2B 头 + varint；无 magic/version/channel） | 同左 |

- TCP binding 使用**独立 TCP 监听端口**，MUST NOT 与 QUIC 在同一监听入口混合。
- 两个 ALPN 由服务端 `TLSMode` 配置切换：false（默认）= `mbta-ntls/1`；true = `mbta-tls/1`。

---

## 2. 握手映射

```
TCP 连接建立
   │
   ├──[mbta-ntls/1]──> TLCP 握手（SM2 双证书：签名证书 + 加密证书）
   ├──[mbta-tls/1]──> TLS 1.3 握手（X.509 单证书 / SNI / 可选 mTLS）
   ▼
MBTA 帧（[type][flags][varint length][payload]）
   │
   ├── HELLO ──────> （C→S，1-RTT 握手开始）
   ├── HELLO_ACK / HELLO_NAK（S→C）
   ▼
Ready：BATCH（data 域帧）⇄ RESULT / CREDIT / PONG / REDIRECT（control 域帧）
```

- **MUST** 先完成 TLCP/TLS 握手，才能收发任何 MBTA 帧；传输层握手未完成到达的字节由 TLS/TLCP 层拒绝。
- 证书校验 MUST NOT 关闭（`InsecureSkipVerify` 仅测试，且实现 MUST 告警——core §11.1）。
- HELLO 在传输层握手完成后发送；本 binding **不支持 0-RTT / 早数据**（core §3.1、§12.4）。
- `mbta-ntls/1` 的 TLCP 要求 **SM2 双证书**（签名 + 加密各一对），标准 X.509 加载路径不识别 SM2 曲线，须经国密证书加载器（参考实现：`pollux-go/cert` 的 `LoadDualCertificateFiles`）。
- 客户端 TLCP 握手整体 MUST 有界（参考值 30s，ctx deadline 更早则取较早者）；握手完成后 MUST 清零 deadline，交还协议层读超时管理。

---

## 3. 帧与通道映射

### 3.1 帧格式

完全遵循 core §1：`[type(1B)][flags(1B)][varint length][payload]`，flags 恒 0，无帧层 CRC。本 binding 无增改。

### 3.2 单连接 mini-mux（type 高位 demux）

TCP 是单字节流，无原生多路复用。本 binding 以**帧 type 的最高位**做逻辑流 demux（core §9.1）：

- 读侧：单读循环逐帧解码，按 `type & 0x80` 分流——
  - control 域（0x00–0x7F）→ control 逻辑通道（HELLO / RESULT / CREDIT / PING / PONG / CLOSE / REDIRECT / ABORT）；
  - data 域（0x80–0xFF）→ data 逻辑通道（BATCH；本 binding 无 DGRAM，§5）；
  - 逻辑通道缓冲 MUST 有界（参考值：control 16 帧 / data 64 帧）。
- 写侧：control 与 data 帧**交替写入同一 TCP 流**；写侧 MUST 串行化（同一连接的帧不得交错）——实现须用单一写许可（锁或容量 1 信号量），且锁等待 MUST 可被 ctx 取消（慢速对端 + 不可取消锁 = goroutine 泄漏）。
- 写操作 MUST 设写超时（ctx deadline 或默认 30s）；写失败（含部分写）MUST 关闭连接（流去同步不可恢复，core §1.5-4）。
- 服务端应答帧（RESULT/CREDIT/PONG/…）与数据帧读侧并发处理互不阻塞。

### 3.3 拆包 / 粘包 / 短读 / 半开防护（MUST）

TCP 是连续字节流，接收端 MUST（core §1.5）：

1. 按 varint `length` 精确读取 payload；
2. 长度上限（默认 16MB）校验**先于分配**；
3. varint 非最短编码 / 超长编码拒绝；
4. payload 短读时按实际已读 n drain 剩余声明字节，维持帧边界；
5. 处理半开连接（RST/FIN 异常经由读错误暴露，关闭清理）；
6. 关闭路径 MUST 唤醒阻塞在读/写两侧的 goroutine（关闭底层 conn + done 信号），杜绝泄漏。

---

## 4. 保活：PING/PONG（本 binding MUST 实现）

TCP 层没有空闲超时机制（OS keepalive 只能杀死死链路，活着的静默对端会 ACK 探测包），读侧空闲超时依赖应用层 PING 维持：

- **客户端** MUST 周期发送 PING（默认间隔 30s，单次写超时 5s）；写失败即退出心跳循环（连接由读侧收敛）。
- **服务端** MUST 对 PING 回 PONG（回显 `time_unix_ms` 与 `nonce`，`status="ok"`）；QUIC binding 不发 PING（传输层 keepalive 承担），服务端在 QUIC 侧对 PING 静默。
- PING/PONG 是双向类型，但本 binding 中仅由客户端发起、服务端应答；服务端不主动探测。

### 4.1 读超时档位（pre-auth / 认证后）

| 阶段 | 每帧读超时 | 依据 |
|------|-----------|------|
| pre-auth（HELLO 完成前） | 默认 30s | 防未认证静默连接无限占用服务端并发槽位（DoS） |
| 认证后（握手完成，MarkAuthed） | 默认 5 分钟（空闲） | 由 PING 30s 维持活性；超时 = 连接收敛 |

- 档位切换由协议层在握手完成后触发（binding 内建机制，不上 wire）。
- 服务端并发连接上限 MUST 有界（默认 10000）；连接槽位在 handler 退出时释放。

---

## 5. 不可靠通道（DGRAM）

**本 binding 不支持不可靠通道**：`SupportsDatagram()` 恒为 false，`SendDatagram` 返回"不支持"错误。

- `datagram` capability 在本 binding 下不协商（服务端策略含 `datagram` 时客户端也不会在 TCP 上获得它——能力交集生效的前提是 binding 实际提供通道）。
- 需要不可靠投递的场景 MUST 使用 QUIC binding（QUIC DATAGRAM，RFC 9221）。
- 本 binding 的可靠语义不受影响：一切数据走 BATCH（credit 流控 + RESULT 反馈）。

---

## 6. pre-auth 策略

- **pre-auth 超时**：认证前每帧读超时 30s（§4.1）；超时即拆连接释放槽位。
- **pre-auth 限速**：proof 验证前的 CPU 放大面（ECDH + HKDF + 候选 token 反查）SHOULD 按连接限速（core §9.3）。
- **数据面延迟**：服务端在握手完成前不启动数据帧处理；握手前到达的 data 帧停留在有界缓冲中，密钥就绪前不可解密（core §9.3）。

---

## 7. 服务端并发参数（本 binding 取值）

| 参数 | 取值 | 说明 |
|------|------|------|
| 并发处理 BATCH（每连接） | 8 | 超出并发上限的新 BATCH → `RESULT(released, server_draining)` + retry_hint（不拆连接） |
| DGRAM 并发槽 / 速率限 | 不适用 | 本 binding 无 DGRAM（§5） |
| sink 队列 / reaper / drain | core 默认 | 见 core §5、§10 |

（QUIC binding 的对应并发上限为 64——TCP 单连接的 head-of-line 阻塞更强，故取更小值。）

---

## 8. 与 core 的差异边界

本 binding 完全遵循 core，仅在以下传输相关开放点具体化：

1. **握手段**：强制 TLCP（双 SM2 证书）或 TLS 1.3（单证书）；
2. **多路复用**：type 高位单连接 mini-mux（core §9.1 的 TCP 模型），非 QUIC stream；
3. **不可靠通道**：不支持，`datagram` 能力不可用（core 允许 binding 声明不支持）；
4. **保活**：MUST 使用 PING/PONG（core §9.2 的 TCP 分支）；
5. **pre-auth 读超时**：30s 每帧（core §9.3 的取值）。

其余（帧格式、握手语义、Envelope、credit、去重、RESULT、错误码、Sink 契约、协商）与 core 完全一致。

---

## 9. 证书与运维

### 9.1 测试证书生成

集成/e2e 测试需要证书，证书不入库（防私钥泄露），由脚本生成：

```bash
# 一并生成 TLS 1.3 测试证书 + SM2 双证书
make gen-certs

# 等价于：
bash test/data/certificates/gen_certs.sh   # v1/TLS：CA + server + client（RSA-2048/SHA-256，
                                           #        SAN=localhost/127.0.0.1，365 天）
go run test/data/ntls/gen_certs.go         # ntls/TLCP：SM2 签名证书 + 加密证书（test/data/ntls/）
```

证书过期（365 天）后重新执行上述命令即可。

### 9.2 服务端证书配置

| 模式 | 必填配置 |
|------|----------|
| `mbta-ntls/1`（TLSMode=false） | `SignCertFile` + `SignKeyFile` + `EncCertFile` + `EncKeyFile`（四者缺一即构造失败）；可选 `CAFile`（mTLS） |
| `mbta-tls/1`（TLSMode=true） | `CertFile` + `KeyFile`；可选 `CAFile`（提供即启用 mTLS：RequireAndVerifyClientCert） |

### 9.3 客户端凭证

- TLCP：可选双 SM2 客户端证书——签名对与加密对 MUST 成对出现（只配一对 = 构造期失败，防静默不加载拖到握手才报错）；全空合法（非 mTLS）。
- TLS 1.3：`CertFile`/`KeyFile` 同填或同空。
- `InsecureSkipVerify=true` 仅限测试，实现 MUST 打告警日志；生产 MUST NOT 使用。
- `ServerName` 用于 SNI/主机名校验。

### 9.4 profile 默认值

- 本 binding（两个 ALPN）的客户端/服务端**零值默认 profile = `gm`**。
- profile 实际以 HELLO 声明为准（双方按同一 profile 执行密钥日程，core §8.1）；部署 `mbta-tls/1` 且需要国际应用层密码时 MUST 显式配置 `PROFILE_INTL`。

---

## 10. 一致性测试要求（本 binding 特有）

实现 MUST 通过：

- TLCP 双证书握手 + TLS 1.3 握手测试（含 mTLS、证书校验失败路径）；
- TCP 拆包/粘包/短读 drain/半开连接测试；
- 超大 length 声明防护（分配前拒绝）与 varint 非最短编码拒绝；
- type 高位 demux（control/data 帧交替到达正确分流）；
- 写侧串行化（并发发送者帧不交错）与写失败拆连接；
- PING/PONG 保活 + pre-auth 30s 读超时（未认证静默连接被拆）；
- HELLO → HELLO_ACK/NAK → BATCH → RESULT/CREDIT 端到端；
- credit 耗尽阻塞、released 重投（新 seq）语义；
- CLOSE drain（服务端对放弃项发 released）与 ABORT 路径；
- REDIRECT 地址校验（非法地址被忽略）。

---

## 11. 两个 ALPN 的选择指引

| 部署需求 | 选择 |
|----------|------|
| 国密合规（金融/政务/关基） | `mbta-ntls/1`（TCP+TLCP，SM2 双证书） |
| 国际合规、海外、非国密要求 | `mbta-tls/1`（TCP+TLS1.3）或 QUIC binding（`mbta/1`） |
| UDP/QUIC 受限网络 | TCP 系列（二者皆可，按合规选） |
| 需要多流低延迟、连接迁移、不可靠投递 | QUIC binding，非本文件 |
