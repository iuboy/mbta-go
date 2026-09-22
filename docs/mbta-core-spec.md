# MBTA 核心协议规范（r3）

**状态：** 实施规格（r3，2026-08）
**权威性：** 所有传输 binding（QUIC / TCP+TLS1.3 / TCP+TLCP）文档是本规范的实例；与本文件冲突时以本文件为准。消息 schema 的唯一权威是 `proto/control.proto`；密码与字节级规范以 `core/` 参考实现（`frame.go`、`keyschedule.go`、`envelope.go`、`errors.go`、`policy.go`、`credit.go`）为准。
**范围：** 线上字节格式与语义状态机。性能、内存、并发模型属实现范畴，不在此规定。
**关键词：** MUST / MUST NOT / SHOULD / MAY 按 RFC 2119 解读。

---

## 0. 概述与术语

MBTA 是 Agent → Server 的单向遥测信号传输协议，数据模型对齐 OpenTelemetry（OTLP 映射见附录 B）。

### 0.1 版本治理声明（r3）

r3 是**直接在 v1 代码库上的原地破坏性重构**，不引入新的线上版本号：

- ALPN **保持不变**：`mbta/1`（QUIC+TLS1.3）、`mbta-ntls/1`（TCP+TLCP）、`mbta-tls/1`（TCP+TLS1.3）。
- 帧内**没有**任何版本域（无 magic、无 version 字节）。版本是连接属性，唯一来源是 ALPN + 握手 transcript 绑定（§3）。
- 无生产部署，故无兼容负担；v1(r2) 的线上格式与本文档不兼容（差异摘要见附录 A）。设计过程与审查裁决记录见 [v2-design.md](./v2-design.md)（r3 设计与审查记录）。

### 0.2 术语

| 术语 | 定义 |
|---|---|
| 通道域（channel domain） | 帧类型 type 的最高位：`0x00–0x7F` control / `0x80–0xFF` data |
| profile | 应用层密码组合（ECDH + KDF + AEAD + 哈希），注册表见 §2.1 |
| transcript | 握手消息的规范编码哈希链，密钥派生的输入（§2.2） |
| Envelope | BATCH/DGRAM 帧的载荷格式（明文元数据 + AEAD 密文，§4） |
| seq | 连接级单调计数器值，BATCH/DGRAM 共享，从 1 起，唯一 wire 主键 |
| credit | 服务端权威发放的发送额度（批数 + 字节两维，§5） |
| RESULT level | 反馈级别：accepted / durable / rejected / released（§7） |
| 终态（terminal） | accepted_only 模式下的 accepted；任意模式下的 durable / rejected / released |
| drain | 等待全部已发 seq 达终态的关闭路径 |
| sink | 服务端注册的数据投递回调（§10） |
| binding | 传输绑定：QUIC 或 TCP 系列对帧的承载方式（§9） |

### 0.3 设计原则

1. 传输层已做的不在应用层重做（帧完整性、保活、优雅关闭、通道复用）。
2. 应用层加密要么做对要么不做：**密钥由握手派生，永不上线**。
3. 一个正交概念一个机制：流控只有 credit（返还通道唯一 = CREDIT 帧）；反馈只有 RESULT；协商只有 profile + capabilities 一条轨。
4. 流控状态与去重状态分离：inflight 承载流控，终态环承载去重应答——生命周期不同，不得同源强并。

---

## 1. 帧格式

### 1.1 字节布局

```
 0        1         2..
+--------+---------+--------------------+---------------------+
|  type  |  flags  |  varint length     |  payload            |
| (1B)   |  (1B)   |  (1–10B, LEB128)   |  (length 字节)      |
+--------+---------+--------------------+---------------------+
```

| 字段 | 偏移 | 大小 | 说明 |
|---|---|---|---|
| type | 0 | 1B | 帧类型（§1.2）。最高位 = 通道域：`0`=control，`1`=data |
| flags | 1 | 1B | 全部保留（§1.3）。发送端 MUST 置 0 |
| length | 2 | varint | payload 字节数（无符号 LEB128，最短编码） |
| payload | 2+v | length | 控制帧 = 对应 control 消息的 proto 编码；BATCH/DGRAM = Envelope 编码（§4） |

- 无帧层 CRC——完整性由传输层 AEAD（TLS 1.3 / TLCP）+ 应用层 Envelope AEAD（§4）承担。
- 无 magic、无 version、无 channel 域字节——版本由 ALPN 管（§0.1），通道由 type 高位管。
- 每帧开销 2B + varint（典型 1–3B）。
- 最小帧 = 3B（type + flags + length=0，空 payload）。

### 1.2 帧类型注册表（append-only，13 个）

| type | 名称 | 方向 | 通道 | 载荷消息 | 说明 |
|---|---|---|---|---|---|
| 0x01 | HELLO | C→S | control | `Hello` | 握手（profile / token_proof / eph / capabilities） |
| 0x02 | HELLO_ACK | S→C | control | `HelloAck` | 密钥确认 + epoch + 限额 + 初始 credit |
| 0x03 | HELLO_NAK | S→C | control | `HelloNak` | 握手拒绝（code / retryable / retry_hint） |
| 0x20 | RESULT | S→C | control | `Result` | 对某 seq 的反馈（唯一反馈帧） |
| 0x21 | CREDIT | S→C | control | `Credit` | credit 发放（唯一流控发放帧） |
| 0x22 | DICT | S→C | control | `ZstdDict` | zstd 静态字典下发（`zstd_dict` 能力协商后，HELLO_ACK 之后立即发送；见 §8.2/§8.4） |
| 0x30 | PING | 双向 | control | `Ping` | 保活（仅 TCP binding，§9） |
| 0x31 | PONG | 双向 | control | `Pong` | 保活应答（仅 TCP binding） |
| 0x40 | CLOSE | 双向 | control | `Close` | 优雅关闭（drain 超时提示） |
| 0x41 | REDIRECT | S→C | control | `Redirect` | HA 重定向（地址经校验） |
| 0x50 | ABORT | 双向 | control | `Abort` | 立即拆除（写失败 / 协议违规 / 账本漂移） |
| 0x90 | DGRAM | C→S | data | `Envelope` | 不可靠批次（豁免 credit，服务端硬限速） |
| 0x91 | BATCH | C→S | data | `Envelope` | 可靠批次（消耗 credit） |

约束：

- **data 方向的帧类型 MUST 落在 data 域**（type ≥ 0x80）；**control 方向的帧类型 MUST 落在 control 域**。这是 conformance 断言（TCP binding 依赖该位做逻辑流 demux，QUIC binding 以 stream 角色放置）。
- 新类型只能追加（append-only），且 MUST 先经 capability 协商再使用（§12.1）。
- 未在本表注册的 type：接收端 MUST 跳过 payload + 计数 + 日志（帧自定界使跳过安全），MUST NOT 拆连接。

### 1.3 flags：冻结面

- r3 首版 flags 的全部 8 位均为保留位，**无任何定义语义**。压缩标识位于 Envelope 内（载荷属性，必须在 AEAD 覆盖内，§4.1），不在帧层。
- 发送端 MUST 置 flags = 0；接收端对任何非零 flags MUST 判协议违规并 ABORT（`protocol_error`）。
- flags 演进冻结：未来新增任何位都是破坏性变更（§12.1）。

### 1.4 varint 规则（length 字段）

- 编码：无符号 LEB128（protobuf varint），最多 10 字节（uint64 上限）。
- 接收端 MUST 拒绝：
  1. **非最短编码**（如 `0x80 0x00` 表示 0）；
  2. 超过 10 字节仍未终结的编码；
  3. 解码失败。
- 最短性判定的规范性表述：以 i+1 字节编码的值必须 ≥ 2^(7·i)。

### 1.5 接收端 MUST 清单

1. **长度上限校验先于分配**：`MaxFrameBytes`（默认 16MB = 16<<20）的拒绝必须发生在 `make` 分配之前——防声明式 varint 长度直接 OOM。
2. varint 规范性校验（§1.4）。
3. **短读 drain**：payload 部分短读时 MUST 按实际已读 n drain 剩余声明字节，维持帧边界（TCP 系 binding）。
4. **短写检测**：帧写出错（含部分写）MUST 拆连接（ABORT 语义）——流上残留半帧会让后续帧全部错位，流去同步不可恢复。
5. 未知 type：跳过 + 计数 + 日志；未知/非零 flags：ABORT（§1.3）。
6. **typed 输入校验**：agent_id 非空、≤ 256 字节、不含控制字符（含 \t \n \r）；HELLO meta 键值同强度校验；trace 字段过 W3C hex 与 tracestate 上限校验（§11.3）；一切进入日志的网络来源字符串 MUST 过 `SanitizeForLog` 类清洗。

---

## 2. 密码与密钥日程

### 2.1 Profile 注册表

| profile | 注册名（wire/transcript 用字符串） | ECDH | KDF/哈希 | AEAD（密钥长） | HMAC（密钥长） |
|---|---|---|---|---|---|
| `PROFILE_INTL = 1` | `"intl"` | X25519 | HKDF-SHA256 / SHA-256 | AES-256-GCM（32B） | HMAC-SHA256（32B） |
| `PROFILE_GM = 2` | `"gm"` | SM2（sm2p256v1 原始 ECDH） | HKDF-SM3 / SM3 | SM4-GCM（16B） | HMAC-SM3（32B） |

- profile 是**密码敏捷性的唯一锚点**：新增组合（含后量子 hybrid，§12.5）只追加一行注册、不动 wire。不存在单独的密码套件协商。
- 临时公钥 wire 编码（严格校验，违例 = `hello_eph_invalid`）：
  - intl：X25519 公钥 32 字节；
  - gm：SM2 非压缩点 65 字节（`0x04 ‖ X ‖ Y`，拒绝压缩点）。
- ECDH 输出 zz：两 profile 均为 32 字节（gm 取 x 坐标 32B 大端）。

### 2.2 密钥派生（逐字节规范）

密钥从握手 transcript 派生（不上线）——wire 上不存在任何密钥传递。以下记号：`H` = profile 哈希（SHA-256 / SM3）；`lp(x)` = 4 字节大端长度前缀 ‖ x；`‖` = 字节拼接。

```
zz           = ECDH(client_eph, server_eph)
th_hello     = H( lp(profile_name) ‖ lp(canonical(HELLO, proof 置零)) )
ck           = HKDF-Extract(salt = th_hello, ikm = zz)
token_proof  = HMAC(H, key = token, msg = th_hello)
psk_ck       = HKDF-Extract(salt = HKDF-Expand(ck,  "mbta/psk",   32),
                           ikm  = token_proof)
keyblock     = HKDF-Expand(psk_ck, "mbta/split", L)
th_full      = H( lp(profile_name) ‖ lp(canonical(HELLO, proof 置零))
                ‖ lp(canonical(HELLO_ACK, finished 置零)) )
finished     = HMAC(H, key = handshake_key, msg = th_full)
```

要点（规范性）：

1. **token_proof 与 psk_ck 的 ikm 同值**：`Hello.token_proof` 字段就是 psk_ck 的 ikm 输入，无额外前缀或变换。
2. **token 不上线**：token 只作为 HMAC 密钥参与 token_proof 计算，wire 上只出现 proof。
3. **transcript 拼接规范**：每段一律带 `lp` 4B BE 长度前缀（防未来 profile 名互为前缀）；profile 用注册名字符串。
4. **canonical 编码** = proto deterministic marshal（map 字段按键排序）。proof 与 finished 在各自消息**入链前置零**（内容进链、占位清零）。跨实现一致性依赖此规范（conformance 断言）。
5. **HELLO_ACK 全字段入链**：limits / credits / ack_mode / selected_capabilities / epoch / expiry / server_eph 全在 finished 覆盖内——TLS 终止点对这些服务端声明的任何篡改都会使客户端 finished 校验失败。
6. **handshake_key 独立派生**：finished 不复用数据密钥（密钥用途分隔，对齐 TLS 1.3 / Noise 的 finished 子密钥）。
7. **nonce 构造**：`nonce = nonce_prefix(4B) ‖ seq(8B 固定宽度大端)`，共 12B。seq 以全 64 位宽度参与 nonce——截断重用（seq=k 与 k+2³² 同 nonce 的 GCM 灾难）在构造上不可表达。
8. **s2c_key 首版预留**：派生但无 s→c 数据加密帧使用。

### 2.3 split 长度表

`L = 2 × AEADKeyLen + HMACKeyLen + 8`：

| profile | L | keyblock 切分（顺序固定） |
|---|---|---|
| intl | 104 | c2s_key(32) ‖ s2c_key(32) ‖ handshake_key(32) ‖ nonce_prefix_c(4) ‖ nonce_prefix_s(4) |
| gm | 72 | c2s_key(16) ‖ s2c_key(16) ‖ handshake_key(32) ‖ nonce_prefix_c(4) ‖ nonce_prefix_s(4) |

- c2s_key：BATCH/DGRAM 的 Envelope AEAD 密钥（客户端加密、服务端解密，两侧用同一把——本协议数据面单向 c→s）。
- nonce_prefix_c：数据面 nonce 前缀；nonce_prefix_s：预留。
- HKDF info 串固定为 `"mbta/psk"` 与 `"mbta/split"`（无版本后缀——版本由 ALPN 与 transcript 承担）。

### 2.4 token_proof 的服务端验证

- 服务端认证接口 MUST 提供 `ResolveToken(agentID) → 候选 token 列表（确定性顺序）`；按注册序逐候选以 `HMAC(H, token, th_hello)` 与 proof **常量时间比对**（`hmac.Equal` 类原语）。
- 匹配任一候选即通过；全部失配 = `hello_proof_invalid`（对外与 `auth_failed` 同面，仅日志区分——防 agent/token 枚举 oracle）。
- proof 验证 MUST 先于任何密钥派生执行（§3.2 处理次序）。

---

## 3. 握手与状态机

### 3.1 消息流（1-RTT，唯一模式）

```
Client                                          Server
  |                                               |
  |--- HELLO {profile, agent_id, meta,            |  ① 
  |            capabilities, client_eph,          |
  |            token_proof}                       |
  |                                       解码校验 → proof 验证（ResolveToken）
  |                                       → eph 生成/ECDH → 派生 → 构造 ACK
  |<-- HELLO_ACK {session_id, epoch, ack_mode,    |  ②
  |               selected_capabilities, limits,  |
  |               credits, server_eph,            |
  |               finished, expiry_unix}          |
  |   或                                          |
  |<-- HELLO_NAK {code, retryable, retry_hint_ms} |  ②'
  |                                               |
  |  客户端：ECDH → 派生 → finished 验证          |
  |  （失败 = auth_failed，拆连接）               |
  |                                               |
  |=== Ready：BATCH / DGRAM =====================>|  ③
  |<== RESULT / CREDIT / REDIRECT ================|
```

- 无 0-RTT、无早数据（0-RTT 为演进项，前置条件见 §12.5）。
- 握手完成后客户端才持有密钥，故 Ready 前不可能有合法数据帧。

### 3.2 服务端处理次序（MUST）

解码校验（`ValidateHello`）→ 能力协商 → transcript 计算 → **proof 验证** → 临时密钥生成 → ECDH → 密钥派生 → 构造 HELLO_ACK（transcript + finished）→ 发送 → 进入 Ready。

- 任何优化都 MUST NOT 把 proof 验证后置（防仅持票据/伪造身份者消耗 ECDH+HKDF 计算）。
- 握手请求与校验 MUST 在 binding 的 pre-auth 窗口内完成（§9.3）。

### 3.3 消息字段（schema 权威 = `proto/control.proto`）

**Hello（C→S）**

| 字段 | 类型 | 语义 |
|---|---|---|
| profile | enum | §2.1 注册表值；未知值 = `unsupported_profile` |
| agent_id | string | 必填；≤256B、无控制字符（§1.5-6） |
| meta | map<string,string> | 可选元数据（hostname/os/version…）；键值同强度校验；入链按 deterministic 排序 |
| capabilities | repeated string | 客户端能力宣告（§8.2） |
| client_eph | bytes | 临时公钥（§2.1 长度严格校验） |
| token_proof | bytes | §2.2 公式；入链前置零 |

**HelloAck（S→C）**

| 字段 | 类型 | 语义 |
|---|---|---|
| session_id | bytes | 16B 服务端生成唯一标识；对客户端不透明；入 Envelope AD（§4.2） |
| epoch | uint64 | 服务端按 agent 单调分配（§3.4） |
| ack_mode | enum | §8.3 |
| selected_capabilities | repeated string | 协商交集（§8.2） |
| limits | Limits | `max_frame_bytes`（Envelope wire 字节）/ `max_batch_bytes`（解压后 batch payload 字节） |
| credits | Credits | 初始 credit（批数/字节，两维均 MUST > 0） |
| server_eph | bytes | 服务端临时公钥 |
| finished | bytes | §2.2 公式；入链前置零 |
| expiry_unix | int64 | 会话过期时刻（MUST > 0） |

**HelloNak（S→C）**：`{code（错误码注册表）, retryable, retry_hint_ms}`。

### 3.4 epoch 分配

- epoch 由**服务端分配**（MUST NOT 客户端自报）：每次握手成功，服务端对该 agent 的分配器自增（首个 epoch = 1），per-agent 单调。
- 分配器 MUST 服务端级共享（跨连接复用）——无票据/票据丢失的重连同样获得新的更高 epoch，杜绝低 epoch 围栏死锁。
- `stale_epoch` 码首版预留（无跨连接 seq 去重，不可达）；一旦启用，对客户端是连接级致命（ABORT 重连，不可逐批重试）。

### 3.5 HELLO_NAK 语义

- 未认证阶段的 NAK 在认证维度只允许单一代码 `auth_failed`（token 过期等原因合并其中），detail 对未认证方不透传——防 agent/token 枚举 oracle。
- proof 验证失败：NAK `auth_failed` + `retryable=true` + `retry_hint_ms=1000`，**不拆传输层**（客户端按退避重试，防坏 token 批量下发时的连接风暴）。
- 消息非法/不支持 profile/eph 非法：对应注册表码，`retryable=false`。
- 客户端收到 NAK：握手失败；SHOULD 按 retryable + retry_hint_ms 做指数退避后以新连接重试。
- 握手完成后收到第二个 HELLO：NAK `bad_handshake_message` 并结束连接。

### 3.6 状态机

**客户端（4 态；Closed 是任意状态的一等出边）**

| 当前态 | 允许目标态 | 触发 |
|---|---|---|
| Idle | Ready | HELLO_ACK 验证通过 |
| Idle | Closed | 从未连接即 Close / dial 失败后放弃 |
| Ready | Draining | 发起 Close |
| Ready | Closed | 致命错误强制收敛 / ABORT |
| Draining | Closed | drain 完成（全部已发 seq 终态）或超时 |
| （任意） | Closed | close 收敛保证（强制出边，幂等） |

注：握手进行中属 Idle（握手子步骤不是 wire 可见状态）；dial 失败回滚 Idle（同实例可重试），握手失败后实例单次使用（重连须新建实例）。

**服务端（3 态）**

| 当前态 | 允许目标态 | 触发 |
|---|---|---|
| Handshaking | Ready | HELLO 处理完成、HELLO_ACK 已发送 |
| Ready | Draining | 进入排空（收尾/关停） |
| Draining | （无出边；连接终结） | drain 预算耗尽后拆除 |

### 3.7 CLOSE / ABORT 交错矩阵（规范性）

| 交错 | 收敛动作 |
|---|---|
| 双方同时 CLOSE | 双方各自按 drain 判定收敛；重复 CLOSE 幂等忽略 |
| Draining 中收到 CREDIT/RESULT（客户端侧） | 正常处理：RESULT 参与 drain 判定，CREDIT 更新账本 |
| 服务端 drain 超时放弃 inflight | MUST 对每个放弃项发 `RESULT(released, server_draining)` 后拆连接（禁止沉默——否则客户端白等满超时） |
| 客户端 CLOSE 后关闭读路径 | 最后一批 RESULT 允许丢失；客户端以本地 drain 判定为准（at-least-once 由重连重发兜底） |
| Draining/Handshaking 中收到 ABORT | 立即拆除，无 drain；未终态 batch 由客户端重连重发 |
| 协议违规（未知 flags / 窗外 seq / 账本漂移） | ABORT，code 指明 |

- CLOSE 携带 `drain_timeout_ms`，服务端 MUST clamp 到 [1000, 30000] ms 作为排空预算。
- 客户端 drain 判定 = 计数谓词：**全部已发 seq 均达终态**（连续终态前缀水位 == last_sent，或等价的在途计数归零）。MUST NOT 用 `max(已终态 seq) == last_sent` 的 max 谓词（乱序 durable 下提前关连接丢数据）。客户端 drain 等待上限默认 30s，超时强制关闭。
- 服务端收尾路径：有界排空数据面与 sink 队列；对放弃的在途项合成 released（上表第 3 行）。

---

## 4. Envelope 与数据面

### 4.1 处理顺序：compress-then-encrypt

发送（Seal）：

```
Batch 消息编码（proto 编码，含 seq/correlation/trace/events_count/payload）
  → 可选压缩（Envelope.compression 声明算法，四选一）
  → AEAD 加密（c2s_key；nonce 与 AD 见 §4.2）
  → 组装 Envelope{key_epoch, seq, compression, ciphertext}
  → proto 编码 = BATCH/DGRAM 帧 payload
```

接收（Open）：proto 解码 Envelope → key_epoch/seq 合法性检查 → AEAD 解密（AD 校验失败 = `envelope_open_failed`）→ 按声明算法解压（上限强制）→ Batch 消息解码。

- **压缩标识只在 Envelope，逐帧自描述**（单一真相源；帧层无压缩位）。压缩算法不做协商：五个注册算法（NONE/GZIP/ZSTD/LZ4/ZSTD_DICT，§8.4）接收端 MUST 全支持，发送端 MAY 逐帧自选。
- 解压上限 `MaxDecompressedSize` = 8MB，MUST 流式强制、先于任何放大分配（zstd 额外 `WithDecoderMaxMemory` 同值；字典模式 DecodeAll 同受该上限约束），超限 = `decompress_limit`。

### 4.2 nonce 与 AD（字节级）

```
nonce = nonce_prefix_c(4B) ‖ seq(8B BE)          // 12B，确定性构造
AD    = type(1B) ‖ flags(1B, 恒 0) ‖ lp(session_id) ‖ key_epoch(1B 固定宽)
        ‖ seq(8B BE) ‖ compression(1B) ‖ lp(profile_name)
```

- `lp` = 4B BE 长度前缀；`compression` 取 proto enum 数值（1B）；`key_epoch` 固定 1 字节宽（首版恒 0）。
- AD 绑定帧头（type/flags）、会话、纪元、序号、压缩算法与 profile——帧头与全部明文元数据都在完整性覆盖内，密文剪贴/元数据篡改在构造上不可行。
- Seal 与 Open 的 `frame_type` MUST 一致（BATCH 与 DGRAM 的 AD 不同，错配 = `envelope_open_failed`）。

### 4.3 Envelope 与 Batch 字段

**Envelope**（BATCH/DGRAM 帧 payload 的外层）：

| 字段 | 语义 |
|---|---|
| key_epoch | 首版恒 0；非 0 = `envelope_open_failed`（rekey 演进项，§12.5） |
| seq | 连接级计数器（§4.4）；≥1 |
| compression | 五注册值之一（§8.4） |
| ciphertext | AEAD(压缩后的 Batch 编码) |
| mac | 外层 HMAC，`dual_integrity` 能力协商启用时发送端填充：`HMAC(profileHash, DualMACKey, AD‖ciphertext)`，DualMACKey 由 psk_ck 追加 Expand（info=`"mbta/dual"`），不改 §2.3 split 布局。未启用时发送端 MUST 置空；接收端判定 fail-closed——「未启用却非空」「启用却为空」「校验失败」一律 `envelope_open_failed` |

**Batch**（密文内）：

| 字段 | 语义 |
|---|---|
| seq | MUST 与 Envelope.seq 一致（AD 绑定 Envelope.seq；不一致 = `batch_invalid`） |
| correlation | 可选对账句柄；RESULT 原样回显；服务端不解释不存储 |
| trace | 可选 TraceContext（`trace_context` 能力；校验规则 §11.3） |
| events_count | 事件数（Raw 快速路径不解码即知；上限 10000） |
| payload | SignalBatch 编码（codec 见 §8.4） |

### 4.4 seq 规则

- **单一连接级计数器（MUST）**：BATCH 与 DGRAM 共享同一分配临界区——分设计数器会跨通道复用 nonce（GCM 灾难）。
- seq 从 1 起，单调递增；**0 非法**（哨兵）。
- 客户端 credit 消耗与 seq 分配 MUST 在同一临界区（额度不足时不消耗 seq）。
- `Envelope.seq ≠ Batch.seq` = `batch_invalid`。

### 4.5 服务端校验次序（MUST，逐级短路）

```
帧层 MaxFrameBytes（先于分配，§1.5-1）
  → 窗口/credit 准入（§6 判定 + 额度检查）
  → AD/解密（OpenEnvelope；失败 = rejected(envelope_open_failed)）
  → 解压上限（decompress_limit）
  → max_batch_bytes（解压后 batch payload 字节；超限 = rejected(batch_too_large)）
  → Batch 解码与 Envelope.seq 一致性、events_count、trace 校验
  → 投递 sink
```

计量口径：credit 字节维与 `max_frame_bytes` 按 **Envelope wire 字节数**计（Open 之前可判）；`max_batch_bytes` 按**解压后 batch payload 字节**计。

### 4.6 DGRAM（不可靠通道）

- DGRAM 豁免 credit（无额度消耗、无 RESULT、无去重准入），语义为 **at-most-once**。
- 服务端 MUST 施加硬限（RFC 9221 明示实现方须自设）：
  - per-connection 并发处理槽（默认 64，满则静默丢弃）；
  - 字节速率硬上限（令牌桶；部署 SHOULD 配置，见 §5.8）。
- 一切失败（限速超限、解密失败、超限、解码失败）MUST 静默丢弃，不回任何反馈。
- DGRAM 帧载荷同样是完整 Envelope（加密与 AD 绑定与 BATCH 一致，仅 frame_type 不同）。
- 不支持不可靠通道的 binding（TCP 系列）：DGRAM 不可用；需要可靠语义的发送端降级使用 BATCH（§9）。

---

## 5. credit 流控（模型 B：服务端权威）

### 5.1 模型

credit 是唯一流控机制，模型 B（服务端权威发放）：

- 服务端通过 HELLO_ACK（初始额度）与 CREDIT 帧（追加额度）**发放**；
- 额度**返还的权威在服务端**：服务端在 batch 达回收点时回收，经 CREDIT 帧重新发放；
- **RESULT 不隐含返还**——客户端收到 RESULT MUST NOT 回补本地账本；
- 客户端本地回收必然与服务端 granted 视图发散，MUST NOT 存在。

### 5.2 客户端账本

```
ledger = { granted_batches, granted_bytes, consumed, returned }（逐维）
available = granted − consumed + returned          （批数、字节两维独立）
发送 BATCH 前置（MUST）：available_batches ≥ 1 且 available_bytes ≥ len(envelope wire)
```

- 消耗口径 = Envelope wire 字节（§4.5）。
- 本地钳制（防恶意/受损服务端发放天量额度撑爆客户端内存）：累计可用不得超过本地钳制上限（默认批数 65536 / 字节 4GiB）。

### 5.3 生命周期（RESULT level × ack_mode）

| RESULT level | 语义 | 服务端动作 |
|---|---|---|
| `accepted`（ack_mode=durable） | 已入内存队列，**非终态** | inflight 保留；额度不回收 |
| `accepted`（ack_mode=accepted_only） | **即终态** | inflight 除名 + 额度回收 |
| `durable` | 持久化完成（终态） | inflight 除名 + 额度回收 |
| `rejected` | 终态拒绝（内容非法/超限），携带 code | inflight 除名 + 额度回收 |
| `released` | 未处理可重投，携带 retry_hint | inflight 除名 + 额度回收 |

### 5.4 服务端发放（攒批策略）

- 回收额度不逐批发放（高 RTT 链路上逐批 RESULT+CREDIT 双帧会重演 HTTP/2 BDP 空转）。
- 服务端 SHOULD 按攒批发放到点发放：**回收批数 ≥ max(1, 初始窗/4)** 即发 CREDIT；SHOULD 辅以短定时器兜底小流量场景。
- 每次发放同步推进去重窗口上界（§6.1 的 cap）。

### 5.5 服务端 reaper（MUST）

- inflight 条目（**含 accepted 态**）超过滞留时限（默认 60s）无终态 → 服务端主动 `RESULT(released, internal)` + 额度回收；扫描间隔默认 10s。
- 服务端排空收尾时对放弃项一律 `RESULT(released, server_draining)`（§3.7）。
- 由此闭环：sink 卡死时窗口不会慢性萎缩（客户端最终必得 RESULT + CREDIT 或连接拆除）。

### 5.6 客户端 reaper（职责收缩）

- RESULT 超时（默认等待上限 5 分钟）：客户端只**标记失败并通知应用层**（回调/事件）。
- 客户端 reaper **严禁回补 credit 账本**——本地回补必然与服务端视图发散；最终一致性由服务端 reaper 保证（§5.5）。

### 5.7 CREDIT 帧校验（客户端 MUST）

| 输入 | 处理 |
|---|---|
| 两维 delta 均为 0 | 忽略（幂等） |
| 任一维为负（含 uint64→int64 回绕成负） | 计违规 + 丢弃（非致命） |
| 返还量超过已消耗未返还余额 | 钳制到余额生效 + 计违规（非致命） |
| 累计可用超过本地钳制上限 | 按钳制值生效 + 计违规 |
| HELLO_ACK 初始 credit 任一维 ≤ 0 | 握手失败（`credit_invalid`） |

（回绕/超钳制 = 钳制生效 + 违规计数，非致命——这是对 v1 旧流控帧"零值窗口被静默冻结"缺陷的对应防护。）

### 5.8 初始额度与不变式

- HELLO_ACK 初始 credit 两维 MUST > 0；默认 256 批 / 64MB；服务端 SHOULD 按 sink 吞吐与 BDP 估计调整（≥ BDP/平均批大小）。
- 服务端不变式（可检验）：`|inflight| ≤ granted_outstanding ≤ initial + ΣCREDIT`。
- DGRAM 豁免 credit 但受 §4.6 硬限（并发槽 + 字节速率）。

### 5.9 账本漂移

- 客户端收到 ref 超出自身已发视图的 RESULT（`ledger_divergence` 类信号）→ 判定漂移 → ABORT 重连（连接级致命）。该码首版预留。

---

## 6. 去重与投递语义

### 6.1 集合制窗口

服务端每连接维护准入窗口：

```
可接受 seq ∈ [low, cap]
cap = 累计已发放批数额度（初始 credit + ΣCREDIT，随发放增长）
low = 连续已接受前缀上界 + 1：
      [1, low) 内每个 seq 都被接受过（在途或已终态）
```

- 窗口宽度 = cap − low + 1，由 credit 守恒隐式保证：每个已接受未终态 seq 占一份未回收额度（客户端 seq 分配与 credit 消耗同源，§4.4——超过 cap 即无额度发送 = 协议违规）。
- 去重深度与流控窗口解耦：窗口承载准入，终态环（§6.2）承载去重应答。

### 6.2 low 前缀推进语义

- `low` 沿**连续已接受前缀**推进：乱序到达（先 3 后 1）不推进——seq=1 未接受前 low 停在 1，晚到的 1/2 仍落窗内被接受。
- 全部终态后 low = max+1：重发同 seq 落入 `< low` 分支查终态环，不会被重新接受（会话内 exactly-once 投递效果）。
- low 单调不回退。

### 6.3 终态环

- 独立于流控的最近 K 条（默认 K=256，推荐 `max(W, 256)`）终态记录：`seq → {level, code}`，容量淘汰最旧。
- 用途：RESULT 丢失后客户端同 seq 幂等重发时，服务端可回存储 outcome。
- 内存上界：窗口集合 ≤ 窗宽、终态环 ≤ K，均由 credit 界定，无全局 LRU。

### 6.4 四判定分支（Admit，规范性）

```
seq = 0                      → 协议违规（ABORT window_exceeded）
seq 已在途（seen）           → 幂等回执：accepted（correlation 从在途 slot 回显）
seq > cap                    → 协议违规（超发/重放；ABORT window_exceeded）
seq < low：
    终态环命中               → 回执存储 outcome（原 level + code）
    未命中                   → RESULT(released, internal)（不可知——宁重发不吞数据）
窗内未见（low ≤ seq ≤ cap）  → 接受（乱序到达合法），解密成功后登记 in-flight
```

- 在途重发的回执级别 = 当前实际状态（在途即 accepted；已终态走环命中分支）。
- 登记时点：解密**之后**（correlation 来自明文 batch，密文外不可预取）；解密失败的 seq 同样写入终态环（避免被重复试探）。

### 6.5 重试语义（规范性）

| 场景 | 客户端动作 | seq |
|---|---|---|
| RESULT 丢失（超时未达终态） | 幂等重发**原载荷** | **原 seq**（服务端经 seen/终态环回执） |
| released / 可重试 rejected | 重新投递（客户端保留载荷至终态；首版不自动重试，经回调上抛由应用决定） | **新 seq**（独立计费与去重） |
| 连接拆除后未终态 | 重连后按应用决定重发 | 新连接的新 seq（从 1 重新开始） |

- 乱序/gap 类非终态否决一律用 `released`；`rejected` 仅用于终态否决（内容非法、超限）。集合制窗口下窗内 gap 直接接受，不存在 out_of_order 否决场景；窗外为协议违规走 ABORT。

### 6.6 多副本 / 重启边界（诚实声明）

epoch 与去重状态是**副本内存态**——跨副本与重启窗口内为纯 at-least-once（Kafka 幂等生产者同款限制：幂等仅限单 broker 会话）。宣称跨副本 exactly-once 需共享状态存储，本协议不承诺。此边界纳入威胁模型（§11.5）。

---

## 7. RESULT 与错误码

### 7.1 RESULT 帧

```
Result{ ref_seq, level, code, detail, retry_hint_ms, correlation(echo) }
```

- `ref_seq`：被反馈的 seq。
- `level`：proto enum（wire 上不传字符串），四值见 §5.3。
- `code`：错误码注册表数值（§7.2），0 = ok。
- `detail`：仅日志；MUST NOT 对未认证方透传。
- `retry_hint_ms`：released 类附默认退避提示（1000ms）。
- `correlation`：回显 Batch.correlation。
- RESULT 是唯一反馈帧；level 非法值（含零值 UNSPECIFIED）接收端 MUST 丢弃。

### 7.2 错误码注册表（varint，append-only，只增不改不复用）

分组段位（粗粒度追加预留）：1x/2x 段 = 握手与数据期错误，3x/4x 段 = 会话与服务端错误；下表"组"列按实际使用时点标注。

| 码 | 名称 | 组 | 语义 |
|---|---|---|---|
| 0 | ok | — | 成功 |
| 10 | auth_failed | 握手 | 未认证维度唯一码（proof 失败对外同面） |
| 12 | unsupported_profile | 握手 | profile 不在注册表 |
| 13 | unsupported_capability | 握手 | 能力不被支持 |
| 14 | bad_handshake_message | 握手 | 握手消息非法（解码/校验失败、HELLO 重复） |
| 20 | batch_too_large | 数据 | 解压后 payload 超 limits.max_batch_bytes |
| 21 | batch_invalid | 数据 | Batch 非法（含 Envelope.seq ≠ Batch.seq、events_count 超限、trace 非法） |
| 22 | decompress_limit | 数据 | 解压超上限 |
| 23 | envelope_open_failed | 数据 | AEAD 开启失败（AD/nonce/key_epoch/解密） |
| 24 | window_exceeded | 数据 | 协议违规（窗外 seq / 额度超发），配合 ABORT |
| 25 | stale_epoch | 数据 | 预留（票据演进项；连接级致命） |
| 26 | ledger_divergence | 数据 | 预留（连接级致命） |
| 27 | result_level_bad | 数据 | RESULT level 非法 |
| 28 | ack_mode_bad | 握手 | HelloAck.ack_mode 非法 |
| 29 | credit_invalid | 握手 | 初始 credit 非法 / CREDIT 帧非法 |
| 30 | hello_eph_invalid | 握手 | 临时公钥格式/长度非法 |
| 31 | hello_proof_invalid | 握手 | token_proof 验证失败（对外与 10 同面，仅日志区分） |
| 32 | server_draining | 会话 | 服务端排空/收尾（released 携带） |
| 40 | internal | 服务端 | 服务端 reaper 合成 released 时使用 |
| 41 | unavailable | 服务端 | 服务端不可用 |
| 42 | protocol_error | 服务端 | 通用协议违规（未知 flags / 类型错域等） |

- 全部枚举字段（profile / ack_mode / level / compression / codec）用 proto enum，wire 上不传字符串；零值 UNSPECIFIED 接收端 MUST 拒绝。
- 名称仅日志用途，不上 wire；数值稳定可直作 metrics label。

### 7.3 四级语义总表

| level | 终态性 | credit | 客户端后续 |
|---|---|---|---|
| accepted | accepted_only 模式终态；durable 模式非终态 | accepted_only 回收；durable 保留 | durable 模式继续等 durable/released |
| durable | 终态 | 回收 | 释放载荷 |
| rejected | 终态 | 回收 | 释放载荷（内容问题，重试无意义除非码可重试） |
| released | 终态（本次投递放弃） | 回收 | 可用**新 seq** 重投（§6.5） |

---

## 8. 协商

单轨协商：客户端 HELLO.capabilities ∩ 服务端 SupportedCapabilities → HELLO_ACK.selected_capabilities（保序：按服务端策略顺序）。profile 与 ack_mode 由服务端策略声明/确认。

### 8.1 profile

- HELLO.profile 声明（MUST 为注册表值，未知 = NAK `unsupported_profile`）。
- profile 不做交集协商——双方按 HELLO.profile 执行同一密钥日程，握手在 profile 维度要么整体成功要么 NAK。
- 服务端 MAY 按本地策略约束可接受 profile 集合。

### 8.2 capabilities（注册表）

| capability | 语义 |
|---|---|
| `trace_context` | 启用 Batch.trace 承载 W3C trace 上下文（§11.3） |
| `datagram` | binding 提供不可靠通道，DGRAM 可用 |
| `cbor` | SignalBatch payload 可用 CBOR 编码（§8.4） |
| `dual_integrity` | Envelope 追加外层 HMAC（Envelope.mac，§4.3）：`HMAC(profileHash, DualMACKey, AD‖ciphertext)`，DualMACKey 由 psk_ck 追加 Expand（info=`"mbta/dual"`，长度 HMACKeyLen），**不改 §2.3 split 布局**。默认关闭：注册进 KnownCaps（客户端可合法宣告），但 DefaultServerPolicy.SupportedCapabilities 不含——服务端以策略显式加入才协商启用。启用是连接级整体开关：双方由 selected_capabilities 对称驱动派生与 Seal/Open；任一侧判定不对称（mac 非空但未启用 / 启用但 mac 空 / 校验失败）= `envelope_open_failed`（fail-closed） |
| `zstd_dict` | 服务端静态 zstd 字典下发：协商选中时服务端在 HELLO_ACK 之后立即发 DICT 帧（0x22，`ZstdDict{dict_id, dict}`），客户端激活后可逐帧选用 `COMPRESSION_ZSTD_DICT`（§8.4）。边界（r3 裁决，修订 §12.5 原案）：字典内容**不入 transcript**——HELLO_ACK 的 finished 已签发后无法追加入链；字典经传输层 AEAD（TLS/TLCP）通道保护，被篡改最坏导致解压失败（fail-closed），无安全降级。服务端未配置字典时 MUST NOT 选中该能力（即使 SupportedCapabilities 含它）；字典尺寸有界（≤ 1MB）；解压上限规则（§12）同样适用于字典模式 |

- 客户端 MUST 只声明注册表内能力（未知能力构造期失败，fail-fast）；服务端取交集，未选中能力对应的特性 MUST NOT 使用。
- 注册表 append-only；生命周期见 §12.3。

### 8.3 ack_mode

- 服务端在 HELLO_ACK 声明（不协商）：`ACK_MODE_ACCEPTED_ONLY`（accepted 即终态并返还）或 `ACK_MODE_DURABLE`（accepted 中间态，durable 终态）。默认 accepted_only。
- 重连时模式切换：旧连接未 durable 的 batch 按未投递处理，由客户端重发（显式损失语义）。
- durable 模式要求 sink 声明 Durable 供给（§10）。

### 8.4 codec 与压缩

- codec 默认 proto；`cbor` 能力被选中即整连接使用 CBOR 编码 SignalBatch payload（单连接单一 codec）。
- 压缩算法不协商：五注册算法（NONE/GZIP/ZSTD/LZ4/ZSTD_DICT）收端 MUST 全支持（ZSTD_DICT 的前提是字典已激活，否则 fail-closed 拒绝），发送端逐帧在 Envelope.compression 自选（§4.1）。`COMPRESSION_ZSTD_DICT = 5` 隐含"当前字典"（`zstd_dict` 能力 + DICT 帧下发，§8.2）——dict_id 由 DICT 帧携带，Envelope 不重复；字典为 raw content dictionary（任意高冗余语料字节合法，无需 `zstd --train` 训练格式）。
- 客户端发送启发（SHOULD，实现参考）：字典路径（`zstd_dict` 协商且 DICT 已到达）batch wire > 512B 选用 ZSTD_DICT；非字典路径 batch wire ≥ 4096B 选用 ZSTD；其余选 NONE（小批压缩收益低于 CPU 成本）。

---

## 9. 传输绑定要求

### 9.1 统一抽象

binding MUST 向协议层提供两个逻辑通道（control / data）与可选不可靠通道：

```
RecvControlFrame / RecvDataFrame   // 两个逻辑读通道，必须支持并发调用
SendFrame                           // 按帧 type 的通道域路由（binding 决定物理承载）
SupportsDatagram / SendDatagram     // 不可靠通道（可选）
Multiplexing / Close / RemoteAddr
```

- 帧路由依据 type 高位（control/data 域），语义在两种模型下一致：
  - **QUIC（多流）**：首个双向 stream = control stream（MUST；首 stream 不是 control → 连接错误）；其余 stream = data stream，后台聚合到 data 通道（乱序到达是常态——集合制窗口为此设计，§6）。服务端应答帧均走 control stream。不可靠通道 = QUIC DATAGRAM（RFC 9221，需双方启用扩展；任一侧未启用即视为不支持）。
  - **TCP 系（单连接）**：单连接 mini-mux，读侧按 type 高位分流到 control/data 两个逻辑通道；写侧 MUST 串行化（同连接帧不交错）。无不可靠通道（`datagram` 能力不协商，DGRAM 不可用）。
- 写失败（含部分写）MUST 拆连接（§1.5-4）。

### 9.2 保活

- **QUIC**：使用 QUIC 传输层 keepalive；MUST NOT 发 PING（应用层保活与传输层重复）。
- **TCP 系**：MUST 用 PING/PONG 保活——客户端周期发送 PING（默认 30s 间隔、5s 写超时），服务端 MUST 回 PONG（回显 time_unix_ns 与 nonce，status="ok"）。读侧空闲超时依赖 PING 维持。 <!-- 2026-09-22 破坏性升级：毫秒→纳秒（无存量兼容）；UTC epoch -->

### 9.3 pre-auth 策略（binding 内建职责）

- **pre-auth 超时**：认证通过前的读等待 MUST 有界（参考值 30s：QUIC 等待首个 control stream、TCP 每帧读超时）——防未认证静默连接无限占用并发槽位。
- **pre-auth 限速**：proof 验证前的 CPU 放大面（ECDH+HKDF+候选反查）SHOULD 按连接限速。
- **认证后切换**：握手完成后 binding 把读超时切换到认证后空闲超时（默认 5 分钟，TCP 由 PING 维持活性）。
- **数据面延迟启动**：服务端 MUST 在握手完成前不启动数据面处理路径（未握手到达的 data 帧不进入处理；缓冲必须有界）。
- 传输层 MUST 强制 TLS 1.3 / TLCP；证书校验 MUST NOT 关闭（§11.1）。

### 9.4 binding 文档要求

每个 binding 文档 MUST 定义：ALPN 与密码轴；握手映射（TLS/TLCP 完成后才开始 HELLO）；control/data 到传输多路复用单元的映射；不可靠通道有无及降级行为；拆包/粘包/短读/半开防护（字节流类）；写侧串行化；保活方式；pre-auth 策略取值；与 core 的差异边界（无偏离须显式声明）。binding 文档与 core 冲突时以 core 为准。

### 9.5 与 RFC 8998 的正交性

gm profile 跑 QUIC + TLS 1.3（RFC 8998 国密套件）时，应用层仍按 profile 密码执行——传输层与应用层密码正交，互不约束。

---

## 10. Sink 契约

服务端恰有一个 sink handler（注册式：`SinkOptions` + `BatchHandler`，构造期注册，重复/缺失注册在启动期报错）：

```
SinkOptions{ Raw, Durable, Async }        // 供给偏好，静态声明
BatchEvent{ Agent, Meta, Decoded|Raw }     // Raw/Decoded 恰一供给
Outcome{ Level, Code, RetryAfter }         // handler 经 done 回报
```

能力在注册时静态声明，协议层据此选择供给路径——"声明能力与供给路径不匹配"这类接口矩阵缺陷在结构上不可表达。

### 10.1 八条 MUST

1. **done 幂等**：首次调用生效，后续调用安全丢弃。
2. **单调性**：accepted 的 RESULT 已发出后（durable 模式中间态），合法 Outcome 收缩为 Durable | Released（done 汇报 Accepted 等价推进为 durable）。
3. **sink deadline**：handler 在服务端 deadline（默认 60s，可配）内未调 done → 服务端 MUST 合成 `Outcome{Released, code=internal}`（衔接服务端 reaper，§5.5）。
4. **panic**：per-invocation recover → 合成 released + SinkFailures 计数；MUST NOT 拆连接。
5. **迟到调用**：ctx 取消（连接关闭）后迟到的 done 安全丢弃。
6. **队列满/入队失败**：MUST 映射到 wire 语义——`RESULT(released, server_draining)` + 额度回收。
7. **投递队列限界**：条数（默认 256）+ 字节（默认 32MB）双限界、有界排空超时、超时放弃路径对在途 accepted 项合成 released——全部 MUST。
8. **conformance 覆盖**：以上各项全部进入一致性断言清单（§12.6）。

### 10.2 供给路径

- `Raw=true`：供给原始编码字节（跳过逐事件解码；events_count 供不解码即知规模）。
- `Raw=false`：供给解码后的 SignalBatch（按协商 codec 解码，§8.4）。
- `Durable=true` 是 ack_mode=durable 的前置（服务端策略校验）。
- `Async=true`：done 允许在 handler 返回后异步调用（协议层保证幂等与超时合成）。

---

## 11. 安全考虑

### 11.1 传输与凭证

- TLS 1.3 / TLCP 强制；证书校验 MUST NOT 关闭（跳过校验仅限测试，且实现 MUST 告警）。
- mTLS / 双证书（TLCP 签名+加密双 SM2 证书）由 binding 配置面承担。

### 11.2 密钥与认证

- 密钥由 ECDH + transcript 派生，**永不上线**；token 不上线（仅 HMAC 密钥角色）。
- proof 常量时间比对（§2.4）；finished 验证常量时间比对。
- token_proof 绑定 th_hello（含双方 profile/身份/能力/临时公钥）——proof 无法跨会话/跨 agent 剪贴重放。
- HELLO_ACK 全字段入链：TLS 终止点（企业代理/LB 卸载，视为**不可信转发者**）对 limits/credits/ack_mode/epoch/expiry 的任何篡改导致 finished 校验失败。
- Envelope AD 覆盖帧头与全部明文元数据（§4.2），密文剪贴/元数据篡改不可行。
- nonce 确定性构造 + 全宽 seq + 单计数器（§2.2、§4.4），同密钥下 nonce 复用在构造上不可表达。

### 11.3 输入校验（typed validation，继承 v1 加固资产）

- agent_id：非空、≤256B、无任何控制字符（含 \t \n \r——日志注入防护）；HELLO meta 键值同强度。
- Signal 字符串字段 ≤4096B + 控制字符校验（多行文本字段放宽 \t\n\r）。
- trace 字段：trace_id/span_id/parent_span_id 非空时 MUST 为小写 hex（32/16/16 字符）且非全零；trace-flags ≤ 0xff；tracestate ≤32 成员、单成员 ≤256 字符。
- 日志输出：网络来源字符串 MUST 经清洗（控制字符替换 + 超长截断至 UTF-8 边界）。

### 11.4 资源耗尽防护

- 帧长度上限先于分配（§1.5-1）；varint 规范性（§1.4）。
- 解压炸弹防护：流式 8MB 上限、zstd 解码内存上限、上限先于放大分配、预分配封顶。
- pre-auth 超时 + 限速；认证后空闲超时；并发连接上限。
- DGRAM 并发槽 + 速率硬限（§4.6）；sink 队列双限界（§10.1-7）。
- REDIRECT 地址 MUST 经 host:port 结构校验后才可使用（防被入侵服务端诱导 agent 连向攻击者）。

### 11.5 投递语义边界

- 会话内 exactly-once 投递效果依赖集合窗口 + 终态环 + credit 守恒；跨副本与重启窗口内为纯 at-least-once（§6.6，多副本共享状态不在承诺内）。
- released 的重投语义（新 seq）使端到端为 at-least-once；下游消费 SHOULD 幂等。

---

### 11.6 部署模型与投递语义

**单领导处理（推荐）**：HA 部署经 REDIRECT 机制收敛到单领导处理——全部 agent
连接领导副本，epoch 分配与去重状态集中在单进程内，语义完备。follower 副本仅
接受连接并在握手后重定向（RedirectChecker）。脑裂窗口（双领导并存）内可能
重复投递——标准 HA 注意事项。

**Active-active 的边界（MUST 知悉）**：epoch 与去重状态是副本内存态且作用域为
本进程——跨副本不围栏、跨连接不去重。跨连接重复投递的根本场景：batch 在连接 1
上 accepted 未 durable → 连接死亡 → 客户端在连接 2 以新 seq 重发。任何 seq/epoch
设计都无法跨连接关联（seq 是连接级空间）。**MUST** 由 sink 实现者按
`Batch.Meta.Correlation` 做应用层幂等收敛；参考实现
`core.NewCorrelationDeduper(capacity, ttl)`（进程级 LRU + 可选 TTL 的一行式）。

**服务端重启**：epoch 分配器随进程重置。旧连接随进程死亡，新连接获得从 1 起的
新 epoch——与旧纪元无碰撞（旧纪元连接不存在了）。重启窗口内客户端重发同样依赖
correlation 幂等。

## 12. 演进机制

### 12.1 帧类型与 flags 的不对称演进

- **type 开放**：未知 type 跳过 + 计数 + 日志；新类型 MUST 先经 capability 协商（或新 profile）再使用。
- **flags 冻结**：非零 flags = 协议违规（ABORT）。任何新位都是破坏性变更，只能随大版本（新 ALPN）进行。

### 12.2 append-only 规则

- 错误码：只增不改不复用，分组段位预留（§7.2）。
- profile：注册表追加，新 profile 非破坏（wire 上 eph 为不定长 bytes）。
- 消息 schema：字段号只加不复用（proto 权威）；enum 值只追加。
- 帧类型编号：只追加，方向-通道域约束不变（§1.2）。

### 12.3 Capability 生命周期

`experimental（x- 前缀）→ stable → deprecated → removed`；stable 化以 conformance 用例为门槛。注册表（§8.2）append-only；当前注册客户端侧 fail-fast（未知能力构造期失败），故 experimental 能力必须先同版本升级客户端。

### 12.4 版本节奏

- ALPN 单轨；双栈并行 ≥ 2 个大版本周期；新 ALPN 触发条件仅限帧头/语义模型级变更。
- 会话票据 / 0-RTT 为演进项（首版不含），前置条件：原子票据消费、(agent, epoch) 级去重覆盖早数据、envelope `key_epoch` 区分 early/main 密钥 + 显式切换帧、proof 验证先于早数据解密、早数据限额与 RESULT 时序规则。

### 12.5 规格化扩展点

| 扩展点 | 位置 | 用途 |
|---|---|---|
| `key_epoch` | Envelope 字段（**已规格化**，首版恒 0） | rekey / 0-RTT 密钥切换 |
| credits 第三维 | Credits 消息 | events 维度额度 |
| `correlation` | Batch / Result echo | 已实现，语义可扩展 |
| RESULT 范围确认 | Result 消息扩展字段 | 高带宽下批量确认（终态环只读投影） |
| type 高位域 | 帧头 | 新逻辑通道 |
| 后量子 profile | profile 注册表追加（如 `intl-pq`，X25519MLKEM768 类 hybrid KEM） | wire 零变更 |
| 共享字典压缩 | DICT 帧 0x22（`zstd_dict` 能力，已落地 §8.2/§8.4） | zstd 静态字典下发；字典不入 transcript（r3 裁决，经传输层 AEAD 保护 + fail-closed），训练字典轮换为后续演进 |

### 12.6 Conformance 断言清单

1. accepted 不返还 credit；durable/rejected/released 返还（模型 B 语义）。
2. CREDIT 校验规则（零 delta / 负值与回绕 / 超钳制 / 初始 ≤0）。
3. 集合制窗口：乱序窗内接受、窗外 ABORT、窗下界查终态环、在途重发幂等回执。
4. drain 谓词 = 全部终态（构造乱序 durable 序列验证）。
5. Sink 契约 §10.1 全部 8 条（panic / 双调 / 迟调 / 不调 / 队列满 / 排空超时）。
6. 帧接收 MUST §1.5 全部（含分配前长度校验、varint 规范性）。
7. epoch：服务端分配、重连获得新 epoch、连接级语义。
8. nonce：单一 seq 计数器（BATCH+DGRAM 交叉发送无 nonce 复用）。
9. transcript：跨实现 canonical 编码一致性（proof/finished 互验）。
10. HELLO_ACK 篡改（limits/credits/ack_mode）导致 finished 校验失败。
11. Envelope：AD 错配（frame_type/session/seq/compression）解密失败；解压上限强制。
12. CLOSE/ABORT 交错矩阵（§3.7）各行的收敛动作。

---

## 附录 A：与 v1(r2) 的差异摘要

| 维度 | v1(r2) | r3 |
|---|---|---|
| 帧头 | 8B 定长前缀（魔数/版本字节/标志/类型/通道域）+ varint | 2B（type/flags）+ varint；无魔数/版本/通道域字节 |
| flags | 多个语义位（信封/控制/数据/分片/合并/流类别） | 全保留，恒 0 |
| 握手 | 四帧两段式（能力宣告 + 挑战-应答认证） | 两帧（HELLO/HELLO_ACK）+ HELLO_NAK；1-RTT |
| 认证 | 挑战-应答；会话密钥上线传递 | token_proof（HMAC transcript）；密钥派生（不上线） |
| 流控 | 容量上限帧 + 速率节流帧双机制 | CREDIT 单机制（模型 B：服务端权威、唯一返还通道、reaper） |
| 反馈 | 三种确认帧（整批确认/整批拒绝/部分成功） | RESULT 四级（accepted/durable/rejected/released） |
| 去重 | 全局唯一 ID + 服务端去重缓存 | (epoch, seq) 集合制窗口 + 终态环；seq 为唯一 wire 主键 |
| 数据面加密 | 信封可选加密 + 外层 HMAC 双轨 | Envelope 单 AEAD + AD 绑定（compress-then-encrypt） |
| 状态机 | 客户端 9 态 / 服务端 7 态 | 客户端 4 态 / 服务端 3 态 |
| 错误码 | 千位段 + 数字/字符串双轨 | varint 注册表（append-only），字符串仅日志 |
| sink | 多接口矩阵（同步/异步/Raw/Durable 组合） | 注册式单接口（SinkOptions + BatchHandler + done 契约） |
| 保活 | 双侧应用层心跳 | QUIC 用传输层 keepalive；仅 TCP 保留 PING/PONG |
| 0-RTT/票据 | session ticket + resumption 派生 | 整体移除（演进项，§12.4） |
| 密码协商 | 套件枚举在线协商 | profile（注册表，无协商） |
| 压缩 | capability 逐算法协商 | 不协商：收端全算法支持（含 ZSTD_DICT 字典变体），发送端逐帧自选 |
| 能力面 | 大 registry（投递/通道/帧/算法） | 精简五项：trace_context / datagram / cbor / dual_integrity / zstd_dict（后两项默认关闭） |

## 附录 B：OTLP 映射（简表）

数据模型沿用 SignalBatch（`proto/signal.proto`）：`Resource` + `InstrumentationScope` + 统一 SignalRecord 外壳。

| MBTA | OTLP |
|---|---|
| `SignalBatch.resource` | Resource |
| `SignalBatch.scope` | InstrumentationScope |
| `signal_type="log"` | Logs LogRecord |
| `signal_type="gauge"` | Metrics Gauge |
| `signal_type="counter"` | Metrics Sum |
| `signal_type="histogram"`（explicit / exponential） | Metrics Histogram / Exponential Histogram |
| `signal_type="summary"` | Metrics Summary |
| `signal_type="span"` | Traces Span |
| `signal_type="profile"` | Profiles Profile（OTLP v1.3.0+） |
| `attributes` | record / data point attributes |
| `Batch.trace`（trace_context 能力） | W3C traceparent/tracestate 传播 |

帧、握手、Envelope、RESULT/CREDIT、credit 账本、去重状态属 MBTA 传输控制语义，不映射为 OTLP 数据模型字段。RESULT 码注册表数值稳定，可直作 exporter 侧 metrics label。
