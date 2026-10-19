# MBTA 协议重设计（r3 实施版）

> 状态：**实施规格（r3）**。r2 经第二轮深度审查（实施完备性 + 本库可行性两路）修订；**实施方式变更为：直接在 v1 代码库原地破坏性重构，不引入新版本号**（ALPN 保持 `mbta/1`/`mbta-ntls/1`；无生产部署故无兼容负担）。
> r3 裁决记录与密钥日程依赖验证结论见 §18。

## 18. r3 实施裁决（闭合 r2 审查发现）

**Blocker 裁决**：
- B1：`HelloAck.selected_capabilities` 增补（入链）；压缩算法不做协商——四个注册算法（NONE/GZIP/ZSTD/LZ4）收端 MUST 全支持，发送端逐帧在 Envelope.compression 自选。
- B2：proto 补全 `Limits{max_frame_bytes,max_batch_bytes}`、`Credits`、`Abort{code,detail}`、`Ping/Pong`；全部枚举加 `*_UNSPECIFIED=0` 且收端拒绝零值。
- B3（重试语义）：**幂等重发（RESULT 丢失）= 原 seq**（终态环回执）；**released/可重试 rejected 的重新投递 = 新 seq**（客户端保留载荷至终态；首版不自动重试，经回调上抛由应用决定——与 v1 ACK 回调语义对称）。
- B4：`dual_integrity` 能力**首版删除**（注册表移除，留作演进项）；envelope 单 AEAD。
- B5：**credit 字节维与 max_frame_bytes 按 Envelope wire 字节数计**（Open 之前可判）；**max_batch_bytes 按解压后 batch payload 字节计**（与 v1 语义一致）。校验次序：帧层 MaxFrameBytes → 窗口/credit 准入 → AD/解密 → 解压上限 → max_batch_bytes。

**High 裁决**：
- H1：去重窗口 W = **当前 granted_outstanding 的批数维**（随 CREDIT 动态增长，上界 = 账本本身）。
- H2（字节级规范）：transcript 段拼接 = 每段 4B BE 长度前缀；profile 用注册名字符串（"intl"/"gm"）；`token_proof ≡ HMAC(profileHash, key=token, msg=th_hello)`（与 psk_ck 的 ikm 同值）；AD = `type(1B) ‖ flags(1B) ‖ lenPrefix(session_id) ‖ key_epoch(1B 固定宽) ‖ seq(8B BE) ‖ compression(1B) ‖ lenPrefix(profile_name)`。
- H3：split 长度表——intl `L=104`：c2s(32)‖s2c(32)‖handshake(32)‖pre_c(4)‖pre_s(4)；gm `L=72`：c2s(16)‖s2c(16)‖handshake(32)‖pre_c(4)‖pre_s(4)。s2c_key 首版预留不使用。
- H4：REDIRECT 唯一载体 = 0x41 帧，时序 = HELLO_ACK 之后任意时刻（服务端发出后关闭连接）；客户端回调后断连；RESULT 码表删除 31。
- H5（默认值）：CREDIT 攒批 = 回收批数 ≥ max(1, 初始窗/4) 或 100ms 定时（SHOULD）；服务端 reaper 扫描 10s、stuck T=60s（配置 `SinkDeadline`）；DGRAM per-conn 并发槽 64 + 令牌桶速率默认 32MB/s（配置 `DatagramRateLimit`）。
- H6：Draining 中收到 BATCH——已见 seq 幂等回执；新 seq → `RESULT(released, server_draining)`。

**Low 裁决**：OnBatch 单注册（冲突启动期报错）；`Batch.events_count` 保留（Raw 路径需要）；Envelope.seq ≠ Batch.seq → `rejected(batch_invalid)`；`stale_epoch`/`ledger_divergence` 首版预留不可达；CREDIT 回绕/超钳制 = 钳制生效 + 日志计数（非致命）。**Transport 接口保持 v1 形状**（RecvControlFrame/RecvDataFrame/SendFrame…），SendFrame 由 binding 按 type 高位路由——语义同 r2 的 Control/Data 抽象，减小改动面；AuthMarker（pre-auth 读超时切换）作为 binding 内部机制保留。

**可行性验证结论（已实证）**：X25519=标准库 crypto/ecdh；**SM2 原始 ECDH = `github.com/emmansun/gmsm/ecdh`（P256() 即 sm2p256v1，ECDH() 输出 32B x 坐标）**，无需替代方案；HKDF=x/crypto/hkdf（已是 direct 依赖）+ pollux/sm3；SM4-GCM/AES-GCM 复用 core.NewAEAD（gm 密钥 16B）；deterministic marshal 对 map 按键排序可用（protobuf 版本升级视为互操作面变更，CI 加 cross-version 校验）；nonce 4B+8B=12B 两套件均通过；buf 1.72 + protoc-gen-go v1.36.11 与仓库生成物逐字节一致。

**删除清单（v1 → 删除）**：session_store.go 及票据体系、ack_tracker.go、delivery.go（ReplayCache）、envelope 旧 SecureEnvelope、codec_json、errors 的 legacyWireCodes/MatchWireCode、6 个 sink 接口、WINDOW/THROTTLE/ACK/NACK/AUTH_*/ERROR/PARTIAL_ACK 全部帧与处理路径、AuthMessage 系、多流 picker 残留无（已单流）、QUIC 侧心跳（QUIC keepalive 承担；TCP 保留 PING/PONG）。


---

## 0. 先例研究 → 设计决策映射

v2 的每个核心决策都锚定一个经过大规模验证的开源/标准设计：

| v2 决策 | 先例 | 先例的关键教训 |
|---|---|---|
| credit 单机制流控 | AMQP 1.0 per-link credit、HTTP/2 WINDOW_UPDATE、QUIC MAX_DATA | credit 只覆盖数据帧；**credit 必须在消费后而非接收后返还**，否则流控失效甚至死锁 |
| accepted/durable 二级确认 | AMQP settlement（unsettled → 终态 outcome） | accepted≈received，durable≈settled，released=可重投 |
| (epoch, seq) 窗口去重 | Kafka 幂等生产者（PID + epoch + sequence） | broker 只缓存最近若干批元数据——**去重深度是独立于流控窗口的参数**；epoch 由 broker 分配（InitProducerId），非客户端自报 |
| 重试语义 | Fluentd Forward（chunk+ack，at-least-once）vs MQTT QoS 2（四向握手） | 以一轮确认 + 服务端窗口去重达到会话内 exactly-once 投递效果 |
| 密钥派生 | Noise 框架（transcript→chaining key→Split；PSK 经 MixKeyAndHash） | 密钥从握手 transcript 派生、永不上线；**transcript 必须是规范编码**（否则跨实现校验随机失败） |
| 帧不重复传输层职责 | HTTP/2/QUIC（无逐帧 magic/version；ALPN 管版本） | 完整性由 TLS/TLCP 承担；版本是连接属性 |
| 小而稳定的错误码集 | gRPC status codes | varint 数字 + 注册表，字符串仅日志 |
| DATAGRAM 零流控 + 载荷自描述 | RFC 9221 + RFC 9297 | 不可靠通道豁免 credit，**但实现方须自设硬限额**（RFC 9221 明示） |

## 1. 设计原则

1. **传输层已做的不在应用层重做**（帧完整性、保活、优雅关闭、通道复用）。
2. **应用层加密要么做对要么不做**：密钥永不上线；默认单算（AEAD），双算（AEAD+HMAC）是 profile 选项。
3. **一个正交概念一个机制**：流控只有 credit（且**返还通道唯一**：一律经 CREDIT 帧）；反馈只有 RESULT；协商只有 profile+capabilities 一条轨。
4. **能力静态声明优于运行时接口探测**。
5. **标识符最小化**：seq 是唯一 wire 主键。
6. **流控状态与去重状态分离**（审查裁决，修正 r1 的"去重窗口=流控窗口"）：inflight 承载流控（终态即除名），最近 K 条终态环承载去重应答——生命周期不同，不得同源强并。

## 2. 帧格式

```
 0        1         2..
+--------+---------+--------------------+
| type   | flags   | varint length      |   payload（length 字节）
+--------+---------+--------------------+
```

- **type（8 bit）**：最高位是通道域——`0x00–0x7F` control、`0x80–0xFF` data；**data 方向的帧类型必须落在 data 域**（conformance 断言；r1 曾将 BATCH 编在 0x10 违反此规则，已修正为 0x91）。TCP binding 依赖该位做逻辑流 demux；QUIC binding 以 stream 角色放置。
- **flags（8 bit）**：**v2 首版全部为保留位**（r1 的 COMPRESSED 位移入 envelope——压缩是载荷属性而非帧属性，且必须在 AEAD 覆盖内，见附录 envelope schema 与审查裁决 §4.2/§8）。未知 flags 位 → ABORT。
- **版本唯一来源**：ALPN（`mbta/2`、`mbta-ntls/2`）+ 握手 transcript 绑定。
- 每帧开销 2B + varint（典型 4B，对照 v1 约 14B——每批净省 ~10B，对 1KB batch 约 1% 量级，收益真实但**非数量级**，此前的"实测收益显著"措辞撤回）。

### 2.1 接收端 MUST 清单（继承 v1 加固资产，逐条规范性）

1. 帧长度上限常量（`MaxFrameBytes`，初值沿 v1 16MB）**校验先于分配**（拒绝在 `make` 之前完成，防声明式 varint 长度直接 OOM）。
2. varint **非最短编码拒绝**、最大字节数限制、续位处理（继承 v1 frame.go 全部规则）。
3. 短读 drain：payload 部分短读时按实际 n drain 剩余字节维持帧边界（TCP binding）。
4. 短写检测：帧写出错（含部分写）→ ABORT 拆连接（流去同步不可恢复）。
5. 未知 type：跳过 payload + 计数 + 日志（帧自定界使跳过安全）；未知 flags：ABORT。
6. typed 输入校验：agent_id / HELLO meta / trace 字段的长度与控制字符校验、`SanitizeForLog`（继承 v1 validation.go 全套）。

## 3. 帧类型注册表（12 个，对照 v1 的 17 个）

| type | 名称 | 方向 | 通道 | 说明 |
|---|---|---|---|---|
| 0x01 | HELLO | c→s | control | 握手（token 证明、临时公钥、协商） |
| 0x02 | HELLO_ACK | s→c | control | 密钥确认 + epoch 分配 + 限额 + 初始 credit |
| 0x03 | HELLO_NAK | s→c | control | 握手拒绝（含 retryable/retry_hint） |
| 0x20 | RESULT | s→c | control | 对某 seq 的反馈（唯一反馈帧） |
| 0x21 | CREDIT | s→c | control | credit 发放（**唯一流控发放帧**；返还一律经它） |
| 0x30/0x31 | PING/PONG | 双向 | control | 仅 TCP binding（QUIC 内置保活） |
| 0x40 | CLOSE | 双向 | control | drain 超时提示 |
| 0x41 | REDIRECT | s→c | control | HA 重定向（proto 载荷；地址经校验） |
| 0x50 | ABORT | 双向 | control | 立即拆除（写失败/协议违规/账本漂移） |
| 0x90 | DGRAM | c→s | data | 不可靠批次（envelope 加密；豁免 credit，服务端硬限速） |
| 0x91 | BATCH | c→s | data | 可靠批次（envelope 加密，消耗 credit） |

删除：WINDOW、THROTTLE、ACK、NACK、AUTH、AUTH_OK、AUTH_FAIL、ERROR、PARTIAL_ACK。

## 4. 密码与密钥日程

### 4.1 Profile

| profile | ECDH | KDF | AEAD | 外层 HMAC（可选） |
|---|---|---|---|---|
| `intl` | X25519 | HKDF-SHA256 | AES-256-GCM | HMAC-SHA256 |
| `gm` | SM2 | HKDF-SM3 | SM4-GCM | HMAC-SM3 |

profile 是**密码敏捷性的唯一锚点**：新增组合（含后量子 hybrid，§15.1）只加一行注册、不动 wire。
`dual_integrity`（可选能力）：envelope 外再包一层 HMAC，默认关闭。

### 4.2 密钥派生

```
zz            = ECDH(client_eph, server_eph)
th_hello      = H(len_prefix(profile) ‖ canonical(HELLO, proof 置零))
ck            = HKDF-Extract(salt = th_hello, ikm = zz)
psk_ck        = HKDF-Extract(salt = HKDF-Expand(ck, "mbta/v2/psk", 32),
                             ikm = HMAC(profile.hash, token, th_hello))
c2s_key ‖ s2c_key ‖ handshake_key ‖ nonce_prefix_c ‖ nonce_prefix_s
              = HKDF-Expand(psk_ck, "mbta/v2/split", L)
```

审查裁决（修订项）：

- **transcript 规范编码**：canonical = proto deterministic marshal + map 字段按键排序。proof 字段与 finished/ticket 字段在各自消息入链前**置零**（内容进链、占位清零）。拼接一律带长度前缀（防未来 profile 名互为前缀）。
- **HELLO_ACK 全字段入链**：`th_full = th_hello ‖ canonical(HELLO_ACK, finished 置零)`；`finished = HMAC(handshake_key, th_full)`——limits/credits/ack_mode/expiry/epoch 全在覆盖内，防 TLS 终止点篡改服务端声明（r1 的"全 transcript"未定义，已修正）。
- **handshake_key 独立派生**：finished 不复用数据密钥（密钥用途分隔，对齐 Noise/TLS 1.3 的 finished 子密钥）。
- **nonce 构造（修正 r1 的 4 字节截断缺陷）**：`nonce = nonce_prefix(4B) ‖ seq(8B 固定宽度大端)`——seq 以全 64 位宽度参与 nonce，截断重用（seq=k 与 k+2³² 同 nonce 的 GCM 灾难）在构造上不可表达。
- **单一连接级 seq 计数器（MUST）**：BATCH、DGRAM 共享同一分配临界区——分设计数器会跨通道复用 nonce。
- **token_proof 的服务端索引（修正 r1 隐含的 O(N) 全表扫描）**：`ResolveToken(agentID) ([]TokenCandidate, error)` 升级为 Auth **必选**接口；多候选按注册序确定性遍历，上限常量；比对常量时间；失败计账与限速联动（§5.1）。
- 应用层加密仅覆盖 BATCH/DGRAM 的 envelope 载荷；control 帧依赖 TLS/TLCP 通道（显式边界）。

## 5. 握手与状态机

### 5.1 消息流（1 RTT，首版唯一模式）

```
c → HELLO{profile, agent_id, meta, capabilities, client_eph, token_proof}
s → HELLO_ACK{session_id, epoch, ack_mode, limits, credits, server_eph,
              finished, expiry}
   或 HELLO_NAK{code, retryable, retry_hint_ms}
```

审查裁决（修订项）：

- **epoch 由服务端分配**（修正 r1 的客户端自报 + max 围栏）：HELLO_ACK 携带 `epoch = max_epoch(agent)+1`，max 仅在**连接建立时**推进。无票据/票据丢失的重连同样获得新的更高 epoch——修正 r1 中"票据丢失 → epoch=0 < max → 永久 stale_epoch 拒绝"的围栏死锁。`stale_epoch` 对客户端是**连接级致命**（ABORT 重连，不可逐批重试）。
- **HELLO_NAK 信息面收敛**：未认证阶段的 NAK 在认证维度只允许单一代码（`auth_failed`；token_expired 合并），detail 对未认证方不透传（防 agent/token 枚举 oracle）。
- **NAK 携带 retryable / retry_hint_ms** + 客户端指数退避 + 服务端 pre-auth 限速为 MUST——修正 r1"一切失败走新连接"在坏 token 批量下发时的连接风暴面（每次重连成本 = TLS + ECDH + HKDF + proof 验证）。
- 握手处理次序 MUST：解码校验 → proof 验证（ResolveToken）→ eph 生成/ECDH → 派生 → 回 ACK。任何优化不得把 proof 验证后置。
- HELLO 请求与校验在 pre-auth 窗口内完成（binding 内建 pre-auth 超时 + 限速，继承 v1）。

### 5.2 状态机

- server：`Handshaking → Ready → Draining`。
- client：`Idle → Ready → Draining → Closed`；**Closed 是任意状态的一等出边**。

### 5.3 CLOSE/ABORT 交错矩阵（规范性）

| 交错 | 收敛动作 |
|---|---|
| 双方同时 CLOSE | 双方各自按 drain 判定收敛；重复 CLOSE 幂等忽略 |
| Draining 中收到 CREDIT/RESULT | 正常处理（RESULT 参与 drain 判定；CREDIT 忽略） |
| 服务端 drain 超时放弃 inflight | **必须**对每个放弃项发 `RESULT(released, server_draining)` 后 ABORT（禁止沉默——客户端否则白等满超时） |
| 客户端 CLOSE 后关闭读路径 | 最后一批 RESULT 允许丢失；客户端以本地判定为准（at-least-once 由重连重发兜底） |
| Draining/Handshaking 中收到 ABORT | 立即拆除，无 drain；未终态 batch 由客户端重连重发 |
| 协议违规（未知 flags / 窗外 seq / 账本漂移） | ABORT，code 指明 |

## 6. 流控：credit 单机制（模型 B：服务端权威）

> 审查裁决：r1 存在"客户端本地返还（RESULT 隐含）"与"服务端发放"两种读法各取一半的歧义，且客户端本地回收必然与服务端 granted 视图发散。本版**规格化为单一模型 B**。

### 6.1 状态与不变式

```
client：ledger = {granted_batches, granted_bytes, used}
  发送 BATCH 前置：granted − used ≥ (1, len)
  RESULT 不隐含返还——返还一律经 CREDIT 帧

server（每连接）：
  inflight: map[seq] = {bytes, state}       // 流控状态：终态即除名
  terminal ring: 最近 K 条 seq → outcome    // 去重应答状态：独立于 inflight（§7）
  granted_outstanding = initial + ΣCREDIT − Σ终态回收
  不变式（可检验）：|inflight| ≤ granted_outstanding ≤ initial + ΣCREDIT
```

### 6.2 credit 生命周期

| RESULT level | 语义 | 服务端动作 |
|---|---|---|
| `accepted`（ack_mode=durable） | 已入内存队列，未持久化 | inflight 保留（state=accepted） |
| `accepted`（ack_mode=accepted_only） | **即终态** | inflight 除名 + 回收额度 |
| `durable` | 持久化完成（终态） | inflight 除名 + 回收额度 |
| `rejected` | 终态拒绝，携带 code | inflight 除名 + 回收额度 |
| `released` | 未处理可重投，携带 retry_hint | inflight 除名 + 回收额度 |

- 回收额度不逐批发放：服务端按**攒批策略**发放 CREDIT（窗口回收 ≥ 25% 或 RTT 定时器到点）——高 RTT 链路上逐批 RESULT+CREDIT 双帧会重演 HTTP/2 BDP 空转。
- **服务端 reaper（MUST）**：inflight 条目（含 accepted 态）T 秒无终态 → 服务端主动 `RESULT(released, internal)` + 回收，或按策略 ABORT——修正 r1 把 reaper 留在客户端的归属错误；sink 卡死时窗口慢性萎缩的失效链由此闭环。
- **客户端 reaper 职责收缩**：超时只**标记失败并通知应用层**，**严禁回补 credit 账本**（本地回补必然与服务端视图发散，r1 未定义此边界）。
- **账本漂移检测**：客户端收到 ref 超出自身 granted 视图的 RESULT → 判定漂移 → ABORT 重连。
- **DGRAM 豁免 credit 但有硬限**：per-connection 并发处理槽（满则静默丢弃，at-most-once 语义允许）+ 字节速率硬上限（RFC 9221 明示实现方须自设）。
- **初始 credit 尺寸**：HELLO_ACK 下发值应 ≥ BDP/平均批大小（服务端按 sink 吞吐估计；公式进实现指南）。

### 6.3 CREDIT 帧校验（客户端 MUST）

零 delta 忽略；单维为 0 且另一维 >0 → 协议违规 ABORT；加法回绕/超过本地钳制上限 → 按钳制值生效并记违规；HELLO_ACK 初始 credit ≤0 → 视为 HELLO_NAK 级错误。
（v1 的 WINDOW 零值静默冻结 bug 的直接对应防护。）

### 6.4 drain 判定（修正 r1 的 max 谓词）

`drained ⟺ 所有已发 seq 均达终态`（连续终态前缀水位 == last_sent，或等价的计数判空）。
r1 的 `max(终态 seq) == last_sent` 在乱序 durable 下误判（seq=5 先 durable、4 仍 accepted 时提前关连接丢数据）。CLOSE 携带 drain 超时提示，服务端 clamp [1s, 30s]。

## 7. 投递语义与去重

### 7.1 标识符

- **seq（varint，从 1 起；0 非法）**：连接内单调、**BATCH/DGRAM 共享单一计数器**；唯一 wire 主键。
- `correlation`（可选字符串）：客户端对账句柄，RESULT 原样回显，服务端不解释不存储。
- **epoch**：服务端在 HELLO_ACK 分配（§5.1），per-agent 单调；stale_epoch 连接级致命。

### 7.2 去重算法（集合制窗口 + 终态环；修正 r1 的连续窗口）

> 审查裁决：r1 的 Kafka 式 `next_expected` 连续窗口要求顺序接收，与 §10.1 的多流聚合（乱序到达是常态）直接冲突——首个 gap 被终态拒绝即丢数据。本版改为集合制。

```
窗口 [low, low + W)，W = credit 批数上限：
  seq ∈ 窗口且未见        → 接受（乱序到达合法），记入集合
  low 沿连续已见前缀推进；推进时窗口整体滑动
  seq ∈ 窗口且已见        → 幂等回执：查 inflight 状态或终态环，回当前最高结果
  seq ≥ low + W           → 协议违规（超发/重放）→ ABORT(window_exceeded)
  seq < low               → 查终态环：命中 → 回存储 outcome；未命中 → released（不可知，宁重发不吞数据）
```

- **终态环（K 条）独立于流控**：inflight 终态即除名（credit 守恒），但客户端 RESULT 丢失后重发同 seq 需要可答——K 取 `max(W, 256)` 推荐。这正是 Kafka "broker 缓存最近 5 批"的去重深度独立于窗口语义的教训。
- 内存上界：集合 ≤ W、终态环 ≤ K，均由协商 credit 界定，无全局 LRU。
- **多副本/重启限制（诚实声明，入安全考虑）**：epoch 与去重状态是**副本内存态**——跨副本与重启窗口内为纯 at-least-once（Kafka 同款限制：幂等仅限单 broker 会话）。宣称跨副本 exactly-once 需共享状态存储，v2 不承诺。

## 8. RESULT 帧与错误码

```
RESULT{ref_seq, level, code, retry_hint_ms, correlation(echo)}
level: accepted | durable | rejected | released   // proto enum，非字符串
```

- 乱序/gap 类非终态否决一律用 `released`（可重投）；`rejected` 仅用于终态否决（内容非法、超限）——r1 曾把 out_of_order 挂在 rejected 上，语义错位已修正（集合制窗口下窗内 gap 直接接受，该场景消失；窗外为协议违规走 ABORT）。
- 错误码注册表（varint，append-only，分组）：

| 码 | 名称 | 组 |
|---|---|---|
| 0 | ok | — |
| 10 | auth_failed | 握手（未认证维度唯一码） |
| 12 | unsupported_profile | 握手 |
| 13 | unsupported_capability | 握手 |
| 14 | bad_handshake_message | 握手 |
| 20 | batch_too_large | 数据 |
| 21 | batch_invalid | 数据 |
| 22 | decompress_limit | 数据 |
| 23 | envelope_open_failed | 数据 |
| 24 | window_exceeded | 数据（协议违规，配合 ABORT） |
| 25 | stale_epoch | 数据（连接级致命；票据演进项预留） |
| 26 | ledger_divergence | 数据（连接级致命） |
| 27-31 | result_level_bad / ack_mode_bad / credit_invalid / hello_eph_invalid / hello_proof_invalid | 握手/数据校验（30/31 对外与 10 同面，仅日志区分） |
| 32 | server_draining | 会话（含 session TTL 过期） |
| 40 | internal | 服务端（reaper 合成 released 时使用） |
| 41 | unavailable | 服务端 |
| 42 | protocol_error | 通用协议违规（未知 flags/类型错域等） |

- 全部枚举字段（profile/ack_mode/level/compression）用 proto enum，wire 上不传字符串。

## 9. 协商

- `profile: enum`（§4.1）；capabilities：`trace_context`、`datagram`、`dual_integrity`、`zstd_dict`（§15.2）、`cbor`。
- `ack_mode: enum` 由 HELLO_ACK **声明**；accepted_only 下 accepted 即终态并返还（§6.2）。重连时模式切换：旧连接未 durable 的 batch 按未投递处理，由客户端重发（显式损失语义，继承 v1 "potential data loss" 日志要求）。
- codec 默认 proto；cbor 是能力。**压缩算法标识在 envelope 内逐帧自描述**（附录），协商限制可用算法集合。

## 10. 传输绑定

### 10.1 统一抽象

```go
type Transport interface {
    Control() Stream            // 控制逻辑流
    Data() Stream               // 数据逻辑流（多流聚合，乱序到达合法——§7.2 集合制窗口为此设计）
    Datagram() (DatagramSender, bool)
}
```

- QUIC：Control = 首个 bidi stream；Data = 其余 stream 聚合（乱序是常态，去重已适配）；Datagram = RFC 9221。
- TCP/TLCP：单连接 mini-mux，type 高位域路由；Datagram 返回 false → DGRAM 降级 BATCH（`datagram` capability 告知）。
- pre-auth 超时 + **pre-auth 限速**（修正 r1 缺失：proof 验证前的 CPU 放大面——ECDH+HKDF+反查按连接限速）+ 认证后空闲超时为 binding 内建职责。
- Data 流帧在 Ready 前**一律丢弃**（不解析、不缓冲）——防 pre-auth 数据洪水以解码/缓冲成本放大。

### 10.2 v2 与 RFC 8998

gm profile 跑 QUIC+TLS1.3(RFC 8998) 时应用层仍按 profile 密码——传输层与应用层密码正交。

## 11. Sink API（Go，注册式单接口）

```go
type SinkOptions struct {
    Raw     bool
    Durable bool
    Async   bool
}
type BatchEvent struct {
    Agent   string
    Meta    BatchMeta // Seq, Correlation, TraceContext, ReceivedAt
    Decoded *SignalBatch // Raw=false 时供给
    Raw     []byte       // Raw=true 时供给
}
type Outcome struct {
    Level      OutcomeLevel // Accepted | Durable | Rejected | Released
    Code       uint32
    RetryAfter time.Duration
}
func (s *Server) OnBatch(opts SinkOptions, handler func(ctx context.Context, ev BatchEvent, done func(Outcome)))
```

### 11.1 Sink 契约（**规范性 MUST**；审查裁决：r1 把下列各项降格为"实现细节"是错误的——它们决定 wire 行为，是协议语义）

1. `done` **幂等**：首调生效，后续调用安全丢弃。
2. **单调性**：accepted 的 RESULT 已发出后，合法 Outcome 收缩为 `Durable | Released`。
3. **sink deadline**：handler 在服务端 deadline 内未调 done → 服务端合成 `Outcome{Released, code=internal}`（防 credit 永久卡死，衔接 §6.2 服务端 reaper）。
4. **panic**：per-invocation recover → 合成 released + SinkFailures 计数。
5. **ctx 取消后**（连接关闭）迟到的 done 安全丢弃。
6. **队列满/入队失败** → `RESULT(released, retry_hint)` + 额度回收（enqueue 失败路径必须映射到 wire 语义，v1 THROTTLE+ResetToProcessing 的等价物）。
7. 投递队列**条数+字节双限界、排空超时、超时放弃路径对在途 accepted 项合成 released**——全部 MUST。
8. 以上各项均进 conformance 断言清单（§16）。

## 12. 安全考虑（v1 r2 资产继承 + 本版新增）

- TLS/TLCP 强制；证书校验 MUST NOT 关闭（InsecureSkipVerify 仅测试）。
- **REDIRECT 地址校验**（ValidateHostPort 等价物）：防被入侵服务端诱导 agent 连向攻击者。
- 解压炸弹防护全保留：`MaxDecompressedSize` 流式上限、zstd `WithDecoderMaxMemory`、预分配封顶（v1 Grow 4× 放大教训）、解压上限**先于**解压执行。
- typed 输入校验（§2.1-6）。
- pre-auth 超时 + 限速；认证后空闲超时。
- **多副本/重启的 at-least-once 边界**（§7.2 诚实声明）纳入威胁模型。
- 威胁模型声明：TLS 终止点（企业代理/LB 卸载）视为**不可信转发者**——transcript 绑定 + AD 覆盖（附录）使其对 HELLO/HELLO_ACK/envelope 元数据的任何篡改导致密钥校验失败。

## 13. 工程改造清单（v1 → v2 映射）

| v1 组件 | v2 处置 |
|---|---|
| frame.go magic/version/channel | 删除域；2B 头 + varint；接收 MUST 清单（§2.1） |
| envelope.go 密钥下发/明文模式 | ECDH 派生；明文模式删除；dual_integrity 可选 |
| auth.go challenge/票据 master | token_proof + ResolveToken；票据机制整体后移为演进项（§15.4） |
| ack_tracker.go ring/span | credit 账本（模型 B）+ 终态环 |
| delivery.go ReplayCache | inflight 集合窗 + 终态环 K |
| handler_batch.go sink 分支 | OnBatch 单路径 + §11.1 契约 |
| handler_handshake.go 四帧握手 | 两帧握手 + epoch 服务端分配 |
| client_control.go 五帧分发 | RESULT/CREDIT 两 handler |
| session.go 双状态机（9+7） | 4+3 态 |
| errors.go 双轨码 + legacy 别名 | varint 注册表 |
| 6 sink 接口 + 四层配置透传 | OnBatch + 单层配置 |
| DATAGRAM 半成品 | 客户端 lossy 路径 + 硬限速成文 |

## 14. 演进机制

### 14.1 帧类型与 flags 的不对称演进

type 开放（未知 type 跳过+计数；新类型须先 capability 协商）；flags 冻结（未知位 ABORT）。v2 首版 flags 无定义位，全保留。

### 14.2 append-only 规则

错误码（只增不改，分组段位预留）；profile（注册表追加，新 profile 非破坏）；消息 schema（字段号只加不复用）；capabilities（14.3）。

### 14.3 Capability 生命周期

`experimental（x- 前缀）→ stable → deprecated → removed`；stable 化以 conformance 用例为门槛。

### 14.4 版本节奏

ALPN 单轨；双栈并行 ≥ 2 个大版本周期；v3 触发条件仅限帧头/语义模型级变更。

### 14.5 规格化扩展点

| 扩展点 | 位置 | 用途 |
|---|---|---|
| `key_epoch` | envelope varint（**已规格化字段**，首版恒 0） | rekey / 0-RTT 密钥切换（演进项） |
| credits 第三维 | Credits 消息 | events 维度 |
| `correlation` | Batch/Result echo | 已实现，语义可扩展 |
| RESULT 范围确认 | §15.3 | 批量确认 |
| type 高位域 | 帧头 | 新逻辑通道 |

## 15. 先进性增强（2026 基线）

### 15.1 后量子就绪

RFC 10024 已标准化 X25519MLKEM768 等 hybrid KEM；浏览器默认开启，Cloudflare 度量 2025 年末人类流量过半走 PQ，OpenSSL 3.5 默认；NIST IR 8547 给出 RSA/ECC 2030 弃用/2035 禁用。v2 落点：profile 追加 `intl-pq` 一行注册 + ECDH 接口实现，wire 零变更（eph 字段不定长 bytes 容纳 KEM 封装输出）。排在 1-RTT 落地后；gm 侧跟踪中国 PQC 标准。

### 15.2 共享字典压缩（`zstd_dict`）

zstd 训练字典对重复性日志的小记录收益显著（RocksDB 生产案例，字典解压快 2.2–2.4×）。字典经服务端下发（control type 走 §14.1 追加），字典内容**入 transcript**（防跨连接字典混淆），解压上限规则（§12）同样适用字典模式。首版先做静态字典下发，训练轮换为演进。

### 15.3 RESULT 范围确认（演进方向）

高带宽/高 RTT 下 RESULT 流量放大时启用（触发条件：确认帧带宽占比 > 5% **或** 高 RTT 基线），扩展 `ref_ranges` 字段——语义是终态环的只读投影，不新增状态。

### 15.4 0-RTT（**演进项，首版不实现**）

> 审查裁决：r1 的 0-RTT 安全论证链断裂——早数据结构性豁免 credit 而去重窗口=credit 界定（早数据不在去重覆盖内）；票据 Get-then-Delete 非原子可双消费；append 投递非幂等。整体后移，且列出前置条件：

1. 原子票据消费（DEL 原子判定）+ 多副本共享票据存储或显式单副本亲和声明；
2. (agent, epoch) 级去重覆盖早数据 seq 区间（独立于 credit 窗口）；
3. envelope `key_epoch` 区分 early/main 密钥 + END_OF_EARLY_DATA 显式切换帧（对齐 TLS 1.3 record epoch）；
4. proof 验证先于早数据解密（MUST，防仅持票据者注入伪造早数据）；
5. 早数据条数/字节上限与"早数据 RESULT 一律在 HELLO_ACK 后发出"的时序规则。

### 15.5 传输层继承

QUIC connection migration 天然继承（会话绑定连接非四元组）；TLCP → RFC 8998 传输层可替换（Transport 抽象隔离）。

### 15.6 可观测性

OTLP 映射继承；`trace_context` 对齐 W3C/OTel；RESULT 码注册表数值稳定可直作 metrics label。

## 16. Conformance 断言清单（浓缩）

1. accepted 不返还 credit / durable·rejected·released 返还（模型 B 语义）。
2. CREDIT 校验四规则（零 delta/单维零/回绕/初始 ≤0）。
3. 集合制窗口：乱序窗内接受、窗外 ABORT、窗下界查终态环。
4. drain 谓词 = 全部终态（构造乱序 durable 序列验证）。
5. Sink 契约 §11.1 全部 8 条（panic/双调/迟调/不调/队列满/排空超时）。
6. 帧接收 MUST §2.1 全部（含分配前长度校验、varint 规范性）。
7. epoch：服务端分配、无票据重连获得新 epoch、stale_epoch 连接级致命。
8. nonce：单一 seq 计数器（BATCH+DGRAM 交叉发送无 nonce 重用）。
9. transcript：跨实现 canonical 编码一致性（proof/finished 互验）。
10. HELLO_ACK 篡改（limits/credits/ack_mode）导致 finished 校验失败。

## 17. 修订记录

- **r2（本版）**：对抗性审查（安全 + 分布式两路）3C/10H/10M 全部闭合。结构性裁决：① 0-RTT 移出演进为首版不含（论证链断裂）；② 去重改集合制窗口 + 独立终态环（与流控状态分离，原则 6 重写）；③ credit 规格化为模型 B（服务端权威、CREDIT 唯一返还通道、服务端 reaper、客户端 reaper 职责收缩、漂移检测）；④ epoch 改服务端分配（修围栏死锁）；⑤ BATCH 重编号 0x91（修自违反）；⑥ nonce 全宽 seq + 单计数器 MUST（修 GCM 重用）；⑦ envelope schema 补全 + AD 覆盖 + 压缩标识入 envelope（删双真相源）；⑧ transcript canonical + HELLO_ACK 入链 + 独立 handshake_key；⑨ ResolveToken 必选接口；⑩ Sink 契约升格规范性 MUST；⑪ 继承 v1 安全资产清单成节；⑫ 性能声明诚实化。
- **r1**：初版（先例映射 + 分层设计）。

## 附录：消息 proto 草案

```protobuf
enum Profile     { PROFILE_INTL = 0; PROFILE_GM = 1; }
enum AckMode     { ACK_ACCEPTED_ONLY = 0; ACK_DURABLE = 1; }
enum ResultLevel { ACCEPTED = 0; DURABLE = 1; REJECTED = 2; RELEASED = 3; }
enum Compression { NONE = 0; GZIP = 1; ZSTD = 2; LZ4 = 3; }

message Hello {
  Profile profile = 1;
  string agent_id = 2;
  map<string,string> meta = 3;      // 入链时按键排序（canonical）
  repeated string capabilities = 4;
  bytes client_eph = 5;
  bytes token_proof = 6;            // 入链前置零
}
message HelloAck {
  bytes session_id = 1;
  uint64 epoch = 2;                 // 服务端分配
  AckMode ack_mode = 3;
  Limits limits = 4;                // max_batch_bytes（压缩后 wire 尺寸；解压上限为独立常量）
  Credits credits = 5;
  bytes server_eph = 6;
  bytes finished = 7;               // 入链前置零
  int64 expiry_unix = 8;
}
message Envelope {                  // BATCH/DGRAM 的帧 payload（加密后整体见下）
  uint64 key_epoch = 1;             // 首版恒 0
  uint64 seq = 2;                   // 与 Batch.seq 一致（AD 绑定）
  Compression compression = 3;
  bytes ciphertext = 4;             // AEAD(Batch 编码)
  // nonce = nonce_prefix(4B) ‖ seq(8B 大端)；AD = 帧type ‖ 帧flags ‖ session_id
  //         ‖ key_epoch ‖ seq ‖ compression ‖ profile（帧头与元数据全部完整性覆盖）
}
message Batch {
  uint64 seq = 1;                   // 从 1 起；BATCH/DGRAM 共享计数器
  string correlation = 2;
  TraceContext trace = 3;
  bytes payload = 4;                // SignalBatch 编码（压缩标识只在 Envelope，单一真相源）
}
message Result {
  uint64 ref_seq = 1;
  ResultLevel level = 2;
  uint32 code = 3;
  string detail = 4;                // 仅日志，不对未认证方透传
  uint32 retry_hint_ms = 5;
  string correlation = 6;
}
message HelloNak { uint32 code = 1; bool retryable = 2; uint32 retry_hint_ms = 3; }
message Credit     { uint64 batches = 1; uint64 bytes = 2; }
message Close      { string reason = 1; uint32 drain_timeout_ms = 2; }
message Redirect   { string leader_addr = 1; string leader_id = 2; }  // 地址经校验
```

## 参考文献

- AMQP 1.0：[Part 2 Transport（credit flow）](https://docs.oasis-open.org/amqp/core/v1.0/os/amqp-core-transport-v1.0-os.html)、[Part 3 Messaging（settlement/outcome）](https://docs.oasis-open.org/amqp/core/v1.0/amqp-core-messaging-v1.0.html)、[RabbitMQ flow control](https://www.rabbitmq.com/blog/2024/09/02/amqp-flow-control)
- Kafka 幂等生产者：[AutoMQ producer internals](https://www.automq.com/blog/understanding-kafka-producer-part-2)、[ProducerStateManager 源码](https://github.com/a0x8o/kafka/blob/master/core/src/main/scala/kafka/log/ProducerStateManager.scala)、[producer config（5-batch 窗口警告）](https://kafka.apache.org/41/configuration/producer-configs/)
- HTTP/2 / QUIC 流控：[RFC 9113 §5.2](https://www.rfc-editor.org/rfc/rfc9113.html)、[QUIC flow control 设计文档](https://docs.google.com/document/d/1F2YfdDXKpy20WVKJueEf4abn_LVZHhMUMS5gX6Pgjl4/mobilebasic)、[HTTP/2 流控死锁分析](https://nitely.github.io/2024/08/23/http-2-flow-control-dead-lock.html)
- Noise：[Noise Protocol Framework](https://noiseprotocol.org/noise.html)、[Noise* 形式化验证](https://eprint.iacr.org/2022/607)
- TLS 1.3 0-RTT：[TLS WG #1001（单次票据）](https://github.com/tlswg/tls13-spec/issues/1001)、[Trail of Bits: early data](https://blog.trailofbits.com/2019/03/25/what-application-developers-need-to-know-about-tls-early-data-0rtt/)、[Cloudflare 0-RTT](https://blog.cloudflare.com/introducing-0-rtt/)
- MQTT / Fluentd：[HiveMQ QoS](https://www.hivemq.com/blog/mqtt-essentials-part-6-mqtt-quality-of-service-levels/)、[Fluentd Forward Protocol v1](https://gist.github.com/tagomoris/85ea72b178e89e18f92e9c0e639e3eed)
- gRPC / RFC 9221：[gRPC status codes](https://grpc.io/docs/guides/status-codes/)、[RFC 9221](https://datatracker.ietf.org/doc/html/rfc9221)、[RFC 9297（Context ID）](https://www.rfc-editor.org/info/rfc9297/)
- 后量子：[RFC 10024（PQ/T Hybrid KEM）](https://datatracker.ietf.org/doc/rfc10024/)、[Cloudflare: State of the post-quantum Internet in 2025](https://blog.cloudflare.com/pq-2025/)、[OpenSSL post-quantum](https://openssl-corporation.org/post-quantum.html)、[NIST PQC](https://www.nist.gov/pqc)
- zstd 字典：[RocksDB dictionary compression](http://rocksdb.org/blog/2021/05/31/dictionary-compression.html)、[HTTP Toolkit: dictionary compression benchmarks](https://httptoolkit.com/blog/dictionary-compression-performance-zstd-brotli/)、[zstd manual](https://facebook.github.io/zstd/zstd_manual.html)
