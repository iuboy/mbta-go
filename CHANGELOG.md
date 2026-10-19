# Changelog

本文件记录 mbta-go 的显著变更。版本号遵循 [Semantic Versioning](https://semver.org/)。

## [Unreleased]

### 依赖更新与兼容适配

- **pollux-go v0.4.4→v0.5.2**：承接其三轮安全审查成果——tlcp 空套件回退对齐 DefaultCipherSuites（防静默降级到无 PFS+CBC）、`configToNative` 入口套件校验、客户端 ALPN 信任门、CKE 解密失败错误统一（消格式预言机）；本仓库 import 面（cert/sm3/sm4/smx509/tlcp 核心 API）零适配，双模式（standalone 代理 / workspace 本地）全量验证通过。已知事项：smx509 存在 IP 名称约束绕过缺口（gmsm 上游同步问题，pollux-go 侧已实证并文档化）——依赖 IP 名称约束做隔离的部署不应将 GM 校验路径作为唯一防线；本库 ntls 不使用 quicgm（fork replace 不随其发布生效的警告不适用）。
- **prometheus/common v0.72.0→v0.72.1**、x/net v0.60.0→v0.61.0（pollux-go 随动）。protobuf pin 保持 v1.36.12（CI protoc-gen-go pin 不变）。
- **Go 基线 go1.26.5→go1.26.9（stdlib 安全修复）**：清零 govulncheck 的 8 条 stdlib 漏洞（GO-2026-6617 net/http HPACK 竞态、GO-2026-6613/6612/6611/6607/6603 crypto/tls、GO-2026-6090 等，修复版最大交集 go1.26.9）；CI 以 `go-version-file: go.mod` 自动取新基线。**恢复 Vulnerability scan 硬门禁**（移除 continue-on-error——"TLS 库必然命中"的旧理由不成立：stdlib 漏洞由 go 指令钉住，升级即清零，扫描失败应显式处理而非静默放行）。
- **直接依赖全量更新**：gmsm v0.44.1→v0.45.0、quic-go v0.61.0→v0.64.0、x/crypto v0.54.0→v0.58.0、x/sync v0.22.0→v0.24.0、cbor v2.9.2→v2.9.6、klauspost/compress v1.19.2→v1.20.3、pierrec/lz4 v4.1.28→v4.1.33、prometheus/client_golang v1.24.1→v1.25.0（client_model/common/procfs 随动）、x/net v0.57.0→v0.60.0、x/sys v0.47.0→v0.49.0。
- **protobuf v1.36.11→v1.36.12**（prometheus/common v0.72.0 硬性要求，MVS 不可回调）：仍在握手互操作策略 pin 的 1.36 minor 内（patch 级，wire 序列化稳定）；CI `protoc-gen-go` pin 同步 v1.36.11→v1.36.12（插件版本写入生成文件头，drift 校验依赖两侧一致），corepb 已按 v1.36.12 重新生成验证逐字节一致。
- **ntls TLCP ServerName 推导**（pollux-go tlcp 新增握手期校验「ServerName 与 InsecureSkipVerify 至少其一」的适配）：客户端未显式指定 ServerName 且未跳过校验时，从拨号地址 host 推导（与 crypto/tls 语义对齐），由证书 SAN 完成校验——存量「仅配 CAFile」的调用方无需改动即恢复可连。
- **lint 收敛**：handleHello 认知复杂度 33→达标（ECDH/密钥派生段抽取 `deriveServerKeys`、NAK 码映射抽取 `helloNakCode`，行为不变）；注释格式修正。

## [0.6.0] - 2026-08-22

### chore: 无用代码与文档清理（第七轮：r3 收尾后无引用面清扫）

- **死代码删除**（全部经 GitNexus impact + 全仓 grep 验证零引用）：`CreditLedger.MarkFailed`（生产 reaper 用 `ReapExpired`，仅测试引用的死 API，连同 conformance 断言一并移除）、`CreditManager.LookupSlot`、`SettleGrant.Seq`、`CoreClient.AckMode`（连同 write-only 的 `ackMode` 字段与握手 Store）、`CoreClient.DictID`、`SessionEvent.Hostname/InstanceID/AgentVersion/OS`（r3 HELLO 无对应 wire 字段、handler 从未填充，扩展元数据经 HELLO.meta 自由携带）。
- **过时注释修正**：v1/quic_transport.go 旧帧名（ACK/NACK/WINDOW/THROTTLE/AUTH_OK → r3 RESULT/CREDIT/PONG/DICT/CLOSE/ABORT）；AUTH_OK 术语（→ HELLO_ACK）；core/codec.go 已删除的 JSON codec 提及；client_control.go 对已删 MarkFailed 的提及。
- **文档修正**：docs/performance-optimization.md 全量重写（原为 r3 前实现笔记，引用已删除的 delivery.go/ack_tracker.go/flow.go/RawEventSink 接口族/AUTH_OK 密钥下发/0-RTT 等大量失效内容）；docs/README.md「已知实现差距」三条已关闭项移除（100ms 定时攒批/客户端压缩启发/Draining 显式入口均已实现）；mbta-core-spec.md 重复的 §11.5 编号修正（部署模型 → §11.6）；v2-design.md 悬空引用 §4.3/§4.4 修正；根 README 服务端选项表补 `WithZstdDict`；CHANGELOG §11.5 引用同步；.golangci.yml 移除指向不存在的 core/capability.go 的 goconst 豁免；Makefile `.PHONY` 补全（test-all/tidy/help）；AGENTS.md/CLAUDE.md 索引计数刷新。

### 协议 r3 重设计（破坏性，直接在 v1 代码库原地重构，不引入新版本号）

按 docs/v2-design.md（r3 实施版）执行的全量协议重写，**无向后兼容**（无生产部署）：

- **帧格式**：`[type(1)][flags(1)][varint len]`（~4B vs 旧 ~14B）；type 高位为通道域（control 0x00-0x7F / data 0x80-0xFF）；删除 magic/version/ChannelID/MoreFollows/Coalesced 死位；flags 全保留（压缩标识移入 Envelope）。
- **握手 1-RTT**：HELLO（profile+eph+token_proof）→ HELLO_ACK（epoch+ack_mode+limits+credits+server_eph+finished）。token_proof = HMAC(token, H(transcript))——token 不上线；密钥 ECDH+transcript 派生（intl=X25519/AES-GCM，gm=SM2/SM4-GCM），**密钥永不上 wire**（删除 AUTH_OK 明文下发）；HELLO_ACK 全字段入链（防 TLS 终止点篡改 limits/credits）；epoch 服务端按 agent 单调分配。
- **流控 credit 单机制（模型 B）**：RESULT 不隐含返还，返还一律经 CREDIT 帧；服务端 reaper（60s）回收 stuck inflight；客户端 reaper 只标记不回补（防账本发散）；DGRAM 豁免 credit 但限并发+令牌桶。
- **去重（集合制窗口）**：`[low, cap]`，low=连续已接受前缀+1（乱序不推进）、cap=累计发放批数；窗内乱序接受；duplicate 幂等回执；终态环 K 条（RESULT 丢失后同 seq 重发回存储 outcome）；窗外 → ABORT(window_exceeded)。删除全局 ReplayCache。
- **RESULT 统一反馈帧**：accepted/durable/rejected/released 四级（AMQP settlement 语义）；错误码 wire 上只传 varint 数字（注册表 §8）；删除 ACK/NACK/THROTTLE/WINDOW/ERROR/AUTH_* 帧族。
- **Envelope**：compress-then-encrypt；确定性 nonce = prefix(4B)‖seq(8B)（全宽 seq，无截断重用）；AD 覆盖帧 type/flags + session_id + key_epoch + seq + compression + profile。
- **Sink API**：注册式单接口 `OnBatch(SinkOptions, handler)`（Raw/Durable/Async 静态声明），替代 6 接口矩阵；done 契约（幂等/单调/deadline 合成/panic recover）为规范性 MUST。
- **状态机**：client 4 态（Idle/Ready/Draining/Closed，Closed 一等出边）/ server 3 态；zombie 会话 teardown（控制读循环致命退出统一收敛）。
- **配置单层化**：v1/ntls ServerConfig 直接承载 ServerPolicy + SinkOpts/SinkHandler；facade WithSink 替代 WithEventSink。
- **删除**：AUTH 族消息、SecureEnvelope 旧结构、ReplayCache、AckTracker ring、ThrottleState/Window/Inflight、challengeNonce 往返、session ticket 体系（0-RTT 移为演进项）、JSON codec、错误码字符串双轨+legacy 别名、接口探测矩阵。
- 测试全量重建：conformance 81 项（握手/密钥日程/envelope/credit 账本/集合窗口/sink 契约/dedup/close + capability 四项）+ integration 5 项（v1 QUIC + ntls TLCP 全链路 + 并发 + 连接背压）+ 基准 45 项（密钥日程/envelope/帧/流控/密码原语 + E2E 吞吐/延迟 + perf JSON 导出）。
- **capability 演进项落地**：`dual_integrity`（envelope 外层 HMAC，协商启用，独立 Expand 密钥段，fail-closed 对称校验）；`zstd_dict`（服务端静态字典经 DICT 帧(0x22)下发，>512B 批自动 ZSTD_DICT 压缩，字典不入 transcript——经 TLS 通道保护、篡改最坏解压失败）；客户端 `SendDatagram`（QUIC DATAGRAM 不可靠通道，豁免 credit；传输/能力不满足降级可靠路径）；压缩启发（≥4096B ZSTD、字典激活后 512B-4096B ZSTD_DICT）；QUIC 服务端 datagram 接收接入 data 通道。
- **实现差距修复**（spec/bench 审查发现）：zstd encoder 池化（4KB seal 374µs/13.5MB allocs → 微秒级）；v1.Dial UDP socket 泄漏（Conn 持有引用、全部关闭路径统一走 Close）；CREDIT 100ms 定时攒批（消除低吞吐连接的额度拖死与"服务端阈值>客户端钳制"饿死组合）；HELLO.profile 与服务端策略一致性校验；CLOSE 进入 Draining 态；CREDIT 单维零 → ABORT；服务端 session TTL 强检。
- 文档：README 按新 API 重写；mbta-core-spec.md / mbta-tcp-binding.md 按 r3 全量重写（旧 diagrams/sink-async-design 移除）；v2-design.md 为设计与三轮审查记录。

### Refactored（第六轮清理：回归验证 + 兼容代码移除 + 调用链审查）

**兼容/向后代码移除**：
- **Metrics 接口清理**：删除 9 个旧概念 counter/gauge（BatchesAcked/Nacked、Throttled、PartialAck、ReplayCacheHits/Evictions、WindowCurrent×3、ThrottleSeconds——协议中已不存在的 THROTTLE/ACK/NACK/WINDOW/ReplayCache 概念的遗留面）；新增 r3 语义 `CreditsOutstanding()`/`SinkQueueDepth()` gauge。
- **错误码别名重构**：旧 `ErrCode*` 别名收敛为显式 `Local*` 家族（`LocalConfig`/`LocalSession`/`LocalBatch` 等——不上 wire 的本地错误分类面，与 wire 注册表的语义混淆消除）；删除零引用别名（ErrCodeValidation/ErrCodeEnvelope/ErrCodeThrottle）。

**不合理分支及调用链修复**（agent 审查产出 12 项，全部修复）：
- **死分支**：客户端 profile 交叉校验恒假（hello 由本侧构造）删除；Settle alreadyTerm 死防御（stale 检查已覆盖）删除；OnCredit 恒假 clampB 检查删除；binding.Handshake 恒失败 RollbackIdle 删除（及 SmTransition/RollbackIdle 死方法）。
- **重复处理**：processBatch 的 Envelope 双重解码消除（decodeAndValidate 接受已解码引用）；makeEvent 的 Batch 重复解码消除（直接用形参 payload）；密钥日程 pskCK 三步链两处复制粘贴收敛为共用 helper；runSinkTask 手抄的 panic 契约收敛到 callHandler 单点。
- **死存储/死常量**：CoreHandler.profile 零引用字段删除；creditFlushFraction 死常量删除（阈值攒批机制已在根治版移除，注释同步修正）。
- **注释与代码矛盾**：TCP SendDatagram 虚构回退路径、ntls 客户端降级机制描述错误、reaper 阈值注释、PubBytes 首返回值恒 nil——全部修正或简化签名。
- close 状态收敛去重（teardownPhase 单层）；controlLoop 双 default 分支合并。

### Refactored（结构根治收尾：第五轮审查剩余项）

- **teardown 单一收敛序列**：`teardownPhase` 抽取为 close 与 fatalTeardown 的公共尾部（取消 lifecycle/状态收敛/清账本/唤醒 drain）——未来新增清理步骤只改一处，两条路径的步骤漂移在结构上收敛。
- **SetTransport 竞态守卫**：lifecycle 启动后注入 → panic（fail-fast 编程错误）；重复注入 → 告警覆盖。"Ready 后替换 transport 的数据竞争"与"未注入即用的 nil panic"（已有 nil 守卫）双封闭。
- **DualMAC 派生单点**：`core.DeriveSessionKeysWithCaps`（基础日程 + dual_integrity 协商追加）双端共用——两侧逐行复制的漂移面（能力名/info 串笔误 → mac 判定不对称全连拒）消除。
- **DICT 客户端防护**：未协商 zstd_dict 收到 DICT → 拒绝（越权注入）；字典尺寸 > MaxZstdDictBytes → 拒绝（CPU/注册表翻搅）。
- **Seal 对称拒绝 KeyEpoch≠0**：不再可构造"本地成功、对端必拒"的静默故障帧。
- **EpochAllocator facade 共享注入**：v1/ntls ServerConfig 新增 Epochs 字段，facade 双监听共享一份——同 agent 跨 binding 纪元单调（此前各自独立计数）。
- 测试钩子（OverrideExpiry/ResetZstdDicts/Config）doc 明示"测试专用、禁用于生产"（conformance 为外部包无法用 export_test 模式，保留为显式契约而非隐式污染）。

### Refactored（结构根治批次：设计可规避缺陷第五轮审查产出）

以「令牌化 settle + 单一真相」根治六项活缺陷与其背后的 bug 温床：

- **SettleGrant 令牌**（core/credit.go）：准入返回一次性 grant，`Accept/Settle/Release` 内部原子完成 RESULT 发送 + 终态环记录 + 额度回收——双发与漏偿在构造上不可表达（历史 RESULT 双发 ×3 的结构性根治）。stale grant（被 ForceSettle 抢先）完全 no-op（终态不可变）。
- **CreditManager 单一真相**（core/credit.go）：AdmissionWindow + handler 六计数器 + SetCap 三处真相同步合并为单锁单结构；删除公共 SetCap。占位式准入根治「Admit→Register 解密间隙并发同 seq 双接受」；`accepted` 集合查环根治「乱序前缀下幂等重发失效」（low 推进不再是正确性前提）；ForceSettle 与 grant.Settle 共享防双回收守卫。
- **六项活缺陷修复**：① sem-full 直拒 grant 化（credit 守恒闭环，不再单向泄漏）；② accepted_only 统一 enqueue-then-settle（先 ACK 后入队丢数据的顺序不可再发生）；③ 乱序终态重放幂等回执；④ facade ntls profile 推导单点化 `NTLSProfileFor`（服务端/客户端共用，TLSMode=true 组合经 facade 可互通）；⑤ 客户端写失败 `CreditLedger.Rollback` 补偿；⑥ 移除 cap 数值判定（超发防线=额度检查；seq 空间含 DGRAM 的混发误杀根治）。
- **双管线收敛**：`decodeAndValidate` 共享校验管线（BATCH/DGRAM 单一清单——DGRAM 此前缺 TTL/events 上限且尺寸检查次序在解码后）。
- **客户端收敛**：fatalTeardown 置 closed（与 close 共享终态语义）；nil-tr 守卫（未注入即 Handshake 给明确错误）；AckTimeout 实驱动（AckReaperLoop——此前 MarkFailed/ReapExpired 为死配置，超时 slot 经回调以 "timeout" 通知）。
- **资源惰性化**：sink worker 懒启动（首个成功入队触发，握手前零 goroutine）；CREDIT flush 懒 arm（首个 Settle 后一次性 100ms 定时器，替代常驻 ticker——万连接省 10k/s 唤醒）；DGRAM 限速配置化（Policy.DatagramRateBytes）。
- 测试：CreditManager 单元 8 项（守恒/双 Settle 防护/占位并发/直拒守恒等）+ 既有 conformance 全量适配（超发断言改为额度语义）。

### Fixed（遗留问题批次：规格/基准双向审查产出）

- **max_frame_bytes 接入接收路径**：服务端 transport 构造参数携带 policy 值（v1 data/control 读、ntls readLoop）；客户端经 `FrameLimitSetter` 在 HELLO_ACK 后注入协商值（clamp 16MB 硬顶）；`core.ReadFrameCtxLimit` 新增；`ServerPolicy.Validate` 加帧上限硬顶校验。
- **客户端 TTL 实检**：HELLO_ACK `expiry_unix` 存入 `CoreClient.expiry`，`SendBatch` 前置拒绝过期会话（与服务端 TTL abort 对称；此前为恒返回 0 的 stub）。
- **ntls TLSMode→profile 推导**：facade `initNTLSServer` 按传输模式推导（mbta-tls/1→intl、mbta-ntls/1→gm），消除"TLS1.3 通道上跑 SM2/SM4 应用层"的静默错配。
- **zstd 字典从进程单例改为键控注册表**：`core.ZstdDictCodec`（池化 encoder + 共享 decoder），`RegisterZstdDict` 按 (dict_id, 内容哈希) 幂等注册（LRU 上界 8 防字典洪水）；`SealParams.Dict`/`OpenEnvelope` 显式传 codec——共享的是池（性能），隔离的是选择权（正确性）；同进程多服务端/多客户端配不同字典不再互相覆盖。
- **CREDIT 100ms 定时攒批**：服务端 reaper 增加 flush ticker，任何 >0 回收量按时发放——消除低吞吐连接的额度拖死与"服务端阈值>客户端钳制"饿死组合。
- **多副本 at-least-once 边界的应用层闭环**：新增 `core.CorrelationDeduper`（进程级 LRU + 可选 TTL）；spec §11.6"部署模型与投递语义"成文（单领导处理推荐 / active-active 边界 / 重启语义）。
- zstd encoder 池化（4KB seal 374µs/13.5MB allocs → 微秒级）；v1.Dial UDP socket 泄漏修复（Conn 持有引用、全部关闭路径统一 `Conn.Close`）。
- 回归测试 +8：帧自定义上限/TTL 拒绝/定时攒批/TLSMode 推导（gm/intl）/v1 恒 intl/CorrelationDeduper 4 项。

### Fixed（第二轮深查修复批次）

- **High**：未认证连接可无限钉死并发连接槽位（DoS）——QUIC 等待首个 control
  stream 无 deadline（改 30s 超时，`firstStreamTimeout`）；TCP readLoop 无读超时
  （认证前 30s、认证后空闲超时，经新增 `protocol.AuthMarker` 钩子在 AUTH_OK 后切换）。
- **High**：`Server.Close()`（不取消 ctx）后 AcceptLoop 对 `net.ErrClosed` 无限自旋、
  Run 永不返回——现在识别 listener 关闭并退出。
- **High**：Close-before-Connect 耗尽 closeOnce 后，Connect 放行、最终 Close 变
  no-op（连接与 4 个 lifecycle goroutine 泄漏）——CoreClient 新增 closed 权威标志，
  状态机补齐任意早期态 → Closed 出边，StartLifecycle 拒绝在已关闭实例上启动。
- **High**：控制读循环致命退出（读错误/服务端 CLOSE/fatal ERROR）后会话不收敛
  （僵尸 READY：SendBatch 持续"成功"、ACK 永不到来、Close 白等满 DrainTimeout）——
  三条路径统一 teardown（取消 lifecycle + 退回 Disconnected + 清空 tracker + 拆连接）。
- **Medium**：`close()` 清零密钥与锁外 `buildAndSend` 读密钥的数据竞争（竞态窗口内
  envelope 用半零密钥算 HMAC，静默丢 batch）——密钥快照移入 sendMu 临界区。
- **Medium**：解压预分配 `Grow(len(src)*4)` 在不可压缩 16MB 帧上放大 4 倍内存
  （单帧 64MB 立即分配）——封顶 `MaxDecompressedSize+1`。
- **Medium**：`ReadFrameCtx` 的 ctx 取消不能唤醒已阻塞的读（最长挂 5 分钟；QUIC
  服务端控制读同模式）——新增 ctx.Done watcher 立即唤醒。
- **Medium**：TLCP 握手不可中途取消（pollux-go 仅入口检查一次 ctx），stalled 对端
  使 Dial 永久阻塞——对 rawConn 设整体握手 deadline。
- **Medium**：WINDOW/HELLO_ACK 携带零/负值窗口使客户端发送永久静默冻结——
  校验并忽略非法帧（保留当前限额）。
- **Medium**：帧写部分失败（短写/deadline 中断）后连接不拆除、流永久去同步——
  `core.Write` 检测短写，服务端 transport 写失败即拆连接。
- **Medium**（第一轮修复自查）：`SinkQueueMaxBytes<0` 时字节记账只扣不记（负漂移）
  ——归一化为 MaxInt64 使记账无条件配平；`enqueueSinkTask` 的 sinkDone 检查 TOCTOU
  收口（发送后二次检查，跳过 accepted 谎报）；`close_timeout_ms` 增加服务端下限 1s。
- **Low**：AckTracker 拒绝 `seq==0`（伪造 ACK 命中空槽使计数下溢、drain 白等）；
  AUTH_OK 密钥长度强校验（省略 AEAD 密钥不再静默降级 HMAC-only）；Replay 回退不
  降级已 Durable 条目（消除重复 durable ACK 窗口）；客户端会话过期前置检查；
  redirect handler ctx 挂接 lifecycleCtx；v1 Dial 本地 UDP socket 绑定 wildcard
  （修复 IPv6 对端 EINVAL）；QUIC transport Close 使用非零 error code；ntls 客户端
  写锁改 ctx 可取消信号量；SendFrame 的 ChannelID 路由文档校正；示例代码改用
  CA 校验（不再 InsecureSkipVerify）。

### Fixed（第一轮代码审查修复批次）

- **Critical**：`RawEventSink` + `AsyncDurableSink` 组合下原始 batch 字节被静默丢弃、
  且服务端仍发 durable ACK（数据丢失 + 谎报持久化）。修复：新增可选接口
  `core.RawAsyncDurableSink`（`OnRawBatchAsync`）承载 raw 异步快速路径；未实现该
  接口的组合强制完整解码后走 `OnSignalBatchAsync`（接口契约）。
- **High**：sink worker 排空无超时——卡死的 sink（不感知 ctx）使 `Handle` 永不返回，
  连接槽位（connSem）与 goroutine 永久泄漏。修复：排空改为有界等待（复用 drain
  超时），超时后取消 `sinkCtx` 并放弃等待。
- **High**：客户端窗口满时的重试风暴白白消耗 seq 产生空洞，推大 AckTracker 跨度，
  即使容量已空出发送仍被拒（连接停摆至全部排空）。修复：`SeqGenerator` 新增
  `Peek()`，`reserveInflight` 改为「Peek 构造 → CanSend → 通过后 Next 消耗」。
- **High**：CI 从未执行 `test/` 下 815 行集成/性能测试（缺 `-tags integration`）。
  新增 `integration` job：生成证书后运行 `./test/ ./v1/ ./ntls/`。
- **High**：proto 漂移校验使用 `protoc-gen-go@latest`，插件版本写进生成文件头导致
  校验随上游发版必然失败。已 pin `@v1.36.11`。
- **High**：`test/data/ntls/gen_certs.go` 输出目录基于 cwd 的 fallback 会把 PEM 写到
  仓库根。改为基于 `runtime.Caller` 的源码路径定位。
- **Medium**：`durableNotifier.seen`（sync.Map）只增不删，长连接内存无界增长。改用
  ReplayCache 状态去重（新增 `ReplayCache.MarkDurable`），顺带修复异步 durable 路径
  不回写 `ReplayDurable` 导致重试 batch 收 ACCEPTED、useAckLevel 客户端 slot 钉满
  窗口的问题。
- **Medium**：data drain 超时后 `close(sinkQueue)` 与存活 `processBatch` 的入队构成
  send-on-closed-channel panic。`sinkQueue` 永不 close，改用 `sinkDone` 通知 worker
  排空退出。
- **Medium**：sink 异步队列只按条数（256）限界，单连接内存可放大至 ~2GB。新增字节
  维度上限（默认 32MB，`SinkQueueMaxBytes` 可配）。
- **Medium**：`durable_ack` 能力未按 sink 类型门控——纯 EventSink 配置该能力时
  useAckLevel 客户端 slot 挂满 5 分钟超时。握手时按 sink 是否能产生 durable 确认
  过滤 SelectedCapabilities。
- **Medium**：DATAGRAM 路径未纳入 DoS 防护（同步调 sink 阻塞整个 dataLoop）。改走
  batchSem 并发上限 + 前置压力检查。
- **Medium**：`NewChunkID` 每次调用新建 `ulid.Monotonic` 熵源，丢失毫秒内单调性且
  热路径多 4KB 分配。恢复进程级共享 `LockedMonotonicReader`。
- **Medium**：Close 后 Connect 报误导性 "already connected"；dial 失败后状态机滞留
  `Connecting` 导致同实例重试必然失败。按状态区分报错 + dial 失败回退
  `Disconnected`。
- **Medium**：v1 客户端 control 通道写无超时（与 ntls 不对称），对端停止读控制流时
  `Close()` 卡死。补 deadline 绑定。
- **Low**：错误码新增旧 `ERR_*` wire 码别名（`MatchWireCode` 接收方向兼容 v0.x 对端）
  与 `NumOf` 大类判断助手；协商失败改用专用码 `unsupported_capability`；
  HELLO 元数据字段（hostname/instance_id/agent_version/os）补长度与控制字符校验；
  typed-nil `*core.MBTAMetrics` 防护恢复；`Server.Run` 收尾 watcher 的 listener
  关闭竞态修复；ntls TLCP 双证书/TLS1.3 单证书部分填充 fail-fast；
  facade 透传 `DrainTimeout`（`WithDrainTimeout`）；`applyPressure` 的 WINDOW 帧
  改为锁内按序发送。

### Breaking Changes（相对 v0.x）

- **错误码体系重写**：wire 字符串码从 `ERR_*` 大写风格改为 snake_case（如
  `ERR_HMAC_FAILED` → `hmac_mismatch`），数字大类码不变。`NewError/WrapError` 签名
  改为接收 `ErrorCode`；删除 `Error.Is`、全部 sentinel（`ErrSession` 等）、
  `GetErrorCode/GetErrorCodeString/WrapWireCode/NumSpool`。程序化匹配用
  `core.CodeOf(err)` / `core.NumOf(err)`，接收旧对端 wire 码经 `MatchWireCode`
  别名解析（发送方向始终用新码）。
- **v1.StreamPicker 接口简化**：`Pick(tag, source)` → `Pick()`；删除
  `AddStream/RemoveStream/Len`、`NewHashStreamPicker`、`ErrNoStreams`
  （`v1/errors.go` 整文件删除）。多流分流已移除，单 data stream 模式。
- **v1.ClientConfig** 删除 `PickStrategy`、`StreamCount`。
- **删除 `v1.DialEarly`**（0-RTT 客户端入口）与 `v1.Conn.TLSState` 字段。
- **`SetRedirectHandler` 回调签名**：`func(payload []byte)` →
  `func(ctx context.Context, payload []byte)`。ctx 带 30 秒超时，handler 必须
  监听 `ctx.Done()`（否则超时后 goroutine 泄漏）。
- **`Metrics` 字段类型**：`*core.MBTAMetrics` → `core.Metrics` 接口
  （`v1.ServerConfig`、`ntls.ServerConfig`、facade `ServerConfig`/`ClientConfig`
  及对应 `WithMetrics`/`WithClientMetrics` option）。
- **`Version` 类型化**：`string` → `ProtocolVersion`。无类型字符串常量仍可编译
  （隐式转换），传 `string` 变量处需改用 `ParseVersion`。
- **删除 `mbta.Version2` 常量**与 v2 分派逻辑（v2 仍在计划中，发布时重新引入）。
- **option 更名**：`WithClientNTLS` → `WithNTLSCredentials`。
- **`ntls.FrameVersion` 常量删除**。
