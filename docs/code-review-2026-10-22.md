# mbta-go 全面代码审查报告（代码风格 / 组织 / 命名 / 安全 / 对抗性）

- 审查日期：2026-10-22
- 审查基线：dev @ c88d7cc
- 范围：全部 54 个非测试文件（13,359 行）+ 7,579 行测试代码，逐模块逐文件审读
- 方法：core 安全关键模块人工逐行审读 + 4 路并行深审（internal/protocol、ntls/v1、根包/binding、core 其余+proto），所有 P0/P1 与关键 P2 均经第二人源码级复核（含依赖库 pollux-go v0.5.2、quic-go v0.64.0、prometheus/client_golang v1.25.0 实际源码查证与行为实测）

## 〇、工具交叉验证结果（全绿）

| 工具 | 结果 |
|---|---|
| `go vet ./...` | 0 问题 |
| `golangci-lint run ./...` | 0 issues |
| `staticcheck ./...` | 干净 |
| `govulncheck ./...` | 无可达漏洞 |
| `go test ./...` | 全部通过 |
| `go test -race ./...` | 无数据竞争 |
| `buf generate` 重生成比对 | 与仓库零漂移 |
| `buf lint` / `buf breaking` | 配置正确 |

**总体评价：7.5/10。** 亮点真实：SettleGrant 令牌化从构造上消除 RESULT 双发/额度漏偿；帧读取"长度先验 + canonical varint + 短读 drain"；解压全路径 8MB 硬顶；nonce 全宽 seq 使回绕在构造上不可表达；注释普遍解释"为什么"并保留审查裁决记录。**问题模式高度集中**：① 防线已建成但没接线（SignalBatch 校验层悬空）；② "TCP/服务端做对了，QUIC/客户端没跟上"的对称性缺口；③ 若干"承诺与实现不符"的契约漂移（注释声称的安全性质实际不存在）。

发现合计：**P0 ×1、P1 ×4、P2 ×26、P3 ×约50**。

---

## 一、P0（必须立即修复）

### P0-1｜ntls TLCP 服务端 mTLS 静默失效
- **位置**：`ntls/transport.go:104-122`（`buildServerTLCP`）
- **机制**（已查证 pollux-go v0.5.2 源码）：`tlcp.NewConfig()` 默认 `ClientAuth: NoClientCert`；`LoadRootCAs()` 只设置服务端证书链校验用的 `SignRootCAs/EncRootCAs`，**不设置 `ClientCACertificates`、不设置 `ClientAuth`**。因此配置了 `CAFile` 的 TLCP 服务端从不请求客户端证书——mTLS 完全不生效，且无任何告警。
- **对照证据**：同一配置字段在 TLS 1.3 分支 `buildServerTLS13`（`ntls/transport.go:171-176`）中正确设置了 `ClientCAs + RequireAndVerifyClientCert`——两条路径行为相反，`ServerConfig.CAFile` 注释宣称"两种模式共用"的语义在 TLCP 路径落空。
- **影响**：国密部署的"双向 TLS"承诺静默失效，代理身份不可绑定（协议层 token 认证仍在，非认证全绕过）。
- **修复**：设置 `tc.ClientCACertificates` + `tc.ClientAuth = tlcp.RequireAndVerifyClientCert`（注意 pollux 的 iota 顺序与 stdlib 不同）；补集成测试：配 CAFile + 无证书客户端必须握手失败。

## 二、P1（重要，优先修）

### P1-1｜服务端去重 `accepted` 集合无界增长（认证后内存 DoS）
- **位置**：`core/credit.go:427-442`（Settle 写入）、`core/credit.go:536-541`（`advanceLowLocked` 是唯一删除点）
- **机制**：`accepted` 条目仅在连续前缀水位 `low` 推进时删除。持有有效 token 的攻击者**永不发送 seq=1**，持续发送 seq=2,3,4,…，每个都正常 Consume→Settle（额度经 CREDIT 返还，攻击可无限持续），`low` 恒为 1，map 无上限增长。terminal 环有 256 上限，`accepted` 没有。
- **修复**：给 `accepted` 设上限（超限沿最小 seq 跳过空洞推进 low——等价于终态环淘汰，重放回落 BelowUnknown released）；补敌意序列单测。

### P1-2｜`SignalBatch.Validate()` 在服务端接收路径零调用——整层校验悬空
- **位置**：`core/codec_proto.go:32`（注释锚点指向不存在的 `handler_batch.go:258`）；`core/signal.go:100-118`；实际管线 `internal/protocol/handler_batch.go:124-158`
- **机制**：全仓 grep 确认 `sb.Validate()` 仅测试调用。服务端只校验 Envelope 层（解密/尺寸/seq 绑定/events_count **自报值**），从不解码 SignalBatch、从不校验 signal_type 闭合枚举、属性条数 ≤128、4096 字段上限、控制字符、trace hex 格式。不可信数据直达 sink。附带实锤：`makeEvent`（`handler_batch.go:359-363`）解码失败静默得 `Decoded=nil` 仍回 ACK accepted——**数据丢失伪装成投递成功**。
- **修复**：`decodeAndValidate` 中解码并调 `sb.Validate()`，失败 `CodeBatchInvalid`；makeEvent 解码错误上抛；补 conformance 测试。

### P1-3｜客户端写失败不拆连接 → 流去同步、后续帧持续损坏
- **位置**：`ntls/client.go:91`、`v1/client.go:102` 与 `v1/client.go:166-182`
- **机制**：服务端两侧写失败均 `conn.Close()` 并注释了原因（半帧使后续帧全部错位，`ntls/tcp_transport.go:155-158`、`v1/quic_transport.go:205-207`），客户端三处写路径都没有。ntls 单 TCP 连接承载 control+data，一次写超时留半帧后连接仍"可用"，对端解析乱码帧，期间 batch 静默丢失。
- **修复**：三处补 `_ = t.conn.Close()`，对齐服务端语义。

### P1-4｜QUIC 服务端认证前资源钉住窗口失守
- **位置**：`v1/quic_transport.go:154-158`（控制流 5min/帧）、`v1/quic_transport.go:124-140`（data 流**完全无 deadline**）、`v1/quic_transport.go:167`（服务端主动 keepalive 使连接永不闲置）；根因 `core/session.go:145`（`DefaultReadTimeout=5min`）
- **机制**：TCP binding 有 `tcpPreAuthReadTimeout=30s` + `AuthMarker`；QUIC binding 两者皆无。攻击者建连后只回 ACK 不发帧，每连接钉住 1 个 connSem 槽位（默认 10000）达 5 分钟，重连循环可占满；认证前还可开 data 流（每连接 256 条），慢滴使读取 goroutine 永久阻塞。同文件 38-40 行注释声称"认证前钉死窗口已收敛"仅对首条流成立，与实际不符。
- **修复**：quicTransport 实现 `AuthMarker`，认证前 per-frame 30s deadline；data 流读取同样设界。

---

## 三、P2（应修，按模块）

### core/
| 位置 | 问题 |
|---|---|
| `core/keyschedule.go:45-50` | `ProfileHash` 对未知 profile **静默回退 SHA-256**（`ProfileName` 回退空串）——上游漏校验时以错误哈希继续运算而非 fail-fast |
| `core/auth.go:67-71` | `ResolveToken` 直接返回内部 slice，调用方可改写 backing array 污染跨连接共享的 validator（缺防御性拷贝） |
| `core/credit.go:344-363` | `SettleGrant.Consume` 不拒绝负 `frameBytes`：负值走 `outstandingY -= frameBytes` **反向增加额度**（守恒核心的防御缺口） |
| `core/envelope.go:209-215` | 全局 zstd 字典注册表跨连接共享，恶意对端反复注册新字典可 LRU 淘汰**其他活跃会话**在用字典（cap=8 缓解但干扰面在） |
| `core/codec*.go` + `core/signal.go` | validate-after-decode：proto map / CBOR（默认上限 131072 对、32 层嵌套）解码完成后才校验，8MB 恶意载荷可放大数十倍堆分配；`events_count` 是客户端自报字段，与实际解码条数无比对 |
| `core/metrics.go:244-251` | `guardedCounter` 只拦负值，**不拦 NaN/+Inf**（实测通过且永久毒化计数器） |
| `core/policy.go:76-80` | `ServerPolicy.IsZero` **漏掉 `DatagramRateBytes`**——单独配 DGRAM 限速会被判全零回退默认（=不限速），安全配置静默失效 |
| `core/message.go:70-95` | `ValidateHello` 对 capabilities 零校验（meta 逐键校验了）——认证前超长/控制字符 cap 进入 Negotiate 与日志 |
| `core/codec_proto.go:16-25` | 注释声称"确定性编码"，实测 `proto.Marshal` 默认非确定（含 map 时 50 次中 45 次字节不同）；当前 dualMAC 不依赖故非漏洞，但属虚假安全声明 |

### internal/protocol/
| 位置 | 问题 |
|---|---|
| `client_control.go:96-110` + `handler_batch.go:110` + `core/credit.go` | **CREDIT 单零维度误杀链路**：占位未 Consume 被 reaper `ForceSettle(slot.Bytes=0)` → 下发 `CREDIT{1,0}` → 客户端守卫 `GetBytes()==0` 命中 → fatalTeardown 拆连接。注释声称"双零忽略"但 `\|\|` 条件连双零也拆（与 `CreditLedger.OnCredit` 实现矛盾） |
| `client_control.go:371-375` | `seenCommands` 满时整体清空——**刚插入的 CommandId 立即被遗忘**，重发窗口内重复执行 |
| `client_control.go:81-89,309-312` | 超时回调后迟到的真实 RESULT 仍派发（`Terminal` 返回值被丢弃）——同一 seq 用户回调收两次 |
| `internal/protocol/transport.go:74-78` | `ClientTransport.WriteFrame` 被 ≥4 个 goroutine 并发调用，接口文档零声明 |
| `command_registry.go:118-126` | pending 以 CommandId 为全局 key，跨 agent 同 ID 互相覆盖、ACK 串线；应为 `(agentID, commandId)` |
| `handler.go:362-368` | 认证失败日志直接打印攻击者可控的 capabilities（无 sanitize/截断）——日志注入 + 放大 |
| `handler.go:207` + `handler_batch.go:95-117` | Handle 收尾 `releaseStuck` 用可能已取消的 ctx → released RESULT 全部静默丢弃，同时 WARN 日志谎报"已释放 N 条" |
| `handler.go:176-184` | `SessionDisconnected` 对未认证连接也触发（空 agentID 事件污染消费方连接表） |
| `command_registry.go:140-162` | `AckError` 是死代码，文档承诺的 `errors.As` 契约从未成立 |
| `handler_batch.go:277-300` | DGRAM 默认不限速（`DatagramRateBytes=0`=放行）且豁免 credit，TCP binding 上 16MB DGRAM × 64 并发槽 = 解压/CPU 放大面 |

### ntls / v1（传输层）
| 位置 | 问题 |
|---|---|
| `v1/quic_transport.go:172` | `Allow0RTT: true` 且注释表述不实（已核 quic-go 源码：0-RTT 早数据在握手完成前投递且天然可重放）；应默认关 |
| `v1/quic_transport.go:64`、`ntls/tcp_transport.go:52-53` | 聚合通道无字节预算：64 帧 × 16MB 上限 ≈ 1GB/连接理论驻留 |
| `internal/protocol/client.go:112,433-441` + `v1/client.go:268-269` + `ntls/client.go:105` | `SetTransport`/`close`/`tr.conn` 无同步——Connect 与 Close 并发存在数据竞态 |
| `ntls/client.go:69-77`、`tcp_transport.go:138-143` | close 后 `WriteFrame` 持无取消 ctx 永久挂起（writeSem 被 drain 且不归还） |
| `ntls/transport.go:269` | **待验证**：`tlcp.Listen` 若在 Accept 内同步握手且无 deadline，静默客户端可阻塞整个 accept 循环（全服不可用） |
| `v1/quic_transport.go:209-215` | `Conn.Close` 用 error code 0（="no error"），与同文件 260 行及 `v1/server.go:110` 自定规约（用 1）矛盾 |

### 根包 / internal/binding
| 位置 | 问题 |
|---|---|
| `server.go:466-471` vs `server.go:279-302` | **Commands 命令通道对 NTLS 完全失效**（`initNTLSServer` 漏拷 `Commands`，且 ntls.ServerConfig 无此字段）——根因是两处 14 行手抄并行拷贝 |
| `server.go:84,97-104` | `EnableV1` 默认 true + 必填地址延迟到 Start 才校验：只想用 NTLS 的用户得到指向 v1 的错误（违反同文件自述 fail-fast 原则） |
| `internal/binding/server_generic.go:168-176` | `starting` 态调 `Close` **返回 nil（成功）**但服务器随后照常监听 |
| `internal/binding/server_generic.go:94-101` | Run 退出兜底 `Store(stopped)` 会踩掉并发的第二个 Run 的 starting 态 |
| `client.go:249-268` | Close 后 `SetResultHandler`/`SetRedirectHandler` 静默丢弃 |
| `client.go:216-231` | `Client.Close` 的 token 清理是**安全剧场**：Go string 不可变、内层副本无清理——暗示了并未兑现的安全承诺 |
| `client.go:167-184` | `Connect` 持写锁跨越整个网络握手（可达秒级），期间 Close/SendBatch 全阻塞 |
| `client.go:107` | `ClientConfig` 浅拷贝：Meta map / Capabilities slice 与调用方共享底层数据 |

---

## 七、第二轮修复（同日追加）

**P2-9 验证结论（证伪，无需修复）**：pollux-go v0.5.2 `tlcp.Listener.accept()` 显式镜像 stdlib `crypto/tls.Listener`——**惰性握手**（首次 Read/Write 才握手，源码注释明确说明 Accept 内同步握手会让静默客户端阻塞整个 accept 循环）；`Conn.SetReadDeadline` 穿透到 rawConn。故 TCP binding 的 pre-auth 30s read deadline 已覆盖惰性握手，全服阻塞风险不存在。

本轮已修复（含回归测试）：

| 修复 | 位置 | 测试 |
|---|---|---|
| CommandRegistry pending 改 (agentID, commandId) 复合键——跨 agent 同 ID 命令不再串线；ACK 由 handler 按自身 agentID resolve | `internal/protocol/command_registry.go`、`handler.go` | `TestRegistry_SendCommand_PerAgentPendingKeys` |
| `AckError` 从死代码变为真实返回：REJECTED/FAILED 返回 `*AckError`，`errors.Is` 命中哨兵 + `errors.As` 取完整应答（文档承诺首次成立） | `command_registry.go` | `TestRegistry_SendCommand_FailedAckCarriesAckError` |
| `CoreClient.tr` 改 `atomic.Pointer[ClientTransport]`——SetTransport 与并发 Close 的数据竞态消除 | `internal/protocol/client.go`、`client_control.go` | 既有全量测试 + race |
| ntls 客户端传输与 TCP 服务端：close 后携带无取消 ctx 的写快速失败（done channel 三路 select），不再永久挂起 | `ntls/client.go`、`ntls/tcp_transport.go` | 既有全量测试 |
| binding 状态机 redesign：Run 代次号（退出兜底仅对本代生效，F4）+ `sync.Cond` starting-wait（starting 态 Close 等待收敛后再关闭，F3） | `internal/binding/server_generic.go` | `TestServer_CloseDuringStartingWaitsThenCloses`、`TestServer_StaleRunExitDoesNotStompNextGeneration`（binding 包首个测试文件） |
| CBOR 解码上限收紧：MaxMapPairs 256 / MaxArrayElements 10000 / MaxNestedLevels 16（此前默认 131072，8MB 恶意载荷放大数十倍堆分配后才被拒） | `core/codec_cbor.go` | `TestCborUnmarshal_RejectsOversizedMap/Array`、`AllowsMaxBatchEvents`（恰好 10000 不误伤） |
| 解压超限（decompress_limit）与解密失败分开归因，DecryptFailures 指标不再误导排障 | `internal/protocol/handler_batch.go` | 既有全量测试 |
| envelope zstd 池 Get 断言与 compressZstdDict 统一（防御性 ok-check，不再裸断言 panic） | `core/envelope.go` | 既有全量测试 |
| facade：Close 后 Set handler 告警；NewClient 防御性拷贝 Meta/Capabilities；Dial 配置错误（ErrCodeConfig）原样透传不再包装为 transport 错误 | `client.go`（根包） | 既有全量测试 |
| `ClientTransport.WriteFrame` 接口显式声明多 goroutine 并发契约（帧交错防护 MUST 由实现内部串行化） | `internal/protocol/transport.go` | 文档面 |

**仍未修复（留待后续版本）**：见第八节。

---

## 八、第三轮修复与遗留方案建议（同日追加）

### 已执行

| 修复 | 位置 | 说明 |
|---|---|---|
| TLS 客户端配置构造上提 `tlshelper.BuildClientTLSConfig` | `internal/tlshelper/tls.go`、`v1/transport.go`、`ntls/transport.go` | v1/ntls 两处逐行重复 ~30 行收敛为单点（InsecureSkipVerify 告警同步单点化，gosec 指令随迁） |
| facade wrapper 泛型化 | `client.go` | `v1ClientWrapper`/`ntlsClientWrapper` 逐字等价 8 方法对 → `versionWrapper[C versionedCore[C]]`（40 行重复税清零） |
| `Client.Close` token 清理诚实化 | `client.go` | 删除三行表面 scrub（Go string 不可变、清零副本不触及堆上其他引用），文档明示"唯一防线是 token 熵（spec §163）"——消除未兑现的安全承诺 |
| `Connect` 持锁延迟文档化 | `client.go` | 明示持锁跨握手可达 ctx 超时上限、需快速中断取消 ctx（锁语义保持，串行化是有意设计） |
| initV1/initNTLS 并行拷贝交叉引用注释 | `server.go`、`client.go` | 防再次漏抄共享字段（Commands 事故的制度性防呆） |
| `AcceptLoop` 去除恒 nil 的 error 返回值 | `internal/binding/server.go` | 签名与实现对齐（review F15） |
| `handleConn` recover 记录完整堆栈 + `safeClose` 防 recover 分支二次 panic 击穿进程 | `internal/binding/server.go` | review F16 |
| `Addr` 改读锁 | `internal/binding/server_generic.go` | mu → RWMutex（Cond 兼容 Locker，语义不变） |
| `internal/binding/errors.go` 死文件删除，包文档迁 `doc.go` | `internal/binding/` | review F18 |
| facade Server 优雅退出（ctx 取消正常返回）后复位 `started`，允许直接重启 | `server.go` | review F6 |
| metrics 孤儿注释删除、NoOp `ResultsByLevel` 死方法删除、`core.New` → `NewMetrics`（additive + Deprecated 标记） | `core/metrics.go` | review P3-3/4/5 |
| `signal.go` validateAttrsMap 虚假声明修正（原注释声称的"codec 层协议约束"无对应实现，改为如实描述边界） | `core/signal.go` | review P1-1 附带 |
| `errors.go CodeOf` 注释与导出面一致 | `core/errors.go` | review P3-7 |
| `testutil/rand.go` 头注释诚实化（randHexID 双熵源 + 静默降级如实声明） | `internal/testutil/rand.go` | review F19 |
| `examples/basic_client` 注释与代码对齐、证书路径修正为可运行 | `examples/basic_client/main.go` | review F21 |
| Makefile `check` 目标去除写副作用（`fmt` → `fmt-check` 只列出违规） | `Makefile` | review P3-14 |
| conformance/binding 测试 5 处 select 丢弃 error 显式化（errcheck） | `internal/conformance/*_test.go`、`internal/binding/server_generic_test.go` | lint 收尾 |

### 版本决策项——已按裁决实施（无兼容别名）

以下 4 项已按建议直接落地（2026-10-23，用户裁决不留过渡版本）：

| 项 | 实施 | 回归测试 |
|---|---|---|
| TLSMode bool → Mode 枚举 | `ntls.Mode`（`ModeTLCP` 零值缺省/`ModeTLS13`），`ServerConfig`/`ClientCredentials` 删除 `TLSMode`，未注册值构造期 fail-fast；`NTLSProfileFor(mode ntls.Mode)` | `TestServerConfig_ModeValidation`、`TestClientCredentials_ModeValidation`、`TestNTLSProfileFollowsMode` |
| Outcome 零值 → Unspecified | `OutcomeUnspecified` 零值；makeDone durable 分支合成 released(internal)+WARN，accepted_only 分支 WARN（无 wire 效果） | `TestMakeDone_UnspecifiedLevelSynthesizesReleased`、`ExplicitDurableSettlesDurable`、`AcceptedOnlyIgnoresDone` |
| go_package 统一 corepb | 两 proto `;mbta`→`;corepb`，`buf generate` 重生成，仓库内 import 均带别名零改动 | `buf generate` 零漂移 + 全量构建 |
| ServerPolicy fail-fast 注记 | CHANGELOG [Unreleased] 破坏性变更节 | — |

破坏性变更与迁移指引已汇总至 CHANGELOG.md `[Unreleased]`。

## 九、第四/五轮修复（同日追加：版本决策项落地 + 剩余项清零）

### 第四轮：版本决策项实施（无兼容别名，用户裁决）

| 项 | 实施 | 回归测试 |
|---|---|---|
| TLSMode bool → Mode 枚举 | `ntls.Mode`（`ModeTLCP` 零值缺省/`ModeTLS13`），`ServerConfig`/`ClientCredentials` 删除 `TLSMode`，未注册值构造期 fail-fast；`NTLSProfileFor(mode ntls.Mode)`；docs 全同步 | `TestServerConfig_ModeValidation`、`TestClientCredentials_ModeValidation`、`TestNTLSProfileFollowsMode` |
| Outcome 零值 → Unspecified | `OutcomeUnspecified` 零值；makeDone durable 分支合成 released(internal)+WARN，accepted_only 分支 WARN（无 wire 效果） | `TestMakeDone_UnspecifiedLevelSynthesizesReleased`、`ExplicitDurableSettlesDurable`、`AcceptedOnlyIgnoresDone` |
| go_package 统一 corepb | 两 proto `;mbta`→`;corepb`，`buf generate` 重生成（生成代码 `package corepb`），仓库内 import 均带别名零改动 | `buf generate` 零漂移 + 全量构建 |
| ServerPolicy fail-fast 注记 | CHANGELOG [Unreleased] 破坏性变更节 | — |

破坏性变更与迁移指引汇总于 CHANGELOG.md `[Unreleased]`。帧读 watcher：**裁决维持现状**（正确性无虞，改造等 profile 证据）。

### 第五轮：剩余项清零

| 项 | 实施 |
|---|---|
| P2-6 聚合通道无字节预算 | v1 dataCh / ntls dataCh+controlCh 容量 64/16 → 8（消费阻塞时读侧背压天然生效，囤积驻留封顶 ~128MB/连接） |
| F1 根因：ntls Commands 通道 | `ntls.ServerConfig` 增 `Commands` 并透传 + facade 拷贝——命令通道双 binding 生效（此前 facade 文档告警的静默失效被真正修复）；`WithCommandRegistry` 文档更新、Start 告警移除、CHANGELOG 新特性节 |
| F30 | `dispatchCommand` 校验 `control_commands` 已协商（与 handleDict 对称） |
| F23 | `handleResult` 拒绝 `RefSeq==0` |
| F13 | `StartLifecycle` 加 `lifecycleOnce`（二次调用不再替换字段泄漏旧 goroutine） |
| F28 | 认证失败清空 negCaps/codec 残留 + 连续失败渐进退避（>3 次 100ms×n、2s 封顶；成功复位）；`handleAuthFailure` 提取为独立方法（gocognit） |
| P3-6/11/13/16/17/21 | v1 `Listener.Close` 错误 join；`buildClientTLCP` 补 `Validate()`；TCP readLoop 退出记 Debug 日志；ntls `CloseConn` nil 守卫；v1 WriteFrame 移除非 wrapper 裸写回退（自定义 DataStream 拒绝并指引导） |
| P3 去重 | `epochAlloc` 两处 → `binding.EpochAlloc`；帧上限"0=默认"四处 → `core.LimitsFor`；`10s` 写超时 → `controlWriteTimeout` 常量；protocol 包 doc 迁 `doc.go`；`command_registry` 冗余别名删除；`ledgerKeys` → `sessionKeys`（名实一致） |
| P3-11(gen_certs) | `selfSignCA` 返回 der 直接写盘——消除同一模板二次签名 |
| P3-9(zstd 字典) | 复核降级：LRU 淘汰只移除注册表条目，活跃连接持指针不受影响，新会话握手后必收 DICT 自愈——不构成实际 DoS，代码注释澄清 |
| P3-12 | v1 ServerConfig 尾部孤儿注释块删除 |
| F26 | facade `SetResultHandler` 文档声明"回调内禁调 Close"契约 |

**接受残差（记录不修）**：① proto map 解码放大——`MaxBatchBytes`(8MB) 封顶输入后 proto 侧无条目数预检，最坏数十倍瞬时堆分配（CBOR 路径已用 DecOptions 收紧）；彻底修复需 protowire 预扫描，复杂度/收益不匹配。② v1 `Conn` 导出字段（QC/RemoteAddr/udpConn）封装泄漏——unexport 属 public API 变更且外部可能合法需要底层句柄，保留。③ 帧读 watcher goroutine/帧——等 profile 证据。

### 需版本决策的遗留项（方案建议，未动手）

> 以下原建议已被第四轮裁决取代（全部按"无兼容别名"直接实施）。

1. **`ntls.ServerConfig.TLSMode bool` → 枚举**（review P3：一个 bool 同时切换 ALPN/密码栈/证书形态，第三种模式无法扩展）
   - 建议方案：新增 `type Mode string`（`ModeTLCP`/`ModeTLS13`），`ServerConfig` 增 `Mode` 字段；`TLSMode bool` 标记 Deprecated 保留一个版本（两者同写时 Mode 优先 + 启动告警）；下个 minor 发布迁移公告，再下个 major 删除 bool。
   - 决策点：是否接受两个过渡版本的迁移窗口；`ClientCredentials.TLSMode` 同步处理。

1. **`ntls.ServerConfig.TLSMode bool` → 枚举**（review P3：一个 bool 同时切换 ALPN/密码栈/证书形态，第三种模式无法扩展）
   - 建议方案：新增 `type Mode string`（`ModeTLCP`/`ModeTLS13`），`ServerConfig` 增 `Mode` 字段；`TLSMode bool` 标记 Deprecated 保留一个版本（两者同写时 Mode 优先 + 启动告警）；下个 minor 发布迁移公告，再下个 major 删除 bool。
   - 决策点：是否接受两个过渡版本的迁移窗口；`ClientCredentials.TLSMode` 同步处理。
2. **`core.Outcome` 零值 = `OutcomeAccepted`**（P3-9：handler 漏设字段静默变 accepted，durable 下直接合成 DURABLE）
   - 建议方案：新增 `OutcomeUnspecified`（零值），`makeDone` 对零值合成 `released(CodeInternal)` + WARN 日志——把漏设从静默成功变显式故障。风险：现有外部 sink 若依赖 `done(core.Outcome{})` 的 accepted 语义会收到行为变化；建议在 changelog 中以 breaking 注记发布。
   - 决策点：是否允许该行为破坏；或仅文档警告不动语义。
3. **`go_package` 目录 `corepb` vs package `mbta` 不一致**（P3：全靠 import 别名维持可读性）
   - 建议方案：统一为 package `corepb`（`option go_package = ".../corepb;corepb"`），全仓 `mbta.` 前缀引用改 `corepb.`——机械改动但波及全部调用点，宜独立 PR + `buf generate` 验证。
   - 决策点：独立 PR 排期。
4. **`ServerPolicy` 显式部分配置现在 fail-fast**（第一轮 IsZero 修复的连带行为变化）：仅配置个别字段的策略不再静默回退默认而是构造报错。若存在此类存量调用方，升级时需补全字段或显式全零。建议在 changelog 注记。
5. **帧读 watcher goroutine/帧**（`core/frame.go:41-53`，P3 性能项）：每次读帧起一个 goroutine 监听 ctx。**裁决：维持现状**——正确性无虞，改造（timer 复用或 deadline 语义替代）等 profile 证据驱动；若压测显示热路径开销显著再立项。

## 四、P3 摘要（风格 / 组织 / 命名 / 低风险）

**core**：`keyschedule.go:232-234` pskCK 注释整句重复；`keyschedule.go:329` `io_readFull` 重写 stdlib `io.ReadFull`；`frame.go:41-53` 每帧读起一个 watcher goroutine；`credit.go:73` `violations` 计数器只增不读；`credit.go:220-224` `Reset` 只清 slots、命名与行为不符；`deduper.go:57-63` TTL 过期 O(n) 扫描；`envelope.go:327` 池 Get 后裸断言 vs `compressZstdDict` 有 ok 检查（不一致）；`ulid.go:45-51` 降级路径两次重叠写难读；`errors.go:152-163` 迁移别名待删；`errors.go:127` `CodeOf` 注释"内部用途"却已导出；`metrics.go:56` 孤儿注释、`:216` NoOp 独有方法（接口漂移）、`core.New` 命名不可读；`sink.go:42` Outcome 零值=Accepted；`signal.go:232` 声称 codec 层保证嵌套约束——实际不存在；测试面：`codec*/message/policy/errors` 无专属单测。

**internal/protocol**：`client.go:391-416` `StartLifecycle` 无 Once；`client.go:530` 手写 `hmacEqual` 双实现；`handler_batch.go:83-87` sem-full 路径对 BelowUnknown 不回执（行为不一致）；`handler_batch.go:124-156` 解压超限与解密失败混用错误码、`Policy.Validate` 不查 `MaxBatchBytes ≤ 8MB`；`handler_sink.go:145-150` 挂死 handler 永久钉住 worker（不可配、无指标）；`handler.go:249-255` 认证失败可无限重试 HELLO 无退避；魔法数字 `10s`×3、`256`；`client.go:357` `ledgerKeys()` 名不副实；`command_registry.go:18` 冗余 import 别名；包 doc 放 transport.go。

**ntls/v1**：`TLSMode bool` 一开三切，应改枚举；`v1` 包名零描述性；TLS 1.3 客户端配置构造两处逐行重复（`ntls/transport.go:181-208` vs `v1/quic_transport.go:108-139`）；`epochAlloc` 两处重复；协商帧上限"0=默认"四处重复；writeSem 模式三份近似实现；`Conn` 导出可变字段封装泄漏；`ntls` 无 `Commands`/`SetCommandHandler`（API 面不对称）；`buildClientTLCP` 不调 `Validate()`；`tcp_transport.go:86` 读错误全静默；孤儿注释若干。

**根包/binding/示例**：`v1ClientWrapper`/`ntlsClientWrapper` 40 行逐字等价可泛型化；`internal/binding/errors.go` 死文件；`AcceptLoop` 签名承诺 error 但恒返 nil；`handleConn` recover 缺堆栈、recover 分支内二次 panic 会击穿进程；`Addr` 持写锁应 RLock；`server.go:112-119` epochs 赋值先于 started 检查 + 重启清零计数零文档；优雅退出后 `started` 不复位；`Dial` 把配置错误包成 `ErrCodeTransport`；库内固定 `slog.Info` 无 logger 注入点；`examples/basic_client/main.go:25-32` 注释与代码错位、路径跑不通；`testutil/rand.go` 文件头与实现矛盾。

**corepb/proto**：`go_package` 目录 `corepb` 与 package `mbta` 不一致；`signal.proto:84` 内嵌历史叙事应入 CHANGELOG；Makefile `check` 里 `fmt` 是写操作；CI 无 `buf generate` 漂移断言（本次实测一致靠自觉）。生成配置本身全绿。

---

## 五、验证面观察

- **测试与 race**：全绿。但单包独立覆盖率偏低（internal/protocol 5.7%、v1 2.0%、根包 11.6%），主力覆盖在 `-tags=integration` 的 conformance 套件（76.8%）——回归防线集中在集成层，accepted 无界这类敌意序列没有单测兜底。
- **internal/binding 零测试文件**：泛型外壳 + 状态机（两个 P2 时序缝所在地）无直接测试。
- **组织性缺口**：安全校验的"提供方"（core.Validate*）与"调用方"（internal/protocol 管线）之间没有契约测试——P1-2 正是这个缺口的事故现场。

## 六、修复优先级

1. **立即**：P0-1（TLCP mTLS）→ P1-2（接线 `sb.Validate()` + makeEvent 错误上抛）→ P1-1（accepted 上限）→ P1-3（客户端写失败拆连）→ CREDIT 零维守卫对齐（`client_control.go:96`）→ P1-4（QUIC pre-auth 超时）。
2. **近期（小改动大收益）**：`ServerPolicy.IsZero` 补 `DatagramRateBytes`、guardedCounter 补 NaN/Inf、DGRAM 默认限速、caps 日志 sanitize、`releaseStuck` 用 `WithoutCancel`、`Allow0RTT` 默认关、`Conn.Close` 改 code 1、`initNTLSServer` 补 Commands 或明确文档、NewServer 提前校验 v1 地址、binding 状态机代次号 redesign。
3. **随版本**：TLS 配置构造上提到 tlshelper、TLSMode 改枚举、wrapper 泛型化、P3 清理，并为 F1/CREDIT 链路/重复回调补敌意序列回归测试。
