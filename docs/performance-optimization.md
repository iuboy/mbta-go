# 性能与架构参考（r3）

本文档记录 mbta-go 参考实现（r3 协议）的性能特征、序列化策略、传输层架构与压测数据。

> **范围说明**：本文档是 Go 参考实现的实现笔记，**不构成协议一致性要求**。对象池 / atomic 等属 Go 优化，协议规范见 [mbta-core-spec.md](./mbta-core-spec.md)。

---

## 一、热路径优化

| 组件 | 优化 | 位置 |
| ---- | ---- | ---- |
| gzip/zstd/lz4 压缩 | `sync.Pool` 复用 reader/encoder/decoder | `core/envelope.go` |
| zstd 字典 codec | 池化 encoder（按 dict 注册）+ 共享 decoder | `core/envelope.go`（`ZstdDictCodec`） |
| frame header | `var [N]byte` 栈数组 | `core/frame.go` |
| 客户端 seq 分配 | `atomic.Uint64` 单计数器（BATCH/DGRAM 共享，nonce 安全前提） | `core/credit.go`（`SeqGenerator`） |
| 服务端准入/守恒 | 单锁单结构（`CreditManager`：准入 + 去重 + credit 回收） | `core/credit.go` |
| CREDIT 攒批发放 | 懒 arm 100ms 定时器（首个 Settle 触发，替代常驻 ticker） | `internal/protocol/handler_batch.go`（`maybeScheduleFlush`） |
| sink 异步队列 | 懒启动 worker（首个成功入队触发）+ 条数/字节双限界 | `internal/protocol/handler_sink.go` |
| SendBatch 锁粒度 | `sendMu` 临界区内仅 seq 分配 + 编码 + 封装 + credit 消耗；帧写在临界区外 | `internal/protocol/client.go` |
| QUIC 写超时 | ctx deadline 绑定 `SetWriteDeadline`（流控背压下防永久阻塞） | `v1/quic_transport.go` / `v1/client.go` |

## 二、序列化策略：SignalCodec 注册表

SignalBatch 的编码由 `core.SignalCodec` 接口 + 包级注册表分发（`core/codec.go`）；HELLO 协商（`core.CodecFor`，`cbor` 能力被选中即用 cbor）决定用哪种 codec。

| Codec | capability | 实现 | 适用 |
| ----- | ---------- | ---- | ---- |
| Protobuf | —（默认） | `core/codec_proto.go`（经 corepb AnyValue oneof） | **baseline 默认**：wire 紧凑、跨语言、OTLP 互通 |
| CBOR | `cbor` | `core/codec_cbor.go`（fxamacker/cbor v2，Canonical EncMode） | constrained 场景：自描述、紧凑 |

- 第三方可经 `core.RegisterCodec` 注册私有 codec（注册表开放，见 codec.go 注释）。
- **Raw 快速路径**：`SinkOptions{Raw: true}` 注册的 sink 收到 `BatchEvent.Raw`（协商 codec 的原始字节），跳过逐事件解码；`BatchMeta.EventsCount` 供不解码取事件数。

## 三、密码套件（profile）

profile（`corepb.Profile`：intl/gm）与传输层正交（`core/keyschedule.go` / `core/cipher.go`）：

- intl：X25519 ECDH + HKDF-SHA256 + AES-256-GCM + HMAC-SHA256
- gm：SM2 ECDH（emmansun/gmsm）+ HKDF-SM3 + SM4-GCM + HMAC-SM3
- 密钥由 1-RTT 握手 transcript 派生，**永不上 wire**（core spec §4）；nonce = prefix(4B)‖seq(8B) 确定性构造
- SM2 证书认证（mTLS）属传输层 TLS（TLCP / RFC 8998），依赖 pollux-go 国密 TLS 栈

## 四、传输层架构

### v1（QUIC + TLS 1.3，`mbta/1`）

`v1/` 包。QUIC：首个 bidi stream 为 control stream，单 data stream（`StreamPicker` 单流实现）绕过队头阻塞的多流复杂度；可选 QUIC DATAGRAM 不可靠通道（需两侧启用扩展，`SendDatagram` 自动降级可靠路径）。

### ntls（TCP + TLCP / TLS 1.3，`mbta-ntls/1`、`mbta-tls/1`）

`ntls/` 包。单 TCP 连接按帧 type 高位域 demux（control/data 逻辑通道，后台 readLoop 分发）；写经容量 1 的信号量（`writeSem`，支持 ctx 取消）。TLCP 用 pollux-go/tlcp + SM2 双证书；`mbta-tls/1` 是 TLSMode 分支走标准 TLS 1.3。

| 方面 | v1 (QUIC) | ntls (TCP) |
| ---- | --------- | ---------- |
| 传输 | QUIC（UDP） | TCP 单连接 |
| 证书 | 单 X.509 | 双 SM2（TLCP）/ X.509（TLSMode） |
| control/data | 分离 QUIC stream | 同连接帧多路复用（type 高位域） |
| 不可靠通道 | QUIC DATAGRAM（可选） | 无（DGRAM 降级可靠 BATCH） |
| 保活 | QUIC 内置 keepalive | PING/PONG（HeartbeatLoop，30s） |

### 协议核心共享层（`internal/protocol`）

v1 与 ntls 共享 `internal/protocol.CoreHandler` / `CoreClient`。各 binding 仅实现传输专属的 `Transport` / `ClientTransport` 接口（`internal/protocol/transport.go`），协议逻辑（握手、RESULT/CREDIT、sink 队列、reaper、去重准入）全部在核心层。

## 五、Client.Connect 生命周期

`Connect(ctx)` 的 `ctx` 仅控制握手阶段（Dial、开 stream、HELLO）。握手成功后，后台 goroutine 运行在独立的 lifecycle ctx（派生自 `context.Background()`，见 `internal/protocol/client.go` `StartLifecycle`），不随 ctx 取消退出；client 生命周期完全由 `Close()` 终结。

caller 可安全使用 `context.WithTimeout + defer cancel` 限定握手时长。若需「ctx 取消即停止 client」，调用方应自行监听 ctx 并调 `Close()`。

## 六、可靠投递（reliable 通道）

reliable BATCH 通道为 at-least-once（会话内 exactly-once 投递效果）：

- **发送追踪**：客户端 `CreditLedger`（`core/credit.go`）登记在途 slot（seq/bytes/correlation/deadline）；RESULT（Terminal）移出、CREDIT（OnCredit）返还额度（模型 B：返还权威在服务端）。
- **超时观测**：客户端 `AckReaperLoop`（`internal/protocol/client_control.go`）周期 `ReapExpired`，超时 slot 以 "timeout" 回调通知（不回补 credit）。
- **服务端守恒**：`CreditManager` + `SettleGrant` 一次性令牌保证「RESULT 发送 + 终态环 + 额度回收」原子完成；服务端 reaper 对 stuck inflight `ForceSettle(released)`。
- **去重**：集合制窗口 + 终态环（RESULT 丢失后同 seq 重发回存储 outcome；core spec §7）。

> **持久化限制**：可靠投递基于内存 credit 账本——进程崩溃会丢失未终态 batch。跨连接/跨副本的 at-least-once 收敛由 sink 实现者按 `Batch.Meta.Correlation` 幂等（参考 `core.CorrelationDeduper`）。

## 七、压测与基准文件索引

各环节延迟与吞吐基准。`core/*_bench_test.go` 测协议各子环节（纳秒~微秒级），`test/*.go`（integration tag）测端到端聚合（含传输往返）。

### 环节级基准（`core/`，`go test -bench=. ./core/`）

| 文件 | 覆盖环节 | 报告维度 |
| ---- | -------- | -------- |
| `core/cipher_bench_test.go` | HMAC（SHA-256/SM3）、AEAD Seal/Open（AES-256-GCM/SM4-GCM） | ns/op + MB/s |
| `core/envelope_bench_test.go` | Envelope Seal/Open（compress-then-encrypt），4KB/64KB/1MB × NONE/ZSTD | ns/op + MB/s + allocs |
| `core/frame_bench_test.go` | Frame Write/Read/RoundTrip | ns/op |
| `core/keyschedule_bench_test.go` | 完整握手密钥日程（intl/gm）：eph/ZZ/transcript/proof/finished | ns/op |

### 端到端基准（`test/`，`go test -tags integration -bench=. ./test/`）

| 文件 | 覆盖 | 报告维度 |
| ---- | -------- | -------- |
| `test/bench_test.go` | E2E：握手 1-RTT / Raw 与 facade SendBatch 吞吐 / RESULT 延迟 / 大 batch | ns/op + MB/s + batch/op |
| `test/perf_bench_test.go` | `TestPerfExport`：各环节延迟 + E2E 吞吐采集与 JSON 导出 | JSON 报告 |

### 其他

| 文件 | 覆盖 |
| ---- | ---- |
| `internal/conformance/` | 传输无关 conformance（fake transport：帧/密钥日程/握手/credit/去重/envelope/sink/close/capability） |
| `test/integration_test.go` | 黑盒 facade 集成（v1 QUIC + ntls TLCP 全链路） |
| `ntls/tcp_preauth_test.go` | TCP pre-auth 读超时档位切换 |

### 运行示例

```bash
# 全部环节级 bench（快，秒级完成）
go test -bench=. -benchtime=200ms ./core/

# 结构化 JSON 性能报告（各环节延迟 + E2E 吞吐）
go test -tags integration -run TestPerfExport -v ./test/

# 端到端聚合吞吐 bench
go test -tags integration -bench=. -benchtime=3s ./test/
```

### JSON 报告导出

`TestPerfExport` 跑完自动写结构化 JSON 报告到 `test/results/perf-<timestamp>.json`，含环境信息（go_version/goos/goarch/num_cpu）、端到端各环节延迟与吞吐、核心环节度量（envelope/HMAC/密钥日程，intl vs gm）。报告文件被 .gitignore 排除（运行时产物）。CI 可归档不同 commit 的报告做回归对比，无需 benchstat 等外部工具。
