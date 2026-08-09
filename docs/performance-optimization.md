# 性能与架构参考

本文档记录 mbta-go 参考实现的性能特征、序列化策略、传输层架构与压测数据。

> **范围说明**：本文档是 Go 参考实现的实现笔记，**不构成协议一致性要求**。对象池 / atomic / 分片等属 Go 优化，协议规范见 [mbta-core-spec.md](./mbta-core-spec.md)。

---

## 一、热路径优化

| 组件 | 优化 | 位置 |
| ---- | ---- | ---- |
| 压缩 writer/reader（gzip/zstd） | `sync.Pool` 复用，预分配 cap | `core/envelope.go` |
| envelope Build | 随机 nonce 预分配 `make([]byte, AEADNonceSize)` | `core/envelope.go:91` |
| envelope Open | 预分配 buffer（`make([]byte, 0, len(src)*4)` 解压放大预留） | `core/envelope.go:294` |
| frame header | `var [N]byte` 栈数组 | `core/frame.go` |
| ReplayCache 淘汰 | `container/list` 双链表（processingList + doneList） | `core/delivery.go` |
| client 流控（AckTracker） | seq-indexed ring buffer 替代 sync.Map+独立计数器；编译期固定 100 槽，零分配 | `core/ack_tracker.go` |
| ACK 排空检测 | `AckTracker.Empty()` O(1) 判空（drain 触发） | `internal/protocol/client_ack.go` |
| QUIC 流控窗口 | 按 maxBatchBytes 匹配 | `v1/quic_transport.go` |
| SendBatch 锁粒度 | `reserveInflight`（锁内 CanSend/seq/Reserve）+ `buildAndSend`（锁外 marshal/Build/Write） | `internal/protocol/client_batch.go` |
| 多流支持（v1 QUIC） | 一致哈希 StreamPicker + N 流，绕过队头阻塞 | `v1/stream_picker.go` |
| EnhancedRouter | EventsIn atomic + RLock 快路径，evict 节流 | `core/metrics.go` |

---

## 二、序列化策略：SignalCodec 注册表

SignalBatch 的编码由 `core.SignalCodec` 接口 + 包级注册表分发（`core/codec.go`），HELLO 协商决定用哪种 codec（`core/capability.go` pickCodec，优先级 proto > cbor > json）。

| Codec | capability | 实现 | 适用 |
| ----- | ---------- | ---- | ---- |
| Protobuf | `codec_proto` | `core/codec_proto.go`（经 corepb AnyValue oneof） | **baseline 默认**：wire 紧凑、跨语言、OTLP 互通 |
| CBOR | `codec_cbor` | `core/codec_cbor.go`（fxamacker/cbor v2，Canonical EncMode） | constrained 场景：自描述、紧凑 |
| JSON | `codec_json` | `core/codec_json.go`（stdlib encoding/json） | 仅调试/人类可读 |

- **MAC 确定性**：HMAC（`core/envelope.go` canonicalMAC）作用于 SecureEnvelope 的 deterministic protobuf wire bytes，与 SignalBatch codec 无关——故 codec 选择不影响跨实现 MAC 可复现性。
- **RawEventSink 快路径**：转发型 sink 可不解码 SignalBatch，直接拿原始 codec bytes（见 §三）。

---

## 三、RawEventSink 快速路径

转发型 sink（不需读取 signal 字段详情）可实现 `RawEventSink` 接口（`core/flow.go:62`），服务端跳过 `UnmarshalSignalBatch` + `Validate`。`BatchMessage.EventsCount`（client 填）供快速路径取事件数。

接口层级：`EventSink` → `DurableEventSink`（+RouteResult）→ `RawEventSink`（+OnRawBatch）。

`OnRawBatch` 收到的 `batchData` 是**按协商 codec 编码的原始字节**（proto/cbor/json 之一）。

---

## 四、国密（GM）密码套件

GM 套件经 `CipherSuite_CIPHER_SUITE_GM` 表达，与 INTL 在每一层对称（`core/cipher.go`）：

- **HMAC**：SM3（`hmac.New(sm3.New)`）
- **AEAD**：SM4-GCM（`NewAEAD` 分发）
- **密钥分发**：`SessionKeys` 按 CipherSuite 生成 HMACKey + AEADKey，AUTH_OK 下发；INTL 取 `AesKey` 字段、GM 取 `Sm4Key` 字段（`internal/protocol/handler_handshake.go`）
- **协商**：client offer `cs_gm` → `pickCipherSuite` 优先选 GM（`core/capability.go`）
- **安全**：每次 Build 生成随机 nonce，连接关闭时密钥清零

SM2 证书认证（mTLS）属传输层 TLS（TLCP / RFC 8998），依赖 pollux-go 国密 TLS 栈。

---

## 五、传输层架构

### v1（QUIC + TLS 1.3，`mbta/1`）

`v1/` 包。QUIC UDP 多流：control/data 分离的 QUIC 流，BATCH 跨多流并发（一致哈希 StreamPicker 绕过队头阻塞）。0-RTT data 完整支持（见 core spec §11.6）。

### ntls（TCP + TLCP / TLS 1.3，`mbta-ntls/1`、`mbta-tls/1`）

`ntls/` 包。单 TCP 连接帧多路复用：control + data 帧在同连接交替，`writeMu` 保护写避免帧头交错。TLCP 用 pollux-go/tlcp（高层 Listen/Dial）+ pollux-go/cert（SM2 双证书）。`mbta-tls/1` 是 TLSMode 分支走标准 TLS 1.3。

| 方面 | v1 (QUIC) | ntls (TCP) |
| ---- | --------- | ---------- |
| 传输 | QUIC UDP 多流 | TCP 单连接 |
| 证书 | 单 X.509 | 双 SM2（TLCP）/ X.509（TLSMode） |
| control/data | 分离 QUIC 流 | 同连接帧多路复用 |
| BATCH 并发 | 多流 goroutine | 单连接顺序 |
| 0-RTT data | ✅ | ❌（crypto/tls 无 0-RTT data API） |

### 协议核心共享层（`internal/protocol`）

v1 与 ntls 共享 `internal/protocol.CoreHandler` / `CoreClient`（CoreClient 接口见 `internal/protocol/client.go`）。各 binding 仅实现传输专属的 `Transport` / `ClientTransport` 与 binding 默认算法注入（spec §8.3：默认 CipherSuite 跟随 binding——v1=INTL，ntls=GM），协议逻辑全部在核心层。

| 方面 | 实现 |
| ---- | ---- |
| 握手 / envelope / 投递 / 流控 / ACK / DATAGRAM / drain | `internal/protocol/handler_*.go` / `client_*.go` |
| Transport 抽象 | `internal/protocol/transport.go` |
| binding 默认算法注入 | `CoreClientConfig.DefaultCodec/DefaultCipherSuite/DefaultCompression` |

---

## 六、Client.Connect 生命周期设计

`Connect(ctx)` 的 `ctx` 仅控制握手超时（Dial、开 stream、HELLO/AUTH）。握手成功后，后台 goroutine 运行在独立的 `lifecycleCtx`（派生自 `context.Background()`，见 `internal/protocol/client.go:258`），不随 `ctx` 取消退出。client 生命周期完全由 `Close()` 终结。

caller 可安全使用 `context.WithTimeout + defer cancel` 限定握手时长。若需「ctx 取消即停止 client」，调用方应自行监听 ctx 并调 `Close()`。

---

## 七、压测与基准文件索引

各环节延迟与吞吐基准。`core/*_bench_test.go` 测协议各子环节（纳秒~微秒级），
`test/*.go` 测端到端聚合（含传输往返）。

### 环节级基准（`core/`，`go test -bench=. ./core/`）

| 文件 | 覆盖环节 | 报告维度 |
| ---- | ---- | ---- |
| `core/cipher_bench_test.go` | HMAC（SHA-256/SM3）、AEAD Seal/Open（AES-256-GCM/SM4-GCM） | ns/op + MB/s（加密吞吐） |
| `core/envelope_bench_test.go` | SecureEnvelope Build/Open（压缩+AEAD+HMAC），INTL/GM × 3 size | ns/op + MB/s + allocs |
| `core/negotiate_bench_test.go` | HELLO 协商（Negotiate：交集+选算法），2/12/256 caps | ns/op + allocs |
| `core/signal_bench_test.go` | SignalBatch marshal/unmarshal（proto codec）各层开销 | ns/op |
| `core/frame_bench_test.go` | Frame Write/Read 真实开销 | ns/op |
| `core/codec` (codec_test.go Benchmark) | 各 codec 编解码 | ns/op |
| `core/delivery_bench_test.go` | ReplayCache SeenOrAdd/淘汰 | ns/op |
| `core/flow_bench_test.go` | Window/AckTracker/Inflight 流控 | ns/op |
| `core/session_bench_test.go` | session 状态机 Transition | ns/op |
| `core/perf_scale_test.go` | ReplayCache/Inflight 高并发规模压测 | ns/op |

### 端到端基准（`test/`，`go test -tags integration -bench=. ./test/`）

| 文件 | 覆盖 | 报告维度 |
| ---- | ---- | ---- |
| `test/perf_stages_test.go` | **各环节延迟分解**：握手/首次/稳态 SendBatch/Close + 大 batch 吞吐 | 各环节延迟 + batch/s + MB/s |
| `test/bench_test.go` | 单连接/大 batch/多连接聚合吞吐/连接建立速率 | ns/op + MB/s + batch/op |

### 其他

| 文件 | 覆盖 |
| ---- | ---- |
| `v1/stream_picker_test.go` | 一致哈希 StreamPicker |
| `v1/e2e_test.go` | 端到端 QUIC（握手 + SendBatch + sink）正确性 |
| `ntls/e2e_test.go` | 端到端 TCP + TLCP / TLS 1.3 正确性 |

### 运行示例

```bash
# 全部环节级 bench（快，秒级完成）
go test -bench=. -benchtime=200ms ./core/

# 端到端各环节延迟分解（可读报告 + 自动导出 JSON）
go test -tags integration -run TestPerf_StagedLatency -v ./test/

# 端到端聚合吞吐 bench
go test -tags integration -bench=. -benchtime=3s ./test/
```

### JSON 报告导出

perf test（`TestPerf_StagedLatency` / `TestPerf_LargeBatch_Throughput`）跑完自动写
结构化 JSON 报告到 `test/results/perf-<timestamp>.json`，含：

- 环境信息（go_version / goos / goarch / num_cpu）
- 端到端各环节延迟（握手/冷启动/稳态 SendBatch/Close）+ 吞吐（batch/s、bytes/s）
- 核心环节度量（envelope Build/Open、HMAC、Negotiate，INTL vs GM）
- 大 batch 吞吐（events/batch、MB/s、batch/s、avg latency）

报告文件被 .gitignore 排除（运行时产物）。CI 可归档不同 commit 的报告做回归对比，
或解析 JSON 绘制趋势图。无需 benchstat 等外部工具。

---

---

## 八、可靠投递（reliable 通道，at-least-once）

reliable BATCH 通道提供 at-least-once 投递语义：

- **发送追踪**：每个 batch 在 `AckTracker`（seq-indexed ring buffer，`core/ack_tracker.go`）登记，含 seq / chunkID / events / bytes / 发送时间 / 超时时刻，用于 ACK 关联与超时回收。
- **ACK/NACK**：`handleAck`/`handleNack` 调 `AckTracker.Release(seq, chunkID)`（ACK 帧自带 seq 取模定位 slot，chunkID 二次校验），返回 slot 供 BatchLatency 观测。
- **超时回收**：`ackReaper`（`internal/protocol/client_ack.go`）周期调 `AckTracker.ReapExpired`，回收超 `ackTimeout` 的 slot 并重算 oldestSeq，解除序号跨度检查的队头阻塞。
- **0-RTT / 重连重发**：握手成功后 pending batch 随 resumption 重发。

### AckTracker 设计要点

- **定长 ring buffer**：编译期固定 `AckRingSize=100` 槽（≈7.2KB），零运行时分配，嵌入式可精确预估。
- **数学消除取模碰撞**：`CanSend` 的序号跨度检查（`newSeq - oldestSeq < AckRingSize`）保证存活 slot 的 seq 在 ring 内唯一，chunkID 比对作防御性兜底。
- **三路并发 claim 安全**：handleAck/handleNack/ackReaper 都经 `Release`/`ReapExpired`，首个成功者清空 slot.seq，后续见 seq==0 失败，天然避免双减。
- **单锁原则**：`AckTracker.mu` 保护 slot 数组与聚合计数；`sendMu`（CoreClient 层）保护取 seq + CanSend + Reserve 复合操作，两层锁不嵌套。

> **持久化限制**：当前可靠投递基于内存 `AckTracker`——进程崩溃会丢失待发 batch。跨进程崩溃的持久化 at-least-once（基于文件的 spool 层）待后续实现。
