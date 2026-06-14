# 性能与架构参考

本文档记录 mbta-go 的性能特征、序列化策略、国密能力、传输层架构，以及端到端压测数据。

---

## 一、热路径优化

| 组件 | 优化 | 效果 |
|------|------|------|
| gzip 压缩/解压 | `sync.Pool` 复用 writer/reader | BuildGzip 分配 815KB→2KB，耗时 -67% |
| HMAC 签名串 | 预分配 `[]byte` + `strconv` 替代 `fmt.Fprintf` | allocs 23→8 |
| envelope Open | 预分配 buffer + reader pool | 内存 -79% |
| frame header | `var [16]byte` 栈数组 | 消除 16B 堆分配（`io.Writer` 接口仍导致 1 次逃逸，ROI 极低接受） |
| ReplayCache 淘汰 | `container/list` 双链表（processingList + doneList）| O(1)，1万→百万恒定 ~720 ns/op |
| Spool 大小检查 | 增量 `curSize int64` 计数 | O(1)，10k→500k 恒定 ~200 ns/op |
| Inflight/Window/ThrottleState | `atomic.Int64` 替代 `sync.Mutex` | 8→256 并发恒定 312 ns/op / 0 allocs |
| EnhancedRouter | EventsIn atomic + RLock 快路径，evict 节流（每 128 次） | 消除全局写锁串行 |
| ACK 排空检测 | `pendingCount atomic.Int64` 替代 `sync.Map.Range` | 每 ACK 零开销 |
| QUIC 流控窗口 | 8/64/16/128 MiB（匹配 maxBatchBytes） | 跨地域大 batch 不多 RTT |
| hashKey | 手写 FNV-1a 零分配 | 消除 fnv hasher 堆分配 |
| BatchMessage wrapper | 手写 `buildBatchPayload`（strconv 拼接）| 280µs→7µs（40x），消除 compact 扫描 |
| SendBatch 锁粒度 | `reserveInflight`（锁内 window/seq/inflight）+ `buildAndSend`（锁外 marshal/Build/Write）| 多发送者并行 +21% |
| 多流支持 | `PickStrategy="hash"` 一致哈希 + N 流 | 跨网络绕过队头阻塞 |
| message.go | 删除冗余 `json.Valid` | 省 25% JSON 处理 |

---

## 二、序列化策略：sonic

`core/json.go` 的 `FastMarshal`/`FastUnmarshal` 封装 [bytedance/sonic](https://github.com/bytedance/sonic)，替换热路径所有 `encoding/json` 调用。

| 场景 | 标准库 | sonic | 收益 |
|------|:---:|:---:|:---:|
| marshal 1k events | 360µs / 5001 allocs | ~378µs / **1002 allocs** | allocs -80% |
| unmarshal 1k events | 824µs / 13008 allocs | **274µs** / 6005 allocs | 耗时 **-67%** |

兼容性：sonic 输出可被 `encoding/json` 正常 Unmarshal（sonic 不做 HTML escape，但两端语义等价）。HMAC 作用于 base64 后的 payload，不受影响。平台：amd64/arm64，其他平台自动回退纯 Go。

未选 jsoniter（marshal 退化 +75%）、easyjson（map 仍反射）、手写 MarshalJSON（经 `json.Marshal` 有 per-record compact 开销，耗时 +33%）。

---

## 三、RawEventSink 快速路径

转发型 sink（不需读取 signal 字段详情）可实现 `RawEventSink` 接口，服务端跳过 `json.Unmarshal(signalBatch)` + `Validate`（~13 allocs/event）。`BatchMessage.EventsCount` 字段（client 填）供快速路径取事件数。

接口层级：`EventSink` → `DurableEventSink`（+RouteResult）→ `RawEventSink`（+OnRawBatch）。

| 场景 | events/s | allocs/op |
|------|:---:|:---:|
| 解码 sink（需 signal 详情）| 125万 | 7,235 |
| **RawEventSink（纯转发）** | **133万** | 1,219 |

---

## 四、SM4-GCM envelope 加密

使用 pollux-go/sm4 `NewGCM`（标准 `cipher.AEAD` 接口）。

- **Build**：compress → SM4-GCM Seal（密文 = nonce(12) + ciphertext + tag(16)）→ base64 → HMAC
- **Open**：base64 decode → SM4-GCM Open → decompress
- **密钥分发**：`SessionKeys.SM4Key`（16B），`GenerateSessionKeys` 总生成，AUTH_OK 下发
- **协商**：`Policy.EnableSM4GCM` + client offer `sm4_gcm` → Negotiate 选中
- **安全**：每次 Build 生成随机 12B nonce（`rand.Read`），无重用风险；连接关闭时 HMACKey + SM4Key 均清零

SM2CertAuth（mTLS）属传输层 TLS，依赖国密 TLS 栈（v2/RFC 8998），v1 标准 TLS 1.3 不支持。

---

## 五、ntls（TCP + TLCP）传输层

使用 pollux-go/tlcp（高层 Listen/Dial）+ pollux-go/cert（SM2 双证书加载）。

### 设计：单连接帧多路复用

ntls 是单 TCP 连接，所有帧（control + data）在同连接交替。`core.Read`/`core.Write` 按 type/flags 区分。`writeMu` 保护所有写（避免帧头交错）。BATCH 在读循环中内联处理（自然背压）。

| 方面 | v1 (QUIC) | ntls (TCP+TLCP) |
|------|-----------|-----------------|
| 传输 | QUIC UDP 多流 | TCP + TLCP 单连接 |
| 证书 | 单 X.509 | 双 SM2（签名+加密） |
| control/data | 分离 QUIC 流 | 同连接帧多路复用 |
| BATCH 并发 | 64 并发流 goroutine | 读循环内联（串行） |

### 实现文件

| 文件 | 行数 | 内容 |
|------|:---:|------|
| `ntls/transport.go` | ~240 | TLCP Config + Listen/Dial + Server |
| `ntls/handler.go` | 815 | ConnectionHandler + 21 协议方法 |
| `ntls/client.go` | ~280 | Client + Connect/SendBatch/Close |
| `ntls/handshake.go` | ~150 | 握手 |
| `ntls/control.go` | ~120 | ACK/NACK/WINDOW 处理 |

E2E 测试（`TestE2E_NTLS_SendBatch`）：TLCP 握手 + HELLO/AUTH + SendBatch + ACK 全链路通过。

### v2 状态

v2（QUIC + RFC 8998 国密）因 pollux-go 缺少高层 `quicgm.Listen/Dial` API 而推迟。

---

## 六、Client.Connect 生命周期设计

`Connect(ctx)` 的 `ctx` 仅控制握手超时（Dial、开 stream、HELLO/AUTH）。握手成功后，后台 goroutine 运行在独立的 `lifecycleCtx`（派生自 `context.Background()`），不随 `ctx` 取消退出。client 生命周期完全由 `Close()` 终结。

caller 可安全使用 `context.WithTimeout + defer cancel` 限定握手时长。若需「ctx 取消即停止 client」，调用方应自行监听 ctx 并调 `Close()`。

---

## 七、端到端吞吐数据

### v1 QUIC（Apple M5，localhost，gzip+HMAC+sonic 全开）

**单发送者**：

| batch events | batch/s | events/s | allocs/op |
|:---:|:---:|:---:|:---:|
| 100 | 1,250 | **125万** | 7,235 |
| 1,000 | 1,329 | **133万** | 1,219（RawEventSink）|
| 10,000 | 57 | **57万** | — |

**多发送者并发**（1000 events/batch）：

| senders | events/s | 备注 |
|:---:|:---:|:---|
| 1 | 57.6万 | 基线 |
| 16 | **70万+** | sendMu 缩小后多核并行 |

### 微基准关键数据

| 基准 | 值 |
|------|:---:|
| `BuildGzip` 4KB | 25µs / 2KB / 7 allocs |
| `OpenGzip` 4KB | 2.8µs / 11KB / 7 allocs |
| `BuildGzip` 1MiB | 1.3ms / 833 MB/s / 21 allocs |
| `MarshalSignalBatch` 1k | 378µs / 1002 allocs |
| `ReplayCache` 淘汰 | 720 ns/op（1万→百万恒定）|
| `Spool Put` | 188-236 ns/op（10k→500k 恒定）|
| `Inflight` 8→256 并发 | 312 ns/op / 0 allocs |

### ntls TLCP

E2E smoke 测试通过。性能 bench 待补（TLCP 加密开销不同于 QUIC TLS，预期吞吐低于 QUIC 但延迟更稳定）。

---

## 八、压测与基准文件索引

| 文件 | 覆盖 |
|------|------|
| `core/perf_scale_test.go` | ReplayCache / Inflight / Spool 规模压测 |
| `core/signal_bench_test.go` | SignalBatch marshal/unmarshal 各层开销 |
| `core/envelope_bench_test.go` | Build/Open/gzip/HMAC 不同 payload 规模 |
| `core/frame_bench_test.go` | Write/Read 真实开销（io.Discard 隔离）|
| `v1/spool_perf_test.go` | Spool Put 规模压测 |
| `v1/stream_picker_bench_test.go` | hash picker 并发基准 |
| `v1/e2e_throughput_test.go` | 端到端 QUIC 吞吐（单/多发送者、RawEventSink、多流对比）|
