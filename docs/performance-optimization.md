# 性能优化与压测记录

本文档记录 mbta-go 的性能优化工作、微基准与规模压测数据，以及端到端 QUIC 吞吐压测中发现的 ACK 传输 blocker 的诊断过程。

---

## 一、性能优化总结（14 项）

按修复 ROI 排序，分四批落地。全部通过编译、lint、`go test -race ./...`。

### 第一梯队：架构级瓶颈（吞吐天花板）

#### P1. 客户端多流启用（PickStrategy）⚠️ 最严重
- **位置**：`v1/client.go` `Connect` / `openDataStreams`
- **问题**：`ClientConfig.PickStrategy` 声明了 `"single"|"hash"` 两种策略，`hashStreamPicker`（一致哈希 + 40 虚节点）也已实现，但 `Connect()` 永远硬编码 `NewSingleStream`，从不读取 `PickStrategy`、从不调用 `NewHashStreamPicker`。服务端 `MaxIncomingStreams=256` 的并发流能力被完全闲置。
- **影响**：单流下慢 batch 阻塞后续所有发送，无法并行利用多核做加密/压缩。
- **修复**：`Connect` 按 `PickStrategy` 分支；`"hash"` 时开 N 条流（`StreamCount`，默认 4）并 `AddStream`。

#### P2. `SendBatch` 全程持 `sendMu`，序列化 + gzip + HMAC + 网络写全串行
- **位置**：`v1/client.go` `SendBatch` / `reserveInflight` / `buildAndSend`
- **问题**：临界区覆盖 3 次 `json.Marshal` + `core.Build`（gzip+HMAC）+ `core.Write`。本意只保证 window 检查与写的原子性，实际锁粒度被放大到整个 payload 处理。
- **修复**：拆分为 `reserveInflight`（锁内：window 检查 + 取 seq/chunkID + inflight/pending 登记）和 `buildAndSend`（锁外：marshal + Build + Write）。失败回滚 inflight/pending。

### 第二梯队：高频路径的 O(n) 退化

#### P3. `ReplayCache` 淘汰最坏 O(n)（TODO 注释低估了风险）
- **位置**：`core/delivery.go` `SeenOrAdd`
- **问题**：触发条件是 `len(entries) >= maxSize`，与 Processing 比例无关——只要缓存填满且新 chunkID 持续到达，每次插入都做 O(n) 扫描 + `append` 切片搬移。满载时退化为 O(n²)，**有 DoS 放大风险**。
- **修复**：改 `container/list` 双链表（processingList + doneList），淘汰 O(1)。

#### P4. `Spool.estimatedSize()` 每次写入 O(n) 全表遍历
- **位置**：`v1/spool.go` `Put` / `PutBatch`
- **问题**：每写 1 条 record 遍历全部 N 条 + M 条 batches，持锁执行，总复杂度 O(N²)。
- **修复**：维护 `curSize int64` 增量计数，Put/Delete 时增减，检查降到 O(1)。

### 第三梯队：序列化/分配热点（单点收益大）

| 项 | 位置 | 修复 |
|----|------|------|
| gzip writer/reader 无 sync.Pool | `core/envelope.go` | `sync.Pool` 复用，BuildGzip 分配 815KB→2KB |
| `CanonicalSigningString` 13 次 fmt.Fprintf | `core/envelope.go` | 预分配 + `strconv.AppendUint`/直接 append，allocs 23→个位 |
| Open 解压 `io.ReadAll` 无预分配 | `core/envelope.go` | 预分配 buffer + reader pool |
| `frame.Read/Write` 16B header 每帧堆分配 | `core/frame.go` | `var [16]byte` 栈数组 |
| `processBatch` 冗余 `json.Valid` | `core/message.go` | 删除（下游 Unmarshal 必然再校验） |

### 第四梯队：锁选型 / 网络

| 项 | 修复 |
|----|------|
| `Inflight` mutex→atomic | `core/flow.go` 三标量改 `atomic.Int64` |
| `Window.CanSend` 双锁 TOCTOU | limits 改 atomic，全程无锁读 |
| `ThrottleState` mutex→atomic | `core/flow.go` until 存 unixnano |
| `EnhancedRouter` 全局写锁 | EventsIn 走 atomic + RLock 快路径，evict 全局节流（每 128 次） |
| `notifyDrainIfEmpty` 每 ACK Range | `pendingCount atomic.Int64` |
| QUIC 流控接收窗口未调优 | `v1/transport.go` 配置 8/64/16/128 MiB |
| `hashKey` 每帧分配 fnv hasher | 手写 FNV-1a 零分配 + 消除字符串拼接 |

---

## 二、微基准收益（vs 优化前基线）

| 基准 | 优化前 | 优化后 | 收益 |
|------|--------|--------|------|
| `BuildGzip` (4KB) | 76548 ns / 815 KB / 24 allocs | 25084 ns / 2 KB / 7 allocs | 耗时 -67%，内存 -99.7% |
| `OpenGzip` (4KB) | 7249 ns / 52 KB / 17 allocs | 2795 ns / 11 KB / 7 allocs | 耗时 -61%，内存 -79% |
| `VerifyHMACSHA256` | 2797 ns / 7.4 KB / 23 allocs | 2256 ns / 6.7 KB / 8 allocs | allocs -65% |
| `BuildGzip` 1 MiB payload | — | 1259529 ns / 833 MB/s / 21 allocs | allocs 不随 payload 增长（pool 生效）|

---

## 三、10 万 / 百万级规模压测

### ReplayCache 淘汰（核心收益，新 vs 旧 baseline）

混合状态（半 Processing / 半已完成，旧实现 O(n) 退化的真实场景）：

| 规模 | 新实现 ns/op | 旧 baseline ns/op | 倍数 |
|------|:---:|:---:|:---:|
| 1k | — | 5,648 | — |
| 10k | **719** | 69,573 | **97x** |
| 100k | **727** | 375,612 | **517x** |
| 1M | **720** | ~3,700,000（推算）| **~5000x** |

新实现 1万→百万恒定 ~720 ns/op（O(1)）；旧实现线性退化。

### Spool Put 增量计数

| 规模 | ns/op | allocs |
|------|:---:|:---:|
| 10k | 188 | 3 |
| 100k | 192 | 3 |
| 500k | 236 | 3 |

10k→500k 恒定（O(1)），优化前应为 O(n) 微秒级。

### Inflight 高并发（atomic 化）

| 并发 procs | ns/op | allocs |
|------|:---:|:---:|
| 8 | 312 | 0 |
| 64 | 312 | 0 |
| 256 | 312 | 0 |

8→256 并发恒定，0 分配——mutex 锁竞争彻底消除。

压测文件：`core/perf_scale_test.go`、`v1/spool_perf_test.go`、`core/envelope_bench_test.go`。

---

## 四、frame.Write/Read allocs 探索结论

端到端 bench 显示 `Write` 4 allocs、`Read` 3 allocs，疑为优化未生效。深入排查：

### 根因（逃逸分析实证）

```
core/frame.go:79: moved to heap: hdr
```

`var hdr [HeaderSz]byte` 看似栈分配，**仍逃逸**——因为 `w.Write(hdr[:])` 把切片传给 `io.Writer` 接口方法，编译器无法证明接口实现不持有该 slice。

### 4 allocs 真实来源（实测隔离）

| Benchmark | writer/reader | allocs | 说明 |
|-----------|---------------|--------|------|
| `Write` (bytes.Buffer) | bytes.Buffer | 4 | Buffer 内部 grow ×3 + hdr 逃逸 |
| **`WriteDiscard`** (io.Discard) | io.Discard | **1** | 仅 hdr 逃逸（真实 quic.Stream 场景）|
| `Read` (每次 NewReader) | bytes.NewReader | 3 | NewReader + hdr + payload |
| **`ReadPersistent`** (Reset reader) | reset | **2** | hdr + payload |

**结论**：端到端 bench 的 4/3 allocs 大部分是**测试方法产物**（bytes.Buffer grow、NewReader）。真实 quic.Stream 场景下 `Write` 仅 1 alloc（16B hdr）、`Read` 仅 2 allocs（hdr + 必要的变长 payload）。

### 消除 hdr 逃逸的方案实测

| 方案 | 结果 | 评价 |
|------|------|------|
| 特化具体类型（`*bytes.Buffer`）| ✅ hdr 不逃逸 | 有效 |
| 泛型 `[W byteWriter]` | ❌ 仍逃逸 | Go GCShape 实现限制 |
| 合并 header+payload 单次写 | — | 大 payload 需分配+拷贝 8MB，得不偿失 |
| net.Buffers / writev | — | quic.Stream 不支持 |

**决策**：hdr 16B 逃逸是 `io.Writer` 接口签名的固有代价（envelope 层已省 800KB/帧，这是其 0.002%），ROI 极低，接受现状。新增 `BenchmarkWriteDiscard` / `BenchmarkReadPersistent` 让真实开销长期可见。

---

## 五、端到端 QUIC 吞吐压测

### 框架

`v1/e2e_throughput_test.go` + `v1/server.go` 新增 `Addr()`：
- 真实 v1 Server + Client，testdata 自签证书，localhost QUIC
- 启用 gzip + HMAC-SHA256 + window 流控（测 SendBatch 全路径）
- 3 个 bench：单发送者不同 batch 规模、多发送者并发、单流 vs 多流对比
- `countSink` 计数服务端实际接收，报告 batch/s 与 events/s

### 吞吐数据（Apple M5，localhost QUIC，gzip+HMAC 全开）

**单发送者**（`BenchmarkE2E_SendBatch`）：

| batch events | batch/s | **events/s** | B/op | allocs/op |
|:---:|:---:|:---:|:---:|:---:|
| 100 | 5,848 | **584,812** | 265 KB | 2,017 |
| 1,000 | 647 | **647,670** | 2.9 MB | 19,798 |
| 10,000 | 40 | **405,508** | 30 MB | 276,993 |

**多发送者并发**（`BenchmarkE2E_Concurrent`，1000 events/batch）：

| senders | **events/s** | 备注 |
|:---:|:---:|:---|
| 1 | 576,134 | 基线 |
| 4 | 667,135 | +16% |
| 16 | **698,748** | **+21%**（sendMu 缩小后多核并行 marshal/Build 收益）|

**单流 vs 多流**（`BenchmarkE2E_SingleVsMultiStream`，1000 events/batch，8 senders）：

| streams | events/s |
|:---:|:---:|
| 1（single）| 693,506 |
| 4（hash）| 684,511 |

localhost 下两者持平——单流已饱和 CPU/内存带宽，多流收益在跨网络/高 BDP 场景才会显现。并发维度（sendMu 缩小）的收益（+21%）更明显。

### 调试过程记录：一个 API 使用陷阱

压测初期观察到"多 batch 时 server 发 N 个 ACK 但 client 只收到 0-1 个"的疑似 quic-go blocker。经最小纯 quic 复现逐步排除：

| 排除项 | 结论 |
|--------|------|
| quic-go v0.60.0 基础传输（server-initiated 多帧）| ✅ 5/5 正常 |
| client-initiated bidirectional 多帧 | ✅ 5/5 正常 |
| `core.Read`/`core.Write` + quic | ✅ 5/5 正常 |
| 双 stream（control + data）+ 并发读写 | ✅ 5/5 正常 |
| v1 完整 quic.Config（窗口/idle/keepalive）| ✅ 5/5 正常 |

**最终根因**：e2e 测试的 `setupE2E` 用 `context.WithTimeout` 调 `Connect`，`defer connCancel()` 在 `Connect` 返回后立即取消 ctx，而 `Client.Connect` 内部 `lifecycleCtx = context.WithCancel(ctx)` 会**级联取消**——导致 `readControlLoop` 等后台 goroutine 在握手后立即退出，无人读 ACK。

**这不是协议栈 bug**，是测试代码的 ctx 生命周期错误。但揭示了一个**产品 API 陷阱**：

> `Client.Connect(ctx)` 会用传入的 `ctx` 派生 `lifecycleCtx`（驱动 readControlLoop/ackReaper/heartbeat）。调用方必须传入**长生命周期**的 ctx（如 `context.Background()` 或应用生命周期 ctx），不能用会被提前取消的 ctx（如 `WithTimeout` + `defer cancel`），否则后台 goroutine 会随 ctx 取消而退出。

修复 `setupE2E` 改用 `context.Background()` 后，ACK 全部正常到达（`pending=0`），吞吐数据如上。

