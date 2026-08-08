# Sink 异步化与 ACK 升级设计

**Status:** Draft / 设计草案（未实施）
**Scope:** EventSink/DurableEventSink/RawEventSink 的异步投递模型、ACK 升级机制、协议兼容性。
**Related:** core spec §9（Session/流控）、§11.6（0-RTT）、`core/flow.go`（sink 接口）、`internal/protocol/handler_batch.go`（routeAndACK）

---

## 0. 动机与问题陈述

### 0.1 当前架构缺陷

协议层 `routeAndACK` 对所有 sink 类型**同步调用** sink 方法，等待返回后才发 ACK：

```
dataLoop → go processBatch() → routeAndACK() → sink.OnSignalBatch()  [同步阻塞]
                                                 ↑ 协议层 goroutine 等 sink 返回
```

协议层（解码 + 校验 + HMAC + ACK）本应是微秒级，但被 sink 的处理耗时（毫秒~秒级）耦合：
- **吞吐受损**：sink 1ms 时单连接吞吐被限制在 ~1k batch/s（协议层本可达 ~70k）。
- **DoS 放大**：慢/恶意 sink 阻塞 handler goroutine。10k 连接 × 64 并发 × 每 goroutine 持有 batch payload（最大 8MB）= 资源耗尽。

### 0.2 设计目标

1. **协议层与 sink 解耦**：协议层回归微秒级，sink 在独立 worker pool 处理。
2. **接口向后兼容**：EventSink/DurableEventSink/RawEventSink 签名不破坏现有实现。
3. **保留可靠投递语义**：DurableEventSink 的"durable 确认"可通过异步回调达成。
4. **精准背压**：sink 处理跟不上时由有界队列自然产生背压，而非 SinkTimeout 粗粒度兜底。

---

## 1. Sink 接口的真实语义（澄清）

| 接口 | 是否需要投递结果 | 当前 ACK 语义 | 异步化可行性 |
| --- | --- | --- | --- |
| `EventSink` | ❌ 不需要（`OnSignalBatch` 返回 error 被协议层忽略，固定发 ACK accepted） | accepted | **可 fire-and-forget** |
| `DurableEventSink` | ✅ 需要 `RouteResult` 决定 ACK 模式（durable/accepted/throttle） | 由 RouteResult 决定 | **需 ACK 升级机制** |
| `RawEventSink` | ✅ 继承 DurableEventSink，`OnRawBatch` 返回 `RouteResult` | 由 RouteResult 决定 | **需 ACK 升级机制**（仅省解码，不省状态） |

> **澄清**：RawEventSink **不是"不关注状态"**。它扩展 DurableEventSink，返回 `*RouteResult` 含 `ACKStatus`（durable/accepted/throttle）。它只省去逐 signal 解码（~13 allocs/event），不省状态反馈。

只有 `EventSink`（error 被忽略的那个）能无副作用 fire-and-forget。Durable/Raw sink 的"决定 ACK 模式"是同步因果链，异步化必须引入 **ACK 升级**。

---

## 2. 总体架构

```
                        协议层（微秒级，不碰 sink 处理耗时）
                            │
            ┌───────────────┼───────────────┐
            ↓               ↓               ↓
      EventSink         DurableEventSink   RawEventSink
      投 queue           投 queue           投 queue
      立即 ACK accepted  立即 ACK accepted  立即 ACK accepted
            │               │               │
            ↓               ↓               ↓
      worker pool       worker pool       worker pool
      处理完即弃         持久化完成         持久化完成
                          ↓                 ↓
                  NotifyDurable(seq, chunkID)
                          ↓
                  发 ACK durable（升级确认）
```

协议层对每个 batch：解码 → 校验 → 投递到 sink queue → 立即发 ACK accepted → 返回（不等待 sink）。sink 在 worker pool 异步处理；Durable/Raw sink 持久化完成后通过 `DurableNotifier` 回调，协议层据此发 ACK durable 升级帧。

---

## 3. 分阶段实施

### 阶段 1：EventSink fire-and-forget（独立有价值，影响面小）

**范围**：仅普通 EventSink 异步化。Durable/Raw sink 保持同步（过渡期）。

**机制**：per-handler 有界 worker pool。

```go
// CoreHandler 新增字段
sinkQueue chan sinkTask   // 有界投递队列（容量 = SinkQueueSize，默认 256）
sinkWG    sync.WaitGroup

type sinkTask struct {
    agentID string
    batch   *core.SignalBatch
}
```

**routeAndACK 普通 EventSink 分支改为**：
```go
select {
case h.sinkQueue <- sinkTask{agentID, signalBatch}:
    // 投递成功，立即发 ACK accepted（不等 sink 处理）
default:
    // 队列满 → 背压：发 THROTTLE + 重置 replay 为 Processing
    h.replay.Update(agentID, chunkID, core.ReplayProcessing)
    h.sendThrottle(ctx, throttleRetryMs, core.ErrCodeQueuePressure, "sink queue full")
    return
}
```

**worker（handler 启动时起 N 个，N = runtime.NumCPU()）**：
```go
for i := 0; i < workers; i++ {
    h.sinkWG.Add(1)
    go func() {
        defer h.sinkWG.Done()
        for task := range h.sinkQueue {
            _ = h.config.Sink.OnSignalBatch(ctx, task.agentID, task.batch)
        }
    }()
}
```

**HandlerConfig 新增**：
```go
// SinkQueueSize 是普通 EventSink 的异步投递队列容量。
// 0=默认 256；负=禁用异步（同步阻塞，仅测试用）。满则发 THROTTLE 背压。
SinkQueueSize int
```

**移除**：上一轮过渡方案的 `SinkTimeout` + 普通 EventSink 的 goroutine 隔离（worker pool 取代，背压由队列满反映，更精准）。

**保留**：`OnPressure` 前置检查（B，sink 自报 critical 时前置 THROTTLE，与队列满互补）。

**阶段 1 影响面**：
- 接口零变更。
- 行为变更：普通 EventSink 的 `OnSignalBatch` 在 worker goroutine 调用（不在 routeAndACK 栈内）。用户若有"ACK 发出前 OnSignalBatch 必须返回"的隐式假设会失效——但 ACK 语义不变（仍 accepted）。
- **不触及 Durable/Raw sink**（它们仍同步，DoS 防护仍靠 SinkTimeout，待阶段 3 改造）。

**阶段 1 预期效果**：
| 指标 | 同步（当前） | 阶段 1 异步 |
| --- | --- | --- |
| sink 1ms 单连接吞吐 | ~1k batch/s | ~70k batch/s |
| sink 慢/卡时 handler goroutine | 阻塞（最多 SinkTimeout） | 不阻塞（投队列立即返回） |
| 慢 sink 下内存 | goroutine × batch 累积 | 受 SinkQueueSize 封顶（256 batch） |

---

### 阶段 2：ACK 升级机制（客户端 tracker 改造）

**范围**：客户端 AckTracker 支持"durable 升级"——先 accepted（释放流控 slot），后 durable（纯通知，触发 durable 回调）。

#### 2.1 技术障碍

当前 `handleAck` 收到 ACK 立即 `tracker.Release(seq)` 释放 slot（`client_control.go:94`）。第一个 accepted 释放后，第二个 durable ACK 找不到 slot，无法"升级"。

#### 2.2 解法：accepted 释放 slot + durable 用 chunkID 映射

**不改变 accepted 的流控语义**（accepted 仍释放 slot 恢复流控），durable 作为"额外通知"：

```go
// CoreClient 新增 durable 回调映射（短期，durable 到达前有效）
type durableEntry struct {
    chunkID  string
    callback func()  // 可选：durable 到达时业务回调
}
durableMap map[string]durableEntry  // chunkID → entry，SendBatch 时注册
```

**SendBatch 注册**（仅当客户端关心 durable 时，如配了 durable ACK handler）：
```go
if c.durableHandler != nil {
    c.durableMap[chunkIDText] = durableEntry{chunkID: chunkIDText}
}
```

**handleAck 改造**：
```go
// 收到 accepted：正常释放 slot（流控恢复），dispatchACK("accepted")
// 收到 durable：
//   - 若 slot 仍在（accepted 还没来，durable 先到）：释放 slot + dispatchACK("durable")
//   - 若 slot 已释放（accepted 已处理）：查 durableMap，dispatchACK("durable")，删除 entry
```

**durableMap 清理**：durable ACK 到达后删除 entry；超时未收到 durable（如服务端崩溃）由 ackReaper 兜底清理（与现有 reaper 对齐）。

#### 2.2 wire 兼容性

**零帧格式变更**。复用现有 AckMessage（`ack_mode` 字段已支持 ACCEPTED=1 / DURABLE=2）。客户端通过"slot 是否已释放"+"chunkID 映射"判断是首次 ACK 还是 durable 升级。

**向后兼容**：
- 旧客户端（无 durableMap）：收到 durable ACK 时 slot 可能已释放，`Release` 返回 false，忽略——行为同当前（durable 当普通 ACK 处理）。
- 旧服务端（不发 durable 升级）：只发一次 accepted/durable，客户端无升级场景——行为不变。

#### 2.3 阶段 2 影响面
- 仅客户端改造（AckTracker + durableMap）。
- 服务端不变（阶段 3 才改服务端发 durable 升级）。
- 阶段 2 独立可测：客户端能正确处理"先 accepted 后 durable"序列（即使服务端还不发，可用测试桩模拟）。

---

### 阶段 3：DurableEventSink / RawEventSink 异步化 + DurableNotifier

**范围**：Durable/Raw sink 异步投递，通过 DurableNotifier 回调发 durable 升级。

#### 3.1 DurableNotifier 接口

```go
// DurableNotifier 由协议层提供，sink 持有。持久化完成后调 NotifyDurable，
// 协议层据此发 ACK durable 升级帧。
type DurableNotifier interface {
    NotifyDurable(seq uint64, chunkID []byte)
}
```

注入方式：协议层在 routeAndACK 投递 task 时，把 notifier 连同 seq/chunkID 一起塞进 task；worker 调 sink 时传入。

#### 3.2 接口适配（保持签名兼容）

**方案：不改动 DurableEventSink/RawEventSink 方法签名**，而是协议层用适配器包装：

- DurableEventSink 的 `OnSignalBatchWithResult` 仍返回 `*RouteResult`，但异步语义下：
  - 立即返回 `ACKStatusAccepted`（"先接受"）
  - 持久化完成后，sink 实现内部调注入的 `DurableNotifier.NotifyDurable`
- 协议层收到 NotifyDurable → 发 ACK durable 帧（阶段 2 的客户端能处理升级）

**问题**：现有 DurableEventSink 实现是同步返回 RouteResult 的，没有 notifier 注入点。需要：
- **方案 A（破坏性）**：DurableEventSink 新增 `SetDurableNotifier(DurableNotifier)` 方法，sink 实现改为异步。
- **方案 B（兼容）**：协议层检测 sink 是否实现新的 `AsyncDurableSink` 接口（可选实现），是则走异步路径 + 注入 notifier；否则回退同步（Durable/Raw sink 仍同步，DoS 靠 SinkTimeout）。

**推荐方案 B**——渐进式，老 sink 实现不受影响，新 sink 实现新接口享异步。

```go
// AsyncDurableSink 可选接口：实现此接口的 DurableEventSink 走异步路径。
// 协议层在投递时注入 notifier；持久化完成后 sink 调 notifier.NotifyDurable。
type AsyncDurableSink interface {
    OnSignalBatchAsync(ctx, agentID string, batch *SignalBatch, notifier DurableNotifier, seq uint64, chunkID []byte)
}
```

#### 3.3 阶段 3 影响面
- 协议层：routeAndACK 的 Durable/Raw 分支改为投 queue（同阶段 1 模式），worker 调 `OnSignalBatchAsync`。
- sink 实现：需实现 AsyncDurableSink 才享异步（否则回退同步）。
- 客户端：阶段 2 已就绪（能处理 durable 升级）。

---

## 4. 协议帧与 wire 兼容性总结

| 阶段 | 帧格式变更 | enum 变更 | 兼容性 |
| --- | --- | --- | --- |
| 1 | 无 | 无 | 完全兼容（内部异步，wire 不变） |
| 2 | 无 | 无 | 完全兼容（复用 AckMessage.ack_mode，客户端侧映射） |
| 3 | 无 | 无 | 完全兼容（服务端发 durable 升级 = 复用 AckMessage DURABLE） |

**整个设计零帧格式变更**。ACK 升级靠"同一 batch 发两次 ACK"（先 accepted 后 durable），客户端通过 slot 状态 + chunkID 映射识别。这是纯客户端/服务端实现层逻辑，不触及 wire。

---

## 5. 背压与 DoS 防护对比

| 机制 | 同步（当前） | 阶段 1 | 阶段 3（全异步） |
| --- | --- | --- | --- |
| 普通 EventSink 背压 | SinkTimeout 粗粒度 | queue 满精确背压 | queue 满精确背压 |
| Durable/Raw sink 背压 | SinkTimeout + RouteResult.Throttle | 同步（SinkTimeout） | queue 满精确背压 |
| OnPressure 前置 | sink critical 时 THROTTLE | 保留 | 保留 |
| 慢 sink 下内存 | goroutine × batch 累积 | queue 封顶（256） | queue 封顶（256） |
| 协议层吞吐 | 被 sink 拖累 | 解耦（普通 sink） | 完全解耦 |

---

## 6. 迁移路径

1. **阶段 1 先行**（推荐立即实施）：EventSink 异步化，解决最常见 sink 的 DoS 面。接口不变，现有 EventSink 实现零改动即可受益。
2. **阶段 2 跟进**：客户端 AckTracker 改造，为阶段 3 铺路。独立可测（测试桩模拟 durable 升级序列）。
3. **阶段 3 完成**：Durable/Raw sink 通过 AsyncDurableSink 可选接口异步化。老 sink 实现回退同步，新实现享异步。

**回退保证**：每个阶段独立，任何阶段失败可回退到上一阶段的行为（阶段 3 回退到同步 Durable，阶段 2 回退到无 durableMap，阶段 1 回退到同步 EventSink）。

---

## 7. 待决问题（Open Questions）

1. **durableMap 生命周期**：durable ACK 超时未到时，entry 何时清理？建议 ackReaper 统一兜底（与现有 batch 超时 reaper 对齐），超时阈值需定义（如 2× heartbeat）。
2. **阶段 3 的 sink 错误语义**：异步路径下 sink 返回 error 怎么处理？普通 EventSink 忽略（现状）；AsyncDurableSink 的持久化失败是否发 NACK？建议不发 NACK（durable 是"升级"，缺失 durable 不代表失败，客户端靠超时重试）。
3. **worker 数量调优**：默认 runtime.NumCPU() 是否合适？高吞吐场景可能需要绑定。建议 HandlerConfig 可配 SinkWorkers。
4. **与 0-RTT 的交互**：0-RTT early data 的 batch 也走异步 queue 吗？建议是（0-RTT batch 同样经 routeAndACK）。

---

## 8. 测试计划

| 阶段 | 测试 |
| --- | --- |
| 1 | queue 满发 THROTTLE；慢 sink 不阻塞协议层（throughput 对比）；worker pool 回收（连接关闭无泄漏） |
| 2 | 先 accepted 后 durable 序列正确升级回调；durable 超时清理；旧客户端收到 durable 不崩溃 |
| 3 | AsyncDurableSink 异步 durable 升级端到端；老 DurableEventSink 回退同步；raw batch 异步 durable |

---

## 附录 A：当前代码位置（实施参考）

| 组件 | 文件:行 |
| --- | --- |
| routeAndACK（sink 调用点） | `internal/protocol/handler_batch.go:270` |
| EventSink/Durable/Raw 接口 | `core/flow.go:40-70` |
| handleAck（客户端 ACK 处理） | `internal/protocol/client_control.go:77` |
| AckTracker.Release | `core/ack_tracker.go` |
| applyRouteResult（ACK 模式决定） | `internal/protocol/handler_batch.go` |
| HandlerConfig（SinkTimeout/SinkQueueSize） | `internal/protocol/handler.go:38` |
| AckMessage proto | `proto/control.proto`（ack_mode 字段） |
