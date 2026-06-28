# MBTA Trace 上下文演进分析

> 记录时间：2026-06-28
> 来源：mebsuta-forwarder v0.7.0-beta.5 跨进程 trace 工作反馈（基于对 mbta-go v0.1.1 规范 + 实现的核实，纠正了早期反馈中的误判）
> 目的：基于核实事实，评估 mbta 协议在分布式 trace 互操作上的真实缺口，给出演进优先级。

## 前提澄清（纠正早期误判）

早期反馈（mebsuta 仓 `docs/superpowers/specs/2026-06-28-mbta-trace-gaps.md`）提出 5 个缺口，但其中部分基于"未读 mbta 规范/实现"的推测，**核实后需纠正**：

| 早期缺口 | 核实结果 | 说明 |
|---|---|---|
| 1. TraceID 格式无约束 | ✅ **真实** | spec 无格式约定，`validateTextField` 仅校验长度/控制字符，无 hex 约束 |
| 2. trace 逐信号冗余 | ⚠️ **真实但属设计权衡** | `Resource`/`Scope` 已做 batch 级共享（对齐 OTLP），trace 字段确实每信号重复，但有 zstd 压缩消除；是否优化取决于实测带宽 |
| 3. 无 W3C traceparent 协商 | ✅ **真实** | spec 无 trace capability 协商，无帧级 traceparent 承载点 |
| 4. span 语义未规范化 | ❌ **错误** | **spec §6.2 + Go 实现都已有完整 span 字段**：`Name`/`Kind`/`StartTimeUnixMs`/`EndTimeUnixMs`/`StatusCode`/`StatusMessage`，`signal_type="span"` 映射 OTLP Traces Span（附录 B），codec_proto 已编解码 |
| 5. HA failover trace 续接 | ❌ **不存在** | trace 走 payload（每 signal），连接无关；重连由 SessionID + spool 重发保证（§11），trace 天然跨重连续接 |

**结论：mbta 在 trace 互操作上的真实缺口是缺口 1（格式约束）和缺口 3（W3C 协商），缺口 2 是优化权衡，缺口 4/5 是误判。**

## 真实缺口详述

### 缺口 1：TraceID/SpanID 无格式约束（本次修复）

**现状**：
- spec 提到 `trace_id`/`span_id`（§6.2 profile 关联字段、附录 B 映射），但**全文无格式约定**（未规定 hex/位数）。
- Go `SignalRecord.Validate()`：`signal_type="span"` 时强制 `trace_id` 非空，但只调 `validateTextField`（长度 + 控制字符），**无格式校验**。

**问题**：OTel 的 TraceID 是 **32 位小写 hex（16 字节）**，SpanID 是 **16 位 hex（8 字节）**。`trace.TraceIDFromHex`/`SpanIDFromHex` 拒绝非 hex 或错误长度。任何上游（不止 mebsuta）可能传入 UUID（带连字符）、base64、任意字符串，导致下游 OTel 集成各自踩坑——trace_id 无法作为 OTel TraceID 使用。

**影响**：mbta 声称 `signal_type="span"` 无损映射 OTLP Traces Span（附录 B），但若 TraceID 格式不约束，这个"无损映射"在 trace 关联上实际是"有损"的（下游无法重建 trace 树）。

**修复**（本次实施）：
- spec §6.2 明确：`trace_id`（非空时）MUST 是 32 位小写 hex；`span_id`/`parent_span_id`（非空时）MUST 是 16 位小写 hex；全零值非法（对齐 OTel）。
- Go `Validate()` 加格式校验函数，对三个字段非空时校验。

### 缺口 3：无 W3C Trace Context 协商（本次实施）

**现状**（已修复）：新增 capability `w3c_trace_context`（stable，附录 C.4），协议级承载 W3C traceparent/tracestate。

**实施内容**：
- `SignalRecord.trace_flags`（W3C trace-flags，≤ 0xff）+ `SignalRecord.trace_state`（有序 tracestate，≤ 32 成员）——per-signal 承载。
- `BatchMessage.trace_context`（`TraceContext`）——batch/stream 级继承头，同一 trace 多 signal 共享，偏离时才单独写（与缺口 2 合并）。
- HELLO 协商 `w3c_trace_context`；Validate 校验 flags 范围与 tracestate 约束；codec_proto 双向映射 + 往返测试。
- spec §6.2.2 新增章节定义语义。

外部请求携带 `traceparent`/`tracestate` 进入 mbta 边界时，现可在协议层无损注入，而非逐 signal 塞 Attributes。消费侧（如 mebsuta 从 HTTP traceparent 提取并填入 BatchMessage）依赖此契约。

### 缺口 2：trace 逐信号冗余（优化权衡，中期）

**现状**：`SignalBatch.Resource`/`Scope` 已 batch 级共享（对齐 OTLP ResourceSpans），但 `trace_id` 每 signal 重复。

**评估**：mebsuta fork-chain 场景下，同 trace 的事件批量上报时 trace_id 重复几十次。但有 zstd 压缩（重复字符串压缩比极高），实际带宽影响小。是否优化需实测。

**修复方向**（中期）：batch 级可选 `trace_context`，signal 偏离时才单独写。属性能优化，非性正确性。

## 本次实施

仅修缺口 1（格式约束）——成本低、收益明确、防止"无损映射 OTLP"的承诺落空。spec 补格式约定 + Go Validate 加校验 + 单测。

缺口 2/3 列入 mbta 后续版本规划（trace 作为一等分布式追踪能力），缺口 4/5 撤销（误判）。
