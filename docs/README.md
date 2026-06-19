# MBTA 文档索引

文档分两层：协议规范（与实现语言无关）、实现文档（Go 参考实现）。

## 第一层：核心协议规范

| 文档 | 说明 |
|------|------|
| [mbta-core-spec.md](./mbta-core-spec.md) | 冻结基准 r2 (2026-06)。所有 binding 的共同核心：帧格式、Flags、SecureEnvelope、codec/压缩/密码套件、session、握手、投递语义、流控、capability registry。binding 文档与本规范冲突时以本规范为准。 |
| [mbta-core-spec-diagrams.md](./mbta-core-spec-diagrams.md) | 图表与字段参考：帧 wire 格式、Flags 位图、消息类型表、SecureEnvelope 字段/处理顺序、CipherSuite 双轨、状态机、握手时序图、投递通道、capability registry、OTLP 映射、错误码范围。 |

## 第二层：传输 Binding

传输轴决定 framing，密码轴决定握手（见 core §10）。binding 文档遵循 core §10.3。

| 文档 | 覆盖 ALPN | 传输 × 密码 | 状态 |
|------|-----------|-------------|------|
| [mbta-tcp-binding.md](./mbta-tcp-binding.md) | `mbta-tls/1`、`mbta-ntls/1` | TCP + TLS1.3 / TCP + TLCP | ✅ |
| mbta-quic-binding.md（待编写） | `mbta/1`、`mbta/2`、`mbta-wt/1` | QUIC+TLS1.3 / QUIC+RFC8998 / WebTransport | 🔲 待编写；`mbta/1` 实现已就绪（`v1/`），`mbta/2` 计划中，`mbta-wt/1` 预留 |

## 第三层：实现文档

| 文档 | 说明 |
|------|------|
| [performance-optimization.md](./performance-optimization.md) | Go 参考实现的性能与架构笔记。对象池/atomic/分片等属 Go 优化，不构成协议一致性要求。 |
| [0-rtt-design.md](./0-rtt-design.md) | 0-RTT（early_data）实现状态：QUIC binding 支持，TCP binding 不支持。 |

## 阅读顺序

1. [mbta-core-spec.md](./mbta-core-spec.md) —— 线格式、握手、投递与流控语义。
2. 按传输场景读对应 binding：
   - TCP → [mbta-tcp-binding.md](./mbta-tcp-binding.md)
   - QUIC → 暂无独立文档；参考 core spec + `v1/` 包（`mbta/1` 已实现）
3. 关心 Go 实现细节时读第三层。

## ALPN 速查

| ALPN | 传输 | 密码 | 文档 | 状态 |
|------|------|------|------|------|
| `mbta/1` | QUIC | TLS 1.3 | （quic-binding 待编写） | ✅ 实现（`v1/`） |
| `mbta/2` | QUIC | RFC 8998 | （quic-binding 待编写） | 🔲 计划中 |
| `mbta-tls/1` | TCP | TLS 1.3 | mbta-tcp-binding | ✅ |
| `mbta-ntls/1` | TCP | TLCP | mbta-tcp-binding | ✅ |
| `mbta-wt/1` | WebTransport | TLS 1.3 | （quic-binding 待编写） | 🔲 预留 |

## r2 实现状态（2026-06）

`go build ./...` + `go test ./...` 通过。协议迁移 r2 核心实现完成。

| 包 | 状态 | 测试 |
|----|------|------|
| `core` | ✅ wire + envelope（proto+双轨 cipher+压缩）+ message（corepb）+ cipher + SignalCodec 注册表（proto/cbor/json）+ capability（codec_cbor/json 可协商）+ session Negotiate + auth + drain | ✅ codec round-trip + Negotiate |
| `corepb` | ✅ proto 生成（envelope/signal/control） | — |
| `internal/protocol` | ✅ Transport 接口 + CoreHandler/CoreClient（握手/envelope/投递/流控/ACK/DATAGRAM/drain）+ binding 默认算法注入 | ✅ conformance（握手/delivery/replay/DATAGRAM/early_data/codec 协商） |
| `internal/binding` | ✅ v1 + ntls 共享握手编排 | — |
| `v1` (QUIC) | ✅ quicTransport + server + client r2 + 0-RTT data（early_data） | ✅ QUIC e2e（握手+SendBatch+sink） |
| `ntls` (TCP+TLCP/TLS1.3) | ✅ tcpTransport + server + client r2 + mbta-tls/1（TLSMode 分支） | ✅ TLCP e2e + mbta-tls/1 TLS1.3 e2e |
| `internal/conformance` | ✅ codec 协商 + algo_mismatch + handler + early_data（FakeTransport，传输无关） | ✅ |

### 待后续
- 持久化 spool（跨进程崩溃的 at-least-once；当前为内存 pendingAcks，见 [performance-optimization.md](./performance-optimization.md) §七）
- mbta-quic-binding.md（QUIC binding 规范文档）
