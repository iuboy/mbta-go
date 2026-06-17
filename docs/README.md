# MBTA 文档索引

MBTA 协议文档分三层，**严格分离**：协议规范（与实现语言无关）、传输 binding（规范的传输实例）、实现文档（特定参考实现）。

## 文档层次

### 第一层：核心协议规范（权威，语言中立）

| 文档 | 说明 |
|------|------|
| **[mbta-core-spec.md](./mbta-core-spec.md)** | **冻结基准 r2 (2026-06)**。所有 binding 的共同核心：帧格式、Flags、SecureEnvelope、codec/压缩/密码套件、session、握手协议、投递语义（reliable/lossy 双通道）、流控、capability registry、演化纪律。与实现语言无关。凡 binding 文档与本规范冲突，以本规范为准。 |
| **[mbta-core-spec-diagrams.md](./mbta-core-spec-diagrams.md)** | r2 协议图表与字段参考：帧 wire 格式图、Flags 位图、消息类型表、SecureEnvelope 字段/处理顺序、CipherSuite 双轨、状态机、握手时序图、投递通道、架构图、capability registry、OTLP 映射、错误码范围。 |

### 第二层：传输 Binding（第一层的实例）

传输轴决定 framing，密码轴决定握手（正交两维，见 core §10）。binding 文档遵循 core §10.3 元规范。

| 文档 | 覆盖 ALPN | 传输 × 密码 | 状态 |
|------|-----------|-------------|------|
| **[mbta-tcp-binding.md](./mbta-tcp-binding.md)** | `mbta-tls/1`、`mbta-ntls/1` | TCP + TLS1.3（国际）/ TCP + TLCP（国密） | ✅ 定义（补齐对称性） |
| **[mbta-quic-binding.md](./mbta-quic-binding.md)** | `mbta/1`、`mbta/2`、`mbta-wt/1` | QUIC+TLS1.3 / QUIC+RFC8998 / WebTransport | ✅ `mbta/1`；`mbta/2` 计划中；`mbta-wt/1` 预留 |

### 第三层：历史 binding 草案（已被 supersede）

| 文档 | 状态 |
|------|------|
| [mbta1-rfc-draft-bilingual.md](./mbta1-rfc-draft-bilingual.md) | ⚠️ 旧 16B 帧草案，superseded by core r2 + mbta-quic-binding |
| [mbta-ntls1-rfc-draft-bilingual.md](./mbta-ntls1-rfc-draft-bilingual.md) | ⚠️ 旧草案，superseded by core r2 + mbta-tcp-binding |
| [mbta2-rfc-draft-bilingual.md](./mbta2-rfc-draft-bilingual.md) | ⚠️ 旧草案，superseded by core r2 + mbta-quic-binding |

### 第四层：实现文档（Go 参考实现，非协议要求）

| 文档 | 说明 |
|------|------|
| [performance-optimization.md](./performance-optimization.md) | Go 参考实现的性能与架构笔记。**实现特定**，对象池/atomic/分片等属 Go 优化，不构成协议一致性要求。 |
| [mbta1-architecture-diagrams.md](./mbta1-architecture-diagrams.md) | 架构图（实现层视角）。 |
| [mbta1-protocol-design.md](./mbta1-protocol-design.md) | v1 设计笔记（实现层）。 |
| [mbta-ntls-tcp-tlcp-design.md](./mbta-ntls-tcp-tlcp-design.md) | ntls 设计笔记（实现层）。 |

## 阅读顺序

1. **[mbta-core-spec.md](./mbta-core-spec.md)** —— 理解协议的线格式、握手、投递与流控语义（权威）。
2. 按传输场景读对应 binding：
   - TCP 部署 → **[mbta-tcp-binding.md](./mbta-tcp-binding.md)**
   - QUIC 部署 → **[mbta-quic-binding.md](./mbta-quic-binding.md)**
3. 仅当关心 Go 参考实现性能时读第四层。

## ALPN 速查

| ALPN | 传输 | 密码 | 文档 | 状态 |
|------|------|------|------|------|
| `mbta/1` | QUIC | TLS 1.3 | mbta-quic-binding | ✅ |
| `mbta/2` | QUIC | RFC 8998 | mbta-quic-binding | 🔲 计划中 |
| `mbta-tls/1` | TCP | TLS 1.3 | mbta-tcp-binding | ✅ 新补齐 |
| `mbta-ntls/1` | TCP | TLCP | mbta-tcp-binding | ✅ |
| `mbta-wt/1` | WebTransport | TLS 1.3 | mbta-quic-binding | 🔲 预留 |

## 关键约束（来自 core-spec）

- **场景中立**：默认服务主力部署；嵌入式与未来场景通过 capability 协商偏移。
- **密码双轨**：国际 / 国密在每一层对称一等，传输与密码正交。
- **长寿演化**：session 与传输 tuple 解耦；字段号 / enum / capability 有演化纪律。
- **实现中立**：协议只规定字节与语义；内存与并发模型由实现自决。
- **双投递通道**：reliable（BATCH）+ unreliable（DATAGRAM，仅 QUIC binding）。

## r2 实现状态（2026-06）

`go build ./...` + `go test ./...` 双绿。协议迁移 r2 核心实现完成。

| 包 | 状态 | 测试 |
|----|------|------|
| `core` | ✅ wire(8B) + envelope(proto+双轨cipher+四压缩) + message(corepb) + cipher + capability + session Negotiate + auth + drain | ✅ |
| `corepb` | ✅ proto 生成（envelope/signal/control） | — |
| `protocol` | ✅ Transport 接口 + CoreHandler（握手/envelope/投递/流控/ACK/DATAGRAM/drain close_timeout） | ✅ conformance（握手/delivery/replay/DATAGRAM） |
| `v1` (QUIC) | ✅ quicTransport + server + client r2 | ✅ QUIC e2e（真实握手+SendBatch+sink） |
| `ntls` (TCP+TLCP/TLS1.3) | ✅ tcpTransport + server + client r2 + mbta-tls/1（TLSMode 分支） | ✅ TLCP e2e + mbta-tls/1 TLS1.3 e2e |
| `spool` | ✅ 共享（at-least-once） | ✅ |

### 待后续
- `early_data` capability（0-RTT BATCH，需 QUIC binding resumption + CoreHandler resumption session 识别）
- 旧 `types.go` legacy 字符串常量清理（r2 用 corepb enum + capability registry，旧常量 unused）
- `go mod tidy`（pollux-go 经 workspace，CI 需 GOPRIVATE 配置）
