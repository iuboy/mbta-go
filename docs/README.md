# MBTA 文档索引

文档分两层：协议规范（与实现语言无关）、设计/实现记录（Go 参考实现）。

## 第一层：核心协议规范与 Binding

| 文档 | 说明 |
|------|------|
| [mbta-core-spec.md](./mbta-core-spec.md) | **核心协议规范 r3**。所有 binding 的共同核心：帧格式（2B 头 + varint、type 通道域）、密钥日程（ECDH/transcript/HKDF，密钥派生不上线）、1-RTT 握手与 4+3 状态机、Envelope（compress-then-encrypt + AD）、credit 流控（模型 B）、集合制去重、RESULT 四级与错误码注册表、协商、传输绑定要求、Sink 契约、安全考虑、演进机制。binding 文档与本规范冲突时以本规范为准。 |
| [mbta-tcp-binding.md](./mbta-tcp-binding.md) | TCP binding 规范（`mbta-tls/1` = TCP+TLS1.3、`mbta-ntls/1` = TCP+TLCP）：type 高位单连接 demux、PING/PONG 保活、pre-auth 策略、证书生成与运维。 |
| mbta-quic-binding.md（待编写） | `mbta/1`（QUIC+TLS1.3，实现已就绪于 `v1/`）；`mbta/2`（QUIC+RFC8998）计划中。 |

> r3 为原地破坏性重构：线上格式全部重写，ALPN 标识不变（core §0.1）。旧的帧格式图、调用图等 diagrams 已随旧协议一并移除（反映的是 r3 之前的历史版本）；现行规范的字节图 / 时序图 / 状态机均内嵌于 core spec 各节。

## 第二层：设计与实现记录

| 文档 | 说明 |
|------|------|
| [v2-design.md](./v2-design.md) | **r3 设计与审查记录**（先例研究、逐节设计 rationale、两轮审查裁决 §18、conformance 断言清单）。协议语义争议时与 core spec 互补：spec 为准，本文提供决策依据。 |
| [performance-optimization.md](./performance-optimization.md) | Go 参考实现的性能与架构笔记。对象池/内存布局等属 Go 优化，不构成协议一致性要求。 |

## 阅读顺序

1. [mbta-core-spec.md](./mbta-core-spec.md) —— 帧格式、密钥日程、握手、流控/去重语义。
2. 按传输场景读对应 binding：
   - TCP（TLS1.3 / TLCP）→ [mbta-tcp-binding.md](./mbta-tcp-binding.md)
   - QUIC → 暂无独立文档；参考 core spec §9 + `v1/` 包（`mbta/1` 已实现）
3. 需要设计决策依据/审查裁决时读 [v2-design.md](./v2-design.md)；Go 实现细节读第二层其余文档。

## ALPN 速查

| ALPN | 传输 | 密码 | 文档 | 状态 |
|------|------|------|------|------|
| `mbta/1` | QUIC | TLS 1.3 | （quic-binding 待编写） | ✅ 实现（`v1/`） |
| `mbta/2` | QUIC | RFC 8998 | （quic-binding 待编写） | 🔲 计划中 |
| `mbta-tls/1` | TCP | TLS 1.3 | [mbta-tcp-binding.md](./mbta-tcp-binding.md) | ✅ 实现（`ntls/`，TLSMode） |
| `mbta-ntls/1` | TCP | TLCP | [mbta-tcp-binding.md](./mbta-tcp-binding.md) | ✅ 实现（`ntls/`） |
| `mbta-wt/1` | WebTransport | TLS 1.3 | — | 🔲 预留（r3 未定义） |

## r3 实现状态（2026-08）

协议 r3 重构完成，core spec 与代码一致。

| 包 | 职责 |
|----|------|
| `core` | 帧编解码、密钥日程、Envelope、错误码注册表、策略/协商、credit 账本与准入窗口、状态机、token 认证面 |
| `corepb` | proto 生成（control/signal 消息 schema 权威：`proto/control.proto`） |
| `internal/protocol` | CoreHandler/CoreClient（握手、RESULT/CREDIT、sink 队列、reaper、去重准入） |
| `internal/conformance` | 传输无关 conformance（帧/密钥日程/握手/credit/去重/envelope/sink/close） |
| `internal/binding` | v1 + ntls 共享外壳（accept 循环、handler 配置、客户端握手编排） |
| `v1` | QUIC binding（`mbta/1`） |
| `ntls` | TCP binding（`mbta-ntls/1` TLCP、`mbta-tls/1` TLS1.3） |

### 已知实现差距（相对设计记录，见 core spec 对照）

- CREDIT 攒批仅阈值触发（初始窗/4），100ms 定时器未接线；
- DGRAM 字节速率限桶默认未启用（并发槽 64 已生效）；
- 客户端发送路径暂固定 COMPRESSION_NONE（接收端四算法全支持）；
- 服务端 Draining 态无显式入口（收尾语义经 released(server_draining) 路径达成）。
