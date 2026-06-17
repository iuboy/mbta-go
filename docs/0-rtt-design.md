# 0-RTT（early_data）实现状态

**状态：已实现（QUIC binding 完整 + CoreHandler 传输无关 + TCP binding 不支持）**

## 已实现（2026-06）

### CoreHandler（传输无关，protocol/handler.go）
- `SessionStore`（`core/session_store.go`）：session ticket → SessionState{keys, agentID, expiry}
- `handleHello`：识别 `HelloMessage.session_ticket` → SessionStore.Get → 恢复 keys + earlyData=true
- `handleAuth`：AUTH_OK 后颁发新 ticket（SessionStore.Put + AuthOKMessage.session_ticket）
- `controlLoop`：earlyData 时 dataLoop 在 **HELLO 后**启动（非 AUTH 后），处理 0-RTT BATCH
- conformance `TestCoreHandler_EarlyData`：✅ 通过

### QUIC binding（v1，完整 0-RTT data）
- server：`quic.Config{Allow0RTT: true}`
- client：`tls.Config{ClientSessionCache: LRU-8}` + `DialEarly`（0-RTT resumption dial）
- 流程：首次 Dial（TLS ticket 自动存）→ resumption DialEarly（0-RTT data）→ OpenStream 发 BATCH

### TCP binding（ntls，不支持 0-RTT data）
- **Go `crypto/tls` 不暴露 0-RTT application data API**（`tls.Conn.Write` 在握手完成后）
- TLCP（pollux-go/tlcp）无 0-RTT data 语义
- TCP binding 使用 `ClientSessionCache` 实现 TLS session resumption（1-RTT，降低 resumption 握手开销），但**不发送 0-RTT data**
- 这与 spec §11.4 `SupportsDatagram=false` 一致

### proto schema
- `HelloMessage.session_ticket`（field 11，resumption indicator）
- `AuthOKMessage.session_ticket`（field 8，server 颁发）

## spec 标注

spec §11.6 已明确标注 `early_data` capability **仅 QUIC binding**（`mbta/1`）。
附录 E capability registry 同步标注。

## 为何 TCP 不支持

Go `crypto/tls` 的 TLS 1.3 实现：
- ✅ session resumption（ClientSessionCache → 1-RTT resumption）
- ❌ 0-RTT application data（tls.Conn 在握手后才暴露 Write；无 early data API）

要实现 TCP 0-RTT data 需：
1. 第三方 TLS 库（如 `refraction-networking/utls`）——引入非标准依赖
2. 或自定义 TLS 0-RTT 层——极复杂

协议规范已正确限定 `early_data` 仅 QUIC，实现与规范一致。
