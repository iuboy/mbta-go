# MBTA-NTLS/1 设计

## 1. 定位

`mbta-ntls/1` 是 MBTA 的 TCP + NTLS/TLCP 传输入口。它用于必须使用 NTLS/TLCP 传输安全的部署环境，复用 MBTA 的 SignalBatch、投递确认、spool、流控和 OTLP 映射语义。

`mbta-ntls/1` 不使用 QUIC，不参与 QUIC ALPN。它必须使用独立 TCP 监听端口。

## 2. 协议入口

| 项           | 值                          |
| ------------ | --------------------------- |
| 协议名       | `mbta-ntls/1`               |
| 帧版本       | `0x01`                      |
| 传输         | TCP + NTLS/TLCP             |
| 默认安全模型 | `gm_transport` + `hmac_sm3` |
| Payload      | SignalBatch                 |
| 端口策略     | 独立 TCP 端口               |

## 3. 传输模型

`mbta-ntls/1` 使用单条或多条 TCP 连接承载 MBTA 帧：

- TCP 连接建立后先完成 NTLS/TLCP 握手。
- 握手完成后进入 MBTA framed stream。
- 每个 TCP 连接必须有一个 control channel。
- data channel 可以通过同连接多路复用帧实现，也可以使用多条 TCP data 连接实现。

因为 TCP 没有 QUIC stream 语义，`mbta-ntls/1` 必须显式定义 channel：

```json
{
  "channel_id": 1,
  "channel_type": "control"
}
```

基础实现可以只使用单连接单 data channel。多 data channel 必须通过 capability 协商启用。

## 4. 帧格式

`mbta-ntls/1` 复用 MBTA 16 字节帧头：

```text
Offset  Size  Field
0       4     Magic = "MBTA"
4       1     Version = 0x01
5       1     Flags
6       2     Type
8       4     Length
12      4     CRC32(payload)
```

TCP 是连续字节流，接收端必须按 `Length` 精确读取 payload，并对超限长度、短读、CRC 错误和半开连接进行防护。

## 5. 应用层安全

`mbta-ntls/1` 的默认应用层安全能力为：

- BATCH 使用 SecureEnvelope。
- HMAC 默认使用 HMAC-SM3。
- 应用层 SM4-GCM 可选。

NTLS/TLCP 已提供传输层国密机密性。应用层 SM4-GCM 只用于端到端 payload 加密、代理或网关终止后仍需保持密文、或多租户隔离要求明确的场景。

## 6. 复用语义

`mbta-ntls/1` 复用以下 MBTA 语义：

- SignalBatch。
- Resource / Scope / Signal records。
- `signal_type="log"`、`gauge`、`counter`、`histogram`、`summary`、`span`。
- HELLO / HELLO_ACK capability 协商。
- AUTH / AUTH_OK / AUTH_FAIL。
- BATCH / ACK / NACK / PARTIAL_ACK。
- WINDOW / THROTTLE。
- PING / PONG / CLOSE。
- Spool 删除规则。
- Durable ACK 语义。
- OTLP Logs / Metrics / Traces 映射。

## 7. 差异语义

| 维度       | `mbta/1`           | `mbta-ntls/1`              |
| ---------- | ------------------ | -------------------------- |
| 传输       | QUIC + TLS 1.3     | TCP + NTLS/TLCP            |
| 连接复用   | QUIC streams       | MBTA channel 或多 TCP 连接 |
| 队头阻塞   | stream 级隔离      | TCP 连接级队头阻塞         |
| 连接迁移   | QUIC 支持          | 不支持                     |
| 流控       | QUIC + MBTA WINDOW | TCP + MBTA WINDOW          |
| 传输层国密 | 不包含             | NTLS/TLCP                  |

## 8. Capability

`mbta-ntls/1` 必须声明：

```json
{
  "transport_profile": "ntls_tlcp_tcp",
  "secure_envelope": true,
  "hmac": ["sm3"],
  "payload": ["signal_batch_v1"]
}
```

可选能力：

- `app_encryption_sm4_gcm`
- `sm2_cert_auth`
- `multi_channel`
- `multi_connection`
- `partial_ack`
- `durable_ack`

> 实现状态备注：`app_encryption_sm4_gcm`、`durable_ack`（DurableEventSink + 内存 ReplayCache）已实现。
> `multi_channel` / `multi_connection` **暂未实现**——当前为单连接单 data channel（RFC §5 明确允许的基础实现）。
> 其原始动机（单连接 HOL）已由服务端 BATCH worker 池解决；多连接跨核并行的边际收益不足以抵消
> TLCP 多次握手开销与协议扩展复杂度。线路格式当前 16 字节帧头无 channel 字段，实现 multi_channel
> 需先增订 RFC（channel_id 表示）+ channel 路由/流控设计。触发条件：实测单连接吞吐瓶颈且 worker 池无法覆盖。

## 9. 验收标准

`mbta-ntls/1` 发布前必须通过：

- TCP + NTLS/TLCP 握手测试。
- 服务端和客户端证书验证测试。
- 帧粘包、拆包、短读、半开连接测试。
- 超大 length 和 CRC 错误防护测试。
- HMAC-SM3 SecureEnvelope 测试。
- SignalBatch 端到端投递测试。
- ACK / NACK / PARTIAL_ACK / Durable ACK 测试。
- WINDOW / THROTTLE 在 TCP 队头阻塞下的行为测试。
- OTLP Logs / Metrics / Traces 映射测试。

## 10. 禁止项

- 禁止与 `mbta/1` 共用 QUIC 监听入口。
- 禁止在同一端口上用不可靠协议嗅探混合 QUIC 和 TCP。
- 禁止未完成 NTLS/TLCP 握手时接收 BATCH。
- 禁止把 TCP 连接级可靠性等同于 Durable ACK。
