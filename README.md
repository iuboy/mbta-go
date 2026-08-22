# MBTA-Go

MBTA (Mebsuta Binary Transport Agent) — 高性能二进制日志传输协议库（r3 协议）。

## 协议版本

| 传输            | ALPN          | 传输层                     | 密码 profile        | 状态    |
| --------------- | ------------- | -------------------------- | ------------------- | ------- |
| v1              | `mbta/1`      | QUIC + TLS 1.3             | intl（X25519/AES-GCM）/ gm | ✅ 可用 |
| ntls            | `mbta-ntls/1` | TCP + NTLS/TLCP            | gm（SM2/SM4-GCM）   | ✅ 可用 |

> 协议完整规格见 [docs/mbta-core-spec.md](./docs/mbta-core-spec.md)（r3）。
>
> **本地开发 / 源码构建说明**：ntls（TCP + TLCP）绑定依赖私有库
> `github.com/iuboy/pollux-go`（提供 SM2/SM3/SM4/TLCP 实现），该依赖通过
> [Go workspace](https://go.dev/ref/mod#workspaces)（`go.work`）引入。
> 从源码构建或运行测试前，将 `pollux-go` clone 到与本项目同级目录。
> 仅 `go get` 外部依赖使用 v1（QUIC + TLS 1.3，intl profile）无需 pollux-go。

## 安装

```bash
go get github.com/iuboy/mbta-go
```

## 快速开始

### Dial 一行连接

```go
client, err := mbta.Dial(ctx, "localhost:7400", "my-agent", "secret-token",
    mbta.WithV1Credentials(v1.ClientCredentials{
        CAFile:     "ca.pem",
        ServerName: "mbta-server",
    }),
)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// 注册 RESULT 回调（accepted/durable/rejected/released）
client.SetResultHandler(func(seq uint64, level string, code uint32, correlation string) {
    if level == "durable" {
        // 批次已持久化
    }
})

// client 已就绪，直接发送；返回连接级序号
seq, err := client.SendBatch(ctx, &core.SignalBatch{
    Signals: []*core.SignalRecord{
        {SignalType: "log", Body: "hello world"},
    },
})
```

### 手动创建客户端

```go
client, err := mbta.NewClient(
    mbta.WithServer("localhost:7400"),
    mbta.WithAgent("my-agent", "secret-token"),
    mbta.WithV1Credentials(v1.ClientCredentials{
        CAFile:     "ca.pem",
        ServerName: "mbta-server",
    }),
)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

if err := client.Connect(ctx); err != nil {
    log.Fatal(err)
}

seq, err := client.SendBatch(ctx, batch)
```

### 服务端

```go
server, err := mbta.NewServer(
    mbta.WithV1(v1.QUICServerConfig{
        Address: "0.0.0.0:7400",
        Credentials: &v1.ServerCredentials{
            CertFile: "server.pem",
            KeyFile:  "server.key",
        },
    }),
    // 注册式 sink：供给偏好（Raw/Durable/Async）静态声明
    mbta.WithSink(core.SinkOptions{Durable: true},
        func(ctx context.Context, ev core.BatchEvent, done func(core.Outcome)) {
            // ev.Decoded（*SignalBatch）或 ev.Raw（原始编码字节）
            if err := persist(ctx, ev.Decoded); err != nil {
                done(core.Outcome{Level: core.OutcomeRejected, Code: core.CodeInternal})
                return
            }
            done(core.Outcome{Level: core.OutcomeDurable}) // 触发 RESULT(durable) + CREDIT 返还
        }),
    // Policy 可选：省略时按版本取默认（v1=intl、ntls=gm）
    mbta.WithAuth(core.NewStaticTokenValidator(map[string]string{
        "secret-token": "my-agent",
    })),
)
```

## RESULT 回调

服务端对每个批次发送 RESULT 帧（四级反馈，AMQP settlement 语义）：

```go
client.SetResultHandler(func(seq uint64, level string, code uint32, correlation string) {
    switch level {
    case "durable":   // 持久化完成（终态；额度已经 CREDIT 返还）
    case "accepted":  // 已入服务端内存队列（durable 模式下为中间态）
    case "rejected":  // 终态拒绝（code 指明原因，不可重投）
    case "released":  // 未处理可重投（服务端压力大/排空放弃；重投需用新 seq）
    }
})
```

## 错误码参考

wire 上只传数字（`Result.code`），注册表 append-only：

| 范围 | 类别 | 示例常量 |
| ---- | ---- | -------- |
| 0    | 成功 | `CodeOK` |
| 1x   | 握手 | `CodeAuthFailed` / `CodeUnsupportedProfile` |
| 2x   | 数据 | `CodeBatchTooLarge` / `CodeEnvelopeOpenFail` / `CodeWindowExceeded` |
| 3x   | 会话 | `CodeServerDraining` |
| 4x   | 服务端 | `CodeInternal` / `CodeUnavailable` |

```go
switch core.CodeNumOf(err) {
case core.CodeAuthFailed:      // 认证失败
case core.CodeWindowExceeded:  // credit 耗尽（本地检查）
default:
}
```

## 配置选项

### 客户端选项

| 选项                       | 说明                                |
| -------------------------- | ----------------------------------- |
| `WithServer(addr)`         | 设置服务端地址                      |
| `WithAgent(id, token)`     | 设置 Agent 标识与令牌               |
| `WithVersion(v)`           | 指定协议版本（`v1`/`ntls`）         |
| `WithAgentMeta(meta)`      | 设置 HELLO 元数据（hostname/os 等） |
| `WithCapabilities(caps)`   | 声明能力（trace_context/datagram/cbor） |
| `WithV1Credentials(creds)` | 配置 V1（QUIC）TLS 凭据             |
| `WithNTLSCredentials(cfg)` | 配置 NTLS（TCP+TLCP）凭据           |
| `WithClientMetrics(m)`     | 注入指标收集器                      |
| `WithDrainTimeout(d)`      | Close 排空超时                      |

### 服务端选项

| 选项                        | 说明                              |
| --------------------------- | --------------------------------- |
| `WithV1(cfg)`               | 启用 V1（QUIC）监听               |
| `WithNTLS(cfg)`             | 启用 NTLS（TCP+TLCP）监听         |
| `WithoutV1()`               | 关闭默认 V1 监听（仅用 NTLS）     |
| `WithAuth(validator)`       | 设置令牌验证器                    |
| `WithPolicy(policy)`        | 设置服务端策略（profile/ack_mode/credits/limits） |
| `WithSink(opts, handler)`   | 注册数据处理器（必需）            |
| `WithSinkQueue(size, maxB)` | sink 队列条数+字节双限界          |
| `WithSinkDeadline(d)`       | handler done 超时（合成 released） |
| `WithMetrics(metrics)`      | 注入指标收集器                    |
| `WithRedirectChecker(fn)`   | HA leader 重定向检查              |
| `WithOnSession(fn)`         | 会话生命周期回调                  |
| `WithMaxConcurrentConns(n)` | 并发连接上限                      |

## 示例

完整可运行示例位于 [`examples/`](./examples/)：

- [`examples/basic_client/`](./examples/basic_client/) —— 最小客户端：Dial + SendBatch + RESULT 回调
- [`examples/basic_server/`](./examples/basic_server/) —— 最小服务端：监听 + WithSink + 认证

示例使用 `test/data/certificates/` 下的测试证书（`make gen-certs` 生成）。

## 架构

```
┌─────────────────────────────────┐
│  client.go / server.go          │  门面：Option API + 版本→profile 映射
├─────────────────────────────────┤
│  v1/  ntls/                     │  传输 binding（QUIC / TCP+TLCP）
├─────────────────────────────────┤
│  internal/protocol              │  协议核心（1-RTT 握手/credit/RESULT/状态机）
│  internal/binding               │  共享 accept/握手编排
├─────────────────────────────────┤
│  core/                          │  帧编码 · 密钥日程 · Envelope · credit 账本 · 集合窗口
└─────────────────────────────────┘
```

### 接口桥接

- `core.BatchHandler`（`OnBatch` 注册式）— 数据投递（Raw/Decoded 按 SinkOptions 供给）
- `core.TokenValidator`（`ResolveToken` 必选）— 认证令牌验证与 token_proof 校验
- `core.OnSession` — 会话生命周期回调
- `core.RedirectChecker` — HA leader 重定向
- `core.CorrelationDeduper` — 跨连接重发的应用层幂等去重（LRU + TTL；配合 `Batch.Meta.Correlation`）

## 许可证

MIT License
