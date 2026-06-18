# MBTA-Go

MBTA (Mebsuta Binary Transport Agent) — 高性能二进制日志传输协议库。

## 协议版本

| 版本 | ALPN          | 传输层                     | 状态      |
| ---- | ------------- | -------------------------- | --------  |
| v1   | `mbta/1`      | QUIC + TLS 1.3             | ✅ 可用   |
| v2   | `mbta/2`      | QUIC + RFC 8998 GM TLS 1.3 | 🔲 计划中 |
| ntls | `mbta-ntls/1` | TCP + NTLS/TLCP            | 🔲 计划中 |

## 安装

```bash
go get github.com/iuboy/mbta-go
```

> **本地开发 / 源码构建说明**
>
> v2（QUIC + RFC 8998 国密 TLS）与 ntls（TCP + TLCP）绑定依赖私有库
> `github.com/iuboy/pollux-go`（提供 SM2/SM3/SM4/TLCP 实现），该依赖通过
> [Go workspace](https://go.dev/ref/mod#workspaces)（`go.work`）引入，**不在
> `go.mod` 中声明**。
>
> 从源码构建或运行测试前，需将 `pollux-go` 仓库 clone 到与本项目同级目录：
>
> ```bash
> git clone git@github.com:iuboy/pollux-go.git ../pollux-go
> ```
>
> 仓库已附带 `go.work`（已在 `.gitignore` 中），Go 工具链会自动识别。仅 `go get`
> 作为外部依赖使用 v1（QUIC + TLS 1.3）功能时无需 pollux-go。

## 快速开始

### Dial 一行连接

最简单的方式，创建 + 连接 + 返回就绪的客户端：

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

// client 已就绪，直接发送
chunkID, err := client.SendBatch(ctx, &core.SignalBatch{
    Signals: []*core.SignalRecord{
        {SignalType: "log", Body: "hello world"},
    },
}, "app", "host-1")
```

### 手动创建客户端

```go
client, err := mbta.NewClient(
    mbta.WithServer("localhost:7400"),
    mbta.WithAgent("my-agent", "hostname", "secret-token"),
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

chunkID, err := client.SendBatch(ctx, batch, "tag", "source")
```

### 服务端

```go
server, err := mbta.NewServer(
    mbta.WithV1(v1.QUICServerConfig{
        Address:     "0.0.0.0:7400",
        Credentials: &v1.ServerCredentials{
            CertFile: "server.pem",
            KeyFile:  "server.key",
        },
    }),
    mbta.WithEventSink(mySink),  // 实现 core.EventSink 接口
    mbta.WithAuth(core.NewStaticTokenValidator(map[string]string{
        "secret-token": "my-agent",
    })),
)
if err != nil {
    log.Fatal(err)
}

if err := server.Start(ctx); err != nil {
    log.Fatal(err)
}
```

## ACK 回调

注册回调以在服务端确认批次时收到通知：

```go
client.SetACKHandler(func(chunkID, ackMode string) {
    switch ackMode {
    case "durable":
        // 批次已持久化，可安全丢弃本地缓存
    case "accepted":
        // 批次已接受但尚未持久化
    case "nack":
        // 批次被拒绝，需要重试
    }
})
```

## 错误码参考

所有 MBTA 错误携带数字码 + 字符串码，可通过 `core.GetErrorCode()` 提取：

| 范围      | 类别 | 常量示例        |
| --------- | ---- | --------------- |
| 1000-1099 | 配置 | `NumConfig`     |
| 2000-2099 | 传输 | `NumTransport`  |
| 3000-3099 | 协议 | `NumProtocol`   |
| 4000-4099 | 数据 | `NumBatch`      |
| 5000-5099 | 流控 | `NumWindowFull` |
| 6000-6099 | 存储 | `NumSpool`      |
| 7000-7099 | 版本 | `NumVersion`    |

### 程序化错误匹配

```go
switch core.GetErrorCode(err) {
case core.NumAuth:
    // 认证失败
case core.NumWindowFull:
    // 窗口满，等待后重试
case core.NumThrottle:
    // 被限流
case core.NumSpool:
    // 本地存储错误
default:
    // 其他错误
}

// 字符串码匹配
if core.GetErrorCodeString(err) == core.ErrTransport {
    // 传输层错误
}

// errors.Is 也支持（按 NumCode 匹配）
if errors.Is(err, core.NewError(core.NumAuth, core.ErrAuth, "")) {
    // 认证错误
}
```

## 配置选项

### 客户端选项

| 选项                       | 说明                  |
| -------------------------- | --------------------- |
| `WithServer(addr)`         | 设置服务端地址        |
| `WithAgent(id, host, tk)`  | 设置 Agent 标识和令牌 |
| `WithVersionPriority(vs)`  | 设置版本优先级列表    |
| `WithV1Credentials(creds)` | 配置 V1 TLS 凭据      |
| `WithV2Credentials(creds)` | 配置 V2 GM TLS 凭据   |
| `WithClientNTLS(cfg)`      | 配置 NTLS 凭据        |

### 服务端选项

| 选项                   | 说明                  |
| ---------------------- | --------------------- |
| `WithV1(cfg)`          | 启用 V1 + QUIC 配置   |
| `WithV2(cfg)`          | 启用 V2 + GM TLS 配置 |
| `WithNTLS(addr, cfg)`  | 启用 NTLS 配置        |
| `WithAuth(validator)`  | 设置令牌验证器        |
| `WithPolicy(policy)`   | 设置会话策略          |
| `WithEventSink(sink)`  | 设置事件接收器        |
| `WithMetrics(metrics)` | 设置指标收集器        |

## 架构

```
┌─────────────────────────────────┐
│          mbta-go                │
├─────────────────────────────────┤
│  client.go / server.go          │  多版本门面
├─────────────────────────────────┤
│  v1/  v2/  ntls/                │  版本实现
├─────────────────────────────────┤
│  core/                          │  帧编码 · 信封 · 会话 · 流控
├─────────────────────────────────┤
│  testing/                       │  测试辅助
└─────────────────────────────────┘
```

### 接口桥接

协议层通过以下接口与业务层解耦：

- `core.EventSink` — 事件投递
- `core.DurableEventSink` — 带 ACK 反馈的事件投递
- `core.TokenValidator` — 认证令牌验证

## 许可证

MIT License
