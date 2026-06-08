# MBTA-Go

MBTA (Mebsuta Binary Transport Agent) — 高性能二进制日志传输协议库。

## 协议版本

| 版本 | ALPN | 传输层 | 状态 |
|------|------|--------|------|
| v1 | `mbta/1` | QUIC + TLS 1.3 | ✅ 可用 |
| v2 | `mbta/2` | QUIC + RFC 8998 GM TLS 1.3 | 🔲 计划中 |
| ntls | `mbta-ntls/1` | TCP + NTLS/TLCP | 🔲 计划中 |

## 安装

```bash
go get github.com/iuboy/mbta-go
```

## 快速开始

### 客户端（发送日志）

```go
import (
    mbtago "github.com/iuboy/mbta-go"
    "github.com/iuboy/mbta-go/core"
    v1 "github.com/iuboy/mbta-go/v1"
)

client, err := mbtago.NewClient(
    mbtago.WithServer("localhost:7400"),
    mbtago.WithAgentID("my-agent"),
    mbtago.WithV1Credentials(&v1.ClientCredentials{...}),
)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

chunkID, err := client.SendBatch(ctx, &core.SignalBatch{Signals: signals}, "tag", "source")
```

### 服务端（接收日志）

```go
import (
    mbtago "github.com/iuboy/mbta-go"
    "github.com/iuboy/mbta-go/core"
)

server, err := mbtago.NewServer(
    mbtago.WithEventSink(mySink), // 实现 core.EventSink 接口
    mbtago.WithAuth(core.NewStaticTokenValidator("secret")),
)
```

## 架构

```
┌─────────────────────────────────┐
│          mbta-go                │
├─────────────────────────────────┤
│  client.go / server.go         │  多版本门面
├─────────────────────────────────┤
│  v1/  v2/  ntls/               │  版本实现
├─────────────────────────────────┤
│  core/                         │  帧编码 · 信封 · 会话 · 流控
├─────────────────────────────────┤
│  testing/                      │  测试辅助
└─────────────────────────────────┘
```

## 接口桥接

协议层通过以下接口与业务层解耦：

- `core.EventSink` — 事件投递
- `core.DurableEventSink` — 带 ACK 反馈的事件投递
- `core.TokenValidator` — 认证令牌验证

## 许可证

MIT License
