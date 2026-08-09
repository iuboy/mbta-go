# Contributing to MBTA-Go

感谢参与 MBTA-Go 开发！本文档涵盖开发流程、测试约定与代码质量要求。

## 开发环境

MBTA-Go 使用 [Go workspace](https://go.dev/ref/mod#workspaces) 引入私有国密依赖
`pollux-go`（SM2/SM3/SM4/TLCP），该依赖**不在 `go.mod` 中声明**，通过 `go.work` 引入。

```bash
git clone git@github.com:iuboy/mbta-go.git
git clone git@github.com:iuboy/pollux-go.git ../pollux-go
```

`go.work` 已在 `.gitignore` 中——每位贡献者本地维护，不提交。

## 常用命令

```bash
make help           # 列出所有目标
make test           # 单元 + conformance 测试（排除 integration）
make test-conf      # 仅 conformance（FakeTransport 协议验证）
make test-int       # 集成 / e2e（需要证书 + 端口）
make test-all       # 全量测试（含集成）
make lint           # golangci-lint（固定版本 v2.12.2）
make vet            # go vet
make proto          # 从 .proto 重新生成 corepb/
make proto-lint     # lint .proto
make proto-breaking # 检测 vs main 的 wire 不兼容变更
make cover          # HTML 覆盖率报告
```

## 测试约定

### Build tags

- **默认**（无 tag）：`go test ./...` 只跑单元 + conformance，不需要证书/端口。
- **`integration` tag**：集成 / e2e 测试，需要 TLS/TLCP 证书 + 可用端口。
  ```bash
  go test -tags integration ./...
  ```
- **`stress` tag**：大规模压测（`core/perf_scale_test.go`），默认不跑以免拖慢 CI。

### 证书生成

集成测试需要 TLS / TLCP 证书。证书**不入库**（防止私钥泄露），由生成脚本产生：

```bash
# v1 (QUIC + TLS 1.3) 测试证书
./test/data/certificates/gen_certs.sh

# ntls (TLCP) 测试证书——见 test/data/ntls/ 下的生成说明
```

生成后证书位于 `test/data/certificates/`（已被 `.gitignore` 忽略）。

### 测试同步原则

- **避免固定 `time.Sleep`** 当同步原语——用 channel / `eventually` 轮询模式
  （参考 `test/integration_test.go` 的 `waitCount`/`waitAddr`）。
- **race 检测**：并发相关改动必须 `go test -race ./...` 通过。

## 代码质量

提交前确保：

```bash
gofmt -l .          # 无输出
go vet ./...        # 无报错
make lint           # golangci-lint 通过
make proto-lint     # proto lint 通过
go mod tidy         # go.mod / go.sum 干净
git diff --exit-code go.mod go.sum
```

## Protobuf 改动

`corepb/*.pb.go` 是生成文件（`DO NOT EDIT`）。改 `.proto` 后：

```bash
make proto          # 重新生成
git diff corepb/    # 确认生成内容
```

CI 会跑 `buf breaking` 检测 wire 不兼容变更——破坏性协议改动需 bump 版本 + 文档说明。

## Commit 规范

使用[约定式提交](https://www.conventionalcommits.org/)前缀：

- `feat:` 新功能
- `fix:` bug 修复
- `refactor:` 重构（无行为变化）
- `test:` 测试
- `docs:` 文档
- `chore:` 杂项 / 依赖

破坏性协议改动加 `!` 后缀（如 `feat!: ...`）。

## 安全报告

发现安全漏洞请**不要**开 public issue——私信维护者。
