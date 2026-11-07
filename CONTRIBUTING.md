# Contributing to MBTA-Go

感谢参与 MBTA-Go 开发！本文档涵盖开发流程、测试约定与代码质量要求。
AI 编码代理（Codex/Cursor/Claude Code 等）的项目约定见 [AGENTS.md](./AGENTS.md)，
提示词面的编写规则见 [docs/prompt-engineering.md](./docs/prompt-engineering.md)。

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
make test           # 单元 + conformance（-race -cover，无需证书/端口）
go test ./internal/conformance/  # 仅 conformance（FakeTransport 协议验证）
make test-int       # 集成 / e2e（需要证书 + 端口）
make test-all       # 全量测试（含集成）
make lint           # golangci-lint（CI 经 golangci-lint-action@v7 执行）
make vet            # go vet
make gen-certs      # 生成 v1/ntls 两套测试证书（见下节）
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

集成测试需要 TLS / TLCP 证书。证书**不入库**（防止私钥泄露），一条命令生成两套：

```bash
make gen-certs   # = bash test/data/certificates/gen_certs.sh + go run test/data/ntls/gen_certs.go
```

生成位置：v1（QUIC + TLS 1.3）证书在 `test/data/certificates/`，ntls（TLCP）SM2 双证书
在 `test/data/ntls/`——两处均已 `.gitignore` 忽略。

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

CI 会跑 `buf breaking` 报告 wire 不兼容变更——本项目**默认允许破坏性变更、
无兼容要求**（见下），该检查是知情门禁而非阻断门禁：看报告确认破坏面是
有意识的决策即可合入，破坏性内容写入 CHANGELOG「破坏性变更」小节。

## 版本与破坏性策略

自 r3 协议重写起（2026-11-07），库版本自 `v0.1.0-0` 重新起算（旧世系
v0.1.0–v0.7.0 标签已移除，CHANGELOG 保留历史条目）：

- 版本号恒为 `v0.1.<patch>-<rev>`，只有 patch 与 rev 递增。
- **默认进行破坏性变更，无兼容要求**：除非维护者明确要求保持兼容，API/
  proto/wire 破坏性调整不做兼容别名、不做迁移期、不升 minor——调用方随
  版本更新同步修正。
- 发版流程：CHANGELOG 定版（patch 递增、rev 复位 0；同 patch 热修递增
  rev）→ 打 `v0.1.x-<rev>` 标签推送 → CI release job 出 Release。
- 目标版本号已被占用即视为重复：rev 向后延续至下一个未占用值
  （`v0.1.2-x` → `v0.1.2-x+1` …），已发布版本号永不重用或覆盖。

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
