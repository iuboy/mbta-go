# 提示词工程约定（AI 协作面）

本仓库"面向 AI 编码代理的提示词面"（下称**提示词面**）的编写与维护约定。
2026-10 基于对 agents.md 规范、Anthropic Claude Code 官方记忆文档与主流提示词
工程指南的检索结论制定（参考见文末）。

## 提示词面清单

| 文件 | 角色 | 维护规则 |
|------|------|----------|
| [AGENTS.md](../AGENTS.md)（根） | **单一真相**：项目约定 + 高频踩坑点，代理中立（Codex/Cursor/Claude Code 等通用） | 项目约定只改这里 |
| [CLAUDE.md](../CLAUDE.md)（根） | Claude Code 入口：仅 `@AGENTS.md` 导入 + 工具自动块 | **NEVER** 复制 AGENTS.md 内容进来（防双文件漂移） |
| 子目录 `AGENTS.md`（预留） | monorepo/子树覆盖 | 未见需要不创建；创建时遵循"最近者优先"覆盖语义 |
| GitNexus 自动块 | 工具自动生成 | 只在 `<!-- gitnexus:start/end -->` 标记外编辑 |

## 检索结论（2026-10，落地为本仓库规则）

来自 [agents.md 规范](https://agents.md)、[Claude Code memory 官方文档](https://code.claude.com/docs/en/memory)、
[dair-ai/Prompt-Engineering-Guide](https://github.com/dair-ai/prompt-engineering-guide)、
[Anthropic 官方提示词教程](https://github.com/anthropics/prompt-eng-interactive-tutorial)：

1. **单一真相 + 导入**：CLAUDE.md 用 `@AGENTS.md` 导入，禁止逐字复制两份维护
   （社区共识：双文件漂移是头号事故源）。
2. **精炼高信号**：目标 < 200 行（Anthropic 对指令遵循率的经验值）；只写"差异
   信息"——linter/CONTRIBUTING/README 能查到的不进提示词面，链接出去（渐进披露）。
3. **可验证指令**：规则须可执行可检验（"提交前 `make check` 全绿"），不写形容词
   堆砌（"写出高质量代码"类规则无效）。
4. **强调词稀用**：`MUST`/`NEVER` 只给真正不可违反的红线；滥用会稀释全部规则的权重。
5. **正例优于禁令**：给一个对的操作样例（如注释风格示例）胜过十条否定句。
6. **声明权威顺序**：用户当前指令 > 提示词面 > 代码 > 文档，显式写出，避免代理
   自行猜测冲突裁决。
7. **结构化标题**：代理按章节检索，`##` 级标题要可预测（概览/环境/命令/约定/提交）。

## 本仓库历史教训（规则的现实依据，2026-10 核实）

每条规则背后都有本仓库真实发生过的事故，修改提示词面前先读一遍：

| 事故 | 教训 → 对应规则 |
|------|-----------------|
| 注释引用失效 spec 锚点（§6.2.2 等已不存在）+ 能力名错写 `w3c_trace_context`（代码注册名 `trace_context`，按注释配置会 fail-fast），2026-10 注释审查修复约 10 处 | 引用必须可解析 → 代码约定「锚点巡检 grep」 |
| CONTRIBUTING.md 引用**不存在的 `make test-conf` 目标**、"固定版本 v2.12.2" 与 CI 实际（action@v7 无 pin）不符，2026-10 核实发现 | 提示词面/文档引用的命令与版本 MUST 逐一对照 Makefile/CI 配置核实，不凭记忆转写 |
| AGENTS.md 初稿把信号类型写成 "log/metric/span/event/profile"，对码核实实为七类 log/gauge/counter/histogram/summary/span/profile（`core/signal.go`） | 一切事实主张 MUST 对码核实——提示词面作者同样会臆造 |
| v1/ntls 客户端 wrapper 逐字等价 8 方法 40 行（维护税），后泛型化为 `versionWrapper`（审查 F14 裁决） | 共享面收敛到 internal/binding/protocol；NEVER 复制出第二份逐字等价实现 |
| facade 共享配置字段两处并行拷贝，Commands 字段在 server 侧漏抄（审查 F1） | 并行拷贝点 MUST 注释互指同步义务 |
| `CreditManager` 更名后 `AdmissionWindow` 旧名残留于测试注释 | 重命名走 GitNexus rename（理解调用图），完成后全仓 grep 旧名清残留 |

## 修改 checklist

改任何提示词面前自问：

- [ ] 这条信息是否 CONTRIBUTING.md / linter 配置 / 文档里已有？（是 → 链接，不复制）
- [ ] 指令是否可验证（能翻译成一条命令或一个可判定动作）？
- [ ] 是否新增了非红线的 MUST/NEVER？（重新考虑降级为普通陈述）
- [ ] 是否给出了正例或反例？
- [ ] 行数预算：根 AGENTS.md **自留内容 ≤ 90 行**（GitNexus 自动块约 44 行由工具控制，
  不计入预算；总行数参考线 130，对标社区 < 200 的宽松上限仍留有余量）。
- [ ] 改完跑一遍真实任务验证（让代理冷启动执行一个典型任务，观察是否遵守）。

## 反模式

- 在 CLAUDE.md 复制 AGENTS.md 内容（本次重构修复的问题：两文件曾逐字等同 44 行）。
- 把长文档内联进提示词面（应链接 `docs/`，由代理按需读取）。
- 写与 CONTRIBUTING.md 重复的命令清单全文（只写差异 + 指针）。
- 用提示词面承载业务文档（协议语义属于 docs/mbta-core-spec.md）。
- 在自动生成块（gitnexus markers 内）手工修改内容。

## 参考文献

- [agents.md — 开放格式规范](https://agents.md)
- [Claude Code memory 官方文档](https://code.claude.com/docs/en/memory)
- [dair-ai/Prompt-Engineering-Guide](https://github.com/dair-ai/prompt-engineering-guide)
- [anthropics/prompt-eng-interactive-tutorial](https://github.com/anthropics/prompt-eng-interactive-tutorial)
- [promptslab/Awesome-Prompt-Engineering](https://github.com/promptslab/awesome-prompt-engineering)
- [OpenAI Codex：Custom instructions with AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md)
