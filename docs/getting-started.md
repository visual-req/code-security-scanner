# 快速上手

5 分钟内跑通一次仓库安全审计。

## 前置条件

- 一个可访问的本地代码仓库（任意语言）
- 一个具备文件读写能力的 AI 助手（需能读代码、执行 Grep/Glob、写文件）
- 无需安装任何安全扫描工具

## 最小步骤

### 1. 获取本技能

```bash
git clone https://github.com/visual-req/code-security-scanner.git
```

详见 [installation.md](installation.md)。

### 2. 向助手发出指令

在对话中显式指向 `SKILL.md`：

```
按照 /path/to/code-security-scanner/SKILL.md 的流程，
审计 /path/to/your-repo 的安全性
```

助手会：

1. 读取 `SKILL.md` → 再读 `prompts/00-index.md` 获取维度清单与编排顺序
2. 侦察目标仓库（技术栈、规模、入口面、审计边界）
3. 按 P0 → P1 → P2 顺序逐个维度审计
4. 汇总去重、定级打分
5. 在目标仓库根目录写出两份报告

### 3. 查看结果

```
/path/to/your-repo/security-audit-report.html   # 浏览器打开
/path/to/your-repo/security-audit-report.json   # 机器可读
```

HTML 报告支持：左侧维度的目录导航、滚动位置感应、按严重等级与维度筛选、关键词搜索、代码片段高亮、移动端适配。

## 带参数的指令示例

```
审计 /path/to/your-repo，只跑 injection 和 authn-authz 两个维度，
报告输出到 /tmp/audit/，用深度模式
```

```
快速看下 /path/to/your-repo 有没有明显安全问题，不用太细
```

```
审计 /path/to/your-repo 的初始化流程，重点是凭证泄露和依赖供应链
```

可用的维度标识见 [structure.md](structure.md#维度标识表)。

## 一次典型审计的产出

助手在对话中的回复结构（保持在 5 段以内）：

1. 一句话总体结论 + 风险分 + 风险等级
2. 各等级问题数量分布
3. Critical / High 问题清单（编号、标题、位置、一句话影响）
4. 本次审计的边界与局限（1–2 条）
5. 两份报告的文件路径

若发现 Critical 级别问题（如生产凭证硬编码），助手会**在回复开头立即预警**，然后继续完成其余维度。

## 常见问题

**Q：为什么助手说「无法确认漏洞可利用」？**

这是刻意的。纯静态审计无法证明漏洞可达性，强行下结论会产生误报。报告中的 `confidence` 字段区分了「置信度」，低置信度条目会标注 `needs_manual_review: true`。

**Q：报告会不会漏掉问题？**

会。静态审计的上限就是「代码里写得出来的问题」。运行时配置、云平台策略、外部依赖的真实漏洞状态都需要另行核对。报告底部 `limitations` 会明确列出未覆盖范围。

**Q：能让助手直接改代码修漏洞吗？**

可以，但需要明确要求。默认流程只出报告、不改目标仓库任何业务代码。

**Q：审计会不会很慢？**

取决于仓库规模。大仓库建议先用「快扫」深度，或只指定关心的维度，详见 [workflow.md](workflow.md#深度模式)。

## 下一步

- 想理解为什么这样设计 → [concept.md](concept.md)
- 想看完整的执行细节 → [workflow.md](workflow.md)
- 想查参数与字段定义 → [manual.md](manual.md)
- 想知道每个文件干什么 → [structure.md](structure.md)
