# 安装与接入

本技能是**纯文档形态**的 Skill，没有二进制、没有运行时依赖，安装的本质是「把文件放到助手能读到的地方」。

## 环境要求

| 项 | 要求 |
|----|------|
| Git | 任意近期版本（仅用于获取本技能） |
| 操作系统 | 无限制（macOS / Linux / Windows） |
| 运行时 | 无。不需要 Python / Node / JDK |
| 外部工具 | 无。不需要 Semgrep / gitleaks / trivy / npm audit |
| 磁盘占用 | < 100 KB |
| 网络 | 仅在克隆时需要；审计过程完全离线 |

## 方式一：克隆到本地（推荐）

```bash
git clone https://github.com/visual-req/code-security-scanner.git ~/tools/code-security-scanner
```

使用时显式指向路径：

```
按照 ~/tools/code-security-scanner/SKILL.md 的流程，审计 ./my-service
```

**优点**：位置自由，不受任何目录约定约束，可同时给多个项目使用。

## 方式二：作为项目子模块

把技能固定在某个项目里，便于团队共享同一版本：

```bash
cd /path/to/your-repo
git submodule add https://github.com/visual-req/code-security-scanner.git tools/code-security-scanner
git commit -m "chore: 引入安全审计技能"
```

其他成员克隆后初始化：

```bash
git submodule update --init --recursive
```

**注意**：子模块目录会被纳入目标仓库，审计时要把它加入 `scope.excluded`，避免审计工具自身。

## 方式三：接入 Trae 技能加载器

Trae 的加载器默认扫描 `.trae/skills/<skill-name>/SKILL.md`。本技能的 `SKILL.md` 位于仓库根目录（按设计要求），因此默认**不会被自动注册**。若希望它出现在可调用技能列表中，把技能目录链接过去：

```bash
mkdir -p .trae/skills
ln -s /path/to/code-security-scanner .trae/skills/repo-security-audit
```

Windows（需管理员权限或开发者模式）：

```powershell
New-Item -ItemType SymbolicLink -Path ".trae\skills\repo-security-audit" -Target "C:\path\to\code-security-scanner"
```

链接完成后重启会话，技能应以 `repo-security-audit` 出现在可用技能列表中，此后可直接说「审计 ./my-repo 的安全性」而无需指定路径。

**注意**：软链方式下 `prompts/` 会一并被链接，技能内部的相对路径仍然有效。

## 方式四：仅复制文件

若只需临时使用：

```bash
cp -r /path/to/code-security-scanner/SKILL.md /path/to/code-security-scanner/prompts /your/workspace/
```

必须具备的两个组成部分：`SKILL.md` 与 `prompts/` 目录（且保持同级关系，`SKILL.md` 内部按相对路径引用 `prompts/`）。

## 验证安装

安装后，让助手读取技能入口并复述维度清单：

```
读一下 <安装路径>/SKILL.md 和 <安装路径>/prompts/00-index.md，
列出所有审计维度及其标识
```

预期返回 10 个维度，标识分别为 `secrets`、`injection`、`authn-authz`、`cryptography`、`supply-chain`、`sensitive-data`、`config-infra`、`business-logic`、`file-network`、`logging`。

若返回数量不符或路径报错，检查：

1. `SKILL.md` 与 `prompts/` 是否在同一层级
2. `prompts/` 下是否 12 个文件齐全（`00`–`11`）
3. 路径中是否含空格或中文导致解析失败

## 更新

```bash
cd /path/to/code-security-scanner
git pull
```

若使用子模块：

```bash
git submodule update --remote tools/code-security-scanner
```

## 卸载

- 方式一 / 方式四：删除对应目录即可
- 方式二：`git submodule deinit -f tools/code-security-scanner && git rm -f tools/code-security-scanner`
- 方式三：删除 `.trae/skills/repo-security-audit` 软链即可，不影响原始文件

卸载不会影响已生成的报告——它们是独立文件，位于各个被审计仓库中。

## 下一步

- [getting-started.md](getting-started.md) —— 跑通第一次审计
- [workflow.md](workflow.md) —— 理解执行流程
