# 目录结构与文件职责

## 全貌

```
code-security-scanner/
├── README.md                                    # 项目介绍入口
├── SKILL.md                                     # 技能入口（委托：触发条件、流程、规则、契约）
├── LICENSE                                      # Apache License 2.0
├── docs/                                        # 文档（给人看的说明）
│   ├── getting-started.md
│   ├── installation.md
│   ├── workflow.md
│   ├── structure.md                             # 本文件
│   ├── concept.md
│   └── manual.md
└── prompts/                                     # 审计知识库（给助手用的规范）
    ├── 00-index.md
    ├── 01-secrets-and-credentials.md
    ├── 02-injection.md
    ├── 03-authn-authz.md
    ├── 04-cryptography.md
    ├── 05-dependency-supply-chain.md
    ├── 06-sensitive-data-exposure.md
    ├── 07-config-and-infrastructure.md
    ├── 08-business-logic-and-race-conditions.md
    ├── 09-file-and-path-handling.md
    ├── 10-logging-error-handling.md
    └── 11-report-spec.md
```

两个目录职责严格分离：

| 目录 | 读者 | 作用 | 是否参与审计执行 |
|------|------|------|-----------------|
| `prompts/` | AI 助手 | 审计知识、判定标准、报告规范 | **是**，执行时逐份读取 |
| `docs/` | 人 | 使用说明、设计说明、参考手册 | 否，仅用于理解与查阅 |

修改审计行为 → 改 `prompts/`；改说明文档 → 改 `docs/`。

## 根目录文件

### SKILL.md

技能入口。包含：

- **frontmatter**：`name`（`repo-security-audit`）与 `description`（含功能与触发条件）
- **何时使用 / 不应使用**：划定适用范围
- **输入参数**：目标路径、维度、输出目录、深度
- **执行流程**：5 个阶段的概要（细节见 [workflow.md](workflow.md)）
- **硬性规则**：7 条不可违反的约束（禁止编造、必须给证据、凭证脱敏等）
- **严重等级定义**：5 级判定标准
- **输出契约**：两份报告的位置与对话回复结构
- **维度文件索引**：指向 `prompts/` 的 12 个文件

**与 `prompts/` 的依赖关系**：`SKILL.md` 通过相对路径引用 `prompts/`，因此两者必须保持同级。移动或复制时必须整体搬迁。

### README.md

面向项目访客的介绍：特点、目录结构、使用方式、维度总览、打分算法、设计约束、已知限制。内容上不重复 `docs/`，只做概览与导航。

## prompts 目录

### 00-index.md —— 调度中枢

审计的**唯一编排依据**，每次审计开始前必须先读。包含：

- **维度标识表**：10 个维度的唯一标识、文件名、默认优先级
- **编排顺序**：P0 → P1 → P2 的执行顺序及其理由
- **按技术栈加权**：不同技术栈的重点维度调整
- **信任边界清单**：Source / Sink / 校验手段的枚举
- **快速检索词库**：通用高危模式、凭证模式、危险配置模式
- **深度模式说明**：快扫 / 标准 / 深度的覆盖差异
- **输出要求**：`dimension_coverage` 的写入规范

### 01–10 —— 审计维度

每个维度文件采用**统一的六段式结构**：

| 章节 | 作用 |
|------|------|
| 审计目标 | 本维度要解决什么问题 |
| 检索线索 | 可直接执行的正则 / Glob 模式，按子类分组 |
| 判定标准 | 什么算成立、什么算误报、判定要点 |
| 分级参考 | 具体情形 → 严重等级的映射表 |
| 修复建议要点 | 该给出什么建议、必须包含哪些要素 |
| 输出要求 | 本维度 finding 的填写规范与 CWE 参考 |

**统一结构的目的**：让助手在任一维度中都能预期「在哪找到什么」，降低漏读概率。

### 11-report-spec.md —— 报告规范

定义两份产出物的**唯一格式标准**：

- JSON 完整 schema 与字段约束表
- 风险打分算法
- HTML 报告的硬性约束（单文件、零外部依赖、禁止硬编码 `height` 等）
- 页面结构图与必须实现的 9 项交互
- 视觉规范（等级配色、置信度展示）
- 数据嵌入方式与渲染内容映射表
- 生成后自检清单

## docs 目录

| 文件 | 回答的问题 |
|------|-----------|
| [getting-started.md](getting-started.md) | 怎么最快跑通一次审计？ |
| [installation.md](installation.md) | 有哪几种安装方式？怎么接入 Trae？ |
| [workflow.md](workflow.md) | 每个阶段具体做什么？深度模式差在哪？ |
| [structure.md](structure.md) | 每个文件负责什么？怎么扩展？ |
| [concept.md](concept.md) | 为什么这样设计？关键术语是什么意思？ |
| [manual.md](manual.md) | 所有参数、字段、规则、FAQ 的完整参考 |

## 维度标识表

报告中 `dimensions` / `by_dimension` / `dimension_coverage` / `dimensions_run` 字段**必须使用下表标识**，不得自造别名。

| 标识 | 维度 | 优先级 | 文件 |
|------|------|--------|------|
| `secrets` | 密钥与凭证泄露 | P0 | `01-secrets-and-credentials.md` |
| `injection` | 注入类漏洞 | P0 | `02-injection.md` |
| `authn-authz` | 认证与授权 | P0 | `03-authn-authz.md` |
| `cryptography` | 密码学实现 | P1 | `04-cryptography.md` |
| `supply-chain` | 依赖与供应链 | P1 | `05-dependency-supply-chain.md` |
| `sensitive-data` | 敏感数据暴露 | P1 | `06-sensitive-data-exposure.md` |
| `config-infra` | 配置与基础设施 | P1 | `07-config-and-infrastructure.md` |
| `business-logic` | 业务逻辑与并发 | P2 | `08-business-logic-and-race-conditions.md` |
| `file-network` | 文件、路径与网络请求 | P1 | `09-file-and-path-handling.md` |
| `logging` | 日志与异常处理 | P2 | `10-logging-error-handling.md` |

优先级含义：P0 必跑；P1 在标准及以上深度必跑；P2 在深度模式下必跑。

## 命名约定

| 对象 | 约定 | 示例 |
|------|------|------|
| `prompts/` 下的文件 | 两位数字编号 + 连字符小写英文 | `03-authn-authz.md` |
| `docs/` 下的文件 | 连字符小写英文，无编号 | `getting-started.md` |
| 维度标识 | 连字符小写英文，语义对齐文件名 | `authn-authz` |
| finding 编号 | `SEC-` + 三位数字 | `SEC-001` |
| 报告文件名 | 固定前缀 | `security-audit-report.json` |

编号顺序即默认执行顺序，新增维度应插入对应位置并保持编号连续。

## 如何扩展

### 新增一个审计维度

1. 在 `prompts/` 下创建 `11-<name>.md`（原 `11-report-spec.md` 顺延为 `12-report-spec.md`），按六段式结构编写
2. 在 [00-index.md](../prompts/00-index.md) 的维度表中登记：编号、标识、文件名、名称、优先级
3. 在 [SKILL.md](../SKILL.md) 的「维度文件索引」表中追加一行
4. 在本文件的「维度标识表」中追加一行
5. 更新 [README.md](../README.md) 的维度表与计数（「10 个维度」→ 新数量）
6. 更新 [manual.md](manual.md) 的维度清单

**注意**：改名或增删维度时，`prompts/11-report-spec.md` 中 `dimensions_run` 的示例数组需要同步更新。

### 调整某个维度的判定标准

直接修改对应的 `prompts/NN-*.md`。**不要**把判定逻辑散落到 `SKILL.md` 或 `docs/` 中——审计行为的唯一来源是 `prompts/`。

### 修改报告格式

改 `prompts/11-report-spec.md`。若字段有增删，同步更新 [manual.md](manual.md) 的字段参考表。

## 下一步

- 理解设计动因 → [concept.md](concept.md)
- 查阅完整参考 → [manual.md](manual.md)
