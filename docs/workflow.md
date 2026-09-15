# 执行流程详解

本文展开 [SKILL.md](../SKILL.md) 的执行流程，说明每个阶段做什么、产出什么、有哪些决策点。

整体链路：

```
确定范围 → 侦察 → 逐维度审计 → 数据流串联 → 去重定级 → 产出报告 → 自检
   ↑                                    ↓
   └──────────── 交付前提是自检全通过 ────┘
```

## 阶段 0 · 确定范围与侦察

**输入**：目标仓库路径、审计维度、深度
**产出**：`meta.scope`、`meta.tech_stack`

### 0.1 判断技术栈

读仓库根的文件与配置：

| 文件 | 推断 |
|------|------|
| `package.json` / `tsconfig.json` | Node / TypeScript |
| `pom.xml` / `build.gradle` | Java / Kotlin + 构建工具 |
| `go.mod` | Go |
| `requirements.txt` / `pyproject.toml` / `manage.py` | Python |
| `Cargo.toml` | Rust |
| `composer.json` / `artisan` | PHP / Laravel |
| `*.csproj` | .NET |
| `Dockerfile` / `docker-compose.yml` / `k8s/` | 容器化部署 |
| `.github/workflows/` | GitHub Actions |

同时读 `README` 获取业务语义——**审计业务逻辑维度必须先理解业务**。

### 0.2 划定审计边界

必须排除的目录（写入 `scope.excluded` 并给出理由）：

```
node_modules  vendor  dist  build  target  .venv  venv  __pycache__
*.min.js  *.min.css  *.map  第三方 SDK 目录
test  tests  __tests__  fixtures  mock  测试数据
生成的代码（protobuf/gRPC 产物、ORM 自动生成实体）
二进制文件、图片、字体
```

**边界必须显式声明**——报告读者需要知道哪些地方没看。

### 0.3 识别入口面

找到「外部能达到的地方」，后续所有数据流追踪都从这里出发：

- HTTP 路由注册（`@RequestMapping` / `router.get` / `urlpatterns` / `mux.Handle`）
- API 控制器与 GraphQL schema
- CLI 入口、定时任务、消息消费者
- 第三方回调地址（支付、Webhook、OAuth）

### 0.4 识别信任边界

| 类别 | 内容 |
|------|------|
| **输入源（Source）** | HTTP 参数/Header/Cookie、上传文件、消息体、外部回调、被污染的历史数据 |
| **敏感操作汇（Sink）** | SQL、命令、模板、反序列化、文件系统、HTTP 客户端、重定向、日志 |
| **校验手段** | 参数校验、ORM 参数化、转义、权限中间件、网关策略 |

## 阶段 1 · 逐维度审计

**输入**：维度文件（`prompts/NN-*.md`）
**产出**：`findings[]`（原始记录）

按 [00-index.md](../prompts/00-index.md) 的优先级顺序执行：

```
P0：secrets → injection → authn-authz
P1：file-network → config-infra → supply-chain → sensitive-data → cryptography
P2：business-logic → logging
```

**为什么 `secrets` 排第一**：一旦命中即最高优先级，且后续维度需要基于「凭证已泄露」的前提重新评估影响面。

**为什么 `file-network` 和 `config-infra` 排在 `injection` 之后但领先于其他 P1**：它们是注射类漏洞的高危放大器（SSRF 打通内网、错误配置使鉴权失效）。

### 单维度内的标准动作

```
读取 prompts/NN-*.md
   ↓
执行「检索线索」章节给出的 Grep / Glob 模式
   ↓
对每个候选点，打开真实代码上下文（前后各数十行）
   ↓
按「判定标准」区分真漏洞与误报
   ↓
按「分级参考」初步定级
   ↓
立即记录（含文件路径、行号、代码证据）
```

**关键约束：一个维度审完立即落笔，不要攒到最后凭记忆汇总。** 凭记忆汇总必然丢失行号精度并引入虚构。

## 阶段 2 · 数据流串联

**输入**：阶段 1 的高危候选点
**产出**：`findings[].attack_chain`、`confidence` 的最终判定

单一维度的点状命中不足以定级。对每个高危候选点：

```
向上追溯 Source：输入到底从哪来？用户可控吗？
   ↓
向下追踪 Sink：最终到了哪里？能造成什么后果？
   ↓
检查中间拦截：有没有参数校验 / 白名单 / 参数化 / 转义 / 权限中间件？
   ↓
判定：完整链路 → 提升置信度与等级
      有有效拦截 → 降级或标记「已缓解」
```

链路要写进 `attack_chain` 字段，形如：

```
HTTP 参数 `orderBy`（OrderController.java:41）
  → 未校验直接拼接进 SQL（OrderDao.java:88）
  → JdbcTemplate.query 执行
```

## 阶段 3 · 汇总去重定级

**产出**：`summary`、最终 `findings[]`

### 3.1 去重（根因合并）

同一根因在多处出现时**合并为一条 finding**，在 `occurrences` 中列出全部位置。

反例：同一个不安全的 `md5()` 工具函数被 20 个文件调用 → 报 20 条。这会让报告失去可读性并虚高风险分。
正例：合并为 1 条，`occurrences` 列出 20 个调用点。

### 3.2 定级

按 [SKILL.md 的严重等级定义](../SKILL.md#严重等级定义) 统一裁定，**不沿用维度文件中的初步分级**。初步分级是单点视角，最终定级需要考虑完整链路与业务影响。

### 3.3 交叉标注

一个 finding 若同时命中多个维度，`dimensions` 数组中全部标出。常见组合：

| 组合 | 典型场景 |
|------|---------|
| `["secrets", "sensitive-data"]` | 前端产物泄露密钥 |
| `["authn-authz", "logging"]` | 鉴权异常被吞导致 fail-open |
| `["injection", "file-network"]` | SSRF 既是注入也是网络请求伪造 |
| `["file-network", "config-infra"]` | 上传目录可被 Web 访问 |
| `["cryptography", "secrets"]` | 硬编码加密密钥 |

### 3.4 打分

```
单条得分 = 严重权重 × 置信系数
risk_score = min(100, Σ 单条得分)
```

权重：Critical 40 / High 15 / Medium 5 / Low 1 / Info 0
系数：高 1.0 / 中 0.7 / 低 0.4

分数必须与 `findings` 数组可复算一致——报告读者能拿清单手动验算。

## 阶段 4 · 产出报告

**顺序不可颠倒**：先写 JSON，再依据 JSON 渲染 HTML。

```
security-audit-report.json   ← 唯一事实源
        ↓ 渲染
security-audit-report.html   ← 单文件、内联 CSS/JS、零外部依赖
```

HTML 必须实现：左侧维度导航、目录锚点平滑滚动、滚动感应高亮、等级与维度筛选、关键词搜索、发现条目折叠、代码高亮、复制路径、回到顶部、移动端适配、打印样式、浅色/深色主题。

完整字段定义与视觉规范见 [11-report-spec.md](../prompts/11-report-spec.md)。

## 阶段 5 · 自检

交付前的强制关卡：

- [ ] 每条 finding 的文件路径与行号真实可复现
- [ ] 没有把推测写成结论（不确定项已标 `confidence: low`）
- [ ] 没有编造文件、函数、依赖版本、CVE 编号
- [ ] 每个维度在 `dimension_coverage` 中都有明确结论（含「未发现问题」）
- [ ] `summary.by_severity` 与 `findings` 实际内容一致
- [ ] `risk_score` 可被复算
- [ ] 报告已落盘且已告知用户路径
- [ ] 未修改目标仓库任何业务代码

自检不通过则回到对应阶段修正，**不得带着已知问题交付**。

## 深度模式

三种深度对阶段 1 的覆盖面不同：

| 深度 | 覆盖 | 适用 |
|------|------|------|
| **快扫** | P0 维度 + 全部维度的高危模式 Grep 命中点 | 用户要求「快速看下」、超大仓库 |
| **标准**（默认） | P0 + P1 维度，全量 Grep + 高危点人工阅读 | 常规审计 |
| **深度** | 全部维度，逐入口追踪完整数据流，逐依赖核对版本 | 上线把关、对外交付 |

深度模式额外要求：

- 每条高危 finding 必须给出完整 `attack_chain`
- 逐条说明拦截措施的有无与有效性
- 完整核对依赖清单中每个高风险组件的版本
- `dimension_coverage` 中不得出现 `items_reviewed: 0`

## 中断与恢复

审计过程中若被中断（用户插话、超长仓库），恢复时：

1. 已写入磁盘的报告是**部分结果**，不是最终结果
2. 向用户说明已完成的维度与未完成的维度
3. 优先完成 P0 维度，再补齐 P1/P2
4. 未完成的维度在 `dimension_coverage` 中标记 `checked: false` 并说明原因，**不得静默省略**

## 下一步

- 理解设计动因 → [concept.md](concept.md)
- 查询参数与字段 → [manual.md](manual.md)
