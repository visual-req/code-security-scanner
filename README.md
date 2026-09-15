# Code Security Scanner

一个面向代码仓库的**静态白盒安全审计技能（Skill）**。给 AI 助手一个仓库路径，它按 10 个安全维度逐项排查，产出人读的 HTML 报告与机器读的 JSON 结果。

## 特点

- **零执行、零依赖**：只读代码，不运行目标仓库的任何代码，不需要 Semgrep / gitleaks / trivy 等外部工具
- **维度化审计**：10 个安全维度各自独立成文，含可直接执行的正则检索线索与判定标准
- **数据流驱动**：不只做模式匹配，要求串联「污点源 → 传播路径 → 敏感操作汇」后再定级
- **可复算的风险分**：统一的权重 × 置信度算法，分数与发现清单可相互校验
- **双格式产出**：JSON 为唯一事实源，HTML 由其渲染，两者强制一致

## 目录结构

```
.
├── README.md                             # 项目介绍入口
├── SKILL.md                              # 技能入口：触发条件、执行流程、硬性规则、输出契约
├── docs/                                 # 使用文档（给人看的说明）
│   ├── getting-started.md                # 快速上手
│   ├── installation.md                   # 安装与接入
│   ├── workflow.md                       # 执行流程详解
│   ├── structure.md                      # 目录结构与文件职责
│   ├── concept.md                        # 核心概念与设计动因
│   └── manual.md                         # 完整参考手册
├── prompts/                              # 审计知识库（给助手用的规范）
│   ├── 00-index.md                       # 维度标识表、编排策略、信任边界、检索词库
│   ├── 01-secrets-and-credentials.md     # 密钥与凭证泄露
│   ├── 02-injection.md                   # 注入类漏洞
│   ├── 03-authn-authz.md                 # 认证与授权
│   ├── 04-cryptography.md                # 密码学实现
│   ├── 05-dependency-supply-chain.md     # 依赖与供应链
│   ├── 06-sensitive-data-exposure.md     # 敏感数据暴露
│   ├── 07-config-and-infrastructure.md   # 配置与基础设施
│   ├── 08-business-logic-and-race-conditions.md  # 业务逻辑与并发
│   ├── 09-file-and-path-handling.md      # 文件、路径与网络请求
│   ├── 10-logging-error-handling.md      # 日志与异常处理
│   └── 11-report-spec.md                 # JSON schema、HTML 规范、打分算法
└── LICENSE
```

`prompts/` 是助手执行审计时读取的规范，`docs/` 是给人看的说明，两者职责分离。详见 [structure.md](docs/structure.md)。

## 文档

| 文档 | 内容 |
|------|------|
| [getting-started.md](docs/getting-started.md) | 5 分钟跑通一次审计 |
| [installation.md](docs/installation.md) | 四种安装方式，含 Trae 技能加载器接入 |
| [workflow.md](docs/workflow.md) | 5 个执行阶段的详细展开 |
| [structure.md](docs/structure.md) | 每个文件的职责、命名约定、扩展方式 |
| [concept.md](docs/concept.md) | 为什么这样设计：污点源/汇、有效拦截、fail-open、唯一事实源 |
| [manual.md](docs/manual.md) | 完整参考：全部参数、JSON 字段、规则、FAQ、故障排查 |

## 使用方式

### 在 AI 助手中启用

向助手提供 `SKILL.md` 的路径并要求执行审计，例如：

```
按照 ./SKILL.md 的流程，审计 /path/to/your-repo 的安全性
```

可指定的参数：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| 目标仓库路径 | 无（必填） | 本地绝对路径 |
| 审计维度 | 全部 10 个 | 可指定只跑某几个维度 |
| 输出目录 | 目标仓库根目录 | 输出文件名固定 |
| 审计深度 | 标准 | 快扫 / 标准 / 深度 |

### 产出物

写入目标仓库根目录（可用参数覆盖）：

- `security-audit-report.json` —— 机器可读，包含 `meta` / `summary` / `findings` / `dimension_coverage` / `limitations`
- `security-audit-report.html` —— 单文件报告，内联 CSS/JS、零外部依赖，支持等级筛选、维度筛选、关键词搜索、目录滚动感应、移动端适配

## 审计维度

| 标识 | 维度 | 覆盖内容 |
|------|------|----------|
| `secrets` | 密钥与凭证泄露 | 硬编码密钥、令牌、私钥、连接串、前端产物泄露 |
| `injection` | 注入类漏洞 | SQL / 命令 / 代码 / 模板 / 反序列化 / XXE / SSTI / 原型链污染 |
| `authn-authz` | 认证与授权 | 认证绕过、会话与 JWT 缺陷、水平/垂直越权、路由鉴权覆盖度 |
| `cryptography` | 密码学实现 | 弱算法、弱随机、密钥与 IV 管理、TLS 校验缺失 |
| `supply-chain` | 依赖与供应链 | 高危组件、安装钩子、CI/CD 权限、容器基础镜像 |
| `sensitive-data` | 敏感数据暴露 | 接口过度返回、调试端点、sourcemap、脱敏缺失 |
| `config-infra` | 配置与基础设施 | 容器、K8s、网关、安全响应头、CORS、云资源与 IaC |
| `business-logic` | 业务逻辑与并发 | 金额篡改、状态机绕过、超卖、幂等、验证码与频控 |
| `file-network` | 文件、路径与网络请求 | 上传、路径穿越、解压、SSRF |
| `logging` | 日志与异常处理 | fail-open、异常泄露、敏感信息入日志、审计日志缺失 |

## 严重等级与打分

单条得分 = 严重权重 × 置信系数，总分封顶 100。

**严重权重：**

| 严重等级 | 权重 |
|---------|------|
| Critical | 40 |
| High | 15 |
| Medium | 5 |
| Low | 1 |
| Info | 0 |

**置信系数：**

| 置信度 | 系数 |
|--------|------|
| 高 | 1.0 |
| 中 | 0.7 |
| 低 | 0.4 |

**风险等级映射：**

| 总分 | 风险等级 |
|------|---------|
| 70 – 100 | 严重 |
| 40 – 69 | 高 |
| 15 – 39 | 中 |
| 1 – 14 | 低 |

## 设计约束

为抑制静态分析常见的「幻觉」问题，技能内置了以下硬性规则：

1. 禁止编造文件路径、行号、代码内容、依赖版本、CVE 编号
2. 每条发现必须附真实代码证据与可复现的行号
3. 无法验证可达性的结论必须标注 `confidence: low` 且 `needs_manual_review: true`
4. 静态审计不得断言「已确认可被利用」，只能表述为风险
5. 报告中出现的疑似凭证一律脱敏展示
6. 未覆盖的目录、未运行的维度、分析局限必须写入 `limitations`
7. 除生成的报告外，不修改目标仓库任何文件

## 已知限制

- 纯静态审计，**不做动态验证**，漏洞可达性需人工确认
- **不比对依赖漏洞数据库**，组件版本影响性结论需结合官方安全公告复核
- 不读取 git 历史，无法确认凭证是否已通过历史提交泄露
- 命名与结构遵循 Trae Skill 规范但置于仓库根目录，**不会被 Trae 的技能加载器自动注册**（加载器默认扫描 `.trae/skills/`），需显式指向 `SKILL.md`

## License

[Apache License 2.0](LICENSE)
