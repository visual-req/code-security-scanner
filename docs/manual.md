# 参考手册

本文件是 `repo-security-audit` 技能的完整参考：所有参数、字段、规则、维度与故障排查。

- 想快速跑通 → [getting-started.md](getting-started.md)
- 想理解设计原理 → [concept.md](concept.md)
- 想改技能本身 → [structure.md](structure.md)

---

## 1. 调用参数

| 参数 | 必填 | 默认值 | 可选值 | 说明 |
|------|------|--------|--------|------|
| 目标仓库路径 | 是 | 无 | 本地绝对路径 | 或可从当前工作区推断时由助手自行推断并声明 |
| 审计维度 | 否 | 全部 10 个 | 维度标识，可多选 | 见 [§3 维度清单](#3-维度清单) |
| 输出目录 | 否 | 目标仓库根目录 | 任意可写路径 | 文件名固定，见 [§4 产出物](#4-产出物) |
| 审计深度 | 否 | 标准 | `快扫` / `标准` / `深度` | 见 [§5 深度模式](#5-深度模式) |

未提供的参数按默认值执行，并在报告 `meta` 中注明。

### 指令模板

```
按照 <技能路径>/SKILL.md 的流程，审计 <目标路径> 的安全性
```

```
按照 <技能路径>/SKILL.md，审计 <目标路径>，
只跑 injection 和 authn-authz，输出到 /tmp/audit/，深度模式
```

```
快速看下 <目标路径> 有没有明显安全问题
```

```
审计 <目标路径>，重点看凭证泄露和依赖供应链
```

---

## 2. 执行流程速查

| 阶段 | 动作 | 产出字段 |
|------|------|---------|
| 0 · 侦察 | 判技术栈、划边界、找入口面、识信任边界 | `meta.tech_stack`、`meta.scope` |
| 1 · 逐维度审计 | 按维度文件中的检索线索 Grep + 人工判定 | `findings[]`（原始） |
| 2 · 数据流串联 | 追溯 Source → Sink，检查拦截 | `attack_chain`、`confidence` |
| 3 · 汇总定级 | 根因合并、统一评级、交叉标注、打分 | `summary.*`、最终 `findings[]` |
| 4 · 产出报告 | 先写 JSON，再渲染 HTML | 两份报告文件 |
| 5 · 自检 | 8 项强制检查 | — |

执行顺序：`secrets → injection → authn-authz → file-network → config-infra → supply-chain → sensitive-data → cryptography → business-logic → logging`

---

## 3. 维度清单

| 标识 | 维度 | 优先级 | 覆盖内容 | 主要 CWE 参考 |
|------|------|--------|---------|--------------|
| `secrets` | 密钥与凭证泄露 | P0 | 硬编码密钥、令牌、私钥、连接串、前端产物泄露 | CWE-798、CWE-321 |
| `injection` | 注入类漏洞 | P0 | SQL / 命令 / 代码 / 模板 / 反序列化 / XXE / SSTI / LDAP / XPath / 原型链污染 | CWE-89、78、94、502、611 |
| `authn-authz` | 认证与授权 | P0 | 认证绕过、会话与 JWT 缺陷、水平/垂直越权、路由鉴权覆盖度 | CWE-287、384、862、639、347 |
| `cryptography` | 密码学实现 | P1 | 弱算法、弱随机、密钥与 IV 管理、TLS 校验缺失、时序攻击 | CWE-327、328、338、295、329、208 |
| `supply-chain` | 依赖与供应链 | P1 | 高危组件、安装钩子、CI/CD 权限、容器基础镜像、依赖源 | CWE-1395、1357、250 |
| `sensitive-data` | 敏感数据暴露 | P1 | 接口过度返回、调试端点、sourcemap、脱敏缺失、缓存与传输 | CWE-200、209、319、213 |
| `config-infra` | 配置与基础设施 | P1 | 容器、K8s、网关、安全响应头、CORS、云资源与 IaC | CWE-16、942、693、250、256 |
| `business-logic` | 业务逻辑与并发 | P2 | 金额篡改、状态机绕过、超卖、幂等、验证码与频控、支付回调 | CWE-840、362、367、472、837 |
| `file-network` | 文件、路径与网络请求 | P1 | 上传、路径穿越、解压、SSRF、任意文件读写 | CWE-22、434、918、29、409、552 |
| `logging` | 日志与异常处理 | P2 | fail-open、异常泄露、敏感信息入日志、审计日志缺失 | CWE-391、532、117、778、209、636 |

### 各维度判定要点摘要

| 标识 | 最关键的判定问题 |
|------|-----------------|
| `secrets` | 该值是否真的能连上/调用某个外部系统？是否在 `.gitignore` 覆盖范围内？ |
| `injection` | 源是否可控、中间是否有参数化/白名单、汇是否危险——三者同时成立 |
| `authn-authz` | 必须做**路由鉴权覆盖度差集**，不能只看有没有鉴权代码 |
| `cryptography` | 先看**用途**再看算法——同是 MD5，做缓存键合规，做口令哈希是漏洞 |
| `supply-chain` | 禁止编造 CVE；仅对版本范围广为人知的漏洞下结论 |
| `sensitive-data` | 泄露了**哪些具体字段**，**哪个角色**能访问 |
| `config-infra` | **该配置生效于哪个环境**——dev 下是 Info，prod 下是 High |
| `business-logic` | 必须先读懂业务规则；规则不明时标 `confidence: low`，不得臆造规则 |
| `file-network` | 逐一验证已有校验能否被绕过（`....//`、`%2e%2e`、`shell.jsp.jpg`、`127.1`） |
| `logging` | 不看有没有 catch，看 catch 之后的**控制流** |

---

## 4. 产出物

| 文件 | 默认位置 | 性质 |
|------|---------|------|
| `security-audit-report.json` | 目标仓库根目录 | 唯一事实源，机器可读 |
| `security-audit-report.html` | 目标仓库根目录 | 由 JSON 渲染，单文件、零外部依赖 |

### 4.1 JSON 顶层结构

```
{
  "schema_version": "1.0",
  "meta": { ... },              // 报告与仓库元信息
  "summary": { ... },           // 汇总、风险分、优先处理清单
  "findings": [ ... ],          // 发现清单
  "dimension_coverage": [ ... ],// 每个维度的覆盖情况与结论
  "limitations": [ ... ]        // 分析局限（必填）
}
```

### 4.2 meta

| 字段 | 类型 | 说明 |
|------|------|------|
| `report_id` | string | `SEC-YYYYMMDD-HHMMSS` |
| `repository.name` | string | 仓库名 |
| `repository.path` | string | 绝对路径 |
| `repository.branch` | string | 分支名 |
| `repository.commit` | string | 提交号 |
| `repository.description` | string | 一句话业务用途（从 README 推断） |
| `scan_time` | string | ISO 8601 带时区 |
| `auditor` | string | 固定为技能标识 |
| `depth` | string | `quick` / `standard` / `deep` |
| `tech_stack` | string[] | 识别到的技术栈 |
| `scope.included` | string[] | 纳入审计的路径 |
| `scope.excluded` | string[] | 排除的路径 |
| `scope.excluded_reason` | string | 排除理由 |
| `scope.file_count` | number | 文件数 |
| `scope.loc` | number | 代码行数 |
| `dimensions_run` | string[] | 本次运行的维度标识 |

### 4.3 summary

| 字段 | 类型 | 说明 |
|------|------|------|
| `total_findings` | number | 发现总数（去重后） |
| `by_severity` | object | `{critical, high, medium, low, info}` 各等级数量 |
| `by_dimension` | array | 每个维度的等级分布与总数 |
| `risk_score` | number | 0–100，按 §6 算法计算 |
| `risk_level` | string | 无 / 低 / 中 / 高 / 严重 |
| `verdict` | string | 40–120 字总体结论，须含「最严重问题」与「整体可控程度」 |
| `top_priorities` | array | 优先处理清单（`finding_id` + `title` + `reason`） |

### 4.4 findings[]

| 字段 | 类型 | 约束 |
|------|------|------|
| `id` | string | `SEC-` + 三位数字，全局唯一，按严重等级降序编号 |
| `title` | string | ≤ 30 字，说明问题本身而非影响 |
| `dimensions` | string[] | 取自 §3 的标识，禁止自造别名 |
| `dimension_names` | string[] | 对应中文名称 |
| `severity` | string | `critical` / `high` / `medium` / `low` / `info` |
| `confidence` | string | `high` / `medium` / `low` |
| `cwe` | string[] | 不确定则空数组，**禁止编造** |
| `owasp` | string[] | OWASP Top 10 2021 编号，不确定则空数组 |
| `location.file` | string | 文件路径 |
| `location.line_start` / `line_end` | number | 真实行号；无法定位填 `0` 并说明 |
| `location.symbol` | string | 函数名/配置项名 |
| `occurrences` | array | 同根因的其他位置；无则 `[]` |
| `description` | string | 客观描述问题，含判据与「为何拦截无效」 |
| `evidence[]` | array | 真实代码片段（可截断、不可改写），凭证必须脱敏 |
| `attack_chain` | string | Source → 传播 → Sink 链路；非数据流问题填触发路径 |
| `impact` | string | 被利用后能做到什么、影响什么 |
| `remediation.summary` | string | 一句话结论，以最紧急动作为开头 |
| `remediation.steps` | string[] | 修复步骤 |
| `remediation.code_before` / `code_after` | string | 改造前 / 改造后代码 |
| `remediation.references` | string[] | 参考链接 |
| `status` | string | `open` / `mitigated` / `accepted` |
| `needs_manual_review` | boolean | `confidence: low` 时必须为 `true` |

### 4.5 dimension_coverage[]

每个维度一条，**包括未检查的维度**（`checked: false` + 原因），不得静默省略。

| 字段 | 说明 |
|------|------|
| `dimension` / `dimension_name` | 维度标识与中文名 |
| `checked` | 是否执行 |
| `depth` | 该维度执行的深度 |
| `items_reviewed` | 检查项数量（深度模式不得为 0） |
| `findings_count` | 该维度发现数 |
| `conclusion` | 一句话结论，含「未发现问题」的情形 |

### 4.6 HTML 报告功能

| 功能 | 说明 |
|------|------|
| 左侧维度导航 | 固定宽度，sticky，独立滚动 |
| 目录锚点平滑滚动 | 含 sticky 顶栏高度偏移 |
| 滚动感应（scroll-spy） | `IntersectionObserver` 高亮当前区块 |
| 等级筛选 | 点击等级分布卡片筛选清单，多选，实时显示「显示 N / 总数 M」 |
| 维度筛选 | 与等级筛选叠加（AND），提供重置 |
| 关键词搜索 | 匹配标题、描述、文件路径 |
| 发现条目折叠 | Critical / High 默认展开，其余默认折叠 |
| 代码高亮 | 自实现轻量高亮，不引入外部库 |
| 复制路径 | `navigator.clipboard`，失败静默降级 |
| 回到顶部 | 滚动一屏后出现浮动按钮 |
| 移动端适配 | ≤ 768px 导航折叠为抽屉，表格转卡片式堆叠 |
| 打印样式 | 隐藏导航与筛选，展开全部内容 |
| 主题 | 浅色默认，跟随 `prefers-color-scheme` 提供深色 |
| 空状态提示 | 无匹配结果时给出明确提示 |

**硬性约束**：单文件、CSS/JS 全内联、零外部依赖（无 CDN / 字体 / 图片外链）、禁止硬编码 `height`（仅允许代码块用 `max-height` + 滚动）。

---

## 5. 深度模式

| 深度 | 覆盖范围 | 适用场景 |
|------|---------|---------|
| **快扫** | P0 维度 + 全部维度的高危模式 Grep 命中点 | 「快速看下」、超大仓库 |
| **标准**（默认） | P0 + P1 维度，全量 Grep + 高危点人工阅读 | 常规审计 |
| **深度** | 全部维度，逐入口追踪完整数据流，逐依赖核对版本 | 上线把关、对外交付 |

深度模式的额外要求：

- 每条高危 finding 必须给出完整 `attack_chain`
- 逐条说明拦截措施的有无与有效性
- 完整核对依赖清单中每个高风险组件的版本
- `dimension_coverage` 中不得出现 `items_reviewed: 0`

---

## 6. 严重等级与打分

### 严重等级

| 等级 | 判定标准 | 典型示例 |
|------|---------|---------|
| Critical | 无需认证或仅需低权限即可直接获取系统控制权 / 批量数据泄露；或已确认提交进仓库的真实生产凭证 | 未授权 RCE、SQL 注入直达全库、硬编码生产 AK/SK |
| High | 需一定前置条件，触发后可造成大范围数据泄露、越权、账户接管 | 存储型 XSS、水平越权、JWT 不验签、路径穿越读任意文件 |
| Medium | 影响范围受限，或需较苛刻前置条件，或为高危漏洞的必要前置条件 | 反射型 XSS、缺少频控、CORS 配置过宽、弱加密算法 |
| Low | 信息泄露有限，或加固类问题，单独利用价值低 | 版本号泄露、错误栈暴露、缺少安全响应头 |
| Info | 非漏洞的最佳实践建议 | 代码规范、可观测性建议、依赖升级提示 |

### 打分算法

```
权重 W = { critical: 40, high: 15, medium: 5, low: 1, info: 0 }
系数 C = { high: 1.0, medium: 0.7, low: 0.4 }
单条得分 = W[severity] × C[confidence]
risk_score = min(100, round(Σ 单条得分))
```

| risk_score | risk_level |
|-----------|-----------|
| 0 | 无 |
| 1 – 14 | 低 |
| 15 – 39 | 中 |
| 40 – 69 | 高 |
| 70 – 100 | 严重 |

**复算规则**：同一根因合并后的 finding 只计一次分；`risk_score` 必须能由 `findings` 数组复算得出。

---

## 7. 硬性规则

执行过程中不可违反的约束，均为抑制静态分析幻觉而设。

| # | 规则 | 说明 |
|---|------|------|
| 1 | **零执行** | 不运行目标仓库的代码、脚本、构建命令，不安装其依赖 |
| 2 | **零改动** | 除生成的报告外，不写入/删除/重命名目标仓库任何文件 |
| 3 | **禁止编造** | 不得虚构文件路径、行号、代码内容、依赖版本、CVE 编号 |
| 4 | **禁止夸大** | 静态审计不得断言「已确认可被利用」，只能表述为风险 |
| 5 | **必须给证据** | 每条 finding 至少含一段真实代码片段 + 路径 + 行号区间 |
| 6 | **边界要声明** | 未覆盖目录、未运行维度、固有局限全部写入 `limitations` |
| 7 | **密钥脱敏** | 疑似凭证仅展示前 4 位 + `***` + 后 2 位 |
| 8 | **Critical 优先** | 发现 Critical 时先在回复开头预警，再继续其余维度 |

### 交付前自检清单

- [ ] 每条 finding 的文件路径与行号真实可复现
- [ ] 没有把推测写成结论（不确定项已标 `confidence: low`）
- [ ] 没有编造文件、函数、依赖版本、CVE 编号
- [ ] 每个维度在 `dimension_coverage` 中都有明确结论（含「未发现问题」）
- [ ] `summary.by_severity` 与 `findings` 实际内容一致
- [ ] `risk_score` 可被复算
- [ ] 报告已落盘且已告知用户路径
- [ ] 未修改目标仓库任何业务代码

HTML 报告另有 8 项自检，见 [11-report-spec.md](../prompts/11-report-spec.md#5-生成后自检)。

---

## 8. 对话回复结构

助手在对话中的回复控制在 5 段以内，细节全部落在报告里：

1. 一句话总体结论 + 风险分 + 风险等级
2. 各等级问题数量分布
3. Critical / High 问题清单（编号、标题、位置、一句话影响）
4. 本次审计的边界与局限（1–2 条）
5. 两份报告的文件路径

---

## 9. 故障排查

| 现象 | 原因 | 处理 |
|------|------|------|
| 助手说找不到 `prompts/` | `SKILL.md` 与 `prompts/` 不在同级 | 整体搬迁，保持同级关系 |
| 技能未出现在可用技能列表 | `SKILL.md` 在仓库根目录，未被加载器扫描 | 软链到 `.trae/skills/repo-security-audit`，见 [installation.md](installation.md#方式三接入-trae-技能加载器) |
| 维度返回数量不是 10 | `00-index.md` 或维度文件缺失 | 核对 `prompts/` 下 12 个文件是否齐全（`00`–`11`） |
| 报告未生成 | 目标目录不可写 | 用 `输出目录` 参数指定可写路径 |
| HTML 打开空白 | JSON 内嵌时未转义 `</script>` | 将内嵌 JSON 中的 `</script>` 转义为 `<\/script>` |
| 风险分与清单对不上 | 未按根因合并，或重复计分 | 检查 `occurrences` 是否被重复计入总分 |
| 报告里出现疑似真实凭证 | 脱敏规则被跳过 | 按 §7 规则 7 处理：仅保留前 4 位 + `***` + 后 2 位，并提示立即轮换 |
| 助手给了具体 CVE 编号但无出处 | 违反规则 3 | 要求改为「建议核对上游安全公告」并标 `confidence: low` |
| 审计中途被中断 | 长仓库或用户插话 | 已落盘的是部分结果；要求助手说明已完成/未完成维度并优先补齐 P0 |

---

## 10. FAQ

**Q：能审私有仓库 / 内网仓库吗？**

可以。技能完全离线运行，只读取本地文件，不产生任何网络请求（生成的 HTML 也无外部依赖）。

**Q：会修改我的代码吗？**

不会。除在指定目录生成两份报告外，不触碰任何文件。若需要修复，须明确要求助手在报告基础上改代码。

**Q：为什么某些维度被跳过了？**

可能是深度模式未覆盖（P2 维度在快扫/标准下不强制），或用户指定了维度。两种情况都会在 `dimension_coverage` 中记录 `checked: false` 与原因，不会静默省略。

**Q：低置信度的问题要不要修？**

要确认，但优先级取决于严重等级。`needs_manual_review: true` 表示助手无法从代码判定可达性，需要熟悉业务的人确认。确认成立后按该等级的优先级处理。

**Q：报告能接入 CI 吗？**

JSON 是机器可读的，可用于 CI 门禁。典型用法是解析 `summary.by_severity.critical` 是否为 0，或 `summary.risk_score` 是否超阈值。技能本身不提供 CI 脚本。

**Q：为什么不用 Semgrep / gitleaks？**

设计上刻意排除外部依赖，目的是让技能在任何环境下都能跑通。代价是无法比对依赖漏洞库、无法做数据流自动化分析——这些局限会写入 `limitations`。

**Q：如何增加团队自定义的审计规则？**

在 `prompts/` 对应维度文件的「检索线索」中追加正则，或在「判定标准」中补充团队约定。扩展流程见 [structure.md](structure.md#如何扩展)。

---

## 11. 附录：常用检索模式

供手工核查时直接使用（`pattern` 支持正则，建议大小写不敏感）。

### 通用高危

```
eval\(|exec\(|system\(|popen|subprocess|Runtime\.getRuntime
pickle\.loads|yaml\.load\(|ObjectInputStream|readObject|unserialize
innerHTML|dangerouslySetInnerHTML|v-html|document\.write
verify=False|InsecureSkipVerify|TrustAllCerts|ALLOW_ALL_HOSTNAME
MD5|SHA1|DES|RC4|ECB|Random\(\)|Math\.random
```

### 凭证

```
(password|passwd|pwd|secret|token|apikey|api_key|access_key|private_key)\s*[:=]\s*["'][^"']{8,}
AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----
(mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s"']+:[^\s"']+@
```

### 危险配置

```
debug\s*=\s*[Tt]rue|DEBUG\s*=\s*True|spring\.profiles\.active
Access-Control-Allow-Origin\s*[:=]\s*["']?\*
0\.0\.0\.0|privileged:\s*true|chmod\s+777
```

### 路径与网络

```
new\s+File\s*\(.*(\+|\$\{)|Paths\.get\(.*(\+|\$\{)
getOriginalFilename|ZipInputStream|extractAll
169\.254\.169\.254|file://|gopher://|dict://
```

---

## 相关文档

| 文档 | 内容 |
|------|------|
| [getting-started.md](getting-started.md) | 5 分钟跑通一次审计 |
| [installation.md](installation.md) | 四种安装方式与 Trae 接入 |
| [workflow.md](workflow.md) | 5 个阶段的详细展开 |
| [structure.md](structure.md) | 文件职责、命名约定、扩展方式 |
| [concept.md](concept.md) | 设计动因与关键术语 |
| [../SKILL.md](../SKILL.md) | 技能入口 |
| [../prompts/00-index.md](../prompts/00-index.md) | 维度编排中枢 |
| [../prompts/11-report-spec.md](../prompts/11-report-spec.md) | 报告格式标准 |
