# 11 · 报告规范（JSON + HTML）

本文件定义两份产出物的**唯一格式标准**。生成报告前必须完整阅读本文件。

产出顺序：**先写 JSON（唯一事实源），再依据 JSON 内容渲染 HTML。** 两者内容必须严格一致，HTML 不得包含 JSON 中不存在的发现。

## 1. 文件与命名

| 文件 | 默认路径 | 说明 |
|------|---------|------|
| `security-audit-report.json` | 目标仓库根目录 | 机器可读，唯一事实源 |
| `security-audit-report.html` | 目标仓库根目录 | 单文件、内联 CSS/JS、零外部依赖 |

## 2. JSON Schema

```json
{
  "schema_version": "1.0",
  "meta": {
    "report_id": "SEC-20260915-143012",
    "repository": {
      "name": "example-service",
      "path": "/abs/path/to/repo",
      "branch": "main",
      "commit": "a1b2c3d",
      "description": "一句话说明该仓库的业务用途（从 README 推断）"
    },
    "scan_time": "2026-09-15T14:30:12+08:00",
    "auditor": "repo-security-audit skill (静态白盒审计)",
    "depth": "standard",
    "tech_stack": ["Java 17", "Spring Boot 2.7", "MySQL", "Redis", "Vue 3"],
    "scope": {
      "included": ["src/main/java", "src/main/resources", "Dockerfile"],
      "excluded": ["node_modules", "src/test", "*.min.js"],
      "excluded_reason": "测试代码与第三方产物不计入生产安全面",
      "file_count": 412,
      "loc": 38650
    },
    "dimensions_run": ["secrets", "injection", "authn-authz", "cryptography", "supply-chain", "sensitive-data", "config-infra", "business-logic", "file-network", "logging"]
  },

  "summary": {
    "total_findings": 12,
    "by_severity": { "critical": 1, "high": 3, "medium": 5, "low": 2, "info": 1 },
    "by_dimension": [
      { "dimension": "secrets", "dimension_name": "密钥与凭证泄露", "critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0, "total": 2 }
    ],
    "risk_score": 78,
    "risk_level": "高",
    "verdict": "一句话总体结论，40-120 字，必须同时说明「最严重的问题」与「整体可控程度」。",
    "top_priorities": [
      { "finding_id": "SEC-001", "title": "生产数据库口令硬编码", "reason": "泄露即可直连生产库" }
    ]
  },

  "findings": [
    {
      "id": "SEC-001",
      "title": "短标题，不超过 30 字，说明问题本身而非影响",
      "dimensions": ["secrets"],
      "dimension_names": ["密钥与凭证泄露"],
      "severity": "critical",
      "confidence": "high",
      "cwe": ["CWE-798"],
      "owasp": ["A07:2021"],
      "location": {
        "file": "src/main/resources/application-prod.yml",
        "line_start": 12,
        "line_end": 14,
        "symbol": "spring.datasource.password"
      },
      "occurrences": [
        { "file": "other/path.py", "line_start": 30, "line_end": 30, "note": "同类问题" }
      ],
      "description": "客观描述问题是什么。只陈述代码事实，不夸大、不含推测性结论。",
      "evidence": [
        {
          "file": "src/main/resources/application-prod.yml",
          "line_start": 12,
          "line_end": 14,
          "language": "yaml",
          "snippet": "数据源配置片段（凭证已脱敏：Abc1***yz）"
        }
      ],
      "attack_chain": "污点源 → 传播 → 敏感操作汇 的链路描述；非数据流类问题填触发路径。",
      "impact": "若被利用，攻击者能做到什么，影响哪些数据/功能/用户规模。",
      "remediation": {
        "summary": "一句话修复结论。以最紧急的动作开头。",
        "steps": ["步骤一", "步骤二"],
        "code_before": "存在问题的代码片段",
        "code_after": "修复后代码片段",
        "references": ["https://owasp.org/..."]
      },
      "status": "open",
      "needs_manual_review": false
    }
  ],

  "dimension_coverage": [
    {
      "dimension": "injection",
      "dimension_name": "注入类漏洞",
      "checked": true,
      "depth": "standard",
      "items_reviewed": 37,
      "findings_count": 3,
      "conclusion": "发现 3 处疑似 SQL 注入，均位于 legacy 模块；新代码统一使用 ORM 参数化。"
    },
    {
      "dimension": "business-logic",
      "dimension_name": "业务逻辑与并发",
      "checked": false,
      "depth": "standard",
      "items_reviewed": 0,
      "findings_count": 0,
      "conclusion": "用户指定跳过该维度。"
    }
  ],

  "limitations": [
    "本次为纯静态白盒审计，未执行目标代码，也未做动态验证，漏洞可达性需人工确认。",
    "未执行依赖漏洞库比对，组件版本影响性结论需结合官方安全公告复核。",
    "仓库 git 历史未纳入分析，无法确认凭证是否已通过历史提交泄露。"
  ]
}
```

### 字段约束

| 字段 | 约束 |
|------|------|
| `id` | 全局唯一，格式 `SEC-` + 三位数字，按 `severity` 降序、同级别按发现顺序编号 |
| `dimensions` / `by_dimension[].dimension` / `dimension_coverage[].dimension` / `dimensions_run[]` | 必须取自 [00-index.md](00-index.md) 的「维度标识」列，禁止自造别名 |
| `severity` | 仅允许 `critical` / `high` / `medium` / `low` / `info`（小写） |
| `confidence` | 仅允许 `high` / `medium` / `low`（小写） |
| `line_start` / `line_end` | 必须是真实存在的行号；无法定位行号时填 `0` 并在 `description` 说明 |
| `cwe` | 只填有把握的编号；不确定则填空数组 `[]`，**禁止编造** |
| `owasp` | 参照 OWASP Top 10 2021 编号，不确定则空数组 |
| `evidence[].snippet` | 保留真实代码，可截断，**不可改写**；凭证类必须脱敏 |
| `attack_chain` | 非数据流问题（如配置类）填「触发路径」，不得留空字符串 |
| `occurrences` | 无重复出现时填 `[]`，不省略 |
| `needs_manual_review` | 当 `confidence` 为 `low` 时必须为 `true` |

### 严重等级与置信度枚举（与 SKILL.md 保持一致）

- `critical`：无前置条件即可系统接管 / 批量数据泄露 / 生产凭证明文
- `high`：触发后可大范围泄露、越权或账户接管
- `medium`：影响受限或需较苛刻前置条件
- `low`：信息泄露有限或加固类问题
- `info`：非漏洞的最佳实践建议

## 3. 风险打分算法

**单条得分：**

```
权重 W = { critical: 40, high: 15, medium: 5, low: 1, info: 0 }
置信系数 C = { high: 1.0, medium: 0.7, low: 0.4 }
单条得分 = W[severity] × C[confidence]
```

**总分：**

```
raw = Σ 单条得分
risk_score = min(100, round(raw))
```

**风险等级映射：**

| risk_score | risk_level |
|-----------|-----------|
| 0 | 无 |
| 1 – 14 | 低 |
| 15 – 39 | 中 |
| 40 – 69 | 高 |
| 70 – 100 | 严重 |

**计算规则：**
- 只统计 `severity` 不为 `info` 的条目（`info` 权重为 0，自然不影响）。
- 同一根因合并后的 finding 只计一次分。
- 计算过程不必写入报告，但 `risk_score` 必须与 `findings` 数组可复算一致。

## 4. HTML 报告规范

### 4.1 硬性约束

| 项 | 要求 |
|----|------|
| 交付形态 | **单个 `.html` 文件**，CSS/JS 全部内联，**零外部依赖**（无 CDN、无字体外链、无图片外链） |
| 数据来源 | 报告中嵌入 JSON（见 4.3），页面由 JS 渲染，确保与 JSON 文件一致 |
| 行高 | **内容自适应，禁止硬编码 `height`**（仅允许 `max-height` + 滚动用于代码块） |
| 移动端 | ≤ 768px 时左侧导航折叠为顶部抽屉/汉堡菜单，表格改为卡片式堆叠，代码块横向滚动 |
| 打印 | 提供 `@media print`，隐藏导航与筛选，展开全部内容 |
| 主题 | 浅色为默认，跟随系统 `prefers-color-scheme` 提供深色 |

### 4.2 页面结构

```
┌─────────────────────────────────────────────────────┐
│ 顶栏：仓库名 · 审计时间 · 风险分徽章 · 风险等级徽章      │
├──────────────┬──────────────────────────────────────┤
│ 左侧导航      │ 右侧内容区                            │
│ （sticky）    │                                      │
│ · 概览        │  1. 概览：结论 + 等级分布 + 维度统计表  │
│ · 与范围      │  2. 审计范围与方法                     │
│ · 严重问题    │  3. 发现清单（可筛选、可折叠）          │
│ · 高危问题    │  4. 维度覆盖度                         │
│ · 中危问题    │  5. 局限与后续建议                     │
│ · 低危/建议   │                                      │
│ · 明细（按维度）│                                     │
│ · 局限        │                                      │
└──────────────┴──────────────────────────────────────┘
```

**布局要求：**
- 左侧导航固定宽度（约 240–280px），`position: sticky; top: 0`，独立滚动
- 右侧内容区自适应剩余宽度，`max-width` 约 1100px 居中，便于长文阅读
- 移动端：导航收起，内容区占满宽度

### 4.3 必须实现的交互

1. **目录锚点平滑滚动**：点击导航项 → `scroll-behavior: smooth` 或 `scrollIntoView({behavior:'smooth'})`，需考虑 sticky 顶栏的高度偏移（`scroll-margin-top`）。
2. **滚动感应（scroll-spy）**：使用 `IntersectionObserver` 高亮当前可视区域对应的导航项，**滚动时同步更新**。
3. **严重等级筛选**：概览区的等级分布卡片可点击，筛选发现清单（多选），并实时显示「当前显示 N / 总数 M」。
4. **维度筛选**：与等级筛选可叠加生效（AND 关系），提供「重置」按钮。
5. **发现条目可折叠**：默认展开 `critical` 与 `high`，折叠 `medium` 及以下。标题行展示：编号、等级徽章、置信度、标题、文件路径。
6. **代码高亮**：`<pre><code>` 展示，使用自实现的轻量关键字高亮（不能引入外部库）；无高亮时保证等宽字体与可读性。
7. **复制路径**：每个发现的位置旁提供「复制路径」按钮（`navigator.clipboard`），失败时静默降级。
8. **回到顶部**：滚动超过一屏后右下方出现浮动按钮。
9. **搜索框**：支持按关键词过滤发现（匹配标题、描述、文件路径）。

### 4.4 视觉规范

**严重等级配色（徽章需同时含文字，不可仅靠颜色区分）：**

| 等级 | 主色 | 含义 |
|------|------|------|
| Critical | `#b91c1c` 深红 | 立即处理 |
| High | `#ea580c` 橙 | 尽快处理 |
| Medium | `#ca8a04` 黄 | 计划处理 |
| Low | `#2563eb` 蓝 | 建议处理 |
| Info | `#6b7280` 灰 | 仅供参考 |

**置信度展示**：用文字标签（高/中/低），低置信度条目加虚线边框并附「待人工确认」提示。

**其他要求：**
- 风险分使用环形进度或大号数字 + 等级文字，一眼可见
- 字体栈使用系统字体，不引入外部字体
- 代码块使用等宽字体，深色背景，`overflow-x: auto`，`max-height` 约 400px
- 表格在移动端转为卡片式（每行一个卡片，字段名作为标签）
- 空状态需有明确提示（如「本次审计未发现该等级的发现项」），不留空白区

### 4.5 数据嵌入方式

在 HTML 末尾嵌入 JSON，页面加载时读取渲染：

```html
<script id="audit-data" type="application/json">
{ /* 与 security-audit-report.json 完全一致的内容 */ }
</script>
```

**注意**：嵌入时需转义 `</script>` 序列（替换为 `<\/script>`），避免提前闭合标签。

### 4.6 渲染内容映射

| 数据字段 | 渲染位置 |
|---------|---------|
| `meta.*` | 顶栏 + 「审计范围与方法」区块 |
| `summary.verdict` | 概览区首屏结论（突出显示） |
| `summary.risk_score` / `risk_level` | 概览区风险分组件 + 顶栏徽章 |
| `summary.by_severity` | 概览区等级分布卡片（可点击筛选） |
| `summary.by_dimension` | 概览区维度统计表 |
| `summary.top_priorities` | 概览区「优先处理清单」 |
| `findings[]` | 「发现清单」区（可筛选、可折叠） |
| `findings[].evidence[]` | 折叠展开后的代码块 |
| `findings[].remediation` | 折叠展开后的修复建议（含代码对比） |
| `dimension_coverage[]` | 「维度覆盖度」表格（含未检查项的标记） |
| `limitations[]` | 「局限与后续建议」区（列表，需醒目） |

## 5. 生成后自检

- [ ] JSON 可被 `JSON.parse` 解析无语法错误
- [ ] HTML 在浏览器打开无控制台报错
- [ ] HTML 与 JSON 的发现数量、等级分布完全一致
- [ ] 所有 `line_start` / `line_end` 指向真实存在的代码位置
- [ ] `risk_score` 与 `findings` 按算法可复算一致
- [ ] 移动端（≤ 768px）检查导航折叠、表格堆叠、代码块滚动
- [ ] 未发现任何外部网络请求（无 CDN、无字体、无图片外链）
- [ ] 存在 `checked: false` 的维度时，页面有明确说明
