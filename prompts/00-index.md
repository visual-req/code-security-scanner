# 00 · 审计维度总览与编排策略

本文件是审计流程的调度中枢。**每次审计开始前先读本文件**，再按需加载具体维度文件。

## 1. 维度清单

下表同时定义了**维度唯一标识（dimension id）**。报告中 `dimensions` / `by_dimension` / `dimension_coverage` 等字段必须使用该标识，不得自造别名。

| 编号 | 维度标识 | 文件 | 维度名称 | 默认优先级 | 典型最高风险等级 |
|------|---------|------|---------|-----------|-----------------|
| 01 | `secrets` | `01-secrets-and-credentials.md` | 密钥与凭证泄露 | P0 | Critical |
| 02 | `injection` | `02-injection.md` | 注入类漏洞 | P0 | Critical |
| 03 | `authn-authz` | `03-authn-authz.md` | 认证与授权 | P0 | Critical |
| 04 | `cryptography` | `04-cryptography.md` | 密码学实现 | P1 | High |
| 05 | `supply-chain` | `05-dependency-supply-chain.md` | 依赖与供应链 | P1 | Critical |
| 06 | `sensitive-data` | `06-sensitive-data-exposure.md` | 敏感数据暴露 | P1 | High |
| 07 | `config-infra` | `07-config-and-infrastructure.md` | 配置与基础设施 | P1 | Critical |
| 08 | `business-logic` | `08-business-logic-and-race-conditions.md` | 业务逻辑与并发 | P2 | High |
| 09 | `file-network` | `09-file-and-path-handling.md` | 文件、路径与网络请求 | P1 | Critical |
| 10 | `logging` | `10-logging-error-handling.md` | 日志与异常处理 | P2 | Medium |
| — | — | `11-report-spec.md` | 报告规范（非审计维度，无标识） | — | — |

优先级含义：P0 必跑；P1 在标准及以上深度必跑；P2 在深度模式下必跑。

## 2. 编排顺序

```
侦察（范围 / 技术栈 / 入口面 / 信任边界）
   ↓
P0：01 密钥 → 02 注入 → 03 认证授权
   ↓  （密钥先审：一旦命中即最高优先级，且后续审计需基于"凭证已泄露"的前提重估）
P1：09 文件与路径 → 07 配置与基础设施 → 05 依赖与供应链 → 06 敏感数据 → 04 密码学
   ↓  （09/07 优先：它们是 02/03 的高危放大器，如 SSRF 打通内网）
P2：08 业务逻辑 → 10 日志与异常
   ↓
数据流串联 → 去重定级 → 生成报告
```

## 3. 按技术栈的维度加权

不同技术栈的风险分布差异明显，按下表调整**投入精力**（不是跳过）：

| 技术栈特征 | 重点加强 | 重点关注点 |
|-----------|---------|-----------|
| Java / Spring | 02, 03, 07 | SpEL/OGNL 注入、反序列化（Fastjson/Jackson）、Actuator 暴露、Spring Security 配置放行 |
| Node.js / 前端 | 02, 05, 06 | 原型链污染、`eval`/`child_process`、npm 依赖投毒、前端打包泄露密钥、sourcemap |
| Python | 02, 05, 09 | `pickle`/`yaml.load` 反序列化、`subprocess shell=True`、`eval`、依赖混淆 |
| Go | 03, 09, 07 | 并发竞态、路径处理、goroutine 泄漏、`text/template` 误用 |
| PHP | 02, 09 | 反序列化、文件包含、`assert`、弱类型比较 |
| 移动端 / 客户端 | 01, 04, 06 | 硬编码密钥（可被反编译提取）、证书固定缺失、本地数据明文存储 |
| Serverless / 云原生 | 07, 03 | 权限过宽 IAM、环境变量泄露、公开存储桶、函数超时导致的部分提交 |
| 含合约 / 支付逻辑 | 08, 04 | 精度与舍入、重放、签名校验、状态机绕过 |

## 4. 信任边界识别清单

审计时先明确以下边界，凡是**跨越边界且未经校验**的数据流动都值得展开：

**输入源（Source）**
- HTTP：Query / Body / Path / Header / Cookie / Multipart 文件名
- 消息队列：Kafka / RabbitMQ / MQ 消息体
- 第三方回调：支付回调、Webhook、OAuth 回调
- 数据库与缓存中已被污染的历史数据
- 文件系统：上传文件内容、配置文件、被外部写入的目录
- 环境变量与启动参数

**敏感操作汇（Sink）**
- SQL / 命令 / 模板 / 反序列化 / 文件系统 / HTTP 客户端 / 重定向 / 日志 / 序列化输出

**边界校验手段（存在即降级）**
- 参数白名单校验、类型与长度约束
- ORM 参数化、预编译语句
- 转义与编码库
- 统一权限中间件、注解式鉴权
- 网关层 WAF / 限流 / 鉴权

## 5. 快速检索词库

按维度执行 Grep 时可直接取用（`pattern` 支持正则，建议大小写不敏感）：

**通用高危模式**
```
eval\(|exec\(|system\(|popen|subprocess|Runtime\.getRuntime
pickle\.loads|yaml\.load\(|ObjectInputStream|readObject|unserialize
innerHTML|dangerouslySetInnerHTML|v-html|document\.write
verify=False|InsecureSkipVerify|TrustAllCerts|ALLOW_ALL_HOSTNAME
MD5|SHA1|DES|RC4|ECB|Random\(\)|Math\.random
```

**凭证模式**
```
(password|passwd|pwd|secret|token|apikey|api_key|access_key|private_key)\s*[:=]\s*["'][^"']{8,}
AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----
(mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s"']+:[^\s"']+@
```

**危险配置模式**
```
debug\s*=\s*[Tt]rue|DEBUG\s*=\s*True|spring\.profiles\.active
Access-Control-Allow-Origin\s*[:=]\s*["']?\*
0\.0\.0\.0|privileged:\s*true|chmod\s+777
```

## 6. 深度模式说明

| 深度 | 覆盖范围 | 适用场景 |
|------|---------|---------|
| **快扫** | P0 维度 + 全部维度的高危模式 Grep 命中点 | 用户要求「快速看下」、仓库规模极大 |
| **标准**（默认） | P0 + P1 维度，全量 Grep + 高危点人工阅读 | 常规审计 |
| **深度** | 全部维度，逐入口追踪完整数据流，逐依赖核对版本 | 上线把关、对外交付 |

深度模式必须额外产出：完整的数据流链路描述（Source → 传播 → Sink），并逐条给出拦截措施的有无判定。

## 7. 输出要求

每个维度审计完成后，向报告的 `dimension_coverage` 写入一条记录：

```json
{
  "dimension": "injection",
  "dimension_name": "注入类漏洞",
  "checked": true,
  "depth": "standard",
  "items_reviewed": 37,
  "findings_count": 3,
  "conclusion": "发现 3 处疑似 SQL 注入，均位于 legacy 模块，新代码统一使用 ORM 参数化。"
}
```

即使用户指定跳过某维度，也要写入 `checked: false` 并说明原因，不得静默省略。

详细字段定义见 [11-report-spec.md](11-report-spec.md)。
