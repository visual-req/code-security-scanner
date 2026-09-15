# 10 · 日志与异常处理

## 审计目标

审计两类问题：一是错误处理方式导致的**安全问题**（fail-open、异常吞噬、堆栈泄露）；二是日志体系导致的**可审计性缺失**（无法追溯安全事件）与**日志自身泄露**。

## 检索线索

### 10.1 异常吞噬与 fail-open

```
# 空 catch / 忽略异常
(?i)catch\s*\([^)]*\)\s*\{\s*\}
(?i)catch\s*\([^)]*\)\s*\{[^}]*(//|/\*)\s*(ignore|暂时|忽略|TODO|FIXME)
(?i)except\s*:\s*pass|except\s+Exception\s*:\s*pass
(?i)\bignore\b.*\b(error|exception)\b
# 捕获后返回成功 / 放行（fail-open）
(?i)catch\s*\([^)]*\)\s*\{[\s\S]{0,300}return\s+(true|null|1|success|ok)
(?i)catch\s*\([^)]*\)\s*\{[\s\S]{0,300}(permit|allow|pass|放行|通过)
(?i)(isAuthenticated|hasPermission|checkAccess|verifyToken)[\s\S]{0,200}catch
# 兜底默认值导致的安全降级
(?i)(||\s*)(true|"admin"|[\*]+)\s*(;|,|\))
检索: 权限判断 / 开关判断中的兜底默认值
# 事务被异常吞噬
(?i)catch[\s\S]{0,200}@Transactional
```

**判定关键：catch 块之后的控制流。** 吞掉异常本身不可怕；吞掉异常后继续执行敏感操作（放行、提交、返回成功）才是漏洞。

### 10.2 敏感信息入日志

```
(?i)(log|logger|LOG|console|print|println|System\.out)[\.\(].*(password|passwd|pwd|token|secret|credential|authorization|apikey|api_key)
(?i)(log|logger)[\.\(].*(idCard|id_card|身份证|bankCard|银行卡|mobile|phone|手机号|email|address)
(?i)(log|logger)[\.\(].*(req|request)\.(body|headers|cookies|params)   # 全量打印请求内容
(?i)(log|logger)[\.\(].*(entire|whole|toString\(\))\s*(req|request|dto|entity|user)
(?i)(log|logger)[\.\(].*(sign|signature|privateKey|secretKey)
(?i)console\.log\((?!.*(?:error|warn))   # 前端生产代码残留（含调试信息泄露）
# 日志级别过低导致大量输出
(?i)(log\.level|logging\.level|rootLogger).*=?\s*(DEBUG|TRACE)
```

### 10.3 日志注入与伪造

```
(?i)(log|logger)[\.\(].*(req\.|request\.|params|query|input|header|userAgent|uri|url)
检索: 是否对用户输入做换行符过滤（\r \n 可伪造日志行、注入假审计记录）
```

### 10.4 堆栈与错误信息外泄

```
(?i)(e\.getMessage\(\)|ex\.getMessage\(\)|e\.toString\(\))\s*\)?\s*(;|,|\+)
(?i)(printStackTrace|traceback\.print_exc|traceback\.format_exc)
(?i)(res\.(send|json)|RespEntity|ResponseEntity)[\s\S]{0,120}(err|error|exception|trace|stack)
(?i)(error\.stack|err\.stack|stack\s*:)
# 前端展示后端错误详情
(?i)(catch\s*\(.*\)\s*\{[\s\S]{0,200}(alert|message\.error|ElMessage\.error)\(.*(err|error)\.)
# 详细的失败原因（账号枚举 / 系统探测）
(?i)(signature\s+(invalid|mismatch)|签名错误|token\s+(expired|invalid)|SQLException|ORA-\d+|com\.mysql)
```

### 10.5 全局异常处理

```
(?i)(@ControllerAdvice|@ExceptionHandler|@RestControllerAdvice|ErrorHandler|errorhandler|exception_handler|app\.use\(\(err)
检索: 全局处理器是否存在 —— 不存在则框架默认错误页可能泄露堆栈
检索: 全局处理器返回体是否包含 exception 类型/消息/堆栈
(?i)(spring\.resources\.add-mappings|server\.error\.include-stacktrace|server\.error\.include-message|server\.error\.include-exception)
检索: 上述配置是否为 always / true
(?i)(whitelabel|error\.html|error\.ftl)   # 默认错误页
```

### 10.6 审计日志与可追溯性

```
# 关键操作是否有日志
检索以下操作是否记录审计日志（操作人、时间、来源 IP、目标对象、结果）:
  - 登录/登出/登录失败    (?i)(login|logout|signin|auth).*log
  - 权限变更              (?i)(role|permission|grant|revoke).*(update|change|assign)
  - 数据导出/批量删除      (?i)(export|download|batchDelete|batchUpdate)
  - 金额/配置变更          (?i)(price|amount|config|setting).*(update|change)
  - 敏感数据访问           (?i)(view|read|access).*(user|patient|order)
# 日志是否可被篡改（本地文件、无远程汇聚、无完整性保护）
(?i)(log4j|logback|logging).*(roll|file|append)
Glob: **/{log4j2?.xml,logback*.xml,log4j*.properties}
检索: 是否配置了远程汇聚（Syslog / Kafka Appender / ELK）
# 日志是否包含可追溯的请求标识
(?i)(traceId|requestId|correlationId|MDC\.put)
```

### 10.7 断言与调试残留

```
(?i)assert\s+\w|(?i)assert\(.*(auth|permission|check|valid|login|admin)
检索: 是否使用 assert 做安全校验（生产环境可能被禁用 → 校验失效）
(?i)(TODO|FIXME|HACK|XXX|WARNING).*(auth|安全|鉴权|校验|验证|临时|绕过)
(?i)(debugger|console\.(log|debug|trace))\s*\(
(?i)(测试|临时|写死|硬编码|先这样|待优化).*(校验|验证|权限|鉴权)
(?i)(//\s*(bypass|skip|disable).*(check|auth|verify|valid))
```

## 判定标准

### 成立

- `catch` 块吞掉异常后**继续放行**敏感流程（鉴权失败被静默忽略并放行）
- 权限校验或开关判断使用兜底默认值为「允许」
- 日志中记录口令、令牌、签名密钥、完整请求体、身份证/银行卡等敏感信息
- 全局异常处理器缺失，且框架配置把堆栈包含在响应中
- 异常消息（含堆栈、SQL、内部路径）被直接返回给客户端
- 日志中直接记录未经处理的用户输入（可注入换行伪造日志）
- 登录、权限变更、数据导出、金额变更等关键操作**无任何审计日志**
- 使用 `assert` 做安全校验
- 代码中留有绕过鉴权/校验的临时标记且仍然生效

### 排除或降级

- 异常被吞但仅影响非安全流程（如清理日志、统计上报），且不影响控制流
- 日志中记录的是脱敏后的字段（`138****8888`）
- 全局处理器存在且返回统一错误码，堆栈仅进服务端日志
- 审计日志由统一的 AOP / 拦截器实现（需确认覆盖了关键操作）
- 前端 `console.log` 仅存在于未打包的开发代码中（`confidence: low`，需确认构建流程）
- `assert` 仅用于单元测试

### 判定要点

1. **安全校验类的异常处理必须逐个阅读控制流。** 不要只看是否有 catch，要看 catch 之后发生了什么。
2. **审计日志判定要落到具体操作。** 在 `dimension_coverage[].conclusion` 中列出「已覆盖的审计点」与「缺失的审计点」。
3. **前后端分离项目**需分别检查后端日志与前端控制台输出。

## 分级参考

| 情况 | 等级 |
|------|------|
| 鉴权异常被吞导致 fail-open（未授权可访问） | Critical（与维度 03 联动，合并计一条） |
| 权限判断兜底默认值为「允许」 | Critical |
| 日志中记录明文口令/令牌/签名密钥 | High |
| 日志中批量记录完整请求体含个人敏感信息（违反合规） | Medium ~ High |
| 全局异常处理器缺失 + `include-stacktrace=always` | Medium |
| 异常消息直接返回客户端（含 SQL/内部路径） | Low ~ Medium |
| 关键操作无审计日志 | Medium |
| 日志可注入换行 | Low |
| `assert` 用于安全校验 | Low ~ Medium |
| 代码中残留绕过标记但仍然生效 | 按实际绕过的影响定级 |
| 生产代码残留 `console.log` | Info ~ Low |

## 修复建议要点

- **fail-closed 原则**：所有安全校验的异常分支必须默认拒绝。统一异常处理器对鉴权类异常返回 401/403
- **禁止空 catch**：至少记录日志并重新抛出或转为明确错误；静态检查工具规则可防回归
- **错误响应标准化**：统一错误码 + 用户可读文案，堆栈只写服务端日志；配置 `server.error.include-*` 为 `never`
- **日志脱敏**：在日志框架层（Layout/Filter）统一脱敏，而非依赖开发者自觉；禁止直接打印 `toString()`
- **日志注入防护**：转义 `\r\n`，或使用结构化日志（JSON）
- **审计日志**：通过 AOP / 拦截器统一记录关键操作（主体、动作、对象、结果、时间、来源 IP、traceId），并写入独立存储，不可被应用进程删除
- **可追溯性**：全链路注入 `traceId`（MDC / AsyncLocalStorage）

## 输出要求

- 判定 fail-open 类问题时，必须画出「异常发生点 → catch 块 → 后续控制流（放行/提交/返回成功）」的路径。
- 审计日志缺失类问题，在 `description` 中列出「应记录但缺失」的具体操作清单。
- 与维度 03 重叠的 fail-open 问题合并为一条，`dimensions` 标注 `["authn-authz","logging"]`。
- `cwe` 参考：错误处理不当 CWE-391、日志泄露敏感信息 CWE-532、日志注入 CWE-117、审计日志不足 CWE-778、堆栈泄露 CWE-209、fail-open CWE-636。
