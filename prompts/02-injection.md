# 02 · 注入类漏洞

## 审计目标

识别外部可控输入未经充分校验/参数化就进入解释器或敏感执行环境的路径。核心方法：**定位 Source → 追踪传播 → 确认 Sink → 检查拦截**。

## 检索线索

### 2.1 SQL / NoSQL 注入

```
# 字符串拼接型 SQL（Java）
(?i)(executeQuery|executeUpdate|createQuery|createNativeQuery|prepareStatement)\s*\(.*\+
(?i)(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY|GROUP BY).*(\+|\$\{|%s|\.format\(|f["'])
(?i)"\s*(SELECT|INSERT|UPDATE|DELETE)[^"]*"\s*\+
# 危险 API
(?i)execute\(.*(f["']|%|\.format|\+)
sequelize\.query\(|knex\.raw\(|db\.run\(|db\.all\(|db\.exec\(
(?i)\.raw\s*\(|\.whereRaw\s*\(|\.havingRaw\s*\(|\.orderByRaw\s*\(
# NoSQL
(?i)\$where|mapReduce|\$expr|find\(\s*\{.*req\.(body|query)
# ORM 逃逸口
(?i)(orderBy|order|sort|groupBy)\s*\(.*(req\.|params\.|request\.|ctx\.)
```

重点：**排序字段、表名、列名、LIMIT 值**是最容易被忽视的注入点——它们通常无法参数化，只能白名单校验。

### 2.2 命令注入

```
(?i)(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|exec\(|execSync|spawn\(|execFile|child_process)
(?i)os\.(system|popen|exec[lv]p?e?|spawn[lv]?p?e?|subprocess\.)
(?i)subprocess\.(Popen|run|call|check_output)\(.*shell\s*=\s*True
(?i)(system|exec|shell_exec|passthru|popen|proc_open)\s*\(   # PHP
(?i)os/exec|exec\.Command
# 拼接特征
(?i)(cmd|command|shell)\s*[:=]\s*.*(\+|\$\{|%s|f["'])
```

### 2.3 代码 / 表达式注入

```
eval\(|exec\(|compile\(|Function\(   # JS/Python
(?i)SpelExpressionParser|ExpressionParser|parseExpression
(?i)Ognl|OgnlUtil|ognl\.getValue
(?i)ScriptEngine|Nashorn|GroovyShell|GroovyClassLoader
(?i)ELProcessor|ValueExpression|createValueExpression
(?i)yaml\.load\((?![^)]*Loader\s*=\s*(yaml\.)?Safe)   # 不安全 YAML
(?i)pickle\.loads?|cPickle|cPickle\.loads
```

### 2.4 反序列化

```
(?i)ObjectInputStream|readObject\(|readUnshared
(?i)XMLDecoder|XStream|fromXML\(
(?i)JSON\.parseObject|JSONObject\.parseObject|@type    # Fastjson autotype
(?i)ObjectMapper.*enableDefaultTyping|activateDefaultTyping
(?i)enableDefaultTyping|@JsonTypeInfo
(?i)unserialize\(|__wakeup|Serializable
```

**Fastjson / Jackson 多态反序列化是 Java 生态最高危的 RCE 入口，命中必查调用是否可控。**

### 2.5 模板注入（SSTI）与 XXE

```
# SSTI
(?i)(render_template_string|Template\()|Jinja2|freemarker|velocity|thymeleaf
(?i)(Thymeleaf|Freemarker|Velocity).*\+|TemplateEngine.*process
handlebars\.compile|Handlebars\.compile|ejs\.render\(|pug\.render
# XXE
(?i)DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|XMLReaderFactory
(?i)SAXReader|DocumentHelper\.parseText|XmlMapper|Unmarshaller
(?i)feign\.Decoder|XMLReader|SchemaFactory
检索后检查是否存在: disallow-doctype-decl|external-general-entities|XMLConstants\.FEATURE_SECURE_PROCESSING
```

**XXE 判定关键**：`DocumentBuilderFactory` 等工厂是否显式关闭了外部实体。未关闭即成立，默认配置下 Java 的 `DocumentBuilderFactory` 是允许 DTD 的。

### 2.6 其他注入面

```
# LDAP
(?i)(search|InitialDirContext|DirContext).*(\+|\$\{|%s)
# XPath
(?i)xpath\.(compile|evaluate)|XPathExpression.*\+
# 日志注入
(?i)(log|logger)\.(info|debug|warn|error|trace)\(.*(req\.|request\.|params|header|input)
# HTTP Header / 响应头注入
(?i)(addHeader|setHeader|Header\()\s*\(.*(req\.|request\.|params|input)
# 重定向（可能升级为开放重定向 → 钓鱼/SSRF）
(?i)(sendRedirect|redirect\(|Location).* (req\.|request\.|params|url|next|return)
# CSV 注入（导出功能）
(?i)(writeCsv|exportExcel|toCsv|\.csv).*\+
# GraphQL
(?i)graphql|apollo|gql`|GraphQLSchema
# 原型链污染
(?i)(merge|extend|defaultsDeep|set|assign)\s*\(.*req\.(body|query)
(?i)__proto__|constructor\s*\[|prototype\s*\[
```

## 判定标准

### 必须确认的三件事

| 环节 | 判定问题 | 结论影响 |
|------|---------|---------|
| **Source 可控性** | 输入是否来自用户/外部，还是常量或内部可信配置？ | 不可控 → 排除 |
| **传播路径** | 输入到 Sink 之间是否经过过滤、转义、类型转换、白名单？ | 有有效过滤 → 降级 |
| **Sink 危险度** | 该 Sink 能否执行代码、读取任意数据、绕过权限？ | 仅能影响性能/格式 → 降级 |

### 有效拦截 vs 无效拦截

**视为有效（可降级）：**
- 预编译语句 + 参数绑定（`PreparedStatement` 占位符、ORM 参数化、`?` / `$1` 绑定）
- 命令执行采用**数组参数形式**且不经 shell（`ProcessBuilder(List)`、`execFile`、`subprocess` 无 `shell=True`）
- 输入经**严格白名单枚举**校验后才进入拼接（如 `orderBy` 只允许 `[id, name, created_at]`）
- 框架级自动转义（如 MyBatis 使用 `#{}` 而非 `${}`）
- 反序列化前有类型白名单 / `ObjectInputFilter` / 关闭 autotype

**不视为有效（不降级）：**
- 仅用 `StringEscapeUtils` / `replace("'", "''")` 做手工转义
- 黑名单过滤（可绕过：大小写、注释、编码、Unicode 归一化）
- 前端 JS 校验（可绕过）
- `addslashes`、`strip_tags` 单独使用
- 在部分调用链上做了校验，但 Sink 是公共方法被其他入口直接调用
- 正则替换过滤了少数字符（如只过滤单引号），未覆盖其他注入语法

## 分级参考

| 情况 | 等级 |
|------|------|
| 未授权可达的 RCE（命令/代码/反序列化注入），且无拦截 | Critical |
| SQL 注入可绕过认证或读取全库 | Critical |
| 需认证但可造成大范围数据泄露的 SQL 注入 / 存储型模板注入 | High |
| 需认证的命令注入、路径可控的模板注入 | High |
| NoSQL 注入、XPath/LDAP 注入、开放重定向 | Medium |
| 日志注入、CSV 注入、Header 注入 | Low ~ Medium |
| 存在拦截但拦截方式脆弱（黑名单） | 按原等级降一级，`confidence: low` |

## 修复建议要点

针对每个 Sink 给出**可直接落地的改法**，必须包含改造前 / 改造后代码对比：

- SQL：改用参数化查询；表名/列名/排序方向用白名单枚举映射
- 命令：改用数组参数 API，禁止 `shell=True`，对参数做白名单
- 反序列化：升级到安全版本并关闭 autotype / 启用类型白名单 / 改用 JSON 纯数据结构
- XXE：显式关闭 DTD 与外部实体，启用 `FEATURE_SECURE_PROCESSING`
- SSTI：禁止将用户输入作为模板内容，改用变量传参
- 模板注入类统一原则：**模板内容必须是常量，用户数据只能作为数据**

## 输出要求

- 每个 finding 必须画出链路：`Source（文件:行）→ 传播（可选）→ Sink（文件:行）`，写入 `evidence`。
- `cwe` 字段填写准确的编号（SQL 注入 CWE-89、命令注入 CWE-78、代码注入 CWE-94、反序列化 CWE-502、XXE CWE-611、路径穿越见维度 09）。
- 同一根因在多处出现时合并，用 `occurrences` 列出全部位置。
