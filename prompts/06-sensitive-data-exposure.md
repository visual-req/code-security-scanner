# 06 · 敏感数据暴露

## 审计目标

识别「数据本不该被看到，却被返回、记录、暴露」的问题。与维度 01（凭证）的区别：本维度关注**业务数据与系统内部信息**的过度暴露。

## 检索线索

### 6.1 接口过度返回

```
# 直接返回实体/表结构（可能包含密码、身份证、手机号等敏感字段）
(?i)(return|ResponseEntity|\.ok\(|json\(|send\(|res\.json\()\s*\(?\s*(user|account|customer|member|order|employee|.*Entity|.*DO|.*PO)\b
(?i)(findAll|list|selectList|queryList|getList)\s*\(   → 检查返回对象是否含敏感字段
# 序列化时未排除敏感字段
检索: 实体类中是否存在 password / idCard / phone / email / bankCard 字段，且:
  - 缺少 @JsonIgnore / @JsonProperty(access = WRITE_ONLY) / @JsonIgnoreProperties
  - 或缺少 DTO 转换（直接返回 DO/Entity）
# GraphQL / 动态字段选择
(?i)(graphql|gql|fields)\s*   → 检查是否允许客户端任意选择敏感字段
# 导出功能无字段控制
(?i)(export|download)(Excel|Csv|Pdf)?\s*\(
```

### 6.2 前端与客户端泄露

```
# 构建配置中注入敏感内容
(?i)(process\.env\.[A-Z_]*(SECRET|KEY|TOKEN|PASSWORD)|VITE_[A-Z_]*(SECRET|KEY|TOKEN))
检索: .env 文件中以 VITE_ / REACT_APP_ / NEXT_PUBLIC_ / NUXT_ENV_ 开头的变量
      —— 这些会被编译进前端产物，绝不能放密钥
# sourcemap 暴露源码
(?i)devtool\s*:\s*["'](source-map|inline-source-map)["']
(?i)sourceMappingURL
Glob: **/dist/**/*.map
# 注释中残留的内部信息
(?i)//\s*(TODO|FIXME|HACK|XXX).*(password|token|secret|admin|内网|账号|地址)
(?i)(账号|密码|内网|测试账号|管理员)\s*[:：]\s*\S+
# 移动端本地存储
(?i)(SharedPreferences|NSUserDefaults|Keychain|localStorage).*(token|password|secret)
```

### 6.3 调试与内部接口暴露

```
# Spring Actuator
(?i)management\.endpoints|management\.endpoint|actuator
检索: 是否暴露 env / heapdump / threaddump / mappings / beans / configprops
检索: management.endpoints.web.exposure.include 是否为 *
# Swagger / API 文档
(?i)(springfox|springdoc|swagger|knife4j|openapi)
检索: 生产 profile 下是否关闭；接口是否包含内部管理 API
# 调试开关
(?i)(debug\s*[:=]\s*[Tt]rue|DEBUG\s*=\s*True|app\.debug|debug_mode)
(?i)(/debug|/test|/internal|/actuator|/druid|/h2-console|/graphiql|/phpinfo)
# Druid / 监控台
(?i)druid.*(stat|web|login)
(?i)(h2-console|H2Console|web-allow-others)
# 健康检查泄露细节
(?i)(health|healthz|readyz).*(show-details|showDetails)\s*[:=]\s*always
```

### 6.4 错误与响应信息泄露

```
(?i)(e\.getMessage\(\)|e\.getStackTrace|ex\.getMessage|printStackTrace|traceback\.format_exc)
(?i)catch\s*\([^)]*\)\s*\{[^}]*return\s+.*(e\.getMessage|ex\.toString)
(?i)(res\.send|ResponseEntity\.status).*(err|error|exception)
(?i)("stack"|'stack'|"trace")\s*:   # 序列化异常对象给前端
```

详见维度 10（日志与异常处理），本维度只登记「导致敏感信息到达客户端」的部分。

### 6.5 传输与缓存

```
# CORS 过宽（与维度 07 联动）
(?i)Access-Control-Allow-Origin\s*[:=]\s*["']?\*
(?i)(allowCredentials|credentials)\s*[:=]\s*true
(?i)allowedOrigins?\s*\(?\s*["']\*["']
# 敏感接口未禁止缓存
检索: 返回个人信息的接口是否设置 Cache-Control: no-store
# 敏感参数出现在 URL（会进入日志、Referer、浏览器历史）
(?i)(password|token|secret|idcard|phone)\s*=\s*   # 在 GET 参数中
```

## 判定标准

### 成立

- 接口直接返回包含 `password` / 密钥 / 身份证 / 银行卡 / 完整手机号的实体对象
- 敏感字段在实体类上未做序列化排除，且存在直接返回实体的接口
- 前端环境变量前缀（`VITE_` / `REACT_APP_` / `NEXT_PUBLIC_`）中注入密钥
- 生产构建开启 sourcemap 且构建产物可公网访问
- 生产环境暴露 Actuator 敏感端点（`env` / `heapdump` / `threaddump` / `configprops`）
- 生产环境暴露 Swagger 且包含内部管理接口
- 调试开关在生产配置中开启
- 异常堆栈直接返回给客户端
- 密码/令牌等敏感信息通过 GET 参数传递

### 排除或降级

- 已使用 DTO/VO 隔离，敏感字段不进入响应体
- 实体字段有 `@JsonIgnore` 或序列化策略排除，且无其他泄露路径
- 接口仅返回脱敏后的数据（如 `138****8888`）
- 调试端点仅监听内网/本地，且部署配置确认不对外（此时降为 `Low` 并在描述中说明依赖部署前提）
- 字段本身非敏感（如 `userId` 为内部不可枚举 ID）

### 导出场景的专项判定

导出接口是过度暴露的高发区，必须单独核对：
1. 导出文件包含哪些列？是否可被普通用户导出敏感列？
2. 导出数据是否按当前用户权限过滤？（越权导出 → 关联维度 03）
3. 导出是否有数量限制？（无限制 → 可被用于批量拖库）
4. 导出文件存放位置是否可被他人下载？（关联维度 09）

## 分级参考

| 情况 | 等级 |
|------|------|
| 接口返回明文口令 / 全量密钥 / 身份证完整号 | High ~ Critical |
| Actuator heapdump / env 生产可达 | Critical（heapdump 可直接提取内存中的凭证） |
| 前端产物泄露密钥 | High（与维度 01 合并计数） |
| 越权导出大规模敏感数据 | High |
| 调试接口 / Swagger 生产暴露 | Medium ~ High |
| sourcemap 暴露源码 | Low ~ Medium |
| 异常堆栈返回客户端 | Low ~ Medium |
| 缺少 Cache-Control、敏感参数走 GET | Low |
| 手机号等未脱敏展示（页面展示场景） | Low |

## 修复建议要点

- **响应隔离**：所有对外接口统一使用 DTO/VO，禁止直接序列化持久化实体；DTO 中显式声明允许返回的字段（正向白名单，优于 `@JsonIgnore` 黑名单）
- **序列化兜底**：实体层对敏感字段加 `@JsonIgnore` 作为第二道防线
- **前端变量**：密钥类配置一律走服务端代理或后端接口下发，禁止使用 `VITE_` / `NEXT_PUBLIC_` 前缀
- **生产构建**：关闭 sourcemap 或限制其访问；清理注释中的内部信息
- **管理端点**：生产 profile 下关闭 Actuator 与 Swagger，如需保留则限定 IP 白名单并开启认证
- **异常处理**：全局异常处理器统一返回错误码 + 通用文案，堆栈只进服务端日志（关联维度 10）
- **脱敏**：统一脱敏工具，在序列化层对手机号/身份证/银行卡做掩码

## 输出要求

- 每条 finding 必须指明**泄露的具体字段名**与**可访问该接口的角色**（未授权 / 普通用户 / 管理员）。
- 若敏感字段同时属于凭证类，与维度 01 合并为一条 finding，`dimensions` 标为 `["secrets","sensitive-data"]`。
- `cwe` 参考：敏感信息暴露 CWE-200、堆栈泄露 CWE-209、明文传输敏感信息 CWE-319、数据过度返回 CWE-213。
