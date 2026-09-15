# 03 · 认证与授权

## 审计目标

验证「谁能进来」（认证）与「进来后能碰什么」（授权）两道关卡的完整性。绝大多数严重业务漏洞（越权读取他人数据、账户接管、后台提权）都出自本维度。

## 检索线索

### 3.1 认证入口与凭据校验

```
(?i)(login|signin|authenticate|doLogin|checkPassword|verifyPassword|validateUser)
(?i)(password|passwd|pwd)\s*(==|!=|\.equals\s*\(|===)
(?i)md5\s*\(.*password|sha1\s*\(.*password|DES.*password|encrypt.*password   # 见维度 04
# 账号枚举 / 时序攻击
(?i)(user\s*(not\s*exist|not\s*found)|no\s*such\s*user|用户名不存在|用户不存在)
# 默认/硬编码账号
(?i)(admin|root|test|guest)\s*[:/]\s*["'][^"']+["']
(?i)default[-_]?(password|pwd|admin)
```

### 3.2 会话与令牌

```
# Cookie 属性
(?i)(Set-Cookie|setCookie|addCookie|response\.cookie)
检索后检查是否含: HttpOnly / Secure / SameSite
(?i)cookie\.(set|setCookie)\(.*(?<!HttpOnly)
# 会话固定（登录后是否重新生成 session id）
(?i)(sessionId|JSESSIONID|PHPSESSID)
检索后检查: login 成功后是否有 invalidate\(\) / rotate / regenerate / changeSessionId
# 会话超时
(?i)(setMaxInactiveInterval|sessionTimeout|expires|maxAge|TTL)
# JWT 校验
(?i)(jwt|jose|jsonwebtoken|jjwt|nimbus|pyjwt)
检索后重点检查:
  - 算法是否写死（防止 alg: none / 算法混淆）
  - 签名是否真的被验证（verify / decode 的区别）
  - 过期时间是否校验（exp / nbf）
  - audience / issuer 是否校验
(?i)decode\s*\((?![^)]*verify)          # 只 decode 不 verify
(?i)algorithms?\s*[:=]\s*\[?\s*["']none["']
(?i)verify\s*\(\s*[^,)]*,\s*[^,)]*,\s*options\s*=\s*\{[^}]*verify_signature["']?\s*:\s*[Ff]alse
# Session / Token 存储位置
localStorage\.|sessionStorage\.   # 前端令牌存储，XSS 可直接窃取
```

### 3.3 授权与越权

```
# 缺失鉴权注解/中间件（识别出所有需要保护的路由，检查是否覆盖）
(?i)(@PreAuthorize|@Secured|@RequiresPermissions|@RequiresRoles|@RolesAllowed|@SaCheckLogin|@SaCheckPermission|@PermissionCheck|@Auth)
(?i)(authorizeRequests|antMatchers|httpSecurity|SecurityFilterChain|permitAll|authenticated\(\))
检索: permitAll\s*\(\)  →  逐个核对其覆盖的路径是否真的应公开
(?i)(hasRole|hasAuthority|isAuthenticated|checkPermission|checkPermissionWithHandler)
# 越权高发模式：直接用请求参数查询/修改资源
(?i)(findById|getById|selectById|updateById|deleteById|removeById)\s*\(\s*(req\.|request\.|params|id|userId|orderId|.*Id\s*\))
检索后确认: 是否校验了资源归属（该资源是否属于当前登录用户）
# 用户身份来源
(?i)(userId|uid|tenantId|orgId|role|isAdmin)\s*[:=]\s*(req\.|request\.|params|body|query|header)
# 前端传来的权限标识（严重）
检索: 后端是否信任前端提交的 role / permission / isAdmin 字段
```

### 3.4 密码策略与账号安全

```
(?i)(minLength|min_length|passwordPolicy|passwordRegex|PasswordValidator)
(?i)(maxLoginAttempts|loginFailCount|lockAccount|lockout|retryLimit)
(?i)(captcha|verifyCode|recaptcha|kaptcha)
(?i)(resetPassword|forgotPassword|changePassword|sendResetMail)
# 密码重置令牌
检索: 重置令牌是否随机、是否单次有效、是否绑定用户、是否有有效期
# 敏感操作二次验证
(?i)(sendSms|sendEmail|sendCode|verifySmsCode).*   → 检查验证码是否可爆破 / 是否绑定场景
```

### 3.5 第三方与联邦认证

```
(?i)(oauth|openid|oidc|saml|sso|callback|redirect_uri)
检索后检查:
  - state 参数是否存在且校验（防 CSRF）
  - redirect_uri 是否严格白名单（防令牌窃取）
  - id_token 是否验签
  - 是否校验第三方返回的 email_verified
(?i)(trustProxy|X-Forwarded-For|X-Real-IP|remoteUser)\s*   # 信任代理头导致鉴权绕过
```

## 判定标准

### 认证维度

**成立：**
- 密码以可逆方式或弱哈希存储/比较（配合维度 04 定级）
- JWT 只 decode 不 verify，或算法可被指定为 `none`/对称混淆
- 会话 ID 在登录成功后未轮换（会话固定）
- 敏感 Cookie 缺少 `HttpOnly` / `Secure` / `SameSite`
- 登录接口无频率限制，且无验证码 → 可无限爆破
- 密码重置流程可被预测（令牌为时间戳/自增 ID/短随机数）、可重放、未绑定用户
- 存在硬编码的默认账号或后门口令

**排除：**
- 使用成熟框架的默认安全配置（如 Spring Security 默认密码编码器、Keycloak 托管认证）
- 凭证校验交由外部 IdP，本仓库仅做透传（但仍需检查信任配置）

### 授权维度

**成立：**
- 路由未纳入鉴权中间件覆盖范围（例如新增了 `/api/admin/**` 但拦截器只配了 `/admin/**`）
- 使用请求参数中的 ID 直接查询/修改资源，且未校验 `resource.ownerId == currentUserId`
- 租户隔离仅靠前端传参，后端未从会话推导 `tenantId`
- 后端信任前端提交的 `role` / `isAdmin` / `permissions` 字段
- 仅在前端隐藏了按钮/菜单，后端接口无对应权限校验
- 批量接口（列表查询/导出/批量删除）未做归属过滤，可越权拉取他人数据

**排除：**
- 全局拦截器 + 注解式鉴权双重覆盖，且经核对路由已包含在内
- 资源本身即为公开数据（如公开文章、公共配置）

### 必须执行的覆盖度核对

授权维度**不能只看有没有鉴权代码，必须做覆盖度核对**：

1. 枚举所有对外暴露的路由/接口（从路由注册、控制器注解、网关配置中提取）。
2. 枚举所有鉴权规则（拦截器路径、注解、网关策略）。
3. 做差集 —— **未被任何规则覆盖的接口即为重点怀疑对象**。
4. 结果写入 `evidence`，并在报告 `dimension_coverage[].conclusion` 中说明覆盖比例。

## 分级参考

| 情况 | 等级 |
|------|------|
| 认证可被完全绕过（JWT 不验签 / 后门口令 / 算法 none） | Critical |
| 未授权即可访问管理接口或执行管理操作 | Critical |
| 水平越权可批量读取/修改他人敏感数据 | High |
| 垂直越权（普通用户执行管理员操作） | High |
| 账户接管（密码重置流程可被劫持） | Critical |
| 会话固定、敏感 Cookie 缺属性、无登录频控 | Medium |
| 账号枚举、错误信息泄露用户存在性 | Low |
| 前端隐藏但后端未校验（若接口确可越权调用） | High |

## 修复建议要点

- 认证：统一收敛到成熟框架（Spring Security / Passport / Django Auth 等），不自研校验逻辑
- JWT：服务端强制指定算法白名单，必须调用 verify 并校验 `exp`/`nbf`/`iss`/`aud`
- 会话：登录成功即 `changeSessionId()`；Cookie 全属性配置
- 授权：**服务端从会话推导主体身份，绝不信任客户端传入的身份与权限字段**
- 越权：所有资源查询统一加归属条件 `WHERE id = ? AND owner_id = ?`；批量接口强制注入归属过滤
- 覆盖度：把「新增路由必须显式声明鉴权策略」做成默认拒绝（deny by default）的配置

## 输出要求

- 本维度的 finding 必须在 `evidence` 中体现「数据流 + 鉴权缺失点」两部分。
- 涉及路由覆盖度问题时，在 `description` 中列出「已覆盖路径」与「未覆盖路径」的对比。
- `cwe` 参考：认证绕过 CWE-287、会话固定 CWE-384、缺失授权 CWE-862、越权访问 CWE-639、JWT 问题 CWE-347。
