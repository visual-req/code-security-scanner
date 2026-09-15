# 07 · 配置与基础设施

## 审计目标

审计部署形态与运行环境的安全基线：容器、编排、网关、安全响应头、跨域、TLS、云资源权限、IaC 模板。这类问题常被忽视，但一个错误的配置即可让前面的代码加固全部失效。

## 检索线索

### 7.1 容器与镜像

```
Glob: **/{Dockerfile,Dockerfile.*,*.dockerfile}
# 以 root 运行
(?i)^USER\s+root|检索: 是否完全没有 USER 指令
# 基础镜像
(?i)^FROM\s+.*:(latest|stable|master)
# 凭证进入镜像层
(?i)^(COPY|ADD)\s+.*(\.env|\.pem|\.key|id_rsa|credentials|secret)
(?i)^ENV\s+\w*(PASSWORD|SECRET|TOKEN|KEY)\s*=\s*\S+
# 过大的攻击面
(?i)^(apt-get|apk add|yum)\s+.*(curl|wget|netcat|nmap|telnet|vim|gcc|make)
# 危险权限
(?i)(chmod\s+777|--privileged|cap_add)
# 构建阶段拉取未固定内容
(?i)ADD\s+https?://
```

### 7.2 容器编排

```
Glob: **/{docker-compose*.yml,docker-compose*.yaml}
# 特权与挂载
(?i)privileged\s*:\s*true
(?i)network_mode\s*:\s*host|pid\s*:\s*host|ipc\s*:\s*host
(?i)(/var/run/docker\.sock|/etc/|/root|/proc)
# 关键应用配置
(?i)(SPRING_PROFILES_ACTIVE|NODE_ENV|APP_ENV|DEBUG).*[:=]\s*(prod|production|dev|debug|true)
# 数据库/中间件默认口令与端口暴露
(?i)(MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|REDIS_PASSWORD)\s*[:=]\s*\S+
(?i)^\s*ports\s*:   → 检查是否将 3306/6379/27017/9200/5601 暴露到宿主机
```

### 7.3 Kubernetes

```
Glob: **/{k8s,kubernetes,deploy,manifests,helm}/**,**/*.yaml(含 apiVersion)
# 特权
(?i)(privileged\s*:\s*true|allowPrivilegeEscalation\s*:\s*true|runAsUser\s*:\s*0)
# 危险能力
(?i)(capabilities|\bSYS_ADMIN\b|\bNET_ADMIN\b|\bSYS_PTRACE\b)
# 主机挂载
(?i)(hostPath|hostNetwork\s*:\s*true|hostPID\s*:\s*true)
# 缺失的安全上下文
检索: 是否缺少 securityContext / readOnlyRootFilesystem / runAsNonRoot
# RBAC 过宽
(?i)(cluster-admin|\*.*\*|resources\s*:\s*\[?\s*["']\*["'])
(?i)kind\s*:\s*(ClusterRoleBinding|RoleBinding)
# Secret 明文
检索: kind: Secret 且 data/stringData 中存在 base64 或明文字面量（base64 不是加密）
# 网络策略缺失
检索: 是否存在 NetworkPolicy
```

### 7.4 网关与安全响应头

```
Glob: **/{nginx.conf,*.conf,default.conf,httpd.conf,apache2.conf},**/{Caddyfile,traefik*.yml}
# 目录列举
(?i)(autoindex\s+on|Options\s+.*Indexes|directory_listing)
# 敏感路径未拦截
检索: 是否可访问 /.git/ / .env / *.bak / *.sql / *.log
# 安全响应头缺失（应逐项核对是否存在）
检索: Strict-Transport-Security | Content-Security-Policy | X-Content-Type-Options
      | X-Frame-Options | Referrer-Policy | Permissions-Policy
# 代理头未清理
(?i)proxy_set_header\s+X-Forwarded-(For|Host)
# 请求体/超时未限制
(?i)(client_max_body_size|proxy_read_timeout)
```

### 7.5 跨域与 Cookie

```
(?i)(cors|Access-Control-Allow-Origin|allowedOrigins|allowCredentials|@CrossOrigin)
检索判定:
  - Allow-Origin 为 * 且 Allow-Credentials 为 true  → 非法且危险
  - Allow-Origin 回显请求的 Origin 且未校验白名单  → 等同于 *
  - allowedOriginPatterns 为 *                     → 危险
(?i)(SameSite|HttpOnly|Secure)\s*[:=]
(?i)(cookie)\.(setDomain|setPath)\(.*\/
```

### 7.6 云与 IaC

```
Glob: **/*.{tf,tfvars,json,yaml}(位于 terraform/cloudformation 目录)
# 存储桶公开
(?i)(acl\s*=\s*"public-read"|public-read-write|block_public_acls\s*=\s*false)
(?i)(allUsers|AllAuthenticatedUsers)
# IAM 过宽
(?i)("Action"\s*:\s*"\*"|"Resource"\s*:\s*"\*"|AdministratorAccess|iam:\*)
# 网络开放
(?i)(0\.0\.0\.0/0|::/0)
检索: 是否开放了 22 / 3389 / 3306 / 6379 到公网
# 加密未开启
检索: 存储/数据库是否启用静态加密
# 日志未开启
检索: 是否关闭了访问日志 / 审计日志 / 流日志
```

### 7.7 应用配置基线

```
Glob: **/{application*.yml,application*.yaml,application*.properties,config*.json,settings.py,config.py,.env*}
# 生产 profile 混用
(?i)spring\.profiles\.active\s*[:=]\s*(dev|test|local)
(?i)(NODE_ENV|FLASK_ENV|DJANGO_DEBUG)\s*[:=]\s*(development|debug|true)
# 危险默认值
(?i)(trustStore|keyStore).*password\s*[:=]\s*(changeit|password|123456)
(?i)(verify|ssl)\s*[:=]\s*(false|disable)
# 日志级别过低（生产打 debug 会泄露敏感数据）
(?i)(log\.level|logging\.level).*=?\s*(DEBUG|TRACE)
# 限流与超时
检索: 是否配置了网关/应用层限流、连接超时、文件大小限制
```

## 判定标准

### 成立

- 容器以 root 运行且无 `readOnlyRootFilesystem` / 能力收紧
- 凭证通过 `COPY`/`ENV` 进入镜像层（镜像可被任意拉取即可提取）
- 容器以 `privileged` / `hostPath` / `hostNetwork` 运行
- K8s 使用 `cluster-admin` 或 `*` 权限的 ServiceAccount，且服务可被低权限用户触发
- K8s Secret 中的敏感值以明文或可解码形式随代码提交
- 网关开启目录列举，或未拦截 `.git` / `.env` / 备份文件
- CORS 为 `*` 且允许携带凭证（或动态回显未校验 Origin）
- 生产环境安全响应头全部缺失（尤其 `CSP`、`HSTS`）
- 云存储桶对公网可读写、IAM 使用 `*`、安全组对 `0.0.0.0/0` 开放数据库端口
- 生产配置中残留 dev/debug profile

### 排除或降级

- 测试/本地开发用的 compose 文件（需确认不用于生产，降为 `Low` 或 `Info`）
- 安全响应头由上游云 WAF / CDN 统一注入（需在描述中说明无法从代码确认）
- `privileged` 仅用于明确的运维工具容器且不对外暴露
- CORS 为 `*` 但接口全为公开只读数据，且未允许携带凭证（`Medium`）
- 已通过 `securityContext` + NetworkPolicy + RBAC 三重收紧

### 判定要点

1. **必须区分环境。** 同一个配置文件中的问题，在 `dev` 下是 `Info`，在 `prod` 下是 `High`。先确认该配置被哪个 profile/环境加载。
2. **响应头缺失类问题**要合并为一条 finding，不要每一项单独列一条刷数量。
3. **无法从代码确认的基础设施**（如云 WAF、外部负载均衡配置）必须写入 `limitations`，不得臆断。

## 分级参考

| 情况 | 等级 |
|------|------|
| 云存储桶对公网可读写、IAM `*` + 服务暴露 | Critical |
| K8s 特权容器 / cluster-admin + 可被外部触发 | Critical |
| 凭证进入镜像层或明文 Secret 提交入库 | High（与维度 01 联动） |
| CORS `*` 且允许携带凭证 | High |
| 生产环境暴露数据库端口到公网 | High |
| 网关目录列举、未拦截 `.git` | Medium ~ High |
| 生产残留 debug/dev profile、日志级别 DEBUG | Medium |
| 缺少安全响应头（合并计一条） | Low |
| 仅开发用配置中的问题 | Info ~ Low |

## 修复建议要点

- 容器：非 root 用户 + 只读根文件系统 + 丢弃全部 capability 后按需添加；密钥改为运行时注入（Secret / 环境变量挂载文件）
- K8s：为每个工作负载创建独立最小权限 ServiceAccount；应用 `securityContext`；加 NetworkPolicy 默认拒绝
- 网关：关闭目录列举、拦截敏感路径、补齐安全响应头（给出具体配置片段）
- CORS：改为显式白名单域名，禁止 `*` 与 `credentials: true` 共存
- 云：收紧安全组到具体来源、开启静态加密与访问日志、存储桶默认私有
- 配置：生产 profile 显式固定、启动时校验危险配置并 fail-fast

## 输出要求

- 每条 finding 必须写明**该配置生效的环境**（prod / staging / dev / 无法确定）。
- 配置类问题需给出「当前配置片段 + 期望配置片段」对比。
- `cwe` 参考：错误配置 CWE-16、CORS 配置错误 CWE-942、缺少安全头 CWE-693、权限过宽 CWE-250、明文存储凭证 CWE-256。
