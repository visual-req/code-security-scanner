# 01 · 密钥与凭证泄露

## 审计目标

找出被硬编码、误提交或可被外部获取的敏感凭证，以及凭证管理与生命周期上的缺陷。这是**唯一可能一次命中即定级 Critical** 的维度，任何疑似命中都必须优先上报。

## 检索线索

按顺序执行以下检索。先用 Glob 排除 `node_modules`、`vendor`、`dist`、`build`、`test/fixtures` 等目录。

**A. 代码中的硬编码赋值**
```
(?i)(password|passwd|pwd|pass)\s*[:=]\s*["'][^"']{3,}["']
(?i)(secret|token|apikey|api_key|app_secret|access_key|accesskey|private_key|credential|auth)\s*[:=]\s*["'][^"'\s]{8,}["']
(?i)(jwt|sign|encrypt|salt|hmac)[_A-Za-z]*(key|secret|salt)\s*[:=]\s*["'][^"']+["']
```

**B. 云厂商与第三方凭证特征**
```
AKIA[0-9A-Z]{16}                    # AWS Access Key ID
(?i)aws_secret_access_key\s*[:=]
AIza[0-9A-Za-z\-_]{35}              # Google API Key
xox[baprs]-[0-9A-Za-z-]{10,}        # Slack Token
gh[pousr]_[0-9A-Za-z]{36,}          # GitHub Token
sk-[A-Za-z0-9]{20,}                 # OpenAI 及同类
-----BEGIN [A-Z ]*PRIVATE KEY-----
eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.  # 疑似 JWT 字面量
```

**C. 连接串**
```
(?i)(jdbc|mysql|postgres|postgresql|mongodb|redis|amqp|kafka|elasticsearch|ftp|smtp)://[^\s"']*:[^\s"']*@
(?i)(server|host|endpoint)\s*=\s*[^\s]*;(?=.*(password|pwd)\s*=)
```

**D. 配置与部署文件**
```
Glob: **/{.env,.env.*,*.pem,*.p12,*.jks,*.keystore,*.key,*.pfx,id_rsa,credentials,secrets.yml,secrets.yaml,application-prod.*,config.prod.*}
Glob: **/{docker-compose*.yml,Dockerfile*,*.tf,*.tfvars,k8s/**,helm/**,.github/workflows/*}
```

**E. 前端与打包产物**
```
Glob: **/{public,static,assets}/**/*.{js,json,map}
检索: (?i)(api[_-]?key|secret|token)\s*[:=]
检索: sourceMappingURL
```

**F. 版本库历史与忽略策略**
```
Glob: **/.gitignore
检查: 是否存在 .env / *.pem / config.prod.* 但未出现在 .gitignore 中
检查: 是否存在 .env.example 且内含真实值（非占位符）
```

## 判定标准

**成立（确认为泄露风险）**
- 明文凭证出现在将被提交或已被提交的源码、配置、IaC 模板中
- 凭证出现在前端构建产物或可被客户端下载的静态资源中
- 私钥文件（`*.pem` / `id_rsa` / `*.jks`）位于仓库内且未被 `.gitignore` 排除
- 凭证通过 `process.env.X || "realvalue"` 这类**兜底默认值**形式硬编码

**降级或排除（误报）**
- 明确为占位符：`your-password-here`、`xxx`、`changeme`、`${DB_PASSWORD}`、`{{ .Values.password }}`、`<REPLACE_ME>`
- 测试专用固定值，且目标指向 `localhost` / `127.0.0.1` / 测试容器，且仓库非公开
- 已失效的历史凭证（需在描述中说明「疑似已失效，需确认」）
- 公钥、证书的公开部分、指纹值
- 示例文档中的演示密钥（如官方文档常见的 `sk-xxxx` 形式），需确认非真实

**判定要点**
1. 优先判断「这个值是否真的能连上/调用某个外部系统」。无法判断时按「疑似泄露」上报但标 `confidence: medium`。
2. 检查是否被 `.gitignore` 覆盖 —— 覆盖了仍要检查历史提交是否已包含（静态审计无法读 git 历史时，在 `limitations` 中声明）。
3. 判断该凭证出现在哪个环境：`prod` / `production` 相关文件一律按最高等级处理。

## 分级参考

| 情况 | 等级 | 置信度参考 |
|------|------|-----------|
| 生产环境数据库 / 云平台 AK/SK / 支付密钥明文硬编码 | Critical | high |
| 生产环境服务间调用 token、第三方 API Secret | High | high |
| 私钥文件（可直接用于身份冒充） | Critical | high |
| 前端产物中泄露的密钥（可被任意访客提取） | High | high |
| 测试环境凭证、内网服务凭证 | Medium | medium |
| 有兜底默认值的凭证（同时意味着配置缺失时静默降级） | High | medium |
| 疑似失效的历史凭证 | Low | low |

## 修复建议要点

给出建议时必须包含以下要素（按适用性选择）：

1. **立即轮换**：泄露凭证的第一优先级是吊销并更换，而非改代码。
2. **迁移到密钥管理**：环境变量 / K8s Secret / Vault / 云厂商 Secret Manager / CI Secret，给出具体的接入方式。
3. **代码层改造**：改为启动时强校验，缺失即 fail-fast，禁止兜底默认值。
4. **清理历史**：说明需要 `git filter-repo` / BFG 清理历史，并强调「清理历史前必须先轮换」。
5. **防回归**：`.gitignore` 补全、提交前钩子、CI 中加密钥检测门禁。

## 输出要求

- 报告中展示疑似凭证时**必须脱敏**：仅显示前 4 位 + `***` + 后 2 位。
- `evidence` 字段中不得包含完整凭证原文。
- 命中 Critical 时，在对话回复的开头**立即口头预警**，再继续后续维度。
- `remediation.summary` 必须以「立即轮换该凭证」开头。
