# 05 · 依赖与供应链

## 审计目标

通过阅读依赖清单、锁定文件、构建脚本与 CI/CD 配置，识别已知高危组件、被投毒风险、构建链路权限过宽三类问题。

**注意：本 skill 不执行 `npm audit` / `mvn dependency-check` 等工具。所有结论必须来自阅读清单文件与代码中的实际引用，不得凭经验断言某版本「有漏洞」—— 除非该版本与已知漏洞的对应关系是明确且广为人知的，此时需标注 `confidence: medium` 并建议人工核对。**

## 检索线索

### 5.1 依赖清单与锁定文件

```
Glob: **/{package.json,package-lock.json,yarn.lock,pnpm-lock.yaml}
Glob: **/{pom.xml,build.gradle,build.gradle.kts,settings.gradle}
Glob: **/{requirements.txt,requirements/*.txt,Pipfile,Pipfile.lock,poetry.lock,pyproject.toml,setup.py}
Glob: **/{go.mod,go.sum}
Glob: **/{Cargo.toml,Cargo.lock}
Glob: **/{composer.json,composer.lock}
Glob: **/{Gemfile,Gemfile.lock}
Glob: **/*.csproj,packages.config
```

读取后重点核对：

1. **是否有锁定文件**——没有 lock 文件意味着构建不可复现，存在依赖漂移风险（`Info` ~ `Low`）。
2. **版本声明方式**——`^` / `~` / `*` / `latest` / `LATEST` 等宽松范围，配合无 lock 文件即高风险。
3. **明显过期的主版本**——如 Spring Boot 1.x/2.x（EOL）、Log4j 1.x、Fastjson 1.2.x（< 1.2.83）、Struts 2、Shiro < 1.7、vue 2 EOL、node 14 以下。
4. **是否引用了非官方源或私有源**，源地址是否可信（`http://` 明文源、来历不明的第三方镜像）。
5. **同一组件多版本共存**（可能导致实际加载的是旧版本）。

### 5.2 高风险组件类别

在清单中检索以下组件，命中即逐个人工判断版本：

```
# Java 反序列化/RCE 历史高发
(?i)(fastjson|jackson-databind|xstream|shiro|struts2?|log4j|logback|commons-collections|groovy|snakeyaml|hutool|dubbo)
# 间接依赖常被忽视
(?i)(commons-beanutils|c3p0|aspectjweaver|bsh|rome|javax\.el)
# Node
(?i)(lodash|express|axios|node-fetch|jsonwebtoken|minimist|qs|ejs|handlebars|serialize-javascript|vm2|next|nuxt|webpack-dev-server)
# Python
(?i)(django|flask|jinja2|pyyaml|requests|urllib3|pillow|cryptography|paramiko|celery|pytorch|torch)
# 通用
(?i)(openssl|log4j|netty|spring-security|spring-core|tomcat|jetty)
```

**版本判定原则**：只对「版本号明确且与公开高危漏洞的版本范围关系广为人知」的情况给结论（如 Log4j 2.x ≤ 2.14.1 → Log4Shell）。其余标为「需人工核对版本」，不给具体 CVE 编号，避免编造。

### 5.3 构建脚本与安装钩子

```
# npm 生命周期脚本（供应链投毒主要载体）
(?i)"(pre|post)?(install|prepare|prepublish|postinstall)"\s*:
# 检查脚本内容是否: 下载远程二进制 / 执行 curl|bash / 访问未知域名 / 读取环境变量外发
(?i)(curl|wget|Invoke-WebRequest)\s+.*\|\s*(bash|sh|python|node)
(?i)node\s+-e\s+["']|eval\s*\(
# Python 构建钩子
(?i)setup\.py.*(cmdclass|os\.system|subprocess)
(?i)^{-r\s+https?://|--index-url\s+http://|--extra-index-url
# Maven/Gradle 远程仓库与插件
(?i)<repository>|<pluginRepository>|maven\s*\{|repositories\s*\{
# 依赖来源可疑
(?i)(git\+http://|github\.com/[^/]+/[^/]+\.git#|https?://[^"']+\.(zip|tar\.gz|jar))
```

### 5.4 CI/CD 与发布链路

```
Glob: **/.github/workflows/**,**/.gitlab-ci.yml,**/Jenkinsfile,**/.circleci/**,**/azure-pipelines.yml,**/.travis.yml
```

检查项：

```
# 表达式注入（GitHub Actions 高危）
(?i)\$\{\{\s*github\.event\.(issue|pull_request|comment|review)\.(title|body|head_ref)
# 权限过宽
(?i)permissions\s*:\s*write-all
(?i)(id-token|contents|packages)\s*:\s*write
# 第三方 Action 未固定版本（应为 commit SHA，而非 @master/@v1）
(?i)uses\s*:\s*[^@\s]+@(master|main|v\d+)\s*$
# 密钥使用方式（是否被回显、是否传入不可信脚本）
(?i)(secrets\.\w+|\$\{?[A-Z_]*(TOKEN|KEY|SECRET|PASSWORD))
# 拉取并执行未固定版本的脚本
(?i)(curl|wget).*\|\s*(bash|sh)
# 自托管 Runner（不可信 PR 可能 RCE）
(?i)(self-hosted|runs-on:\s*\[.*self-hosted)
```

### 5.5 容器与基础镜像

```
Glob: **/{Dockerfile*,*.dockerfile}
# 检查基础镜像来源与标签
(?i)^FROM\s+(?!.*@sha256)
(?i)^FROM\s+.*:(latest|stable|master)$
# 镜像内拉取外部脚本
(?i)(curl|wget|apt-get|pip install|npm i).*(-y|--yes)
# 以 root 运行 / 挂载密钥
(?i)^USER\s+root
检索: 是否存在 COPY/ADD 携带私钥、凭证、.env
```

## 判定标准

### 成立

- 使用了已知存在远程代码执行漏洞且版本范围明确落后的组件（如 Log4j 2.x ≤ 2.14.1、Fastjson ≤ 1.2.80 且开启 autotype、Shiro ≤ 1.6 的默认密钥）
- 无锁定文件 + 宽松版本范围，构建产物不可复现
- 引入来源为 `http://` 明文源、非官方私有源、或直接指向 git/压缩包的未固定版本
- 安装脚本中存在下载远程内容并执行的模式
- CI 中第三方 Action 使用可变引用（`@master` / `@v1`）而非 commit SHA
- CI 具备 `write-all` 权限，且会执行来自 PR 提交的代码
- 容器以 root 运行并将凭证 COPY 进镜像层

### 排除或降级

- 组件版本已更新到安全线以上（明确写出「版本在安全范围内」）
- 依赖存在但**代码中未实际引用**（死依赖，风险大幅降低，降为 `Info`）
- 构建脚本中的远程下载指向官方且带校验和（`sha256sum` 校验）
- CI 权限为只读，或仅对受信任分支触发
- 仅在开发依赖（`devDependencies`）中存在，且不进生产产物

### 重要约束

**不得编造 CVE 编号。** 只有当漏洞与版本范围的对应关系极为明确且广为熟知时才给出 CVE（如 Log4Shell = CVE-2021-44228 对应 Log4j 2.0-beta9 ~ 2.14.1）。其余情况：
- 在 `description` 中写「该版本可能受影响，建议核对上游安全公告」
- `confidence` 标为 `medium` 或 `low`
- `cwe` 可留空或填类别编号，不填具体 CVE

## 分级参考

| 情况 | 等级 |
|------|------|
| 使用明确存在未修复 RCE 漏洞的组件，且在生产依赖中并被实际调用 | Critical |
| 安装脚本执行远程下载内容 / 依赖源不可信 | Critical |
| CI 执行不可信代码且具备写权限 | High |
| 容器内嵌凭证或以 root 运行生产服务 | High（与维度 07 联动） |
| 组件版本未知 / 无锁定文件 | Medium |
| 使用 EOL（已停止维护）的框架主版本 | Medium |
| 死依赖、仅开发依赖存在的老旧组件 | Info ~ Low |

## 修复建议要点

- 组件升级：给出目标版本与升级注意事项（是否破坏性变更）
- 引入锁定文件并提交到仓库，CI 使用 `npm ci` / `--frozen-lockfile`
- 统一私有源并开启校验；Maven/Gradle 增加依赖校验
- CI 加固：第三方 Action 固定到 commit SHA、`permissions` 最小化、禁止在 pull_request_target 下执行未审计代码
- 容器：使用 distroless / 非 root 用户、固定镜像 digest、多阶段构建避免凭证进入镜像层
- 引入 SBOM 与依赖扫描门禁（作为后续改进建议，非本次必须）

## 输出要求

- 每条 finding 必须列出**具体的清单文件路径 + 行号 + 组件名 + 声明的版本字符串**。
- 无法确认版本影响时，`confidence` 标 `low`，并在 `description` 明确写出待人工核对的事项。
- `limitations` 中必须声明「本次未执行依赖漏洞数据库比对，版本影响性结论基于静态阅读，需结合官方公告复核」。
- `cwe` 参考：使用含漏洞组件 CWE-1395、依赖混淆 CWE-1357、CI 注入 CWE-94、权限过宽 CWE-250。
