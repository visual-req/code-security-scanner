# 09 · 文件、路径与网络请求

## 审计目标

审计所有「与文件系统和外部网络交互」的代码。这类 Sink 一旦被污染，通常直接导致任意文件读写或内网穿透，是危害最直观的一类漏洞。

## 检索线索

### 9.1 路径穿越

```
# 直接用外部输入拼路径
(?i)(new\s+File|Paths\.get|Path\.of|Files\.(read|write|delete|copy|move|newInputStream|newOutputStream)|FileInputStream|FileOutputStream)\s*\(.*(\+|\$\{|%s|\.format\(|f["'])
(?i)(open|readFile|writeFile|createReadStream|createWriteStream|unlink|readdir)\s*\(.*(req\.|request\.|params|query|body)
(?i)(os\.path\.join|open|shutil\.(copy|move|rmtree))\s*\(.*(request\.|input|param|filename)
(?i)(stream_copy_to_stream|fopen|file_get_contents|file_put_contents|unlink|readfile)\s*\(.*\$_(GET|POST|REQUEST)
# 未做规范化
检索: 是否在拼接后调用 normalize() / realpath() / CanonicalPath / ResolvePath
检索: 是否存在 startsWith(basePath) 校验 —— 注意此校验在未规范化时容易被 `..` 或绝对路径绕过
# 模板/文件名/下载名
(?i)(filename|fileName|filepath|filePath|path|dir|directory)\s*[:=]\s*(req\.|request\.|params|query|body|@RequestParam|@PathVariable)
```

### 9.2 任意文件读取 / 下载

```
(?i)(download|export|viewFile|readFile|getFile|serveFile|sendFile|StreamingResponseBody)
检索: 下载接口是否使用客户端传入的文件名/路径/ID 直接定位文件
(?i)(@GetMapping|@RequestMapping).*(download|export|file|attach|resource)
检索: 是否校验目标文件属于允许的目录或允许的资源列表
# 静态资源映射
(?i)(addResourceHandler|resourceHandler|static.*location|config\.add_resource)
# 敏感文件清单（用于判断影响面）
(?i)(/etc/passwd|/etc/shadow|\.\./|\.git/|WEB-INF|application\.(yml|properties)|\.aws/credentials|id_rsa|\.ssh/)
```

### 9.3 文件上传

```
(?i)(MultipartFile|mvc\.MultipartFile|@RequestPart|multipart/form-data|formidable|multer|busboy|filepond|upload)
检索清单（逐项确认）:
  1. 是否校验扩展名？是否为黑名单（可绕过：jsp→jspx/phtml、php→phtml/phar/php5、大小写、%00、双后缀）
  2. 是否校验 Content-Type？是否只信客户端声明的 Content-Type？
  3. 是否校验文件魔数（真实内容）？
  4. 是否重命名？是否保留用户提供的文件名？
  5. 存储目录是否在 Web 可访问路径下？
  6. 存储目录是否设置了可执行权限？
  7. 是否有大小限制（防 DoS）？
  8. 是否上传到独立域名/对象存储（防同源解析）？
# 危险特征
(?i)getOriginalFilename|originalname|\.name\s*\+|transferTo\s*\(.*getOriginalFilename
(?i)(jpg|png|pdf|zip|docx?)$ 的扩展名白名单是否可被 `xxx.jsp.jpg` 绕过
(?i)new\s+File\s*\(\s*uploadDir\s*\+\s*.*getOriginalFilename
```

### 9.4 压缩包解压

```
(?i)(unzip|unzipSync|extractAll|ZipFile|ZipInputStream|TarArchive|tarfile|extract\(|Expand-Archive|七牛|压缩|解压)
检索清单:
  1. 是否校验解压后的路径仍在目标目录内（Zip Slip）
  2. 是否限制解压后的总大小 / 文件数（Zip Bomb）
  3. 是否限制嵌套层数
  4. 是否处理符号链接（可能指向目录外）
# 危险模式
(?i)(getName\(\)|getEntry|entryName).* \+ .*destDir   → 未做路径校验即拼接
(?i)extractAll\s*\(\s*\)    → Java 的 extractAll 在旧版本存在 Zip Slip
```

### 9.5 SSRF（服务端请求伪造）

```
(?i)(HttpURLConnection|URLConnection|HttpClient|RestTemplate|WebClient|OkHttp|FeignClient|requests\.(get|post)|axios|fetch|urllib|http\.get|curl_exec|file_get_contents)
检索: URL / host / endpoint 是否来自客户端参数
(?i)(url|uri|target|endpoint|host|domain|redirect|callback|webhook|imageUrl|avatarUrl)\s*[:=]\s*(req\.|request\.|params|query|body|@RequestParam)
# 无防护特征（应逐项核对是否存在）
检索: 是否存在以下任一防护:
  - 协议白名单（仅 http/https）
  - 域名/网段白名单
  - 禁止内网 IP（127.0.0.1 / 10. / 172.16-31. / 192.168. / 169.254.169.254 / ::1 / 0.0.0.0）
  - 解析后重新校验 IP（防 DNS Rebinding）
  - 禁止跟随重定向，或重定向后再次校验
# 云元数据端点（SSRF 的最高价值目标）
(?i)(169\.254\.169\.254|metadata\.google|metadata\.azure|100\.100\.100\.200|latest/meta-data)
# 危险协议
(?i)(file://|gopher://|dict://|ftp://|jar://|expect://|ldap://)
# 图片/URL 预览功能（SSRF 高发点）
(?i)(imageUrl|avatar|avatarUrl|webhook|callback|feed|rss|proxy|preview|screenshot|pdf.*url)
```

### 9.6 文件操作的其他风险

```
# 临时文件竞态
(?i)(File\.createTempFile|tempfile\.mktemp|tmpnam|/tmp/)
检索: 是否先检查存在再创建（TOCTOU）
# 符号链接跟随
(?i)(readSymbolicLink|followLinks|symlink|os\.readlink)
# 删除操作的路径来源
(?i)(delete|remove|unlink|rmtree|deleteFile)\s*\(.*(req\.|request\.|params|body)
# 权限设置过宽
(?i)setReadable\(\s*true\s*,\s*false\s*\)|chmod\s*,?\s*0?777|setPosixFilePermissions.*ALL
# 日志/数据库备份文件
检索: 是否存在 *.sql / *.bak / *.log / *.zip 备份文件位于可访问目录
# 硬编码绝对路径（部署适配与信息泄露）
(?i)["']([A-Z]:\\|/home/|/var/www|/Users/|/opt/)[^"']*["']
```

## 判定标准

### 成立

- 路径由客户端输入拼接而成，且未做「规范化 + 前缀校验」双重检查
  - 仅 `startsWith` 而未先 `normalize` → 仍成立（可用 `..` 绕过）
- 上传文件保留用户原始文件名，或存储于 Web 可访问目录，或扩展名校验为黑名单
- 解压时未校验条目路径（Zip Slip），或未限制解压规模（Zip Bomb）
- 服务端请求的 URL/主机名来自客户端，且无协议白名单与内网地址封禁
- 下载接口未校验目标资源的归属与允许范围

### 排除或降级

- 文件标识使用**服务端映射的 ID**（如数据库主键 → 存储路径），客户端无法影响路径
- 上传文件被重命名为随机 UUID，且存储于非 Web 根目录 / 对象存储私有桶，且做内容类型校验
- 解压前逐条目校验规范化路径，且限制总大小与文件数
- SSRF 已有「协议白名单 + 域名白名单」双重限制（此时降为 `Info`，仅建议补充 DNS Rebinding 防护）
- URL 参数仅取自服务端配置或校验过的枚举
- 仅允许特定受信任域名（需确认匹配逻辑严格，非 `endsWith` 这类可被 `evil.com.trusted.com` 绕过的判断）

### 必须验证的绕过方式

判定路径与 URL 校验是否有效时，必须逐一验证以下绕过：

| 校验方式 | 绕过方式 | 是否有效 |
|---------|---------|---------|
| 黑名单过滤 `..` | `....//`、URL 编码 `%2e%2e%2f`、双重编码、绝对路径 | ✗ |
| `startsWith(base)` | 先未 `normalize`：`base/../../etc/passwd` | ✗ |
| `endsWith(".jpg")` | `shell.jsp.jpg`（若 Web 服务器按后缀解析） | ✗ |
| 域名黑名单 | 短域名、DNS Rebinding、IP 编码（十进制/八进制/十六进制） | ✗ |
| 仅封禁 `127.0.0.1` | `127.1`、`0.0.0.0`、`[::1]`、`localhost`、内网段 | ✗ |
| 检查 `Host` 头 | 直接访问被省略的 Host | ✗ |

## 分级参考

| 情况 | 等级 |
|------|------|
| 未授权任意文件读取（可读配置/凭证/私钥） | Critical |
| 上传任意文件且可 Web 访问执行（GetShell） | Critical |
| SSRF 可达云元数据端点，或可探测内网 | Critical |
| 路径穿越写文件（可覆盖配置/计划任务） | Critical |
| 需认证的任意文件读写 / 下载他人文件 | High |
| Zip Slip / Zip Bomb | High |
| 上传目录可列举、文件类型校验仅用黑名单 | Medium |
| SSRF 已有部分限制但可绕过 | Medium |
| 缺少上传大小限制、临时文件竞态 | Low ~ Medium |
| 硬编码绝对路径 | Info |

## 修复建议要点

- **路径**：不使用客户端输入构造路径；必须使用时，`normalize()` 后校验是否位于基准目录内（`Path.startsWith` 于规范化之后），并拒绝绝对路径
- **文件标识**：改用服务端 ID 映射，客户端只见 ID 不见路径
- **上传**：白名单扩展名 + 魔数校验 + 随机重命名 + 存储到非 Web 目录/私有对象存储 + 强制下载头（`Content-Disposition: attachment`）+ 大小限制
- **解压**：逐条目规范化校验目标路径在解压目录内；限制总大小、文件数、嵌套层数；不跟随符号链接
- **SSRF**：协议白名单 + 解析后 IP 校验（拒私网/环回/链路本地）+ 禁用重定向或重定向后复校 + 出网走统一代理并记录日志
- **网络出口**：生产环境通过统一出口代理限制可访问的目标，从架构层根治 SSRF

## 输出要求

- 每条 finding 必须给出「污染源 → 路径拼接点 → 文件/网络操作」的完整链路。
- 对已有的校验手段，必须在 `description` 中说明其**为何可被绕过**（引用上表的绕过方式）。
- `cwe` 参考：路径穿越 CWE-22、任意文件上传 CWE-434、SSRF CWE-918、Zip Slip CWE-29、Zip Bomb CWE-409、不受限文件下载 CWE-552。
