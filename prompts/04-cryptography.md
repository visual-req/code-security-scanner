# 04 · 密码学实现

## 审计目标

检查加密算法选型、随机数来源、密钥管理、传输层校验四类问题。本维度通常不单独构成严重漏洞，但常作为其他高危漏洞的放大器（如弱哈希使撞库成功、跳过证书校验使中间人可行）。

## 检索线索

### 4.1 弱算法与不安全模式

```
# 弱哈希
(?i)(MD5|MD4|SHA-?1|MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-?1)["'])
(?i)(md5|sha1)\s*\(
(?i)DigestUtils\.md5|crypto\.createHash\s*\(\s*["']md5["']
# 弱对称加密
(?i)(DES|3DES|DESede|RC2|RC4|Blowfish|ARCFOUR)
(?i)Cipher\.getInstance\s*\(\s*["'](DES|DESede|RC4|Blowfish)
(?i)createCipher(iv)?\s*\(\s*["'](des|rc4|bf-)
# 不安全分组模式
(?i)Cipher\.getInstance\s*\(\s*["'][A-Za-z0-9]+/(ECB|CBC/PKCS5Padding)/   # ECB 一律不安全；CBC 需固定 IV 检查
(?i)(AES/ECB|DES/ECB|ECB)
(?i)([Mm]ode)\s*[:=]\s*["'](ecb|ECB)["']
# 不安全填充
(?i)(NoPadding|PKCS1Padding|ZeroPadding)   # 需结合场景判断，RSA 应优先 OAEP
# 弱密钥长度
(?i)(RSA|DSA|DH).*?(512|1024)\b
(?i)new\s+SecretKeySpec\([^,]+,\s*0,\s*(8|16)\b
```

### 4.2 随机数来源

```
# 不安全随机（用于令牌、盐、IV、验证码时成立）
(?i)(Math\.random|new\s+Random\s*\(|java\.util\.Random|rand\(\)|srand\(|mt_rand|srand)
(?i)RandomStringUtils\.random|RandomUtils
# 安全随机（视为合规）
(?i)(SecureRandom|secrets\.|os\.urandom|/dev/urandom|crypto\.randomBytes|crypto\.randomUUID|getrandom|UUID\.randomUUID)
```

**判定关键：用途，而非 API 本身。** `Random` 用于生成业务无关的展示序号可接受；用于生成 token / 盐 / IV / 验证码 / 会话 ID 则成立。

### 4.3 密钥与 IV 管理

```
# 硬编码密钥/盐/IV（与维度 01 联动，此处关注"可用于解密"）
(?i)(SecretKeySpec|IvParameterSpec|KeyGenerator|generateKey)\s*\(.*["'][^"']+["']
(?i)(static|final).*(KEY|SECRET|SALT|IV)\s*[:=]\s*["'][^"']+["']
# 固定 IV（CBC 模式下可预测 IV 等于削弱语义安全）
(?i)IvParameterSpec\s*\(\s*new\s+byte\[\]\s*\{\s*0
(?i)(iv|IV)\s*[:=]\s*["'][A-Za-z0-9+/=]{8,}["']
# 从口令直接派生密钥（未走 KDF）
(?i)new\s+SecretKeySpec\s*\(\s*\w*[Pp]assword\w*\.getBytes
检索后确认是否使用: PBKDF2|bcrypt|scrypt|Argon2|HKDF
```

### 4.4 传输层与证书校验

```
(?i)(TrustAllCerts|TrustManager|X509TrustManager|checkServerTrusted|HostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER)
(?i)verify\s*=\s*False|verify_ssl\s*=\s*False|CERT_NONE
(?i)rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED
(?i)(setHostnameVerifier|setSSLSocketFactory).*(ALLOW_ALL|TrustAll|NoopHostnameVerifier)
(?i)InsecureSkipVerify\s*:\s*true
(?i)(curl|wget).*(-k|--insecure)
(?i)ssl\._create_unverified_context|SSLContext.*TrustAll
# HTTP 明文地址
(?i)http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)
```

### 4.5 认证相关密码学

```
# 口令哈希（应使用 bcrypt/scrypt/Argon2/PBKDF2 且带盐）
(?i)(bcrypt|scrypt|argon2|PBKDF2|PasswordEncoder|BCryptPasswordEncoder|Argon2PasswordEncoder)
# 签名校验
(?i)(verify|checkSign|signature|hmac)\s*\(   → 检查是否使用常量时间比较
(?i)(equals)\s*\(.*(sign|mac|hmac|token|hash)   # 非常量时间比较 → 时序攻击
# 加密后的编码问题
(?i)Base64\.encode   → 检查是否误将 Base64 当作加密
```

## 判定标准

### 成立

- 用 MD5 / SHA1 存储口令或生成签名相关摘要
- 使用 DES / 3DES / RC4 / ECB 模式处理敏感数据
- 使用非密码学安全随机数生成令牌、盐、IV、验证码、会话 ID
- 加密密钥或 IV 硬编码在源码中（同时关联维度 01）
- 关闭 TLS 证书校验或主机名校验（`TrustAllCerts` / `verify=False`）
- 口令直接 `getBytes()` 作为密钥，未经过 KDF
- 敏感信息使用 Base64 编码并当作加密
- 签名/MAC 比较使用非常量时间函数（时序侧信道）

### 排除或降级

- 使用 MD5 做**非安全用途**：缓存键、内容去重指纹、ETag、UUID 生成（需在描述中说明用途已确认）
- 使用 MD5/SHA1 做**兼容外部协议**（如对接既有的签名规范），且已在注释中说明并标注风险
- `Random` 用于日志追踪号、展示用序号等非安全场景
- TLS 校验关闭仅存在于单元测试或本地调试代码（需确认不在生产调用链上）
- 已使用 `SecureRandom` 等安全 API，且用途匹配

### 判定要点

1. **先看用途再看算法。** 同一行 `MD5` 在内容去重场景是合规的，在口令场景是 Critical。
2. **看密钥来源与生命周期。** 密钥是否轮换、是否分环境、是否对称复用于多种用途。
3. **看调用链是否可达生产。** 测试目录下的 `verify=False` 不构成生产风险，但要在 `limitations` 中说明。

## 分级参考

| 情况 | 等级 |
|------|------|
| 生产环境关闭 TLS 证书校验，且传输敏感数据 | High |
| 口令使用 MD5/SHA1 存储或比较 | High（若同时无盐 → Critical 视业务而定） |
| 加密密钥硬编码且用于保护用户数据 | High |
| 使用 DES / RC4 / ECB 加密敏感数据 | Medium ~ High |
| 使用非安全随机生成会话令牌/密码重置令牌 | High |
| 使用非安全随机生成验证码 | Medium |
| 使用非安全随机生成非安全用途的编号 | 排除（不报或 Info） |
| Base64 当作加密、口令直接派生密钥 | Medium |
| 签名比较非恒定时间 | Low |

## 修复建议要点

- 口令存储：`bcrypt`（cost ≥ 10）/ `scrypt` / `Argon2id`，禁止可逆加密与裸哈希
- 对称加密：AES-256-GCM（优先 AEAD），每次加密使用安全随机 IV 并与密文一同存储
- 随机数：统一使用 `SecureRandom` / `secrets` / `crypto.randomBytes`
- 密钥管理：迁移到 KMS / Vault，明确轮换周期与分环境隔离
- 传输：恢复证书校验；如需自签证书，导入受信任的自建 CA 而非全局关闭校验
- 签名比较：使用 `MessageDigest.isEqual` / `hmac.compare_digest` 等常量时间实现

## 输出要求

- 描述中必须写明「用途」判断结论（如「该 MD5 用于缓存键，不构成风险，仅建议升级」）。
- 与维度 01 重叠的硬编码密钥，不重复计数，在 `dimensions` 中同时标注 `["secrets","cryptography"]`。
- `cwe` 参考：弱哈希 CWE-328、弱加密 CWE-327、不安全随机 CWE-338、证书校验缺失 CWE-295、固定 IV CWE-329、时序攻击 CWE-208。
