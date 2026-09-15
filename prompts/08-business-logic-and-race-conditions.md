# 08 · 业务逻辑与并发

## 审计目标

本维度不看「代码写得对不对」，只看「业务流程能不能被绕过」。这类问题无法通过任何自动化工具发现，只能靠理解业务语义后推理，因此是纯人工审计最应投入精力的维度。

**前提**：必须先读懂业务规则（金额如何计算、状态如何流转、次数如何限制），否则无法判断是否被绕过。

## 检索线索

### 8.1 金额与数量篡改

```
# 金额来自客户端
(?i)(amount|price|total|fee|money|payAmount|orderAmount)\s*[:=]\s*(req\.|request\.|params|body|query|@RequestParam|@RequestBody)
(?i)@RequestParam.*(amount|price|total|fee)
检索: 下单/支付接口是否接受前端传入的金额（应服务端依据商品 ID 重新计算）
# 负数 / 零值
检索: 是否校验 amount > 0、quantity > 0、count >= 1
(?i)(int|long|Integer|Long)\s+.*(amount|price|quantity)\s*=.*(\+|\-|\*)
# 精度问题
(?i)(float|double)\s+.*(amount|price|money|balance)
检索: 涉及金额是否使用 BigDecimal / 分为单位的整数
# 舍入方向
(?i)(setScale|toFixed|Math\.round|round\()   → 检查舍入模式是否对用户有利
# 溢出
检索: 数量/金额乘法前是否有上限校验
```

### 8.2 状态机与流程绕过

```
(?i)(status|state|step|stage|phase)\s*(==|===|!=|=)\s*["']?\w+["']?
(?i)(updateStatus|setStatus|changeState|nextStep)
检索: 是否存在"跳跃状态"路径（如订单从"待支付"直接到"已完成"）
检索: 状态流转是否为白名单映射，还是任意赋值
# 校验与使用分离（TOCTOU）
检索: 先校验条件，再到真正执行之间是否有时间窗口 / 事务外操作
(?i)(check|validate|verify).*\n.*(update|insert|delete|save)   # 跨行模式，需人工阅读
# 重复提交
检索: 关键提交接口是否有幂等键 / 去重 token / 唯一索引
(?i)(submitOrder|createOrder|pay|transfer|withdraw|apply)
```

### 8.3 并发与竞态

```
(?i)(@Transactional|BEGIN|session.*begin|transaction)
检索: 事务注解是否生效（同类内部调用、private 方法、捕获异常吞掉 → 事务失效）
(?i)(select.*for\s+update|FOR UPDATE|lock|Lock\(|synchronized|ReentrantLock|distributedLock|Redisson|SETNX|SET\s+\w+\s+\w+\s+NX)
检索: 库存扣减/余额变更是否有锁或原子操作
(?i)(getStock|getBalance|getCount)\s*\(.*\)[\s\S]{0,200}(setStock|setBalance|updateStock)
检索: 典型的"读-判断-写"非原子模式
# 缓存与数据库不一致
(?i)(cache|redis)\.(set|put|del|delete).*\n.*(update|save)
# 分布式环境下的单机锁
检索: 是否使用 synchronized / 本地 Lock 保护跨实例共享资源
# 定时任务并发
(?i)(@Scheduled|cron|schedule)
检索: 多实例部署下定时任务是否会重复执行（是否加分布式锁）
# 异步与消息的可靠性
(?i)(@Async|CompletableFuture|sendMessage|publish)
检索: 异步失败是否回滚、消息是否可能重复消费（幂等）
```

### 8.4 频控与验证码绕过

```
(?i)(rateLimit|limit|throttle|frequency|coolDown|maxAttempts)
检索: 频控键是什么（IP？用户？可伪造的 header？）
(?i)(X-Forwarded-For|X-Real-IP|Client-IP)   # 若频控基于可伪造的 header 则可绕过
(?i)(captcha|verifyCode|smsCode|emailCode|code)\s*(==|===|equals)
检索: 验证码是否：
  - 有有效期与尝试次数限制
  - 使用后立即失效（一次性）
  - 与手机号/场景绑定
  - 存储在服务端（而非前端下发）
(?i)(sendSms|sendCode|sendEmail)
检索: 发送接口本身是否有频控（无频控 → 短信轰炸）
# 计数在缓存中可被清除
检索: 失败计数是否可被客户端影响
```

### 8.5 支付、优惠与资金

```
(?i)(coupon|discount|promotion|voucher|redPacket|points|integral|balance|wallet|withdraw|cashback)
检索:
  - 优惠券是否可重复使用（是否有唯一约束 + 状态流转）
  - 折扣是否可叠加超出预期
  - 积分/余额扣减是否原子
  - 提现是否有金额校验与风控
# 回调与签名
(?i)(notify|callback|webhook|回调)
检索:
  - 是否验证签名
  - 是否验证金额与订单一致性
  - 是否验证来源（IP 白名单 / 证书）
  - 是否防重放（订单是否已处理）
(?i)(sign|signature|hmac|md5|verify).*callback
检索: 签名比较是否在业务处理之前
# 退款
(?i)(refund)
检索: 退款金额是否可超过原订单金额；是否可对同一订单多次退款
# 订单归属
检索: 支付时是否校验订单属于当前用户
```

### 8.6 越权型业务逻辑

```
# 批量接口绕过
(?i)(batch|bulk|batchDelete|batchUpdate|batchGet)
检索: 批量接口是否逐个校验权限（常只校验第一个或完全不校验）
# 参数覆盖
(?i)(@RequestBody.*(userId|id|role|status|amount|balance))
检索: 客户端提交的字段是否被直接用于更新（应白名单可更新字段）
# ID 可枚举 + 无归属校验（与维度 03 联动）
(?i)(id|Id)\s*\+\+|\+1|autoIncrement
# 导出/列表接口过滤条件来自客户端且可绕过
检索: 分页参数/过滤参数是否可被篡改以获取全量数据
```

## 判定标准

### 成立

- 关键业务数值（金额、折扣、数量、状态）直接来自客户端且服务端未重新计算/校验
- 数量或金额缺少下界（可为负/零）或上界（可溢出）校验
- 状态流转可跳过必经环节，或状态可被客户端直接赋值
- 存在「读-判断-写」的非原子序列，且资源需要并发保护（库存、余额、名额、券）
- 单机锁用于保护跨实例共享资源（多副本部署下失效）
- 关键提交接口无幂等保障，重复请求会重复执行
- 验证码无有效期 / 可重复使用 / 不与场景绑定 / 频控键可伪造
- 短信或邮件发送接口无频控
- 支付回调未验证签名、未校验金额、未防重放
- 退款金额未与原订单关联校验
- 批量接口未逐个做权限校验，或参数覆盖导致可修改敏感字段

### 排除或降级

- 服务端已依据可信数据源重新计算金额（客户端金额仅作展示）
- 有数据库唯一约束 / 乐观锁版本号 / 原子 SQL 保证并发正确性
- 状态流转为白名单映射表驱动，无跳跃路径
- 已使用分布式锁或原子操作保护共享资源
- 幂等通过唯一索引/幂等键保证
- 频控在网关层实现（需在描述中说明无法从应用代码确认，标注 `confidence: medium`）

### 判定要点

1. **必须先确定业务规则。** 从 README、注释、字段命名、校验代码反推「原本应该是什么规则」，再判断是否存在绕过路径。规则不明时标 `confidence: low` 并写明推测依据。
2. **关注「校验点」与「使用点」的距离。** 距离越远、跨越事务边界，越可能是 TOCTOU 漏洞。
3. **并发问题必须确认部署形态。** 单实例部署下 `synchronized` 有效；多实例/多线程下无效。无法确认部署形态时按「多实例」保守判断。
4. **不要臆造业务规则。** 若代码中不存在清晰的业务约束，不得假设「应该有一个校验」并据此报漏洞，只能标为 `Info` 级建议。

## 分级参考

| 情况 | 等级 |
|------|------|
| 金额/数量可被客户端任意篡改并直接生效（如 0 元下单） | Critical |
| 支付回调可伪造，导致订单被标记为已支付 | Critical |
| 余额/积分可被负数或并发刷取 | Critical |
| 库存/名额可并发超卖 | High |
| 状态机可绕过导致未支付即发货 / 越权变更 | High |
| 优惠券可重复使用、可叠加超出预期 | High |
| 退款可超额或重复 | High |
| 验证码可爆破 / 复用 → 可用于撞库或短信轰炸 | Medium ~ High |
| 关键接口无幂等，重复提交产生重复业务 | Medium |
| 频控键使用可伪造 Header | Medium |
| 定时任务多实例重复执行（无资金影响） | Low ~ Medium |
| 业务规则不清晰的推测项 | Info（`confidence: low`） |

## 修复建议要点

- **服务端权威**：所有业务数值由服务端依据可信数据重新计算；客户端只传业务标识（商品 ID、数量），不传金额
- **状态机**：用白名单映射表约束流转（`Map<fromState, Set<toState>>`），禁止任意赋值
- **并发**：库存/余额用原子 SQL（`UPDATE ... SET stock = stock - ? WHERE id = ? AND stock >= ?`）或分布式锁；乐观锁加版本号
- **幂等**：业务唯一键 + 数据库唯一索引；或幂等 token 表
- **频控**：以用户 ID 为键（非 IP）；网关 + 应用双层；验证码一次性 + 有效期 + 尝试次数上限
- **支付**：先验签再处理；校验金额与订单一致性；按订单号做处理幂等；来源 IP 白名单
- **可更新字段**：使用专门的更新 DTO，避免 `@RequestBody` 直接绑定实体

## 输出要求

- 每条 finding 必须在 `description` 中写出**被绕过的业务规则**（用一句话描述「本应如何」与「实际可如何」）。
- 并发类问题需说明推定的部署形态及该前提对结论的影响。
- 与维度 03 重叠的越权问题合并为一条，`dimensions` 同时标注。
- `cwe` 参考：业务逻辑缺陷 CWE-840、竞态条件 CWE-362、TOCTOU CWE-367、金额篡改 CWE-472、缺少幂等 CWE-837、参数篡改 CWE-472。
