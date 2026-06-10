# lens: authn — 认证降级 / 绕过 / 授权(设计层)

配合 `00-methodology.md` 使用。这是**设计/逻辑层**审计,重在理解认证状态机与授权点,而非单点 API 误用。

## 一、Bug Patterns
1. **凭证处理缺陷** —— 接受空凭证/默认凭证/硬编码后门;密码/口令比较用 `==`/`strcmp`(非常量时间,时序侧信道);
   登录失败与成功路径耗时差异可区分。
2. **认证回退 / 降级** —— 可被诱导退回弱认证或无认证(协商时未强制最小安全级);"兼容旧版本"分支跳过校验;
   错误处理路径意外放行(fail-open)。
3. **认证状态机混淆** —— **未认证态即处理本应认证后才允许的报文/操作**;认证步骤可被跳过/乱序;
   握手中途切状态导致权限提升;重放已认证消息建立会话。
4. **会话 / 令牌 / nonce** —— 可预测(弱随机、计数器、时间戳);可重放(无 nonce/时间戳/序号);
   不过期/不绑定来源;注销/超时未真正失效。
5. **授权(authz)缺失或错层** —— 特权操作前无权限检查;检查与使用之间有竞态;在客户端/错误的层做检查;
   IDOR(用对象 id 直接取数据,不校验归属)。

## 二、Phase-A grep 种子
```
strcmp\s*\(|memcmp\s*\(|==\s*0          # 凭证/MAC/token 比较(看是否常量时间)
password|passwd|secret|token|apikey|api_key|credential|login|auth|authenticate
nonce|session|cookie|challenge|replay|seq(uence)?
permission|privilege|is_admin|role|capability|authz|access_control|->\s*authenticated
fallback|downgrade|legacy|compat|insecure|allow_|skip_verify|no_auth
```
重点:画出认证状态机(谁能在什么状态处理哪些报文);找"在 authenticated=false 时仍执行"的分支。

## 三、Common False Positives to avoid
- 比较的是非敏感数据(时序无意义);或确实用了常量时间比较(`CRYPTO_memcmp`、`timingsafe_bcmp`)。
- "降级"分支被默认配置或编译期关闭且攻击者无法开启。
- 状态检查确实存在且覆盖该报文路径(去核实,而非假设)。
- 随机源是 CSPRNG;令牌确实绑定来源且会过期。

## 四、严重度提示
认证绕过/状态机混淆通常 CRITICAL/HIGH;认证降级、非常量时间比较通常 HIGH(见 00-severity-rubric,影响认证升一级)。
