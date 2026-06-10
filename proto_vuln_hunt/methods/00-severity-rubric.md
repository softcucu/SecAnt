# 误报判定 + 严重度评级(威胁模型化)

验证阶段用本文给出 FP 判定与严重度。严重度**不是绝对的**:同一个 bug 在 REMOTE 下可能 Critical,
在 LOCAL_UNPRIVILEGED 下可能 Low。先确定威胁模型(由 workflow 的 `threatModel` 参数给出),再套对应表。

---

## 一、FP(误报)判定分类

- `TRUE_POSITIVE` —— 在威胁模型内有效、可达的漏洞。
- `LIKELY_TP` —— 确是 bug,可达性不完全确定但合理。
- `LIKELY_FP` —— 形似漏洞,但定义的攻击者无法到达。
- `FALSE_POSITIVE` —— 根本不是 bug(误读代码)。
- `OUT_OF_SCOPE` —— 是真 bug,但需要威胁模型之外的能力才能触发。

**不确定时,在 LIKELY_TP 与 LIKELY_FP 之间偏向 LIKELY_TP**(安全保守)。判误报必须有证据(见 00-methodology 第六节)。

### 威胁模型对可达性的影响
| 威胁模型 | 攻击者能力 | 可达性关注点 |
|---|---|---|
| `REMOTE` | 仅网络访问,无本地 shell | 网络输入能否到达此处? |
| `LOCAL_UNPRIVILEGED` | 非特权用户 shell | 是否跨越特权边界? |
| `BOTH` | 任一向量 | 两者都评,注明哪条适用 |

### 威胁模型特定规则
- `REMOTE`:仅靠本地配置/CLI 参数/环境变量才能触发 → `OUT_OF_SCOPE`;需要已有 shell → `OUT_OF_SCOPE`。
- `LOCAL_UNPRIVILEGED`:不跨特权边界 → `LIKELY_FP`;需要 root 才能触发 → `OUT_OF_SCOPE`。

---

## 二、严重度评级

### REMOTE 威胁模型
| 严重度 | 标准 |
|---|---|
| CRITICAL | 远程代码执行;认证绕过;可靠利用的远程内存破坏 |
| HIGH | 可靠的远程 DoS;敏感数据泄露;SSRF 打到内网 |
| MEDIUM | 难触发的远程 DoS;有限信息泄露;需特殊网络条件 |
| LOW | 仅本地可触发;理论问题;纵深防御改进 |

### LOCAL_UNPRIVILEGED 威胁模型
| 严重度 | 标准 |
|---|---|
| CRITICAL | 提权到 root;内核代码执行;容器/沙箱逃逸 |
| HIGH | 访问其他用户数据;以特权身份任意读写文件 |
| MEDIUM | 本地 DoS;系统数据泄露;有限的特权边界跨越 |
| LOW | 同用户范围内的 bug(未跨特权边界) |

### BOTH
- 远程可触发 → 用 REMOTE 标准;仅本地 → 用 LOCAL 标准;两者皆可 → **取较高**。

---

## 三、严重度调整项(在基准上加减)
- 缓解(ASLR/canary/FORTIFY)**可绕过** → 保持。
- 缓解在此处**有效阻断** → 降一级。
- 需要**赢得竞态** → 降一级。
- 需要**特定非默认配置** → 降一级。
- 影响**认证 / 密码学** → 升一级。
- 位于**广泛可达的入口**(如主收包/解析路径) → 升一级。

保持粗粒度即可——我们不是在发 CVE,Critical/High/Medium/Low 四档足够。相似的 bug 给相似的严重度。

---

## 四、协议栈语境补充
- **空口/未认证单包**即可崩溃/挂死的 DoS:在 REMOTE 下至少 HIGH(可靠则 HIGH,需特定条件则 MEDIUM)。
- 认证状态机绕过、认证降级:通常 CRITICAL/HIGH。
- 密码完整性缺失(可篡改)、可被降级到弱套件:通常 HIGH。
