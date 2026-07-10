# SecAnt Witness / Blocker 对抗验证方案

本文档描述当前 SecAnt / proto-vuln-hunt 的漏洞候选验证方案。验证阶段采用同一验证会话中的回合制正反辩论:反方先发,正方回应,再各补一轮,最后由第三个 verify 模型裁决。

核心目标不再是让多个 agent 对“真假”投票，而是回答一个可复核问题:

```text
在 攻击者能力 ∩ 输入合法域 ∩ 程序状态 ∩ 代码约束 下，
是否存在可触发坏结果的 witness？
```

## 1. 总体流程

每条候选 finding 默认经过 5 个 verify turn:

```text
audit/recheck 产出候选
  |
  +-> O1 opponent opening      反方先发:提出 blocker / 不可满足证明 / 关键质疑 claim
  |
  +-> P1 proponent response    正方回应 O1 claim,构造或修正合法 witness
  |
  +-> O2 opponent rebuttal     反方回应 P1 witness,判断 blocker 是否仍成立
  |
  +-> P2 proponent closing     正方回应 O2 剩余 claim,给出最终 witness/让步/未闭合点
  |
  +-> A1 final adjudicator     第三个 verify 模型读取同一会话辩论,输出工程决策
```

`verify_votes` 仍保留为兼容配置字段，但当前不再控制裁决票数量。

opencode 后端会把 O1/P1/O2/P2/A1 追加到同一个 session;A1 前先压缩上下文。其它后端按相同顺序独立调用,用结构化 turn JSON 传递上下文。

## 2. 五类 Turn 职责

### 2.1 O1 Opponent Opening

反方先发,优先寻找能打掉 finding 的 blocker、不可满足证明或关键 claim。它需要找:

- 输入域/协议/配置/类型宽度让坏条件不可满足。
- guard / clamp / auth / state / lock / refcount 是否支配所有相关路径。
- sink 语义是否并不危险,或影响/输出通道不成立。

blocker 必须标注作用域:

```text
global | path_local | branch_local | config_local | partial | unknown | none
```

只有覆盖所有相关合法输入或所有相关路径时才允许写 `global`。

### 2.2 P1 Proponent Response

正方必须逐条回应 O1 指定 claim,并构造最小合法触发 witness。它需要说明:

- 攻击者能力与前置条件。
- 输入合法域:协议字段宽度、格式语法、配置上限、枚举范围。
- 程序状态:认证态、连接态、对象生命周期、锁状态。
- 代码约束:沿途 if / clamp / return / assert / check。
- 从入口到 sink / 坏结果的最小路径。
- 触发条件和坏结果。

给不出完整 witness 时必须 `witness_complete=false`，并写明缺口。

### 2.3 O2 Opponent Rebuttal

反方必须回应 P1 的 witness、claim response 和新增 claim。重点核对:

- P1 是否真的解决了 O1 claim。
- witness 是否违反输入合法域、状态约束或代码约束。
- blocker 是否仍为 global,还是降级为 partial/unknown/none。
- 若不能证伪,必须在 concessions 中承认 blocker 不足。

### 2.4 P2 Proponent Closing

正方必须回应 O2 剩余 claim。它可以修正 witness,也可以承认关键 claim 无法闭合。P2 是正方最终立场,后续 A1 优先读取 P2 的 witness/concessions/unresolved_claims。

### 2.5 A1 Final Adjudicator

终局裁判读取同一 session 的前四轮辩论,围绕 claim ledger 收敛到工程决策。它可以继续 Read/rg 必要代码,但新增证据必须说明解决了哪个 claim 或引入了哪个关键冲突。

它同时输出两层结论:

```text
epistemic_verdict: proven_real | proven_false | unresolved
operational_decision: confirmed | rejected | suppressed_unproven | needs_manual_review
```

## 3. 工程决策

- `confirmed`: witness 被基本验证，且没有 verified global blocker。进入漏洞报告 / PoC 流程。
- `rejected`: blocker 被验证为 global / decisive，或坏条件在合法输入、状态、代码约束下不可满足。进入非问题。
- `suppressed_unproven`: witness 不完整，blocker 也不决定性，证据不足以确认或否决。作为漏洞页条目保留，但打 `编码质量问题` 标签，Web 展示为编码质量问题。
- `needs_manual_review`: high/critical 潜在影响且正反证据冲突，终局补查仍无法闭合。作为人工复核候选保留。

验证失败只用于终局裁判无结构化输出、工程决策无效、CLI/解析持续失败等流水线异常；证据未闭合不再简单落到 `verify_failed`。

## 4. 漏洞类型专项证明义务

验证 prompt 会按 finding 的 `bug_class` 注入专项证明义务:

- 整数类:证明合法输入空间内溢出/截断条件可满足，并且结果进入危险 sink；“可控”不等于“可溢出”。
- 内存类:证明合法输入能让访问范围超出对象边界，或对象生命周期进入 UAF / double-free 状态。
- 认证/状态机类:证明未授权或错误状态能到达 protected action，且没有统一 gate 支配路径。
- 注入/路径类:证明 payload 穿过 normalization/filter 后进入解释器语义边界或逃出 base dir。
- 竞态类:给出可行 interleaving，并证明锁/引用/事务没有覆盖 check-use 区间。
- 密码类:先证明 primitive 承担安全属性，再证明攻击者能力能破坏该属性。
- DoS/资源类:证明低成本输入可重复导致资源超过配额/预算并影响服务整体可用性。
- 信息泄露类:证明敏感/未初始化/OOB 数据进入攻击者可见输出通道。

## 5. 保存与展示

验证记录仍保存在 `votes[]`，但阶段名变为:

```text
opponent_opening | proponent_response | opponent_rebuttal | proponent_closing | final_adjudicator
```

Web、候选 JSON、finding JSON 和 Markdown 导出都会展示 witness、blocker、claim 回应/新增/让步/未闭合项、终局补查事实和最终工程决策。

## 6. 实现位置

| 模块 | 职责 |
|---|---|
| `proto_vuln_hunt/schemas.py` | witness / blocker / claim 字段 / final adjudication schema |
| `proto_vuln_hunt/prompts.py` | O1/P1/O2/P2/A1 验证 prompt 与专项证明义务 |
| `proto_vuln_hunt/pipeline.py` | 编排五轮同 session 辩论验证、终态保存、risk/manual/suppressed 流转 |
| `proto_vuln_hunt/exporters.py` | Markdown 导出验证记录 |
| `proto_vuln_hunt/web/static/app.js` | Web 展示新状态与验证详情 |
| `proto_vuln_hunt/tests/test_pipeline_verify.py` | 单元测试覆盖确认、否决、编码质量问题、人工复核与失败重试 |
