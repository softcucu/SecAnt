# SecAnt Witness / Blocker 对抗验证方案

本文档描述当前 SecAnt / proto-vuln-hunt 的漏洞候选验证方案。验证阶段已从“正反举证 + 多 judge 多数票”升级为“witness vs blocker 交叉验证 + 终局裁判定向补查”。

核心目标不再是让多个 agent 对“真假”投票，而是回答一个可复核问题:

```text
在 攻击者能力 ∩ 输入合法域 ∩ 程序状态 ∩ 代码约束 下，
是否存在可触发坏结果的 witness？
```

## 1. 总体流程

每条候选 finding 默认经过 5 个 verify agent:

```text
audit/recheck 产出候选
  |
  +-> witness builder        正方:构造合法触发 witness
  |
  +-> blocker builder        反方:构造 blocker / 不可满足证明
  |
  +-> witness judge          裁判:质询 witness 是否满足合法域、状态、代码约束
  |
  +-> blocker judge          裁判:质询 blocker 是否全局、决定性、支配相关路径
  |
  +-> final adjudicator      终局裁判:定向补查 1-2 个关键缺口,输出工程决策
```

`verify_votes` 仍保留为兼容配置字段，但当前不再控制裁决票数量。

## 2. 五类 Agent 职责

### 2.1 Witness Builder

正方必须构造最小合法触发 witness。它需要说明:

- 攻击者能力与前置条件。
- 输入合法域:协议字段宽度、格式语法、配置上限、枚举范围。
- 程序状态:认证态、连接态、对象生命周期、锁状态。
- 代码约束:沿途 if / clamp / return / assert / check。
- 从入口到 sink / 坏结果的最小路径。
- 触发条件和坏结果。

给不出完整 witness 时必须 `witness_complete=false`，并写明缺口。

### 2.2 Blocker Builder

反方必须构造 blocker 或不可满足证明。它需要找:

- 输入域/协议/配置/类型宽度让坏条件不可满足。
- guard / clamp / auth / state / lock / refcount 是否支配所有相关路径。
- sink 语义是否并不危险，或影响/输出通道不成立。

blocker 必须标注作用域:

```text
global | path_local | branch_local | config_local | partial | unknown | none
```

只有 `global` 且被复核为决定性时才能直接否决。

### 2.3 Witness Judge

只质询 witness，不重新审计整仓。重点核对:

- witness 中的输入/状态是否真的合法。
- witness 是否经过当前代码路径可达。
- witness 是否真的触发坏条件。
- 引用的 `path:line` 是否支撑结论。

输出:

```text
accepted | weakened | rejected | inconclusive
```

### 2.4 Blocker Judge

只质询 blocker。重点核对:

- blocker 是否支配所有相关路径。
- blocker 是否覆盖所有合法输入/状态。
- blocker 是否只是局部分支、局部配置或只打掉某个 witness。

输出:

```text
global_decisive | partial | invalid | unknown_scope
```

### 2.5 Final Adjudicator

终局裁判读取前四阶段结果，做一次限时定向补查，只查最影响最终决策的 1-2 个事实，然后必须输出工程决策。

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

验证 prompt 会按 finding 的 `bug_class` / `lens` 注入专项证明义务:

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
witness | blocker | witness_judge | blocker_judge | final_adjudicator
```

Web、候选 JSON、finding JSON 和 Markdown 导出都会展示 witness、blocker、裁判质询、终局补查事实和最终工程决策。

## 6. 实现位置

| 模块 | 职责 |
|---|---|
| `proto_vuln_hunt/schemas.py` | witness / blocker / review / final adjudication schema |
| `proto_vuln_hunt/prompts.py` | 五阶段验证 prompt 与专项证明义务 |
| `proto_vuln_hunt/pipeline.py` | 编排五阶段验证、终态保存、risk/manual/suppressed 流转 |
| `proto_vuln_hunt/exporters.py` | Markdown 导出验证记录 |
| `proto_vuln_hunt/web/static/app.js` | Web 展示新状态与验证详情 |
| `proto_vuln_hunt/tests/test_pipeline_verify.py` | 单元测试覆盖确认、否决、编码质量问题、人工复核与失败重试 |
