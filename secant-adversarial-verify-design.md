# SecAnt 对抗辩论验证方案

本文档描述当前 SecAnt / proto-vuln-hunt 的漏洞候选验证方案。该方案已经从旧的“多 verifier 直接多数票”升级为“正方举证 + 反方证伪 + 多裁决票 + 证据门槛”的轻量对抗辩论验证流程。

## 1. 背景与目标

旧方案的验证逻辑是：

```text
候选 finding
  -> 启动 verify_votes 个 verifier
  -> 每个 verifier 输出 is_real=true/false
  -> 多数 real 则确认，多数 false 则否决
```

这个方案的主要问题是：只要模型输出了结构化 JSON，就可能参与投票。即使 reasoning 空泛、没有代码证据、没有 source-to-sink 链，仍可能影响最终结论。

当前方案的目标是：

- 不引入外部工具复现、CodeQL、semgrep、sanitizer 或人工复核队列。
- 保留现有无人值守流水线和 retry / final sweep 机制。
- 把验证从“模型观点投票”改成“证据合格裁决票投票”。
- 让确认、否决、失败原因都可以被复核和展示。

核心原则：

> 无代码证据的票不算票；无完整证据链的确认不直接确认；无明确证伪点的否决不直接否决。

## 2. 总体流程

每条候选 finding 的验证流程如下：

```text
audit/recheck 产出候选 finding
  |
  +-> verify_prover      正方举证：尝试证明漏洞成立
  |
  +-> verify_disprover   反方证伪：尝试证明 finding 是误报
  |
  +-> verify_judge * N   裁判：基于正反双方证据做裁决
  |
  +-> pipeline 证据门槛校验
  |
  +-> 只统计合格 judge 裁决票
       |
       +-> confirm 多数：确认漏洞
       +-> reject 多数：否决候选
       +-> 平票 / 有效票不足 / 证据不足：重试或 verify_failed
```

其中 `N = verify_votes`。默认 `verify_votes = 3`，因此默认每条候选会使用：

```text
1 个 prover + 1 个 disprover + 3 个 judge = 5 个 verify agent
```

## 3. 三类验证 Agent

### 3.1 verify_prover：正方举证

正方的职责是证明 finding 成立，不是简单同意 finding。

它必须回答：

- 不可信输入入口在哪里？
- 攻击者能控制什么字段、长度、状态或顺序？
- 从入口到 sink 的关键调用链是什么？
- 漏洞 sink 在哪里？
- 哪个校验缺失或不足？
- 在当前威胁模型下影响和可利用性如何？

如果证据不足，正方必须返回 `supports_real=false`，并在 `missing_evidence` 中说明缺口。

正方结构化输出使用 `VERIFY_PROOF_SCHEMA`，关键字段包括：

| 字段 | 含义 |
|---|---|
| `supports_real` | 正方是否用代码证据坐实 finding |
| `evidence_refs` | 代码证据列表，格式要求为 `path:line - 说明` |
| `source_chain` | 从入口到 sink 的关键路径节点 |
| `sink_ref` | 漏洞 sink 位置 |
| `reachability` | 可达性说明 |
| `controllability` | 可控性说明 |
| `corrected_severity` | 修正后的严重度 |
| `exploitability` | 可利用性判断 |
| `missing_evidence` | 尚缺的证据 |
| `verdict_confidence` | 置信度 |
| `reasoning` | 推理说明 |

### 3.2 verify_disprover：反方证伪

反方的职责是尝试证明 finding 是误报，但不能靠直觉否决。

它必须尝试寻找：

- caller trace 证伪可达性。
- 上游是否已经 clamp / bounds check。
- 状态机、认证态、配置或分支是否阻断路径。
- 数据是否实际上不可控。
- 代码语义是否说明这根本不是 bug。

如果没有拿到证伪证据，反方必须返回 `refutes_real=false`。

反方结构化输出使用 `VERIFY_DISPROOF_SCHEMA`，关键字段包括：

| 字段 | 含义 |
|---|---|
| `refutes_real` | 反方是否用代码证据证伪 finding |
| `evidence_refs` | 代码证据列表，格式要求为 `path:line - 说明` |
| `clearing_checks` | 证伪点，例如 clamp、return、状态检查、不可控条件 |
| `non_issue_reason` | 最终判定为非问题的代码证据与原因 |
| `reachability` | 可达性相关证伪说明 |
| `controllability` | 可控性相关证伪说明 |
| `corrected_severity` | 如果仍有影响，对严重度的修正 |
| `exploitability` | 可利用性判断 |
| `missing_evidence` | 尚缺的证伪证据 |
| `verdict_confidence` | 置信度 |
| `reasoning` | 推理说明 |

### 3.3 verify_judge：裁判裁决

裁判不再做大范围审计，而是基于正方和反方的结构化证据做裁决。裁判可以用 `Read/rg` 核对少量被引用的 `path:line`，但不能凭直觉补齐缺失证据。

裁判输出使用 `VERDICT_SCHEMA`，核心字段包括：

| 字段 | 含义 |
|---|---|
| `decision` | `confirm` / `reject` / `inconclusive` |
| `is_real` | 兼容旧字段；confirm 时 true，reject / inconclusive 时 false |
| `evidence_refs` | 裁决采用的代码证据 |
| `source_chain` | confirm 时需要的调用链 |
| `sink_ref` | confirm 时需要的 sink |
| `clearing_checks` | reject 时需要的证伪点 |
| `non_issue_reason` | reject 时需要的非问题原因 |
| `missing_evidence` | inconclusive 时说明缺口 |
| `verdict_confidence` | 裁决置信度 |
| `reasoning` | 裁决理由 |

裁决规则：

- `decision=confirm`：正方有完整 `source_chain + sink_ref + evidence_refs`，反方没有给出能证伪的 `clearing_checks`。
- `decision=reject`：反方有明确 `clearing_checks + non_issue_reason`，能证伪可达性、可控性或 bug 成立性。
- `decision=inconclusive`：关键证据缺失、双方证据冲突但无法判定、或引用无法核实。

## 4. 证据门槛

Pipeline 会在程序逻辑里检查证据是否合格。Prompt 只是输入侧约束，真正决定一张票能不能参与多数决的是 pipeline 的证据校验。

### 4.1 代码位置证据格式

当前用正则判断是否包含形如：

```text
path:line
```

例如：

```text
src/parser.c:128 - len 来自未认证报文头
src/parser.c:241 - memcpy 使用 len 写入固定缓冲
```

### 4.2 正方合格条件

正方 proof 合格必须满足：

- `supports_real=true`
- `evidence_refs` 至少包含一个 `path:line`
- `source_chain` 至少包含一个 `path:line`
- `sink_ref` 包含 `path:line`
- `reachability` 非空
- `controllability` 非空

不满足则正方举证被标记为无效，原因写入 `validation_reason`。

### 4.3 反方合格条件

反方 disproof 合格必须满足：

- `refutes_real=true`
- `evidence_refs` 至少包含一个 `path:line`
- `clearing_checks` 至少包含一个 `path:line`
- `non_issue_reason` 非空

不满足则反方证伪被标记为无效。

### 4.4 裁决票合格条件

裁决票先被标准化为：

```text
confirm -> is_real=true
reject -> is_real=false
inconclusive -> is_real=false，但不作为最终真假依据
```

`decision=confirm` 的裁决票必须满足：

- 正方 proof 合格。
- `evidence_refs` 至少包含一个 `path:line`。
- `source_chain` 至少包含一个 `path:line`。
- `sink_ref` 包含 `path:line`。
- `reachability` 非空。
- `controllability` 非空。

`decision=reject` 的裁决票必须满足：

- 反方 disproof 合格。
- `evidence_refs` 至少包含一个 `path:line`。
- `clearing_checks` 至少包含一个 `path:line`。
- `non_issue_reason` 非空。

`decision=inconclusive` 的裁决票视为无效裁决票，但要求说明 `missing_evidence` 或 `reasoning`。

## 5. 多数决逻辑

只有合格的 judge 裁决票参与多数决。Prover 和 disprover 的输出会被保存和展示，但不直接参与最终多数决。

设：

```text
required_votes = ceil(verify_votes / 2)
valid_judges = 所有 validation_ok=true 的 judge 票
majority = floor(len(valid_judges) / 2) + 1
```

处理规则：

1. 如果 `len(valid_judges) < required_votes`：
   - 判定为“有效裁决票不足”。
   - 候选进入 retry。
   - retry 耗尽后变成 `verify_failed`。

2. 如果 confirm 票达到 `majority`：
   - 确认为漏洞。
   - 写入 `findings/<id>.json`。
   - 保存完整验证记录。
   - 后续按严重度决定是否进入 PoC。

3. 如果 reject 票达到 `majority`：
   - 候选标记为 rejected。
   - 写入 `candidates/*.json`。
   - 记录 `rejection_reason`、`vote_total`、`vote_false`、`vote_real`。

4. 如果 confirm 和 reject 都没有多数：
   - 判定为“裁决票未形成多数”。
   - 候选进入 retry。
   - retry 耗尽后变成 `verify_failed`。

5. 如果正反双方都没有合格证据：
   - 判定为“正反举证均无合格证据”。
   - 候选进入 retry 或最终 `verify_failed`。

## 6. 保存结构

### 6.1 通用验证记录

所有阶段的验证输出都会被压缩成统一的 `votes[]` 结构：

```json
{
  "phase": "prover | disprover | judge",
  "model": "模型名",
  "verify_lens": "验证视角",
  "decision": "confirm | reject | inconclusive",
  "is_real": true,
  "validation_ok": true,
  "validation_reason": "",
  "reachability": "...",
  "controllability": "...",
  "corrected_severity": "high",
  "exploitability": "...",
  "evidence_refs": ["path:line - 证据说明"],
  "source_chain": ["path:line - 节点说明"],
  "sink_ref": "path:line - sink 说明",
  "clearing_checks": ["path:line - 证伪说明"],
  "missing_evidence": "",
  "verdict_confidence": "high",
  "reasoning": "...",
  "non_issue_reason": "..."
}
```

### 6.2 confirmed finding

确认漏洞时，完整记录写入：

```text
findings/<id>.json
```

其中包括：

- 原 finding 字段。
- `id`
- `corrected_severity`
- `exploitability`
- `votes`
- `verify_models`
- `report_body`
- `poc`
- `report_failed`

### 6.3 rejected candidate

否决候选时，记录写入：

```text
candidates/*.json
```

其中包括：

- 原 candidate 字段。
- `status=rejected`
- `votes`
- `verify_models`
- `vote_total`
- `vote_false`
- `vote_real`
- `rejection_reason`

`rejection_reason` 会优先汇总反方 / 裁决票中的 `non_issue_reason` 和 `clearing_checks`。

### 6.4 verify_failed candidate

验证失败时也会保存当次验证记录，便于排查为什么没有通过证据门槛。

保存字段包括：

- `status=verify_failed`
- `reason`
- `attempts`
- `final_sweep`
- `votes`
- `vote_total`
- `vote_false`
- `vote_real`
- `verify_models`

正常 retry 过程中，状态仍为 `pending`，但也会保存当次失败的 `votes` 和 `verify_models`。

## 7. 报告与导出

### 7.1 report agent 输入

报告正文生成时，会把对抗验证结论作为结构化 JSON 传给 report agent。字段包括：

- `phase`
- `decision`
- `is_real`
- `evidence_refs`
- `source_chain`
- `sink_ref`
- `clearing_checks`
- `reachability`
- `controllability`
- `reasoning`
- `non_issue_reason`

report agent 应把这些内容提炼进漏洞报告的：

- 数据流
- 可达性调用链
- 已检查缓解
- PoC / 验证结果
- 置信度说明

### 7.2 确定性 Markdown 导出

为了避免 report agent 遗漏验证记录，`render_finding_md()` 会在导出的 finding Markdown 末尾确定性追加：

```text
## 对抗验证记录
```

该小节逐条列出：

- 验证阶段
- 裁决结果
- 证据有效性
- 置信度
- 代码证据
- 调用链
- Sink
- 证伪点
- 可达性 / 可控性
- 理由
- 缺失证据

因此即使 `report_body` 没写完整验证细节，最终导出的 Markdown 仍保留结构化证据。

## 8. Web 展示

Web UI 对新验证方案做了同步展示：

- 配置项显示为“裁决票数 verify_votes”。
- 候选列表展示状态和流转入口。
- rejected 非问题详情可以看到多数裁决摘要。
- 漏洞详情展示“裁决票 X 确认 / Y 否决 / Z 合格”。
- 漏洞详情和非问题详情都展示完整“对抗验证记录”。
- 无效证据票使用独立样式，避免被误读成普通 reject。

## 9. 与旧方案的差异

| 维度 | 旧方案 | 当前方案 |
|---|---|---|
| Agent 结构 | 多 verifier 独立投票 | prover + disprover + judge |
| 投票对象 | 所有解析成功的 verifier 输出 | 只有合格 judge 裁决票 |
| 确认依据 | 多数 `is_real=true` | 多数 `decision=confirm` 且满足证据门槛 |
| 否决依据 | 多数 `is_real=false` | 多数 `decision=reject` 且有证伪点 |
| 无证据票 | 可能影响结果 | 不参与多数决 |
| 失败记录 | 主要记录 reason | 保存当次验证记录和失败原因 |
| 报告 | 依赖 report agent 提炼 | report agent + 确定性追加验证记录 |

## 10. 成本与默认参数

默认配置：

```yaml
verify_votes: 3
```

默认每条候选使用：

```text
1 prover + 1 disprover + 3 judge = 5 个 verify agent
```

如果调整参数：

```text
总 verify agent 数 = 2 + verify_votes
```

示例：

| verify_votes | 总 verify agent 数 | 说明 |
|---:|---:|---|
| 1 | 3 | 最低成本，只有一张裁决票，不建议用于正式审计 |
| 3 | 5 | 默认平衡策略 |
| 5 | 7 | 更稳但成本更高 |

## 11. 典型失败模式

### 11.1 正反举证均无合格证据

含义：

- 正方没有完整证明。
- 反方也没有明确证伪。

结果：

- retry。
- retry 耗尽后 `verify_failed`。

### 11.2 有效裁决票不足

含义：

- judge 输出缺少证据字段。
- judge 输出 `inconclusive`。
- judge CLI 失败或 JSON 解析失败。

结果：

- 不确认、不否决。
- retry 或 `verify_failed`。

### 11.3 裁决票未形成多数

含义：

- 合格裁决票里 confirm / reject 分裂。
- 例如 1 confirm / 1 reject。

结果：

- retry。
- retry 耗尽后 `verify_failed`。

### 11.4 reject 缺证伪点

含义：

- judge 认为是误报，但没有 `clearing_checks` 或 `non_issue_reason`。

结果：

- 该 judge 票无效。
- 不参与多数决。

### 11.5 confirm 缺 source-to-sink

含义：

- judge 认为是真的，但没有 `source_chain` 或 `sink_ref`。

结果：

- 该 judge 票无效。
- 不参与多数决。

## 12. 当前边界

该方案仍然不是动态可复现验证，也不是人工审计结论。它的定位是：

```text
比普通 LLM 多数票更强的自动化静态验证 gate
```

它解决的问题：

- 降低无证据确认。
- 降低无证据否决。
- 保存可复核证据链。
- 让失败原因可解释。

它不解决的问题：

- 无法替代 sanitizer / harness / PoC 的动态验证。
- 无法保证 LLM 引用的代码证据一定语义正确。
- 无法替代高危漏洞发布前的人工复核。
- 无法证明所有路径穷尽。

## 13. 实现位置

主要实现点：

| 模块 | 职责 |
|---|---|
| `proto_vuln_hunt/schemas.py` | 定义 proof / disproof / verdict 三类 schema |
| `proto_vuln_hunt/prompts.py` | 定义 prover / disprover / judge prompt |
| `proto_vuln_hunt/pipeline.py` | 编排三阶段验证、证据校验、多数决、保存状态 |
| `proto_vuln_hunt/exporters.py` | Markdown 导出追加“对抗验证记录” |
| `proto_vuln_hunt/web/static/app.js` | Web 展示验证记录 |
| `proto_vuln_hunt/web/static/styles.css` | 无效证据票样式 |
| `proto_vuln_hunt/tests/test_pipeline_verify.py` | 单元测试覆盖确认、否决、无效票、重试、final sweep |

## 14. 建议使用方式

正式审计建议：

- 保持默认 `verify_votes=3`。
- 不建议正式运行使用 `verify_votes=1`，因为单裁决票无法形成交叉验证。
- 对 `verify_failed` 候选重点查看：
  - `reason`
  - `validation_reason`
  - `missing_evidence`
  - prover / disprover / judge 的原始证据差异
- 对 rejected 候选重点查看：
  - `rejection_reason`
  - `clearing_checks`
  - `non_issue_reason`
- 对 confirmed finding 重点查看：
  - `source_chain`
  - `sink_ref`
  - `evidence_refs`
  - `reachability`
  - `controllability`

## 15. 简短总结

当前对抗辩论验证方案的关键变化是：

```text
不是增加更多 verifier，而是让 verifier 的输出必须变成可复核证据；
不是统计所有模型观点，而是只统计通过证据门槛的 judge 裁决票。
```

默认情况下，每条候选会经过 5 个 verify agent：

```text
1 正方举证 + 1 反方证伪 + 3 裁判裁决
```

最终结果会同步保存到结构化状态、Web 界面和 Markdown 导出报告中。
