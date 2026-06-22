"""结构化输出 schema(从 proto-vuln-hunt 原 workflow 逐字段移植)。

因为外部 CLI(claude/opencode/codex)不像 Workflow 引擎那样有 StructuredOutput 工具强约束,
这些 schema 会被序列化进提示词,要求 agent 输出**符合 schema 的单个 JSON**(见 prompts.MUST_STRUCT),
再由 backends.extract_json 从 stdout 中解析。
"""

SURFACE_SCHEMA = {
    "type": "object",
    "required": ["regions"],
    "properties": {
        "purpose": {"type": "string", "description": "这个代码仓是做什么的/要实现什么目标"},
        "threat_summary": {
            "type": "array",
            "description": "基于用途的威胁分析(逐条列出:谁是攻击者、从哪些入口能影响系统、最该担心什么影响、攻击面有多大)",
            "items": {"type": "string"},
        },
        "build_hint": {"type": "string", "description": "如何编译此目标(用于后续 PoC harness),没有就留空"},
        "repo_knowledge": {
            "type": "array",
            "description": "从 README/docs/SECURITY/CHANGELOG 读到的安全相关背景(逐条列出关键事实)",
            "items": {"type": "string"},
        },
        "regions": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "category", "files", "untrusted_input", "priority"],
                "properties": {
                    "name": {"type": "string"},
                    "category": {"type": "string", "enum": ["parser", "network", "ipc", "auth-state", "key-mgmt", "cert-mgmt", "crypto", "deserialization", "state-machine", "memory-mgmt", "other"]},
                    "files": {"type": "array", "items": {"type": "string"}},
                    "entry_points": {"type": "array", "items": {"type": "string"}},
                    "untrusted_input": {"type": "string"},
                    "trust_boundary": {"type": "string"},
                    "crypto_apis": {"type": "array", "items": {"type": "string"}},
                    "priority": {"type": "string", "enum": ["high", "medium", "low"]},
                },
            },
        },
    },
}

FINDINGS_SCHEMA = {
    "type": "object",
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["title", "bug_class", "file", "function", "description", "severity", "confidence"],
                "properties": {
                    "title": {"type": "string"},
                    "bug_class": {"type": "string", "description": "如 heap-overflow / integer-overflow / type-confusion / UAF / OOB-read / race / TOCTOU / injection / deser / authn-downgrade / crypto-misuse / dos-design"},
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "function": {"type": "string"},
                    "description": {"type": "string"},
                    "source_to_sink": {"type": "string"},
                    "variant_of": {"type": "string", "description": "若本 finding 是由某条历史问题模式的同类变体排查命中的:填它**和哪个历史问题类似**(历史模式的根因概述 + 出处提交/文件),让报告能回溯到对应历史问题"},
                    "good_validation_ref": {"type": "string", "description": "若本 finding 由潜在风险点(某被调点/危险原语 B 的安全依赖调用方校验)排查命中:填全仓里**对同一 B 把校验做对了的另一处调用站点** path:line + 一句话说明,作为正面对照(说明正确的不变量该在哪、怎么校验)"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                },
            },
        },
        "new_surfaces": {
            "type": "array",
            "description": "审计中新发现、值得另派 agent 深挖的攻击面/可疑数据流",
            "items": {
                "type": "object",
                "required": ["name", "why"],
                "properties": {
                    "name": {"type": "string"},
                    "why": {"type": "string"},
                    "files": {"type": "array", "items": {"type": "string"}},
                    "lens_hint": {"type": "string", "enum": ["memory", "integer", "race", "injection", "authn", "crypto", "dos", "infoleak", "resource-realtime"]},
                },
            },
        },
        "risk_notes": {
            "type": "array",
            "description": "本轮未坐实为漏洞、但值得人工另行核实的线索。最典型一类:被调函数/危险原语(B)的安全依赖调用方传入已校验的参数,当前路径(A 已校验)安全,但全仓其它调用 B 的地方未必都做了等价校验——登记 B 的位置、其安全所依赖的前提、以及待核实的其它调用方(变体排查种子)。其它如校验分散、错误路径未统一释放、缺深度限制等同理",
            "items": {
                "type": "object",
                "required": ["area", "note"],
                "properties": {
                    "area": {"type": "string"},
                    "note": {"type": "string"},
                    "file": {"type": "string"},
                    "severity_hint": {"type": "string", "enum": ["high", "medium", "low", "info"]},
                },
            },
        },
    },
}

VERIFY_PROOF_SCHEMA = {
    "type": "object",
    "required": ["supports_real", "evidence_refs", "source_chain", "sink_ref", "reasoning"],
    "properties": {
        "supports_real": {"type": "boolean", "description": "正方是否已经用代码证据坐实 finding"},
        "evidence_refs": {
            "type": "array",
            "description": "代码证据,每项格式:path:line - 证据说明",
            "items": {"type": "string"},
        },
        "source_chain": {
            "type": "array",
            "description": "从不可信入口到 sink 的关键调用/数据流节点,path:line + 一句话",
            "items": {"type": "string"},
        },
        "sink_ref": {"type": "string", "description": "漏洞 sink 位置,path:line - sink 说明"},
        "reachability": {"type": "string"},
        "controllability": {"type": "string"},
        "corrected_severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        "exploitability": {"type": "string"},
        "missing_evidence": {"type": "string", "description": "仍缺什么证据;若证据完整可留空"},
        "verdict_confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reasoning": {"type": "string"},
    },
}

VERIFY_DISPROOF_SCHEMA = {
    "type": "object",
    "required": ["refutes_real", "evidence_refs", "clearing_checks", "reasoning"],
    "properties": {
        "refutes_real": {"type": "boolean", "description": "反方是否已经用代码证据证伪 finding"},
        "evidence_refs": {
            "type": "array",
            "description": "代码证据,每项格式:path:line - 证据说明",
            "items": {"type": "string"},
        },
        "clearing_checks": {
            "type": "array",
            "description": "证伪点:上游 clamp/return/状态检查/不可控条件等,path:line + 一句话",
            "items": {"type": "string"},
        },
        "non_issue_reason": {"type": "string", "description": "当 refutes_real=true 时填写:最终验证为非问题的代码证据与原因"},
        "reachability": {"type": "string"},
        "controllability": {"type": "string"},
        "corrected_severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        "exploitability": {"type": "string"},
        "missing_evidence": {"type": "string", "description": "仍缺什么证伪证据;若已证伪可留空"},
        "verdict_confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reasoning": {"type": "string"},
    },
}

VERDICT_SCHEMA = {
    "type": "object",
    "required": ["decision", "is_real", "evidence_refs", "reasoning"],
    "properties": {
        "decision": {"type": "string", "enum": ["confirm", "reject", "inconclusive"]},
        "is_real": {"type": "boolean", "description": "decision=confirm 时为 true;decision=reject 时为 false;inconclusive 时不作为最终真假依据"},
        "evidence_refs": {
            "type": "array",
            "description": "裁决采用的代码证据,每项格式:path:line - 证据说明",
            "items": {"type": "string"},
        },
        "source_chain": {"type": "array", "items": {"type": "string"}},
        "sink_ref": {"type": "string"},
        "clearing_checks": {"type": "array", "items": {"type": "string"}},
        "reachability": {"type": "string"},
        "controllability": {"type": "string"},
        "corrected_severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        "exploitability": {"type": "string"},
        "non_issue_reason": {"type": "string", "description": "当 is_real=false 时填写:最终验证为非问题的代码证据与原因"},
        "missing_evidence": {"type": "string", "description": "decision=inconclusive 时说明缺口"},
        "verdict_confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reasoning": {"type": "string"},
    },
}

VERIFY_WITNESS_SCHEMA = {
    "type": "object",
    "required": ["witness_complete", "evidence_refs", "reasoning"],
    "properties": {
        "witness_complete": {"type": "boolean", "description": "正方是否构造出满足攻击者能力、输入合法域、程序状态、代码约束的触发 witness"},
        "witness": {"type": "string", "description": "最小合法触发见证:输入/状态/顺序/关键值;没有完整 witness 时留空"},
        "attack_preconditions": {"type": "array", "items": {"type": "string"}, "description": "攻击者能力与前置条件,path:line + 说明优先"},
        "input_domain_constraints": {"type": "array", "items": {"type": "string"}, "description": "协议字段宽度、格式语法、配置上限等合法输入域约束"},
        "state_constraints": {"type": "array", "items": {"type": "string"}, "description": "认证态、连接态、对象生命周期、锁状态等程序状态约束"},
        "code_constraints": {"type": "array", "items": {"type": "string"}, "description": "沿途 if/clamp/return/assert/check 等代码约束"},
        "path_nodes": {"type": "array", "items": {"type": "string"}, "description": "从入口到坏结果的最小路径节点,path:line + 一句话"},
        "trigger_condition": {"type": "string", "description": "坏条件如何被 witness 触发,例如越界不等式/状态序列/payload 语义"},
        "bad_result": {"type": "string", "description": "触发后的安全坏结果"},
        "sink_ref": {"type": "string", "description": "危险 sink 位置,path:line - sink 说明"},
        "evidence_refs": {"type": "array", "items": {"type": "string"}, "description": "支持 witness 的代码证据,每项格式:path:line - 证据说明"},
        "missing_evidence": {"type": "string", "description": "witness 不完整时缺什么"},
        "corrected_severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        "exploitability": {"type": "string"},
        "verdict_confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reasoning": {"type": "string"},
    },
}

VERIFY_BLOCKER_SCHEMA = {
    "type": "object",
    "required": ["blocker_found", "blocker_scope", "evidence_refs", "reasoning"],
    "properties": {
        "blocker_found": {"type": "boolean", "description": "反方是否找到能打掉 finding 的 blocker 或不可满足证明"},
        "blocker_scope": {"type": "string", "enum": ["global", "path_local", "branch_local", "config_local", "partial", "unknown", "none"], "description": "blocker 覆盖范围;只有 global 才能直接否决"},
        "blocker_type": {"type": "string", "description": "例如 domain_bound/guard_dominance/state_gate/type_width/not_sink/not_visible"},
        "blocker_description": {"type": "string"},
        "evidence_refs": {"type": "array", "items": {"type": "string"}, "description": "支持 blocker 的代码证据,每项格式:path:line - 证据说明"},
        "blocking_checks": {"type": "array", "items": {"type": "string"}, "description": "具体阻断点/约束/path:line"},
        "impossibility_proof": {"type": "string", "description": "为什么合法输入/状态空间里坏条件不可满足"},
        "affected_witness": {"type": "string", "description": "该 blocker 打掉的是所有 witness 还是某个局部 witness"},
        "non_issue_reason": {"type": "string", "description": "若 blocker_found=true,最终非问题原因"},
        "missing_evidence": {"type": "string", "description": "找不到决定性 blocker 时缺什么"},
        "verdict_confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reasoning": {"type": "string"},
    },
}

WITNESS_REVIEW_SCHEMA = {
    "type": "object",
    "required": ["witness_verdict", "evidence_refs", "reasoning"],
    "properties": {
        "witness_verdict": {"type": "string", "enum": ["accepted", "weakened", "rejected", "inconclusive"], "description": "对正方 witness 的质询结论"},
        "evidence_refs": {"type": "array", "items": {"type": "string"}, "description": "复核 witness 时采用的代码证据"},
        "reviewed_checks": {"type": "array", "items": {"type": "string"}, "description": "已核对的合法输入域/状态/代码约束"},
        "failed_checks": {"type": "array", "items": {"type": "string"}, "description": "witness 不满足的约束或被削弱之处"},
        "missing_evidence": {"type": "string"},
        "verdict_confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reasoning": {"type": "string"},
    },
}

BLOCKER_REVIEW_SCHEMA = {
    "type": "object",
    "required": ["blocker_verdict", "evidence_refs", "reasoning"],
    "properties": {
        "blocker_verdict": {"type": "string", "enum": ["global_decisive", "partial", "invalid", "unknown_scope"], "description": "对反方 blocker 的质询结论"},
        "evidence_refs": {"type": "array", "items": {"type": "string"}, "description": "复核 blocker 时采用的代码证据"},
        "reviewed_checks": {"type": "array", "items": {"type": "string"}, "description": "已核对的支配关系/状态门/约束范围"},
        "failed_checks": {"type": "array", "items": {"type": "string"}, "description": "blocker 作用域不足或无效之处"},
        "missing_evidence": {"type": "string"},
        "verdict_confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reasoning": {"type": "string"},
    },
}

FINAL_ADJUDICATION_SCHEMA = {
    "type": "object",
    "required": ["epistemic_verdict", "operational_decision", "reasoning"],
    "properties": {
        "epistemic_verdict": {"type": "string", "enum": ["proven_real", "proven_false", "unresolved"], "description": "证据层结论"},
        "operational_decision": {"type": "string", "enum": ["confirmed", "rejected", "suppressed_unproven", "promoted_to_risk", "needs_manual_review"], "description": "流水线工程决策"},
        "deciding_facts_checked": {"type": "array", "items": {"type": "string"}, "description": "第 5 agent 定向补查的 1-2 个关键事实,path:line + 说明优先"},
        "final_reason": {"type": "string", "description": "最终工程决策理由"},
        "rejection_reason": {"type": "string", "description": "operational_decision=rejected 时的非问题原因"},
        "risk_note": {"type": "string", "description": "operational_decision=promoted_to_risk 时写入风险登记的说明"},
        "residual_uncertainty": {"type": "string"},
        "why_not_confirmed": {"type": "string"},
        "why_not_rejected": {"type": "string"},
        "recommended_next_action": {"type": "string"},
        "corrected_severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        "exploitability": {"type": "string"},
        "verdict_confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reasoning": {"type": "string"},
    },
}

POC_SCHEMA = {
    "type": "object",
    "required": ["approach", "compiled", "triggered"],
    "properties": {
        "approach": {"type": "string"},
        "harness_code": {"type": "string"},
        "build_cmd": {"type": "string"},
        "compiled": {"type": "boolean"},
        "triggered": {"type": "boolean"},
        "exploitability": {"type": "string"},
        "notes": {"type": "string"},
    },
}

# 仅历史模式:确认漏洞的结构化报告字段。LLM 只填字段,程序用统一模板渲染成 Markdown。
HISTORY_REPORT_SCHEMA = {
    "type": "object",
    "required": ["summary", "description", "vuln_code", "data_flow", "impact",
                 "fix_suggestion", "history"],
    "properties": {
        "summary": {"type": "string", "description": "一句话概述:这是什么漏洞、在哪、为什么是它(攻击者能做什么)"},
        "description": {"type": "string", "description": "漏洞分析说明:破坏了什么不变量、攻击者控制什么、缺陷如何形成"},
        "vuln_code": {"type": "string", "description": "本处漏洞的关键真实代码片段(用 Read 取原文,不要转述;只贴够看清 bug 的几行)"},
        "vuln_code_loc": {"type": "string", "description": "上面代码片段的位置,如 path:line-line"},
        "data_flow": {"type": "string", "description": "数据流:不可信来源(path:line)→ sink(path:line),中途有无校验、为何不足"},
        "call_chain": {"type": "array", "items": {"type": "string"}, "description": "从真实入口到 sink 的可达性调用链,每项 path:line + 一句话"},
        "impact": {"type": "string", "description": "影响与可利用性(结合威胁模型)"},
        "mitigations": {"type": "string", "description": "已检查的缓解:canary/ASLR/FORTIFY/sanitizer/类型上界等是否存在、可否绕过"},
        "poc_result": {"type": "string", "description": "PoC / 验证结果说明;无动态 PoC 则给静态触发构造说明"},
        "fix_suggestion": {"type": "string", "description": "修复建议:具体怎么改,最好与历史修复后的正确写法对齐"},
        "confidence_basis": {"type": "string", "description": "置信度依据(一句话)"},
        "history": {
            "type": "object",
            "description": "与历史已修问题的对比(本漏洞是其同类变体)",
            "required": ["root_cause", "why_recurred"],
            "properties": {
                "source": {"type": "string", "description": "历史问题出处:修复提交 hash / 文件 等"},
                "root_cause": {"type": "string", "description": "历史问题的根因 / 缺陷类型(抽象描述)"},
                "before_code": {"type": "string", "description": "历史修复前(有问题)的关键代码;用 git show 取原文,只贴几行"},
                "after_code": {"type": "string", "description": "历史修复后(正确)的关键代码;用 git show 取原文,只贴几行"},
                "fix_note": {"type": "string", "description": "当时是怎么修的(一句话)"},
                "why_recurred": {"type": "string", "description": "为什么此处重蹈覆辙:漏了同款修复 / 历史修复没覆盖到本调用点"},
                "comparison": {
                    "type": "array",
                    "description": "历史 vs 本处的逐维度对比(渲染成对比表)",
                    "items": {
                        "type": "object",
                        "required": ["dimension", "history", "current"],
                        "properties": {
                            "dimension": {"type": "string", "description": "对比维度,如 根因 / 危险写法 / 是否做了同款校验 / 触发条件 / 位置"},
                            "history": {"type": "string", "description": "历史问题在该维度的情况"},
                            "current": {"type": "string", "description": "本处漏洞在该维度的情况"},
                        },
                    },
                },
            },
        },
    },
}

# 单条 git 提交的「是否安全修复 + 问题模式」判定(每条提交一个 agent)
HISTORY_COMMIT_SCHEMA = {
    "type": "object",
    "required": ["security_related"],
    "properties": {
        "security_related": {"type": "boolean", "description": "该提交是否是一次安全修复(修复了某类安全缺陷)"},
        "pattern": {"type": "string", "description": "若相关:可复用于同类变体排查的问题模式(根因+缺陷类型+触发条件的抽象描述,不要只抄提交标题)"},
        "lens_hint": {"type": "string", "enum": ["memory", "integer", "race", "injection", "authn", "crypto", "dos", "infoleak", "resource-realtime"]},
        "files": {"type": "array", "items": {"type": "string"}, "description": "该问题模式涉及/出现的文件"},
        "rationale": {"type": "string", "description": "判定理由 + 改动要点摘要"},
    },
}

SUBTASKS_SCHEMA = {
    "type": "object",
    "required": ["subtasks"],
    "properties": {
        "subtasks": {
            "type": "array",
            "description": "把该攻击面区域拆成的、各自有界且可被单个 agent 快速审完的审计子任务",
            "items": {
                "type": "object",
                "required": ["objective", "files", "lens_hints"],
                "properties": {
                    "objective": {"type": "string"},
                    "files": {"type": "array", "items": {"type": "string"}},
                    "functions": {"type": "array", "items": {"type": "string"}},
                    "entry_points": {"type": "array", "items": {"type": "string"}},
                    "lens_hints": {"type": "array", "items": {"type": "string", "enum": ["memory", "integer", "race", "injection", "authn", "crypto", "dos", "infoleak", "resource-realtime"]}},
                    "est_lines": {"type": "integer"},
                },
            },
        },
    },
}
