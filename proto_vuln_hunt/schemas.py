"""结构化输出 schema(从 proto-vuln-hunt 原 workflow 逐字段移植)。

因为外部 CLI(claude/opencode/codex)不像 Workflow 引擎那样有 StructuredOutput 工具强约束,
这些 schema 会被序列化进提示词,要求 agent 输出**符合 schema 的单个 JSON**(见 prompts.MUST_STRUCT),
再由 backends.extract_json 从 stdout 中解析。
"""

THREAT_ANALYSIS_SCHEMA = {
    "type": "object",
    "required": ["assets", "attack_trees", "code_path_mappings"],
    "properties": {
        "schema_version": {"type": "string"},
        "analysis_id": {"type": "string"},
        "sources": {
            "type": "object",
            "properties": {
                "repositories": {"type": "array", "items": {"type": "string"}},
                "documents": {"type": "array", "items": {"type": "string"}},
            },
        },
        "assets": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["asset_id", "name", "asset_type", "criticality", "risks"],
                "properties": {
                    "asset_id": {"type": "string"},
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "asset_type": {"type": "string", "enum": ["service", "data", "credential", "privilege", "software", "configuration", "key", "device", "other"]},
                    "criticality": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "risks": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["risk_id", "name", "security_property", "description"],
                            "properties": {
                                "risk_id": {"type": "string"},
                                "name": {"type": "string"},
                                "security_property": {"type": "string", "enum": ["confidentiality", "integrity", "availability", "authenticity", "authorization", "accountability"]},
                                "description": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
        "attack_trees": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["tree_id", "asset_id", "risk_id", "attack_goal", "root_node_id", "nodes"],
                "properties": {
                    "tree_id": {"type": "string"},
                    "asset_id": {"type": "string"},
                    "risk_id": {"type": "string"},
                    "attack_goal": {"type": "string"},
                    "root_node_id": {"type": "string"},
                    "nodes": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["node_id", "node_type", "name", "order", "basis"],
                            "properties": {
                                "node_id": {"type": "string"},
                                "parent_id": {"type": ["string", "null"]},
                                "node_type": {"type": "string", "enum": ["goal", "domain", "surface", "method"]},
                                "name": {"type": "string"},
                                "surface_type": {"type": "string", "enum": ["protocol", "api", "interface", "service", "port", "file", "message", "configuration", "command", "package", "physical", "other"]},
                                "order": {"type": "integer"},
                                "basis": {"type": "array", "items": {"type": "string"}},
                                "preconditions": {"type": "array", "items": {"type": "string"}},
                            },
                        },
                    },
                },
            },
        },
        "code_path_mappings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["surface_node_id", "code_paths"],
                "properties": {
                    "surface_node_id": {"type": "string"},
                    "code_paths": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["path", "description"],
                            "properties": {
                                "path": {"type": "string"},
                                "description": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
    },
}

# 审计项完成后的威胁分析增量识别。结构沿用完整威胁分析 schema,但提示词要求只输出
# 当前审计过程中新增且尚未在攻击树中存在的资产/攻击树/代码路径;没有新增时三个数组均为空。
THREAT_DELTA_SCHEMA = THREAT_ANALYSIS_SCHEMA

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
                    "good_validation_ref": {"type": "string", "description": "若本 finding 由即时风险种子(某被调点/危险原语 B 的安全依赖调用方校验)复查命中:填全仓里**对同一 B 把校验做对了的另一处调用站点** path:line + 一句话说明,作为正面对照(说明正确的不变量该在哪、怎么校验)"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                },
            },
        },
        "risk_notes": {
            "type": "array",
            "description": "即时复查种子,不是风险报告/存档。仅用于这类场景:当前审计路径 A 调 B 且 A 已做校验所以安全,但 B 自身不校验,其它调用 B 的地方未必满足等价前提。写清 B、B 被调用前必须满足的校验/不变量、A 中做对的校验正例;系统会立刻派 recheck agent 枚举全仓 B 调用点",
            "items": {
                "type": "object",
                "required": ["area", "note"],
                "properties": {
                    "area": {"type": "string", "description": "复查主题,例如 helper 名/危险原语 + 必要校验"},
                    "note": {"type": "string", "description": "B 的位置、缺少自校验的原因、调用 B 前必须满足什么前提、A 中正例校验概述"},
                    "file": {"type": "string", "description": "B 所在文件或 A 调 B 的关键文件"},
                    "callee": {"type": "string", "description": "被调函数/危险原语 B 的名称,可含签名或 path:line"},
                    "required_validation": {"type": "string", "description": "调用 B 前必须完成的校验/不变量,例如长度已夹紧到 <= buf_sz、指针非空、已认证"},
                    "good_validation_ref": {"type": "string", "description": "A 中已做对的校验正例,path:line + 一句话说明"},
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
        "side": {"type": "string", "description": "本轮角色,建议固定为 proponent"},
        "turn": {"type": "string", "description": "本轮编号,如 P1/P2"},
        "responded_claims": {
            "type": "array",
            "items": {"type": "object"},
            "description": "逐条回应上一轮指定 claim:claim_id、status、response、evidence_refs",
        },
        "new_claims": {
            "type": "array",
            "items": {"type": "object"},
            "description": "本轮新增的关键 claim:claim_id、claim、impact、evidence_refs",
        },
        "concessions": {"type": "array", "items": {"type": "string"}, "description": "正方承认无法闭合或被削弱的点"},
        "unresolved_claims": {"type": "array", "items": {"type": "string"}, "description": "仍未闭合的 claim_id 或缺口"},
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
        "side": {"type": "string", "description": "本轮角色,建议固定为 opponent"},
        "turn": {"type": "string", "description": "本轮编号,如 O1/O2"},
        "responded_claims": {
            "type": "array",
            "items": {"type": "object"},
            "description": "逐条回应上一轮指定 claim:claim_id、status、response、evidence_refs",
        },
        "new_claims": {
            "type": "array",
            "items": {"type": "object"},
            "description": "本轮新增的关键 claim:claim_id、claim、impact、evidence_refs",
        },
        "concessions": {"type": "array", "items": {"type": "string"}, "description": "反方承认无法证伪或 blocker 被削弱的点"},
        "unresolved_claims": {"type": "array", "items": {"type": "string"}, "description": "仍未闭合的 claim_id 或缺口"},
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
        "operational_decision": {"type": "string", "enum": ["confirmed", "rejected", "suppressed_unproven", "needs_manual_review"], "description": "流水线工程决策"},
        "accepted_claims": {"type": "array", "items": {"type": "string"}, "description": "最终采信的关键 claim_id/事实"},
        "rejected_claims": {"type": "array", "items": {"type": "string"}, "description": "最终不采信的关键 claim_id/事实"},
        "unresolved_claims": {"type": "array", "items": {"type": "string"}, "description": "最终仍未闭合的关键 claim_id/缺口"},
        "deciding_facts_checked": {"type": "array", "items": {"type": "string"}, "description": "第 5 agent 定向补查的 1-2 个关键事实,path:line + 说明优先"},
        "final_reason": {"type": "string", "description": "最终工程决策理由"},
        "rejection_reason": {"type": "string", "description": "operational_decision=rejected 时的非问题原因"},
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

# 单条 git 提交的「是否安全修复 + 问题模式」判定(每条提交一个 agent)
HISTORY_COMMIT_SCHEMA = {
    "type": "object",
    "required": ["security_related"],
    "properties": {
        "security_related": {"type": "boolean", "description": "该提交是否是一次安全修复(修复了某类安全缺陷)"},
        "pattern": {"type": "string", "description": "若相关:可复用于同类变体排查的问题模式(根因+缺陷类型+触发条件的抽象描述,不要只抄提交标题)"},
        "files": {"type": "array", "items": {"type": "string"}, "description": "该问题模式涉及/出现的文件"},
        "rationale": {"type": "string", "description": "判定理由 + 改动要点摘要"},
    },
}
