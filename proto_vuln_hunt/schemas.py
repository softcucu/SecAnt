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
                    "lens_hint": {"type": "string", "enum": ["memory", "integer", "race", "injection", "authn", "crypto", "dos", "infoleak"]},
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
        "lens_hint": {"type": "string", "enum": ["memory", "integer", "race", "injection", "authn", "crypto", "dos", "infoleak"]},
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
                    "lens_hints": {"type": "array", "items": {"type": "string", "enum": ["memory", "integer", "race", "injection", "authn", "crypto", "dos", "infoleak"]}},
                    "est_lines": {"type": "integer"},
                },
            },
        },
    },
}
