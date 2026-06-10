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
        "threat_summary": {"type": "string", "description": "基于用途的威胁分析:谁是攻击者、从哪进、最该担心什么影响"},
        "build_hint": {"type": "string", "description": "如何编译此目标(用于后续 PoC harness),没有就留空"},
        "repo_knowledge": {"type": "string", "description": "从 README/docs/SECURITY/CHANGELOG/git 历史读到的安全相关背景"},
        "history": {
            "type": "array",
            "description": "已知问题模式(同类变体排查种子)",
            "items": {
                "type": "object",
                "required": ["pattern", "lens_hint"],
                "properties": {
                    "pattern": {"type": "string"},
                    "source": {"type": "string"},
                    "lens_hint": {"type": "string", "enum": ["memory", "integer", "race", "injection", "authn", "crypto", "dos", "infoleak"]},
                    "files": {"type": "array", "items": {"type": "string"}},
                },
            },
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
                    "variant_of": {"type": "string"},
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
            "description": "可疑但未坐实为漏洞的潜在风险/可加固点",
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

VERDICT_SCHEMA = {
    "type": "object",
    "required": ["is_real", "reasoning"],
    "properties": {
        "is_real": {"type": "boolean", "description": "反驳不掉为 true;不可达/已被检查/不可控则 false"},
        "reachability": {"type": "string"},
        "controllability": {"type": "string"},
        "corrected_severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        "exploitability": {"type": "string"},
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
