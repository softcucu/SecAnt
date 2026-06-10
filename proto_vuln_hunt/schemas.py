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
