"""配置加载:从 YAML/JSON 配置文件 + 命令行覆盖,组装出一份运行配置。

设计目标(对应用户需求):
  · 通过配置文件选择后端 CLI(claude / opencode / codex)并自定义其调用方式;
  · 为不同阶段(role)配置不同模型;
  · 配置并发数与全部流水线参数。
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:  # pragma: no cover
    _HAS_YAML = False


# 随项目打包的方法库目录(.md 审计方法,agent 运行时会 Read)。
# 这是项目自带的副本,不依赖任何外部目录;用户仍可在配置里用 methods_dir 覆盖。
BUNDLED_METHODS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "methods")

# 审计 lens(8 类)
ALL_LENSES = ["memory", "integer", "race", "injection", "authn", "crypto", "dos", "infoleak"]

# 流水线里会用到的 agent 角色;每个角色都可在 models 里单独指定模型,缺省回落到 default。
ROLES = ["recon", "decompose", "audit", "verify", "report", "poc", "synthesis", "util"]


# ──────────────────────────── 后端默认调用模板 ────────────────────────────
# command 是一个 token 列表;运行时会把:
#   {model}   → 当前角色解析出的模型名
#   {prompt}  → 提示词(仅 prompt_mode == "arg" 时需要;stdin 模式则从标准输入喂入)
# 替换为实际值。其余 token 原样保留。
# parse:
#   claude_json → 把 stdout 当作单个 JSON 解析,取其中的 result 字段作为 agent 文本;
#   text        → stdout 即 agent 文本。
# cwd 一律由子进程的工作目录控制(无需 --add-dir/-C/--dir);PoC 阶段会切到隔离 worktree。
DEFAULT_BACKENDS: Dict[str, Dict[str, Any]] = {
    "claude": {
        "command": [
            "claude", "-p",
            "--output-format", "json",
            "--model", "{model}",
            "--dangerously-skip-permissions",
        ],
        "prompt_mode": "stdin",
        "parse": "claude_json",
    },
    "opencode": {
        # 模型格式需为 provider/model(如 anthropic/claude-sonnet-4-6)
        "command": ["opencode", "run", "--model", "{model}", "{prompt}"],
        "prompt_mode": "arg",
        "parse": "text",
    },
    "codex": {
        "command": [
            "codex", "exec",
            "--model", "{model}",
            "--dangerously-bypass-approvals-and-sandbox",
            "--skip-git-repo-check",
            "{prompt}",
        ],
        "prompt_mode": "arg",
        "parse": "text",
    },
}


@dataclass
class BackendSpec:
    name: str
    command: List[str]
    prompt_mode: str = "stdin"   # stdin | arg
    parse: str = "text"          # text | claude_json
    env: Dict[str, str] = field(default_factory=dict)


@dataclass
class RetrySpec:
    """后端 CLI(opencode/claude/codex)执行任务失败后的重试策略。

    说明:后端 CLI 内部已自行处理瞬时 API 抖动(限流/5xx 等)的重试;本工具这一层只在
    **CLI 任务整体失败**时重试——即子进程非零退出 / 超时 / 输出无法解析为所需结构化 JSON。
    """
    max_attempts: int = 4          # 失败后最多再重试几次(总尝试 = 1 + max_attempts)
    backoff_base_ms: int = 2000    # 退避基数(指数增长)
    backoff_cap_ms: int = 30000    # 单次退避封顶
    timeout_ms: int = 1800000      # 单次子进程墙钟超时(超时也算一次失败 → 计入重试)


@dataclass
class Config:
    # 目标
    target: str = "."
    scope: str = ""
    out_dir: str = ""

    # 后端 / 模型 / 并发
    backend: str = "claude"
    backends: Dict[str, BackendSpec] = field(default_factory=dict)
    models: Dict[str, str] = field(default_factory=dict)
    concurrency: int = 4

    # 流水线参数(对齐 proto-vuln-hunt)
    finders_per_lens: int = 2
    dry_rounds: int = 2
    max_rounds: int = 6
    verify_votes: int = 3
    threat_model: str = "REMOTE"
    enable_poc: bool = True
    lenses: List[str] = field(default_factory=lambda: list(ALL_LENSES))
    decompose: bool = True
    unit_line_budget: int = 1500
    max_subtasks_per_region: int = 16
    max_files_per_unit: int = 4

    # 方法库 / 断点(默认用项目自带的 methods/;可在配置里覆盖为自定义目录)
    methods_dir: str = BUNDLED_METHODS_DIR
    resume: bool = True
    fresh: bool = False
    checkpoint_path: str = ""

    retry: RetrySpec = field(default_factory=RetrySpec)

    # ── Web / serve(仅 `serve` 子命令使用) ──
    host: str = "127.0.0.1"
    port: int = 8000
    runs_dir: str = ""             # web 模式下各 run 的根目录;空=<cwd>/pvh-runs

    # ── 派生 ──
    def __post_init__(self):
        self.target = (self.target or ".").rstrip("/") or "."
        if not self.out_dir:
            self.out_dir = f"{self.target}/.proto-vuln-hunt"
        self.out_dir = self.out_dir.rstrip("/")
        if not self.checkpoint_path:
            self.checkpoint_path = f"{self.out_dir}/checkpoint.json"
        self.threat_model = self.threat_model if self.threat_model in ("REMOTE", "LOCAL_UNPRIVILEGED", "BOTH") else "REMOTE"
        self.lenses = [l for l in (self.lenses or []) if l in ALL_LENSES] or list(ALL_LENSES)
        self.concurrency = max(1, int(self.concurrency))
        self.finders_per_lens = max(1, int(self.finders_per_lens))
        self.dry_rounds = max(1, int(self.dry_rounds))
        self.max_rounds = max(1, int(self.max_rounds))
        self.verify_votes = max(1, int(self.verify_votes))
        self.max_subtasks_per_region = max(1, int(self.max_subtasks_per_region))
        self.max_files_per_unit = max(1, int(self.max_files_per_unit))
        if self.fresh:
            self.resume = False
        self.port = int(self.port)
        if not self.runs_dir:
            self.runs_dir = os.path.join(os.getcwd(), "pvh-runs")
        self.runs_dir = os.path.abspath(os.path.expanduser(self.runs_dir))
        # methods_dir 展开为绝对路径(~ → $HOME)
        self._methods_abs = os.path.abspath(os.path.expanduser(self.methods_dir))

    @property
    def find_dir(self) -> str:
        return f"{self.out_dir}/findings"

    @property
    def methods_abs(self) -> str:
        return self._methods_abs

    def methods_ok(self) -> bool:
        d = self._methods_abs
        try:
            return os.path.isdir(d) and any(f.endswith(".md") for f in os.listdir(d))
        except Exception:
            return False

    def methods_present(self) -> List[str]:
        try:
            return sorted(f for f in os.listdir(self._methods_abs) if f.endswith(".md"))
        except Exception:
            return []

    def model_for(self, role: str) -> str:
        return self.models.get(role) or self.models.get("default") or ""

    def backend_spec(self) -> BackendSpec:
        if self.backend in self.backends:
            return self.backends[self.backend]
        # 未在配置里显式定义 → 用内置默认模板
        d = DEFAULT_BACKENDS.get(self.backend)
        if not d:
            raise ValueError(f"未知后端 '{self.backend}',且配置文件未定义它。可选内置:{list(DEFAULT_BACKENDS)}")
        return BackendSpec(name=self.backend, **d)


def _load_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    if path.endswith((".yaml", ".yml")):
        if not _HAS_YAML:
            raise RuntimeError("配置是 YAML 但未安装 pyyaml,请 `pip install pyyaml` 或改用 JSON 配置。")
        return yaml.safe_load(raw) or {}
    return json.loads(raw)


def load_config(path: Optional[str], overrides: Optional[Dict[str, Any]] = None) -> Config:
    data: Dict[str, Any] = {}
    if path:
        data = _load_file(path)

    # params / web 子节平铺进顶层
    for section in ("params", "web"):
        sub = data.pop(section, {}) or {}
        for k, v in sub.items():
            data.setdefault(k, v)

    # 后端定义:合并内置默认 + 用户自定义
    user_backends = data.pop("backends", {}) or {}
    backends: Dict[str, BackendSpec] = {}
    for name, spec in {**DEFAULT_BACKENDS, **user_backends}.items():
        merged = dict(DEFAULT_BACKENDS.get(name, {}))
        merged.update(spec or {})
        backends[name] = BackendSpec(
            name=name,
            command=merged.get("command") or DEFAULT_BACKENDS.get(name, {}).get("command", []),
            prompt_mode=merged.get("prompt_mode", "stdin"),
            parse=merged.get("parse", "text"),
            env=merged.get("env", {}) or {},
        )

    # 重试配置:优先读 `retry:`;`api:`(旧键名)作为兼容别名,`max_retries` 兼容映射到 max_attempts。
    retry_data = data.pop("retry", None)
    if retry_data is None:
        retry_data = data.pop("api", {})
    else:
        data.pop("api", None)
    retry_data = retry_data or {}
    retry = RetrySpec(
        max_attempts=int(retry_data.get("max_attempts", retry_data.get("max_retries", 4))),
        backoff_base_ms=int(retry_data.get("backoff_base_ms", 2000)),
        backoff_cap_ms=int(retry_data.get("backoff_cap_ms", 30000)),
        timeout_ms=int(retry_data.get("timeout_ms", 1800000)),
    )

    if overrides:
        data.update({k: v for k, v in overrides.items() if v is not None})

    known = {f for f in Config.__dataclass_fields__}  # type: ignore[attr-defined]
    kwargs = {k: v for k, v in data.items() if k in known}
    cfg = Config(backends=backends, retry=retry, **kwargs)
    return cfg
