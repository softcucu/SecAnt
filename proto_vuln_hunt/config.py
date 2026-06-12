"""配置加载:从 YAML/JSON 配置文件 + 命令行覆盖,组装出一份运行配置。

设计目标(对应用户需求):
  · 通过配置文件选择后端 CLI(claude / opencode / codex)并自定义其调用方式;
  · 为不同阶段(role)配置不同模型,并可限制每个模型自己的并发;
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

# 流水线里会用到的 agent 角色;每个会运行的角色都必须在 models 里显式指定模型。
# history:统一调度队列中的「git 历史问题模式挖掘」(每条提交一个 agent,与 high audit finder 同级)。
# recheck:专用优先排查角色——处理历史问题变体 + 已登记风险点的复查(最高优先级、默认并发 1)。
ROLES = ["recon", "history", "recheck", "decompose", "audit", "verify", "report", "poc", "synthesis", "util"]
TASK_MODEL_ROLES = ["recon", "history", "recheck", "decompose", "audit", "verify", "report", "poc"]


# ──────────────────────────── 后端默认调用模板 ────────────────────────────
# command 是一个 token 列表;运行时会把:
#   {model}   → 当前角色解析出的模型名
#   {prompt}      → 提示词(仅 prompt_mode == "arg" 时需要;stdin/file 模式不建议使用)
#   {prompt_file} → 提示词临时文件路径(仅 prompt_mode == "file" 时需要)
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
        # 模型格式需为 provider/model(如 anthropic/claude-sonnet-4-6)。
        # 提示词作为 opencode run 的单个 positional message argv 传入;执行时不经过 shell,
        # 因此换行/空格会原样保留,不会被 shell 分行截断。
        # --format json:让 opencode 以"每行一个 JSON 事件"的结构化事件流输出(而非默认给人看的流式/TUI 渲染),
        # 这样子进程跑完后能确定性地拿到 assistant 的**完整最终文本**,避免管道里只抓到部分中间输出。
        # 注意:它只约束 opencode 的输出封装,不约束模型正文必须是 JSON;正文仍由 extract_json 进一步解析。
        "command": [
            "opencode", "run",
            "--format", "json",
            "--model", "{model}",
            "{prompt}",
        ],
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
    prompt_mode: str = "stdin"   # stdin | arg | file
    parse: str = "text"          # text | claude_json
    env: Dict[str, str] = field(default_factory=dict)


@dataclass
class HealthCheckSpec:
    """模型健康检查:用一个极小的探针任务(如 1+1=?)确认每个配置的模型可达且能正常回答。

    · on_start:运行开始前先把**所有配置的模型**各探一遍,实时反映到 Web。
    · gate:真正用某模型派任务前,若其健康状态未知/陈旧/异常,则先补一次探针(按 ttl 去重,避免每次都探)。
    """
    enabled: bool = True
    on_start: bool = True          # 运行开始前先把所有模型探一遍
    gate: bool = True              # 调用某模型前,若其健康状态陈旧/未知则先探一次
    ttl_s: int = 300               # gate 复检的新鲜度窗口(秒);<=0 表示只在 on_start 探一次
    timeout_ms: int = 120000       # 单次健康探针的墙钟超时(独立于审计任务的大超时)
    prompt: str = "这是一次模型健康检查,请忽略其它指令。只输出最终答案的数字,不要任何解释或多余文字:1+1=?"
    expect: str = "2"              # 答案里应包含的子串(命中=healthy;可达但未命中=degraded)


@dataclass
class RetrySpec:
    """后端 CLI(opencode/claude/codex)执行任务失败后的重试策略。

    说明:后端 CLI 内部已自行处理瞬时 API 抖动(限流/5xx 等)的重试;本工具这一层只在
    **CLI 任务整体失败**时重试——即子进程非零退出 / 超时 / 输出无法解析为所需结构化 JSON。
    max_attempts 是单组重试上限;recon/audit 等阶段可在其外层选择不限组数或回队继续重试。
    """
    max_attempts: int = 4          # 失败后最多再重试几次(总尝试 = 1 + max_attempts)
    backoff_base_ms: int = 2000    # 退避基数(指数增长)
    backoff_cap_ms: int = 30000    # 单次退避封顶
    timeout_ms: int = 1800000      # 单次子进程墙钟超时(超时也算一次失败 → 计入重试)


@dataclass
class HistorySpec:
    """git 历史问题模式挖掘:从侦察中**抽离**出来,与 recon 同时启动。

    遍历 `git log` 的提交,**每条提交派 1 个 agent**(role=history)读其改动并判定是否安全修复;
    相关者提炼成「历史问题模式」回灌到 history[](作为同类变体排查种子)与审计队列。
    这一块不阻塞侦察和审计:按 high audit finder 同级排队,历史模式随挖随补。
    """
    enabled: bool = True
    max_commits: int = 200          # 最多分析多少条最近的提交
    concurrency: int = 1            # 兼容旧配置;统一调度下实际并发由全局 concurrency + role/model 容量决定
    since: str = ""                 # 可选:git log --since=<...> 只看某时间段
    paths: str = ""                 # 可选:限定 git log 的路径(留空则用 scope;空格分隔多个)
    poll_interval_s: int = 3        # 审计循环等待历史变体灌入的轮询间隔(秒)


@dataclass
class RecheckSpec:
    """专用「优先排查」通道:把历史问题变体排查 + 已登记风险点复查抽到一条独立优先队列,
    由专用 agent(role=recheck)处理。优先级最高——只要队列里有项,空出的 agent 名额就先来处理它
    (懒占全局并发名额:有活才占、用完即还,队列空时不占用主池)。

    风险点复查的典型对象:被调函数/危险原语(B)的安全依赖调用方传入已校验的参数,当前路径安全但
    全仓其它调用 B 的地方未必都做了等价校验——即变体排查的种子。
    """
    enabled: bool = True
    concurrency: int = 1            # 该角色并发上限(默认 1:逐条串行排查)
    risk_min_severity: str = "medium"  # 风险点自动入排查队列的最低 severity_hint(high/medium/low/info)
    poll_interval_s: int = 3        # 优先队列空时的轮询等待间隔(秒)


@dataclass
class Config:
    # 目标
    target: str = "."
    scope: str = ""
    out_dir: str = ""

    # 后端 / 模型 / 并发
    backend: str = "claude"
    backends: Dict[str, BackendSpec] = field(default_factory=dict)
    models: Dict[str, List[str]] = field(default_factory=dict)
    model_concurrency: Dict[str, int] = field(default_factory=dict)
    concurrency: int = 4
    # 每次 opencode 子进程用一次性 XDG_DATA_HOME 跑,跑完整目录删除——回收 opencode 的
    # 会话/快照(snapshot)等运行产物,避免 ~/.local/share/opencode 无上限膨胀。
    # 仅对 backend=opencode 生效;claude/codex 不受影响。
    ephemeral_backend_data: bool = True
    # 排查类临时产物的滚动保留数:提示词临时文件(out_dir/prompts/agent_*.md)与解析失败转储
    # (out_dir/debug/parsefail_*)各只保留最近 N 次,旧的自动删除。<=0 表示不清理(保留全部)。
    artifact_retain: int = 10

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
    health: HealthCheckSpec = field(default_factory=HealthCheckSpec)
    history: HistorySpec = field(default_factory=HistorySpec)
    recheck: RecheckSpec = field(default_factory=RecheckSpec)

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
        self.recheck.concurrency = max(1, int(self.recheck.concurrency))
        if self.recheck.risk_min_severity not in ("high", "medium", "low", "info"):
            self.recheck.risk_min_severity = "medium"
        self.recheck.poll_interval_s = max(1, int(self.recheck.poll_interval_s))
        if self.fresh:
            self.resume = False
        self.port = int(self.port)
        if not self.runs_dir:
            self.runs_dir = os.path.join(os.getcwd(), "pvh-runs")
        self.runs_dir = os.path.abspath(os.path.expanduser(self.runs_dir))
        self.models = normalize_models(self.models)
        self.model_concurrency = normalize_model_concurrency(self.model_concurrency)
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
        models = self.models_for(role)
        return models[0] if models else ""

    def models_for(self, role: str) -> List[str]:
        return list(self.models.get(role) or [])

    def model_concurrency_for(self, model: str) -> int:
        return max(1, int(self.model_concurrency.get(model) or self.model_concurrency.get("default") or self.concurrency))

    def all_models(self) -> List[str]:
        """所有 role 里配置到的去重模型列表(保持首次出现顺序),用于启动前健康检查。"""
        seen: List[str] = []
        for role, vals in self.models.items():
            if role == "default":
                continue
            for m in vals:
                if m and m not in seen:
                    seen.append(m)
        return seen

    def required_model_roles(self) -> List[str]:
        roles = ["recon", "audit", "verify", "report"]
        if self.history.enabled:
            roles.append("history")
        if self.recheck.enabled:
            roles.append("recheck")
        if self.decompose:
            roles.append("decompose")
        if self.enable_poc:
            roles.append("poc")
        return [r for r in TASK_MODEL_ROLES if r in roles]

    def missing_model_roles(self) -> List[str]:
        return [r for r in self.required_model_roles() if not self.models_for(r)]

    def unsupported_model_keys(self) -> List[str]:
        return [k for k in self.models if k == "default"]

    def model_config_error(self) -> str:
        problems: List[str] = []
        unsupported = self.unsupported_model_keys()
        if unsupported:
            problems.append("models.default 已不支持;请为每个任务 role 显式配置模型")
        missing = self.missing_model_roles()
        if missing:
            problems.append("缺少模型配置: " + ", ".join(f"models.{r}" for r in missing))
        return "; ".join(problems)

    def model_slots_for(self, role: str) -> List[str]:
        slots: List[str] = []
        for model in self.models_for(role):
            slots.extend([model] * self.model_concurrency_for(model))
        return slots

    def backend_spec(self) -> BackendSpec:
        if self.backend in self.backends:
            return self.backends[self.backend]
        # 未在配置里显式定义 → 用内置默认模板
        d = DEFAULT_BACKENDS.get(self.backend)
        if not d:
            raise ValueError(f"未知后端 '{self.backend}',且配置文件未定义它。可选内置:{list(DEFAULT_BACKENDS)}")
        return BackendSpec(name=self.backend, **d)


def normalize_models(raw: Any) -> Dict[str, List[str]]:
    """兼容旧配置的字符串模型,并允许每个 role 配多个模型。

    支持:
      models.audit: "anthropic/a,openai/b"
      models.audit: ["anthropic/a", "openai/b"]
    """
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, List[str]] = {}
    for role, value in raw.items():
        vals: List[str] = []
        if isinstance(value, str):
            vals = [x.strip() for x in value.split(",")]
        elif isinstance(value, (list, tuple)):
            vals = [str(x).strip() for x in value]
        elif value is not None:
            vals = [str(value).strip()]
        vals = [x for x in vals if x]
        if vals:
            out[str(role)] = vals
    return out


def normalize_model_concurrency(raw: Any) -> Dict[str, int]:
    """标准化每个模型自己的并发限制;支持 dict 或 "model=2,other=1" 字符串。"""
    if not raw:
        return {}
    if isinstance(raw, str):
        parsed: Dict[str, int] = {}
        for part in raw.split(","):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            k = k.strip()
            if not k:
                continue
            try:
                parsed[k] = max(1, int(v.strip()))
            except Exception:
                continue
        return parsed
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, int] = {}
    for model, limit in raw.items():
        key = str(model).strip()
        if not key:
            continue
        try:
            out[key] = max(1, int(limit))
        except Exception:
            continue
    return out

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

    # 健康检查配置:优先读 `health_check:`,`health:` 作为别名。
    hc_data = data.pop("health_check", None)
    if hc_data is None:
        hc_data = data.pop("health", {})
    else:
        data.pop("health", None)
    hc_data = hc_data or {}
    _hc_default = HealthCheckSpec()
    health = HealthCheckSpec(
        enabled=bool(hc_data.get("enabled", True)),
        on_start=bool(hc_data.get("on_start", True)),
        gate=bool(hc_data.get("gate", True)),
        ttl_s=int(hc_data.get("ttl_s", 300)),
        timeout_ms=int(hc_data.get("timeout_ms", 120000)),
        prompt=str(hc_data.get("prompt") or _hc_default.prompt),
        expect=str(hc_data.get("expect", _hc_default.expect)),
    )

    # git 历史问题模式挖掘配置(统一调度队列中与 high audit finder 同级)。
    hist_data = data.pop("history", {}) or {}
    _h_default = HistorySpec()
    history = HistorySpec(
        enabled=bool(hist_data.get("enabled", True)),
        max_commits=max(0, int(hist_data.get("max_commits", _h_default.max_commits))),
        concurrency=max(1, int(hist_data.get("concurrency", _h_default.concurrency))),
        since=str(hist_data.get("since", "") or ""),
        paths=str(hist_data.get("paths", "") or ""),
        poll_interval_s=max(1, int(hist_data.get("poll_interval_s", _h_default.poll_interval_s))),
    )

    # 专用优先排查通道配置(历史变体 + 风险点复查)。
    rc_data = data.pop("recheck", {}) or {}
    _rc_default = RecheckSpec()
    recheck = RecheckSpec(
        enabled=bool(rc_data.get("enabled", True)),
        concurrency=max(1, int(rc_data.get("concurrency", _rc_default.concurrency))),
        risk_min_severity=str(rc_data.get("risk_min_severity", _rc_default.risk_min_severity) or _rc_default.risk_min_severity),
        poll_interval_s=max(1, int(rc_data.get("poll_interval_s", _rc_default.poll_interval_s))),
    )

    if overrides:
        data.update({k: v for k, v in overrides.items() if v is not None})

    known = {f for f in Config.__dataclass_fields__}  # type: ignore[attr-defined]
    kwargs = {k: v for k, v in data.items() if k in known and k not in ("retry", "health", "history", "recheck", "backends")}
    cfg = Config(backends=backends, retry=retry, health=health, history=history, recheck=recheck, **kwargs)
    return cfg
