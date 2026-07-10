"""配置加载:从 YAML/JSON 配置文件 + 命令行覆盖,组装出一份运行配置。

设计目标(对应用户需求):
  · 通过配置文件选择后端(claude / opencode / codex)并自定义其调用方式;
  · 为不同阶段(role)配置不同模型,并可限制每个模型自己的并发;
  · 配置并发数与全部流水线参数。
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .poc import (DEFAULT_POC_COMPONENTS, active_poc_component_specs,
                  normalize_poc_components, required_model_roles_for_poc_specs)

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:  # pragma: no cover
    _HAS_YAML = False


# 随项目打包的方法库目录(.md 审计方法,agent 运行时会 Read)。
# 这是项目自带的副本,不依赖任何外部目录;用户仍可在配置里用 methods_dir 覆盖。
BUNDLED_METHODS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "methods")

# 审计 lens(9 类)
ALL_LENSES = ["memory", "integer", "race", "injection", "authn", "crypto", "dos", "infoleak", "resource-realtime"]
RUN_MODE_FULL = "full"
RUN_MODES = [RUN_MODE_FULL]

# 流水线里会用到的 agent 角色;每个会运行的角色都必须在 models 里显式指定模型。
# history:统一调度队列中的「git 历史问题模式挖掘」(每条提交一个 agent,与 high audit finder 同级)。
# recheck:专用优先排查角色——处理历史问题变体 + 已登记风险点的复查(最高优先级、默认并发 1)。
ROLES = ["threat", "history", "recheck", "audit", "verify", "report", "poc", "synthesis", "util"]
TASK_MODEL_ROLES = ["threat", "history", "recheck", "audit", "verify", "report", "poc"]


# ──────────────────────────── 后端默认调用模板 ────────────────────────────
# command 是一个 token 列表;运行时会把:
#   {model}   → 当前角色解析出的模型名
#   {prompt}      → 提示词(仅 prompt_mode == "arg" 时需要;stdin/file 模式不建议使用)
#   {prompt_file} → 提示词临时文件路径(仅 prompt_mode == "file" 时需要)
#   {hostname}/{port} → opencode serve 监听地址(仅 prompt_mode == "serve" 时需要)
# 替换为实际值。其余 token 原样保留。
# parse:
#   claude_json → 把 stdout 当作单个 JSON 解析,取其中的 result 字段作为 agent 文本;
#   text        → stdout 即 agent 文本。
# cwd 一律由后端调用的工作目录控制(无需 --add-dir/-C/--dir);PoC 阶段会切到隔离 worktree。
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
        # 默认使用一个长驻 `opencode serve` 进程;每个 agent 调用在该 server 内创建一个全新的 session,
        # 避免为成千上万个 agent 反复启动 opencode 进程和重复冷启动项目状态。
        "command": [
            "opencode", "serve",
            "--hostname", "{hostname}",
            "--port", "{port}",
        ],
        "prompt_mode": "serve",
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
    prompt_mode: str = "stdin"   # stdin | arg | file | serve(opencode)
    parse: str = "text"          # text | claude_json
    env: Dict[str, str] = field(default_factory=dict)


@dataclass
class HealthCheckSpec:
    """模型健康检查:用一个短探针任务确认每个配置的模型可达且能正常回答。

    · on_start:运行开始前先把**当前任务会使用的模型**各探一遍,实时反映到 Web。
    · gate:真正用某模型派任务前,若其健康状态未知/陈旧/异常,则先补一次探针(按 ttl 去重,避免每次都探)。
    """
    enabled: bool = True
    on_start: bool = True          # 运行开始前先探当前任务会使用的模型
    gate: bool = True              # 调用某模型前,若其健康状态陈旧/未知则先探一次
    ttl_s: int = 300               # gate 复检的新鲜度窗口(秒);<=0 表示只在 on_start 探一次
    timeout_ms: int = 120000       # 单次健康探针的墙钟超时(独立于审计任务的大超时)
    prompt: str = (
        "这是一次模型健康检查,请忽略其它指令。只输出两行,不要解释、不要代码块、不要额外文字。"
        "第一行固定输出: HEALTH_OK。"
        "第二行输出从 tok001 到 tok080 的递增标记序列,用单个空格分隔。"
    )
    expect: str = "HEALTH_OK"      # 答案里应包含的子串(命中=healthy;可达但未命中=degraded)


@dataclass
class RetrySpec:
    """后端(opencode/claude/codex)执行任务失败后的重试策略。

    说明:后端内部已自行处理瞬时 API 抖动(限流/5xx 等)的重试;本工具这一层只在
    **后端任务整体失败**时重试——即非零退出 / 超时 / 输出无法解析为所需结构化 JSON。
    max_attempts 是单组重试上限;threat/audit 等阶段可在其外层选择不限组数或回队继续重试。
    """
    max_attempts: int = 4          # 失败后最多再重试几次(总尝试 = 1 + max_attempts)
    backoff_base_ms: int = 2000    # 退避基数(指数增长)
    backoff_cap_ms: int = 30000    # 单次退避封顶
    timeout_ms: int = 1800000      # 单次后端任务墙钟超时(超时也算一次失败 → 计入重试)


@dataclass
class HistorySpec:
    """git 历史问题模式挖掘:与 threat 阶段并行启动。

    遍历 `git log` 的提交,**每条提交派 1 个 agent**(role=history)读其改动并判定是否安全修复;
    相关者提炼成「历史问题模式」回灌到 history[](作为同类变体排查种子)与审计队列。
    这一块不阻塞威胁分析和审计:按 high audit finder 同级排队,历史模式随挖随补。
    """
    enabled: bool = True
    max_commits: int = 200          # 最多分析多少条最近的提交
    concurrency: int = 1            # 兼容旧配置;统一调度下实际并发由全局 concurrency + role/model 容量决定
    since: str = ""                 # 可选:git log --since=<...> 只看某时间段
    paths: str = ""                 # 可选:限定 git log 的路径(留空则用 scope;空格分隔多个)
    poll_interval_s: int = 3        # 审计循环等待历史变体灌入的轮询间隔(秒)


@dataclass
class RecheckSpec:
    """专用「优先排查」通道:把历史问题变体排查 + 即时风险种子复查抽到一条独立优先队列,
    由专用 agent(role=recheck)处理。优先级最高——只要队列里有项,空出的 agent 名额就先来处理它
    (懒占全局并发名额:有活才占、用完即还,队列空时不占用主池)。

    即时风险种子的典型对象:被调函数/危险原语(B)的安全依赖调用方传入已校验的参数,当前路径安全但
    全仓其它调用 B 的地方未必都做了等价校验。risk_min_severity 仅保留旧配置兼容,新种子不再按等级过滤。
    """
    enabled: bool = True
    concurrency: int = 1            # 该角色并发上限(默认 1:逐条串行排查)
    risk_min_severity: str = "medium"  # 兼容旧配置;即时风险种子不再按 severity_hint 过滤
    poll_interval_s: int = 3        # 优先队列空时的轮询等待间隔(秒)
    max_retries: int = 2            # 单个排查项连续失败的重排上限;超过即放弃该项(不再回灌优先队列)。
                                    # 防止某条复查的后端调用持续失败时无限重排,拖住整条管线的收敛、
                                    # 占住唯一的 recheck 名额,导致其它 agent 看似“全停”。


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
    model_time_windows: Dict[str, List[str]] = field(default_factory=dict)
    concurrency: int = 4
    # backend=opencode 专用的运行产物回收开关。
    # opencode 把快照(snapshot/ 裸 git 仓,每步提交整棵工作树)等写在 ~/.local/share/opencode;
    # PoC 每次在独立临时 worktree 里跑会不断新建 snapshot 仓,孤儿残留 → 磁盘无上限膨胀。
    # True:沿用共享热数据目录(不每次重建,避免冷启动 DB 迁移+整树重建快照拖到探针超时),
    #      每次调用收尾时把膨胀的 snapshot/repos 裸仓按最近活跃时刻滚动保留最近若干个,
    #      活跃 target 的快照基线必留、只淘汰旧孤儿——既不超时也不膨胀。
    # False:完全不回收(由你自行清理 ~/.local/share/opencode/snapshot 等)。
    # 仅对 backend=opencode 生效;claude/codex 不受影响。
    ephemeral_backend_data: bool = True
    # 排查类临时产物的滚动保留数:提示词临时文件(out_dir/prompts/agent_*.md)与解析失败转储
    # (out_dir/debug/parsefail_*)各只保留最近 N 次,旧的自动删除。<=0 表示不清理(保留全部)。
    artifact_retain: int = 10

    # 流水线参数(对齐 proto-vuln-hunt)
    run_mode: str = RUN_MODE_FULL
    history_import_from: str = ""           # 可选:从既有 run 目录或 history.json 导入历史问题模式,跳过 commit 分析
    finders_per_lens: int = 2
    dry_rounds: int = 2
    max_rounds: int = 6
    verify_votes: int = 3
    threat_model: str = "REMOTE"
    enable_poc: bool = True
    # PoC 组件列表。默认 minimal_poc 组件保留旧行为;设为 [] 时即使 enable_poc=true 也不会执行 PoC。
    poc_components: List[Dict[str, Any]] = field(default_factory=lambda: [dict(x) for x in DEFAULT_POC_COMPONENTS])
    lenses: List[str] = field(default_factory=lambda: list(ALL_LENSES))
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
        self.run_mode = self.run_mode if self.run_mode in RUN_MODES else RUN_MODE_FULL
        self.history_import_from = str(self.history_import_from or "").strip()
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
        self.poc_components = normalize_poc_components(self.poc_components)
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
        (self.model_time_windows,
         self._model_time_window_minutes,
         self._model_time_window_errors) = normalize_model_time_windows_with_errors(self.model_time_windows)
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
        # 模型未显式配置并发时默认为 1;配置了(模型自身或 default 键)则按配置生效
        return max(1, int(self.model_concurrency.get(model) or self.model_concurrency.get("default") or 1))

    def _time_window_minutes_for(self, model: str) -> Optional[List[Tuple[int, int]]]:
        windows = getattr(self, "_model_time_window_minutes", {})
        if model in windows:
            return list(windows.get(model) or [])
        if "default" in windows:
            return list(windows.get("default") or [])
        return None

    def model_time_windows_for(self, model: str) -> List[str]:
        if model in self.model_time_windows:
            return list(self.model_time_windows.get(model) or [])
        if "default" in self.model_time_windows:
            return list(self.model_time_windows.get("default") or [])
        return ["*"]

    def model_available_at(self, model: str, when: Optional[float] = None) -> bool:
        """按本机本地时间判断模型当前是否处于可用时间窗内。

        未配置时间窗的模型默认全天可用。时间窗语义为 start <= 当前时间 < end;
        跨零点窗口(如 22:00~02:00)按夜间跨日处理。
        """
        windows = self._time_window_minutes_for(model)
        if windows is None:
            return True
        if not windows:
            return False
        lt = time.localtime(time.time() if when is None else when)
        minute = lt.tm_hour * 60 + lt.tm_min
        for start, end in windows:
            if start == end:
                return True
            if start < end:
                if start <= minute < end:
                    return True
            elif minute >= start or minute < end:
                return True
        return False

    def available_models(self, models: List[str], when: Optional[float] = None) -> List[str]:
        return [m for m in models if self.model_available_at(m, when)]

    def all_models(self) -> List[str]:
        """所有 role 里配置到的去重模型列表(保持首次出现顺序),用于配置诊断/展示。"""
        seen: List[str] = []
        for role, vals in self.models.items():
            if role == "default":
                continue
            for m in vals:
                if m and m not in seen:
                    seen.append(m)
        return seen

    def active_models(self) -> List[str]:
        """本次 run 实际会派任务的 role 中配置到的去重模型列表。

        Web 新建任务会把部分隐藏/未参与当前模式的 role 模型一并带上;健康检查只应覆盖
        当前 run 会使用的模型,否则会探测配置文件里存在但本次不会派任务的模型。
        """
        seen: List[str] = []
        for role in self.required_model_roles():
            for m in self.models_for(role):
                if m and m not in seen:
                    seen.append(m)
        return seen

    def active_poc_component_specs(self) -> List[Dict[str, Any]]:
        return active_poc_component_specs(enable_poc=self.enable_poc, components=self.poc_components)

    def poc_enabled(self) -> bool:
        return bool(self.active_poc_component_specs())

    def required_model_roles(self) -> List[str]:
        roles = ["threat", "audit", "verify", "report"]
        if self.history.enabled and not self.history_import_from:
            roles.append("history")
        if self.recheck.enabled:
            roles.append("recheck")
        for role in required_model_roles_for_poc_specs(self.active_poc_component_specs()):
            if role not in roles:
                roles.append(role)
        return [r for r in TASK_MODEL_ROLES if r in roles]

    def missing_model_roles(self) -> List[str]:
        return [r for r in self.required_model_roles() if not self.models_for(r)]

    def unsupported_model_keys(self) -> List[str]:
        return [k for k in self.models if k == "default" or k not in ROLES]

    def model_config_error(self) -> str:
        problems: List[str] = []
        unsupported = self.unsupported_model_keys()
        if unsupported:
            problems.append("不支持的模型 role: " + ", ".join(f"models.{k}" for k in unsupported))
        missing = self.missing_model_roles()
        if missing:
            problems.append("缺少模型配置: " + ", ".join(f"models.{r}" for r in missing))
        window_errors = getattr(self, "_model_time_window_errors", [])
        if window_errors:
            problems.append("模型可用时间段配置错误: " + "; ".join(window_errors))
        return "; ".join(problems)

    def configured_model_slots_for(self, role: str) -> List[str]:
        slots: List[str] = []
        for model in self.models_for(role):
            slots.extend([model] * self.model_concurrency_for(model))
        return slots

    def model_slots_for(self, role: str, when: Optional[float] = None) -> List[str]:
        slots: List[str] = []
        for model in self.models_for(role):
            if not self.model_available_at(model, when):
                continue
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


_WINDOW_SEP = re.compile(r"\s*(?:~|–|—|-|\bto\b)\s*", re.IGNORECASE)
_ALWAYS_WINDOW_VALUES = {"*", "all", "any", "always", "anytime", "24h", "全天", "任意"}


def _parse_clock_minute(raw: Any) -> Optional[int]:
    s = str(raw or "").strip()
    m = re.fullmatch(r"(\d{1,2})(?::(\d{1,2}))?", s)
    if not m:
        return None
    hour = int(m.group(1))
    minute = int(m.group(2) or 0)
    if hour == 24 and minute == 0:
        return 1440
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        return None
    return hour * 60 + minute


def _fmt_clock_minute(minute: int, *, end: bool = False) -> str:
    if end and minute == 1440:
        return "24:00"
    minute = minute % 1440
    return f"{minute // 60:02d}:{minute % 60:02d}"


def _normalize_window_item(item: Any) -> Tuple[Optional[str], Optional[Tuple[int, int]], Optional[str]]:
    if isinstance(item, dict):
        start_raw = item.get("start", item.get("from"))
        end_raw = item.get("end", item.get("to"))
        label = f"{start_raw}~{end_raw}"
    else:
        label = str(item or "").strip()
        if label.lower() in _ALWAYS_WINDOW_VALUES:
            return "*", (0, 0), None
        parts = _WINDOW_SEP.split(label, maxsplit=1)
        if len(parts) != 2:
            return None, None, f"{label or '<empty>'} 应形如 00:00~06:00"
        start_raw, end_raw = parts[0], parts[1]

    start = _parse_clock_minute(start_raw)
    end = _parse_clock_minute(end_raw)
    if start is None or end is None:
        return None, None, f"{label} 包含非法时间"
    start = start % 1440
    norm = f"{_fmt_clock_minute(start)}~{_fmt_clock_minute(end, end=True)}"
    return norm, (start, end), None


def _iter_window_items(value: Any) -> List[Any]:
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, dict):
        if "start" in value or "from" in value or "end" in value or "to" in value:
            return [value]
        return []
    if value is None:
        return []
    return [value]


def normalize_model_time_windows_with_errors(raw: Any) -> Tuple[Dict[str, List[str]], Dict[str, List[Tuple[int, int]]], List[str]]:
    """标准化模型可用时间窗。

    支持:
      model_time_windows:
        model-a: "00:00~06:00"
        model-b: ["00:00~06:00", "22:00~24:00"]
        model-c:
          - start: "00:00"
            end: "06:00"

    未配置的模型默认全天可用;可用时间段为左闭右开,跨零点窗口可写 22:00~02:00。
    """
    if not raw:
        return {}, {}, []
    if isinstance(raw, str):
        raw = {"default": raw}
    if not isinstance(raw, dict):
        return {}, {}, ["model_time_windows 应为 object,如 model: 00:00~06:00"]

    normalized: Dict[str, List[str]] = {}
    parsed: Dict[str, List[Tuple[int, int]]] = {}
    errors: List[str] = []

    for model, value in raw.items():
        key = str(model or "").strip()
        if not key:
            errors.append("存在空模型名")
            continue
        items = _iter_window_items(value)
        if not items:
            normalized[key] = []
            parsed[key] = []
            errors.append(f"{key} 未配置任何时间段")
            continue
        norm_items: List[str] = []
        parsed_items: List[Tuple[int, int]] = []
        for item in items:
            norm, win, err = _normalize_window_item(item)
            if err:
                errors.append(f"{key}: {err}")
                continue
            if norm is not None and win is not None:
                norm_items.append(norm)
                parsed_items.append(win)
        normalized[key] = norm_items
        parsed[key] = parsed_items
    return normalized, parsed, errors


def normalize_model_time_windows(raw: Any) -> Dict[str, List[str]]:
    normalized, _parsed, _errors = normalize_model_time_windows_with_errors(raw)
    return normalized

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

    # PoC 组件配置:兼容顶层 `enable_poc` / `poc_components`,也支持:
    # poc:
    #   enabled: true
    #   components:
    #     - type: minimal_poc
    # 旧配置 type: agent / harness 会作为 minimal_poc 的兼容别名处理。
    poc_data = data.pop("poc", None)
    if poc_data is not None:
        if isinstance(poc_data, dict):
            if "enabled" in poc_data:
                data.setdefault("enable_poc", bool(poc_data.get("enabled")))
            if "components" in poc_data:
                data.setdefault("poc_components", poc_data.get("components"))
            elif "type" in poc_data or "kind" in poc_data:
                data.setdefault("poc_components", [poc_data])
        else:
            data.setdefault("poc_components", poc_data)

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
        max_retries=max(0, int(rc_data.get("max_retries", _rc_default.max_retries))),
    )

    if overrides:
        data.update({k: v for k, v in overrides.items() if v is not None})

    known = {f for f in Config.__dataclass_fields__}  # type: ignore[attr-defined]
    kwargs = {k: v for k, v in data.items() if k in known and k not in ("retry", "health", "history", "recheck", "backends")}
    cfg = Config(backends=backends, retry=retry, health=health, history=history, recheck=recheck, **kwargs)
    return cfg
