"""Agent 执行后端:把一段提示词交给外部 CLI(claude/opencode/codex)在目标仓里跑一轮
agentic 循环,拿回最终文本;需要结构化结果时再从文本中解析出 JSON。

对应原 workflow 里的 `agent()` 原语 + `gSafe()` 容错包装,但执行体改为 shell 出去调 CLI。
"""
from __future__ import annotations

import asyncio
import math
import json
import os
import re
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import Config

# 后端 CLI 已自行重试瞬时 API 抖动;本层只在"CLI 任务整体失败"时重试(非零退出/超时/输出不可解析)。
# 这个正则只用来**判断该不该退避更久**:若失败信息像"被限流/额度耗尽",则用更长退避等服务端恢复。
_RATE_RE = re.compile(
    r"(overloaded|rate.?limit|too many requests?|\b429\b|\b529\b|\b503\b|"
    r"usage limit|quota|service unavailable|temporarily unavailable)",
    re.IGNORECASE,
)


def looks_rate_limited(msg: str) -> bool:
    return bool(_RATE_RE.search(msg or ""))


# 终端 CLI(尤其 opencode/codex 的 run 模式)常把会话/工具活动连同 ANSI 颜色码一起打到 stdout。
# 这些转义序列会混进 JSON 文本里,导致 json.loads 失败。解析前统一剥掉。
_ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]"   # CSI 序列(含颜色 SGR、光标移动等)
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC 序列(标题等),以 BEL 或 ST 结束
    r"|\x1b[@-Z\\-_]"             # 其它两字符转义
)


def strip_ansi(s: str) -> str:
    if not s:
        return s
    s = _ANSI_RE.sub("", s)
    # 去掉孤立的回车(进度条回刷)与残留的退格,避免污染 JSON
    return s.replace("\r", "")


def estimate_tokens(text: str) -> int:
    """轻量估算:ASCII 约 4 字符/token,非 ASCII 约 1 字符/token。"""
    if not text:
        return 0
    ascii_chars = 0
    non_ascii = 0
    for ch in text:
        if ord(ch) < 128:
            ascii_chars += 1
        else:
            non_ascii += 1
    return int(math.ceil(ascii_chars / 4.0) + non_ascii)


def _as_int(v: Any) -> Optional[int]:
    try:
        if v is None:
            return None
        return int(v)
    except Exception:
        return None


def _extract_usage(obj: Any) -> Optional[Dict[str, int]]:
    """从常见 CLI JSON 包装里提取真实 usage;拿不到则返回 None。"""
    if not isinstance(obj, dict):
        return None
    candidates = [obj]
    for key in ("usage", "token_usage", "tokens"):
        if isinstance(obj.get(key), dict):
            candidates.insert(0, obj[key])
    for u in candidates:
        inp = (_as_int(u.get("input_tokens")) or _as_int(u.get("prompt_tokens")) or
               _as_int(u.get("input")) or _as_int(u.get("prompt")))
        out = (_as_int(u.get("output_tokens")) or _as_int(u.get("completion_tokens")) or
               _as_int(u.get("output")) or _as_int(u.get("completion")))
        total = _as_int(u.get("total_tokens")) or _as_int(u.get("total"))
        if inp is None and out is None and total is None:
            continue
        if total is None:
            total = (inp or 0) + (out or 0)
        return {
            "input_tokens": inp or 0,
            "output_tokens": out or 0,
            "total_tokens": total,
        }
    return None


# ──────────────────────────── JSON 提取 ────────────────────────────
# opencode/codex 的 run 模式常把一段自然语言 + ```json 代码块 + 工具活动一起打到 stdout,
# 有时还夹带 // 注释、尾随逗号、被截断未闭合等。下面这套解析尽量从这种"脏文本"里把目标 JSON 捞出来:
#   1) 收集所有候选(```json/``` 代码块、整段、括号配对扫描出的顶层 {…}/[…]);
#   2) 每个候选先严格解析,失败再做温和修复(去注释/去尾逗号/补全未闭合)后再试;
#   3) 用 schema 的顶层键给候选打分,选最可能是"最终答案"的那个(键命中多、来自代码块、体量大、靠后)。

def _balanced_json_spans(s: str) -> List[Tuple[str, int]]:
    """扫描出文本中所有"括号配对完整"的顶层 JSON 对象/数组子串及其起始位置。"""
    out: List[Tuple[str, int]] = []
    n = len(s)
    i = 0
    while i < n:
        if s[i] not in "{[":
            i += 1
            continue
        stack: List[str] = []
        in_str = False
        esc = False
        j = i
        closed = False
        while j < n:
            c = s[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c in "{[":
                    stack.append(c)
                elif c in "}]":
                    if not stack:
                        break
                    stack.pop()
                    if not stack:
                        out.append((s[i:j + 1], i))
                        closed = True
                        break
            j += 1
        if not closed and j >= n:
            # 顶层括号一直没闭合(疑似被截断)→ 也作为候选,留给温和修复尝试补全
            out.append((s[i:], i))
        i = (j + 1) if j > i else (i + 1)
    return out


def _sanitize_jsonish(s: str) -> str:
    """字符串感知地去掉 // 与 /* */ 注释、以及对象/数组里的尾随逗号(不动字符串字面量内部)。"""
    out: List[str] = []
    i, n = 0, len(s)
    in_str = False
    esc = False
    while i < n:
        c = s[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "/":
            j = i + 2
            while j < n and s[j] != "\n":
                j += 1
            i = j
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "*":
            j = i + 2
            while j + 1 < n and not (s[j] == "*" and s[j + 1] == "/"):
                j += 1
            i = j + 2
            continue
        if c == ",":
            j = i + 1
            while j < n and s[j] in " \t\r\n":
                j += 1
            if j < n and s[j] in "}]":   # 尾随逗号 → 丢弃
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _autoclose(s: str) -> str:
    """对被截断的 JSON 做尽力补全:补上未闭合的字符串引号与未闭合的括号。"""
    stack: List[str] = []
    in_str = False
    esc = False
    for c in s:
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c in "{[":
                stack.append(c)
            elif c in "}]":
                if stack:
                    stack.pop()
    suffix = '"' if in_str else ""
    for c in reversed(stack):
        suffix += "}" if c == "{" else "]"
    return s + suffix


def _try_load(raw: str) -> Tuple[Any, bool]:
    """尽力把一个候选串解析为 JSON:严格 → 去注释去尾逗号 → 再补全未闭合。返回 (值, 是否成功)。"""
    raw = (raw or "").strip()
    if not raw:
        return None, False
    try:
        return json.loads(raw), True
    except Exception:
        pass
    sanitized = _sanitize_jsonish(raw)
    try:
        return json.loads(sanitized), True
    except Exception:
        pass
    try:
        return json.loads(_autoclose(sanitized)), True
    except Exception:
        return None, False


def _schema_keys(schema: Optional[Dict[str, Any]]) -> Optional[set]:
    """从 schema 取顶层期望键(required + properties),用于在多个候选里挑最贴合的那个。"""
    if not isinstance(schema, dict):
        return None
    keys: set = set()
    props = schema.get("properties")
    if isinstance(props, dict):
        keys.update(props.keys())
    req = schema.get("required")
    if isinstance(req, list):
        keys.update(req)
    return keys or None


def extract_json(text: str, schema: Optional[Dict[str, Any]] = None) -> Optional[Any]:
    """从 agent 的自由文本(可能是"一段话 + JSON")里稳健地解析出目标 JSON。

    传入 schema 时会据其顶层键在多个候选中择优(opencode 常把解释/工具活动和最终 JSON 混在一起)。
    """
    if not text:
        return None
    text = strip_ansi(text)
    want = _schema_keys(schema)
    want_array = isinstance(schema, dict) and schema.get("type") == "array"

    # (value, pos, size, source_rank);source_rank 越小越优先:0=```json 块,1=``` 块,2=整段,3=括号扫描
    candidates: List[Tuple[Any, int, int, int]] = []

    def consider(raw: str, pos: int, source_rank: int) -> None:
        val, ok = _try_load(raw)
        if ok and isinstance(val, (dict, list)):
            candidates.append((val, pos, len(raw or ""), source_rank))

    # 1) fenced ``` 代码块(json 标注优先)
    for m in re.finditer(r"```[ \t]*(json|JSON)?[ \t]*\r?\n(.*?)```", text, re.DOTALL):
        consider(m.group(2), m.start(), 0 if m.group(1) else 1)
    # 2) 整段就是 JSON
    consider(text, 0, 2)
    # 3) 括号配对扫描出的顶层片段
    for raw, pos in _balanced_json_spans(text):
        consider(raw, pos, 3)

    if not candidates:
        return None

    def score(c: Tuple[Any, int, int, int]):
        val, pos, size, source_rank = c
        if want_array:
            type_ok = 1 if isinstance(val, list) else 0
            key_hits = 0
        else:
            type_ok = 1 if isinstance(val, dict) else 0
            key_hits = sum(1 for k in want if k in val) if (want and isinstance(val, dict)) else 0
        # 期望类型匹配 > schema 键命中数 > 来源优先(代码块) > 体量更大 > 位置更靠后(最终答案)
        return (type_ok, key_hits, -source_rank, size, pos)

    candidates.sort(key=score)
    return candidates[-1][0]


_OPENCODE_EVENT_TYPES = {
    "step_start", "step_finish", "tool_use", "text", "reasoning", "error",
    "message.part.updated", "message.part.delta", "message.updated", "session.updated",
    "session.status",
}
_OPENCODE_TOOL_REASONS = {"tool-calls", "tool_calls", "tool-call", "tool_call", "tool-use", "tool_use", "tool"}


def _maybe_json_obj(v: Any) -> Optional[Dict[str, Any]]:
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and v.lstrip().startswith("{"):
        try:
            obj = json.loads(v)
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None
    return None


def _event_part(ev: Dict[str, Any]) -> Dict[str, Any]:
    """兼容 opencode 多个版本的事件外壳,取出真正的 message part。"""
    part = _maybe_json_obj(ev.get("part"))
    if part is not None:
        return part
    for key in ("data", "properties", "payload"):
        inner = _maybe_json_obj(ev.get(key))
        if not inner:
            continue
        part = _maybe_json_obj(inner.get("part"))
        if part is not None:
            return part
        if isinstance(inner.get("type"), str) and (
            "text" in inner or inner.get("type") in ("step-finish", "step-start", "tool", "reasoning")
        ):
            return inner
    if isinstance(ev.get("type"), str) and (
        "text" in ev or ev.get("type") in ("step-finish", "step-start", "tool", "reasoning")
    ):
        return ev
    return {}


def _event_message(ev: Dict[str, Any]) -> Dict[str, Any]:
    msg = _maybe_json_obj(ev.get("message"))
    if msg is not None:
        return msg
    for key in ("data", "properties", "payload"):
        inner = _maybe_json_obj(ev.get(key))
        if not inner:
            continue
        msg = _maybe_json_obj(inner.get("message"))
        if msg is not None:
            return msg
        if "role" in inner and "id" in inner:
            return inner
    return {}


def _text_delta(ev: Dict[str, Any], part: Dict[str, Any]) -> str:
    for obj in (part, ev):
        for key in ("delta", "textDelta", "text_delta"):
            v = obj.get(key)
            if isinstance(v, str):
                return v
            if isinstance(v, dict):
                txt = v.get("text") or v.get("content")
                if isinstance(txt, str):
                    return txt
    return ""


def _extract_opencode_text(stdout: str) -> Optional[Tuple[str, Optional[Dict[str, int]], bool, str]]:
    """识别并解析 opencode `--format json` 的事件流(每行一个 JSON 事件),重建 assistant 的最终文本。

    返回 (text, usage, complete, reason);若 stdout 不像事件流则返回 None(交回上层按普通文本处理)。
      · text     —— 最后一个有文本的 assistant message 正文(同一 part 取最新,delta 逐段累加)。
      · usage    —— 取最后一个 step_finish 的 part.tokens 作为整轮真实 token 用量(取不到则 None,上层回退估算)。
      · complete —— 若事件流以 tool-calls 结束,说明 opencode 还没给最终回答,必须重试/报错。

    设计取舍:`communicate()` 已经把子进程 stdout 读到 EOF(读全整条事件流,含末尾 step_finish),
    所以这里不要求必须见到 reason=stop;但如果 EOF 前最后一个 step_finish 明确是 tool-calls,
    就说明 opencode 在工具调用后停住了,此时返回早先的中间文本会造成"只拿到部分输出"。
    这类输出必须判 incomplete,由上层重试或把健康检查标成失败。

    注:`--format json` 只约束 opencode 的**输出封装**为事件流,**不**约束模型正文为 JSON;
    正文(可能是"一段话 + ```json 块")原样在 text 事件里,之后仍由 extract_json 进一步解析。
    """
    if not stdout or "{" not in stdout:
        return None
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    if not lines:
        return None
    events: List[Dict[str, Any]] = []
    for ln in lines:
        if not ln.startswith("{"):
            continue
        try:
            ev = json.loads(ln)
        except Exception:
            continue
        if not isinstance(ev, dict) or "type" not in ev:
            continue
        etype = str(ev.get("type") or "")
        if etype in _OPENCODE_EVENT_TYPES or "part" in ev or "sessionID" in ev:
            events.append(ev)
    # 至少一半的非空行是 opencode JSON 事件,才认定是事件流(避免把普通最终 JSON 误判为事件流)。
    if not events or len(events) * 2 < len(lines):
        return None

    part_text: Dict[Any, str] = {}
    part_order: List[Any] = []
    part_message: Dict[Any, str] = {}
    message_order: List[str] = []
    message_roles: Dict[str, str] = {}
    usage: Optional[Dict[str, int]] = None
    incomplete_after_tool = False
    last_reason = ""

    def note_message(mid: str) -> None:
        if mid and mid not in message_order:
            message_order.append(mid)

    def note_part(pid: Any, mid: str) -> None:
        if pid not in part_order:
            part_order.append(pid)
        if mid:
            part_message[pid] = mid
            note_message(mid)

    for ev in events:
        etype = str(ev.get("type") or "")
        part = _event_part(ev)
        msg = _event_message(ev)
        if msg:
            mid = str(msg.get("id") or msg.get("messageID") or "")
            role = str(msg.get("role") or "")
            if mid:
                note_message(mid)
                if role:
                    message_roles[mid] = role
        if not part:
            if usage is None:
                u = _extract_usage(ev)
                if u:
                    usage = u
            continue
        ptype = part.get("type")
        pid = part.get("id") or f"_{len(part_order)}"
        mid = str(part.get("messageID") or part.get("message_id") or part.get("messageId") or "")
        role = str(part.get("role") or "")
        note_part(pid, mid)
        if role and mid:
            message_roles[mid] = role

        # step_finish 带本步 tokens;最后一个(终止步)即整轮用量 → 让后写的覆盖先写的
        if etype == "step_finish" or ptype == "step-finish":
            u = _extract_usage(part) or _extract_usage(part.get("tokens") or {})
            if u:
                usage = u
            last_reason = str(part.get("reason") or ev.get("reason") or "").strip()
            incomplete_after_tool = last_reason in _OPENCODE_TOOL_REASONS
        # 收集 assistant 正文 text 片段;reasoning/tool/step 等事件忽略。
        # opencode 版本间可能给累计 part.text,也可能给 delta;两种都兼容。
        if ptype == "text" or etype in ("text", "message.part.updated", "message.part.delta"):
            if isinstance(part.get("text"), str):
                part_text[pid] = part["text"]      # 同一 part 多次出现(流式累积)取最新
                incomplete_after_tool = False
            delta = _text_delta(ev, part)
            if delta:
                part_text[pid] = part_text.get(pid, "") + delta
                incomplete_after_tool = False
        if usage is None:
            u = _extract_usage(ev) or _extract_usage(part)
            if u:
                usage = u

    def msg_text(mid: str) -> str:
        return "".join(part_text.get(pid, "") for pid in part_order if part_message.get(pid) == mid)

    groups: List[Tuple[str, str]] = []
    for mid in message_order:
        text = msg_text(mid)
        if text.strip():
            groups.append((mid, text))
    assistant_groups = [(mid, text) for mid, text in groups if message_roles.get(mid, "assistant") == "assistant"]
    chosen = (assistant_groups or groups)
    text = chosen[-1][1] if chosen else ""
    return text, usage, (not incomplete_after_tool), last_reason


class AgentRunner:
    """封装并发门 + 重试 + 子进程调用。一个实例对应一次运行。"""

    def __init__(self, cfg: Config, logger=print,
                 usage_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
                 health_sink: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.cfg = cfg
        self._sem: Optional[asyncio.Semaphore] = None  # 惰性创建(避免在事件循环外构造时绑错 loop,兼容 py3.8)
        self.spec = cfg.backend_spec()
        self.log = logger
        self.usage_sink = usage_sink
        self.health_sink = health_sink
        self.health: Dict[str, Dict[str, Any]] = {}      # model -> 健康记录
        self._health_locks: Dict[str, asyncio.Lock] = {}  # 每模型一把锁,避免并发重复探针
        self.agent_count = 0
        self.usage_count = 0
        self.usage_totals: Dict[str, int] = {
            "calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "estimated_calls": 0,
        }
        self._jitter = 0
        self._model_cursor: Dict[str, int] = {}
        self._model_sems: Dict[str, asyncio.Semaphore] = {}

    def _semaphore(self) -> asyncio.Semaphore:
        if self._sem is None:
            self._sem = asyncio.Semaphore(self.cfg.concurrency)
        return self._sem

    def _model_semaphore(self, model: str) -> asyncio.Semaphore:
        if model not in self._model_sems:
            self._model_sems[model] = asyncio.Semaphore(self.cfg.model_concurrency_for(model))
        return self._model_sems[model]

    # ── 同一 role 下按模型并发加权轮换 ──
    def _next_model(self, role: str) -> str:
        models = self.cfg.model_slots_for(role)
        if not models:
            return ""
        i = self._model_cursor.get(role, 0)
        self._model_cursor[role] = i + 1
        return models[i % len(models)]

    def _write_prompt_file(self, prompt: str) -> str:
        prompt_dir = os.path.join(self.cfg.out_dir, "prompts")
        os.makedirs(prompt_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".md",
            prefix="agent_",
            dir=prompt_dir,
            delete=False,
        ) as f:
            f.write(prompt)
            return f.name

    def _record_usage(self, prompt: str, output: str, *, role: str, label: str,
                      model: str, attempt: int, backend_usage: Optional[Dict[str, int]]) -> None:
        est_in = estimate_tokens(prompt)
        est_out = estimate_tokens(output)
        usage = backend_usage or {}
        input_tokens = int(usage.get("input_tokens") or est_in)
        output_tokens = int(usage.get("output_tokens") or est_out)
        total_tokens = int(usage.get("total_tokens") or (input_tokens + output_tokens))
        estimated = backend_usage is None

        self.usage_count += 1
        rec: Dict[str, Any] = {
            "id": self.usage_count,
            "ts": time.time(),
            "backend": self.cfg.backend,
            "role": role,
            "label": label or role,
            "model": model,
            "attempt": attempt,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
            "estimated": estimated,
            "source": "estimated" if estimated else "backend",
        }
        self.usage_totals["calls"] += 1
        self.usage_totals["input_tokens"] += input_tokens
        self.usage_totals["output_tokens"] += output_tokens
        self.usage_totals["total_tokens"] += total_tokens
        if estimated:
            self.usage_totals["estimated_calls"] += 1
        if self.usage_sink:
            try:
                self.usage_sink(rec)
            except Exception:
                pass

    # ── 单次子进程调用(不含重试) ──
    async def _invoke(self, prompt: str, model: str, cwd: str,
                      timeout_s: Optional[float] = None) -> Tuple[str, Optional[Dict[str, int]]]:
        prompt_file = ""
        if self.spec.prompt_mode == "file" or any("{prompt_file}" in tok for tok in self.spec.command):
            prompt_file = self._write_prompt_file(prompt)

        cmd: List[str] = []
        prompt_in_args = False
        for tok in self.spec.command:
            t = tok.replace("{model}", model)
            t = t.replace("{prompt_file}", prompt_file)
            if "{prompt}" in t:
                t = t.replace("{prompt}", prompt)
                prompt_in_args = True
            cmd.append(t)
        stdin_data = None
        if self.spec.prompt_mode == "stdin" and not prompt_in_args:
            stdin_data = prompt.encode("utf-8")

        env = dict(os.environ)
        env.update(self.spec.env or {})

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )
        if timeout_s is None:
            timeout_s = max(1, self.cfg.retry.timeout_ms / 1000.0)
        try:
            out_b, err_b = await asyncio.wait_for(proc.communicate(input=stdin_data), timeout=timeout_s)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            raise RuntimeError(f"timed out after {int(timeout_s)}s")

        stdout = (out_b or b"").decode("utf-8", "replace")
        stderr = (err_b or b"").decode("utf-8", "replace")
        if proc.returncode != 0:
            # 把 stderr/stdout 一起带上,供退避决策判别(限流信号常出现在 stderr)
            raise RuntimeError(f"exit={proc.returncode} :: {stderr.strip() or stdout.strip()}"[:600])

        if self.spec.parse == "claude_json":
            try:
                obj = json.loads(stdout)
            except Exception:
                # 某些情况下 claude 直接输出文本而非 JSON,降级当文本用
                return stdout, None
            usage = _extract_usage(obj)
            if isinstance(obj, dict):
                if obj.get("is_error"):
                    raise RuntimeError(f"claude error: {str(obj.get('result'))[:300]}")
                return str(obj.get("result", "") or ""), usage
            return stdout, usage
        # opencode `--format json` 事件流:把所有 text 块拼成 assistant 正文(自动识别,兼容旧配置)。
        # 不再按"是否见到终止 step_finish"硬判完整(会误杀完整答案与健康探针);完整性交给下游:
        # 结构化任务看 extract_json 能否解析,健康探针看 expect 是否命中,解析不出再重试。
        oc = _extract_opencode_text(stdout)
        if oc is not None:
            text, oc_usage, complete, reason = oc
            if not complete:
                raise RuntimeError(f"opencode 输出在工具调用后结束,未收到最终回答(reason={reason or 'unknown'}),将重试")
            if not text.strip():
                raise RuntimeError("opencode 未产出任何 assistant 文本(只有工具/步骤事件),将重试")
            return strip_ansi(text), oc_usage
        usage = None
        try:
            usage = _extract_usage(json.loads(stdout))
        except Exception:
            usage = None
        return strip_ansi(stdout), usage

    def _dump_failed_output(self, role: str, label: str, model: str, attempt: int, text: str) -> str:
        """解析结构化 JSON 失败时,把后端 CLI 的原始输出落盘,便于排查(尤其 opencode/codex)。"""
        try:
            dbg_dir = os.path.join(self.cfg.out_dir, "debug")
            os.makedirs(dbg_dir, exist_ok=True)
            safe = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{role}_{label}_{model}")[:80]
            path = os.path.join(dbg_dir, f"parsefail_{self.agent_count}_{attempt}_{safe}.txt")
            header = (f"# backend={self.cfg.backend} role={role} label={label} model={model} "
                      f"attempt={attempt} len={len(text or '')}\n"
                      f"# 后端 CLI 输出里找不到可解析的 JSON。常见原因:opencode/codex 把工具活动/思考一并打到 stdout,"
                      f"或最终未输出 ```json 代码块。\n{'-' * 60}\n")
            with open(path, "w", encoding="utf-8") as f:
                f.write(header + (text or ""))
            return path
        except Exception:
            return ""

    def _backoff_ms(self, attempt: int, msg: str) -> int:
        """指数退避;若失败像"被限流/额度耗尽"则用更长基数等服务端恢复。带确定性抖动分散惊群。"""
        r = self.cfg.retry
        base = max(r.backoff_base_ms, 8000) if looks_rate_limited(msg) else r.backoff_base_ms
        self._jitter += 1
        grown = base * (1.7 ** min(attempt, 8))
        return int(min(r.backoff_cap_ms, grown)) + (self._jitter % 8) * 250

    # ──────────────────────────── 模型健康检查 ────────────────────────────
    def _health_rec(self, model: str) -> Dict[str, Any]:
        rec = self.health.get(model)
        if rec is None:
            rec = {
                "model": model, "status": "unknown", "backend": self.cfg.backend,
                "last_check_ts": 0.0, "last_ok_ts": 0.0, "last_latency_ms": 0,
                "checks": 0, "ok_checks": 0, "answer": "", "error": "",
                "calls": 0, "call_fails": 0, "reason": "", "ts": time.time(),
            }
            self.health[model] = rec
        return rec

    def _emit_health(self, rec: Dict[str, Any]) -> None:
        rec["ts"] = time.time()
        if self.health_sink:
            try:
                self.health_sink(dict(rec))
            except Exception:
                pass

    def _health_lock(self, model: str) -> asyncio.Lock:
        lk = self._health_locks.get(model)
        if lk is None:
            lk = asyncio.Lock()
            self._health_locks[model] = lk
        return lk

    async def probe_model(self, model: str, *, reason: str = "startup") -> Optional[Dict[str, Any]]:
        """对单个模型发一个极小探针任务(默认 1+1=?),据响应判定 ok/degraded/down。
        探针不计入 token 用量统计,且用独立的较短超时,避免拖慢启动。"""
        if not model:
            return None
        hc = self.cfg.health
        rec = self._health_rec(model)
        rec["status"] = "checking"
        rec["reason"] = reason
        self._emit_health(rec)
        cwd = os.path.abspath(os.path.expanduser(self.cfg.target))
        timeout_s = max(1, (hc.timeout_ms or self.cfg.retry.timeout_ms) / 1000.0)
        t0 = time.time()
        async with self._model_semaphore(model):
            async with self._semaphore():
                try:
                    text, _usage = await self._invoke(hc.prompt, model, cwd, timeout_s=timeout_s)
                    latency = int((time.time() - t0) * 1000)
                    answer = (text or "").strip()
                    healthy = (hc.expect in answer) if hc.expect else bool(answer)
                    rec["checks"] += 1
                    rec["last_check_ts"] = time.time()
                    rec["last_latency_ms"] = latency
                    rec["answer"] = answer[:160]
                    if healthy:
                        rec["ok_checks"] += 1
                        rec["last_ok_ts"] = time.time()
                        rec["status"] = "ok"
                        rec["error"] = ""
                    else:
                        rec["status"] = "degraded"
                        rec["error"] = "模型可达但回答未命中预期(疑似越权/拒答/输出异常)"
                except Exception as e:  # noqa: BLE001
                    rec["checks"] += 1
                    rec["last_check_ts"] = time.time()
                    rec["last_latency_ms"] = int((time.time() - t0) * 1000)
                    rec["status"] = "down"
                    rec["error"] = str(e)[:200]
        self._emit_health(rec)
        return rec

    async def ensure_healthy(self, model: str) -> None:
        """gate:真正调用某模型前,若其健康状态未知/异常/陈旧,则先补一次探针(按 ttl 去重)。
        无论探针结果如何都不阻断真正的调用——只更新状态,失败仍交由 run() 的重试兜底。"""
        hc = self.cfg.health
        if not model or not hc.enabled or not hc.gate or hc.ttl_s <= 0:
            return
        rec = self._health_rec(model)
        now = time.time()
        if rec.get("status") == "ok" and (now - (rec.get("last_check_ts") or 0)) < hc.ttl_s:
            return
        async with self._health_lock(model):
            rec = self._health_rec(model)
            now = time.time()
            if rec.get("status") == "ok" and (now - (rec.get("last_check_ts") or 0)) < hc.ttl_s:
                return
            await self.probe_model(model, reason="gate")

    def _note_call(self, model: str, ok: bool, err: str = "") -> None:
        """用真实 agent 调用的成败顺带更新模型健康(仅在状态发生跃迁时发事件,避免刷屏)。"""
        rec = self._health_rec(model)
        changed = False
        if ok:
            rec["calls"] += 1
            rec["last_ok_ts"] = time.time()
            if rec["status"] in ("unknown", "down", "degraded", "checking"):
                rec["status"] = "ok"
                rec["last_check_ts"] = time.time()
                rec["error"] = ""
                changed = True
        else:
            rec["call_fails"] += 1
            rec["error"] = (err or "")[:200]
            if rec["status"] in ("ok", "unknown"):
                rec["status"] = "degraded"
                changed = True
        if changed:
            self._emit_health(rec)

    # ── 带重试的 agent 调用:一次 CLI 任务执行失败(非零退出/超时/输出不可解析)即重试 ──
    async def run(
        self,
        prompt: str,
        *,
        role: str = "util",
        label: str = "",
        schema: Optional[Dict[str, Any]] = None,
        cwd: Optional[str] = None,
        retries: Optional[int] = None,
        fallback: Any = None,
    ) -> Any:
        """schema 非空 → 返回解析后的 dict/list;schema 为空 → 返回 agent 最终文本。
        失败重试上限取 `retries`(未传则用 cfg.retry.max_attempts);耗尽后返回 fallback(跳过,靠续跑挽回)。
        """
        tag = label or role
        run_cwd = cwd or os.path.abspath(os.path.expanduser(self.cfg.target))
        self.agent_count += 1
        max_attempts = self.cfg.retry.max_attempts if retries is None else retries

        attempt = 0
        while True:
            model = self._next_model(role)
            await self.ensure_healthy(model)   # gate:调用前按需补一次健康探针(ttl 去重,不阻断)
            async with self._model_semaphore(model):
                async with self._semaphore():
                    try:
                        text, usage = await self._invoke(prompt, model, run_cwd)
                        self._record_usage(prompt, text, role=role, label=tag, model=model,
                                           attempt=attempt + 1, backend_usage=usage)
                        self._note_call(model, True)
                        if schema is None:
                            return text
                        parsed = extract_json(text, schema)
                        if parsed is None:
                            path = self._dump_failed_output(role, tag, model, attempt + 1, text)
                            snippet = " ".join((text or "").split())[:240]
                            self.log(f"⚠ {tag} 后端输出无可解析 JSON(共 {len(text or '')} 字符)"
                                     f"{(';原始输出已存 ' + path) if path else ''};前 240 字符:{snippet}")
                            raise RuntimeError("CLI 未产出可解析的结构化 JSON(原始输出已存到 run 目录 debug/)")
                        return parsed
                    except Exception as e:  # noqa: BLE001
                        msg = str(e)
                        self._note_call(model, False, msg)
            # 退避/重试在信号量之外等待(不占用并发额度)
            attempt += 1
            if attempt > max_attempts:
                self.log(f"⚠ {tag} CLI 任务连续失败 {attempt} 次,放弃跳过(留待续跑): {msg[:120]}")
                return fallback
            wait_ms = self._backoff_ms(attempt, msg)
            limited = "(疑似限流,延长退避)" if looks_rate_limited(msg) else ""
            self.log(f"⚠ {tag} CLI 任务失败(第 {attempt}/{max_attempts} 次重试{limited}),{wait_ms // 1000}s 后重试: {msg[:100]}")
            await asyncio.sleep(wait_ms / 1000.0)
