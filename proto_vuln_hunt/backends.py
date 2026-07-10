"""Agent 执行后端:把一段提示词交给外部后端(claude/codex CLI 或 opencode serve)在目标仓里跑一轮
agentic 循环,拿回最终文本;需要结构化结果时再从文本中解析出 JSON。

对应原 workflow 里的 `agent()` 原语 + `gSafe()` 容错包装,但执行体改为外部后端调用。
"""
from __future__ import annotations

import asyncio
import codecs
import collections
import functools
import socket
import math
import json
import os
import re
import shutil
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import Config, normalize_model_concurrency, normalize_models

# 后端已自行重试瞬时 API 抖动;本层只在"后端任务整体失败"时重试(非零退出/超时/输出不可解析)。
# 这个正则只用来**判断该不该退避更久**:若失败信息像"被限流/额度耗尽",则用更长退避等服务端恢复。
_RATE_RE = re.compile(
    r"(overloaded|rate.?limit|too many requests?|\b429\b|\b529\b|\b503\b|"
    r"usage limit|quota|service unavailable|temporarily unavailable)",
    re.IGNORECASE,
)


def looks_rate_limited(msg: str) -> bool:
    return bool(_RATE_RE.search(msg or ""))


# 终端 CLI 常把会话/工具活动连同 ANSI 颜色码一起打到 stdout。
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


def _token_int(v: Any) -> Optional[int]:
    n = _as_int(v)
    if n is None or n < 0:
        return None
    return n


def _first_token_int(*values: Any) -> Optional[int]:
    for v in values:
        n = _token_int(v)
        if n is not None:
            return n
    return None


def _normalized_usage(inp: Optional[int], out: Optional[int],
                      total: Optional[int]) -> Optional[Dict[str, int]]:
    if inp is None and out is None and total is None:
        return None
    input_tokens = inp if inp is not None else 0
    output_tokens = out if out is not None else (
        max(0, total - input_tokens) if inp is not None and total is not None else 0
    )
    total_tokens = total if total is not None else input_tokens + output_tokens
    if total_tokens < input_tokens + output_tokens:
        total_tokens = input_tokens + output_tokens
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }


def _extract_usage(obj: Any) -> Optional[Dict[str, int]]:
    """从常见 CLI JSON 包装里提取真实 usage;拿不到则返回 None。"""
    if not isinstance(obj, dict):
        return None
    candidates = [obj]
    for key in ("usage", "token_usage", "tokens"):
        if isinstance(obj.get(key), dict):
            candidates.insert(0, obj[key])
    for u in candidates:
        rec = _normalized_usage(
            _first_token_int(
                u.get("input_tokens"), u.get("prompt_tokens"), u.get("input"), u.get("prompt")
            ),
            _first_token_int(
                u.get("output_tokens"), u.get("completion_tokens"), u.get("output"), u.get("completion")
            ),
            _first_token_int(u.get("total_tokens"), u.get("total")),
        )
        if rec is not None:
            return rec
    return None


# ──────────────────────────── JSON 提取 ────────────────────────────
# 外部 CLI 常把一段自然语言 + ```json 代码块 + 工具活动一起打到 stdout,
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


# 推理模型常把思维链用 <think>…</think> 直接夹在正文里带出来,思维段里往往含花括号、示例 JSON、
# schema 片段,会污染候选(被 _balanced_json_spans 扫成假候选,甚至盖过真正的最终 JSON)。
# 思维链固定以 </think> 收尾,所以解析 JSON 前:见到 </think> 就丢弃它(及之前)的全部内容,只留最终答案。
def strip_reasoning(text: str) -> str:
    """剥掉正文里内联的思维链:思考固定以 </think> 结束,丢弃最后一个 </think> 及其之前的全部内容。

    覆盖两种情形:成对 <think>…</think>,以及只剩闭合标签(opencode 把 <think> 起始吃进 reasoning
    事件、只把 </think> 漏到 text 里)。无 </think> 则原样返回。"""
    if not text:
        return text
    idx = text.rfind("</think>")
    return text[idx + len("</think>"):] if idx != -1 else text


def _collect_json_candidates(text: str) -> List[Tuple[str, int, int]]:
    """收集 extract_json 会逐个喂给 json.loads 的候选 (raw, pos, source_rank)。

    口径与 extract_json 完全一致(同一份 fenced 正则 + 括号扫描),供 extract_json 与调试落盘共用,
    避免"以为的候选"与"真正解析的候选"不一致。入参须是已 strip_reasoning+strip_ansi 的文本。
    source_rank 越小越优先:0=```json 块,1=``` 块,2=整段,3=括号扫描。"""
    out: List[Tuple[str, int, int]] = []
    # 1) fenced ``` 代码块(json 标注优先);换行可选,兼容 inline ```json {…}``` 同行形态
    for m in re.finditer(r"```[ \t]*(json|JSON)?[ \t]*\r?\n?(.*?)```", text, re.DOTALL):
        out.append((m.group(2), m.start(), 0 if m.group(1) else 1))
    # 2) 整段就是 JSON
    out.append((text, 0, 2))
    # 3) 括号配对扫描出的顶层片段
    for raw, pos in _balanced_json_spans(text):
        out.append((raw, pos, 3))
    return out


def extract_json(text: str, schema: Optional[Dict[str, Any]] = None) -> Optional[Any]:
    """从 agent 的自由文本(可能是"一段话 + JSON")里稳健地解析出目标 JSON。

    传入 schema 时会据其顶层键在多个候选中择优(opencode 常把解释/工具活动和最终 JSON 混在一起)。
    """
    if not text:
        return None
    text = strip_reasoning(strip_ansi(text))
    want = _schema_keys(schema)
    want_array = isinstance(schema, dict) and schema.get("type") == "array"

    # (value, pos, size, source_rank)
    candidates: List[Tuple[Any, int, int, int]] = []
    for raw, pos, source_rank in _collect_json_candidates(text):
        val, ok = _try_load(raw)
        if ok and isinstance(val, (dict, list)):
            candidates.append((val, pos, len(raw or ""), source_rank))

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
        # 期望类型匹配 > schema 键命中数 > 来源优先(代码块) > 位置更靠后(最终答案) > 体量更大
        # 位置排在体量之前:同来源/同命中时,最终答案(靠后)胜过更大的早期草稿 JSON。
        return (type_ok, key_hits, -source_rank, pos, size)

    candidates.sort(key=score)
    return candidates[-1][0]


def _json_type_name(v: Any) -> str:
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, dict):
        return "object"
    if isinstance(v, list):
        return "array"
    if isinstance(v, str):
        return "string"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if v is None:
        return "null"
    return type(v).__name__


def _schema_type_matches(v: Any, want: Any) -> bool:
    if isinstance(want, list):
        return any(_schema_type_matches(v, one) for one in want)
    if want == "object":
        return isinstance(v, dict)
    if want == "array":
        return isinstance(v, list)
    if want == "string":
        return isinstance(v, str)
    if want == "boolean":
        return isinstance(v, bool)
    if want == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if want == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if want == "null":
        return v is None
    return True


def _schema_type_label(want: Any) -> str:
    if isinstance(want, list):
        return "|".join(str(x) for x in want)
    return str(want)


def _coerce_schema_value(value: Any, schema: Optional[Dict[str, Any]]) -> Any:
    """兼容模型把单个必需数组字段直接输出成顶层数组的常见简写。

    例如 FINDINGS_SCHEMA 要求 {"findings": [...]},但有些 CLI/模型会只输出 [...];
    这类结果语义明确,在边界处归一化,避免进入 pipeline 后才因 list.get 崩掉。
    """
    if not isinstance(schema, dict) or not isinstance(value, list):
        return value
    if schema.get("type") != "object":
        return value
    props = schema.get("properties")
    req = schema.get("required")
    if not isinstance(props, dict) or not isinstance(req, list) or len(req) != 1:
        return value
    key = req[0]
    prop = props.get(key)
    if isinstance(prop, dict) and prop.get("type") == "array":
        return {key: value}
    return value


def _schema_shape_error(value: Any, schema: Optional[Dict[str, Any]]) -> Optional[str]:
    """轻量校验结构化输出的外形。

    不做完整 JSON Schema 校验,只检查根类型、必需顶层字段、顶层字段类型,以及数组字段的
    item object 外形。这样能挡住 list/dict 混用,同时避免因为 line="123" 这类可恢复小偏差过度失败。
    """
    if not isinstance(schema, dict):
        return None
    want_type = schema.get("type")
    if want_type and not _schema_type_matches(value, want_type):
        return f"$ 应为 {_schema_type_label(want_type)},实际 {_json_type_name(value)}"
    if not isinstance(value, dict):
        return None
    req = schema.get("required")
    required_keys = set()
    if isinstance(req, list):
        required_keys = set(req)
        missing = [str(k) for k in req if k not in value]
        if missing:
            return "缺少必需字段:" + ", ".join(missing)
    props = schema.get("properties")
    if not isinstance(props, dict):
        return None
    for key, prop in props.items():
        if key not in value or not isinstance(prop, dict):
            continue
        if value[key] is None and key not in required_keys:
            continue
        prop_type = prop.get("type")
        if prop_type and not _schema_type_matches(value[key], prop_type):
            return f"$.{key} 应为 {_schema_type_label(prop_type)},实际 {_json_type_name(value[key])}"
        if prop_type == "array" and isinstance(value[key], list):
            items = prop.get("items")
            item_type = items.get("type") if isinstance(items, dict) else None
            if item_type == "object":
                for i, item in enumerate(value[key]):
                    if not isinstance(item, dict):
                        return f"$.{key}[{i}] 应为 object,实际 {_json_type_name(item)}"
    return None


def best_json_candidate(text: str) -> str:
    """返回 extract_json 真正会喂给 json.loads、且最可能是最终答案的那段候选串。

    复用 `_collect_json_candidates`(与 extract_json 同一套候选),按其偏好挑选:来源优先
    (fenced > 括号片段 > 整段)、同来源取位置最靠后(最终答案)。剥掉 <think>/ANSI,输出纯文本,
    解析失败时单独落盘,便于直接 json.loads/jsonlint 复现报错。"""
    s = strip_reasoning(strip_ansi(text or ""))
    cands = _collect_json_candidates(s)
    if not cands:
        return s.strip()
    # 展示偏好:fenced(0/1)> 括号片段(3,纯 {…})> 整段(2,可能含散文);同档取 pos 最大。
    rank_order = {0: 0, 1: 1, 3: 2, 2: 3}
    raw, _pos, _rank = min(cands, key=lambda c: (rank_order[c[2]], -c[1]))
    return (raw or "").strip()


_OPENCODE_EVENT_TYPES = {
    "step_start", "step_finish", "tool_use", "text", "reasoning", "error",
    "message.part.updated", "message.part.delta", "message.updated", "session.updated",
    "session.status",
}
class BackendOutputError(RuntimeError):
    """后端输出本身不可用时抛出;保留完整 stdout/stderr 便于 debug 落盘。"""

    def __init__(self, message: str, output: str = ""):
        super().__init__(message)
        self.output = output


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


def _extract_opencode_text(stdout: str) -> Optional[Tuple[str, Optional[Dict[str, int]], str]]:
    """识别并解析 opencode JSON 事件流(每行一个 JSON 事件),重建 assistant 的最终文本。

    返回 (text, usage, session_id);若 stdout 不像事件流则返回 None(交回上层按普通文本处理)。
      · text       —— stdout 事件流中所有 assistant text message 正文按出现顺序合并。
      · usage      —— 取最后一个 step_finish 的 part.tokens 作为整轮真实 token 用量(取不到则 None,上层回退估算)。
      · session_id —— opencode 会话 ID,仅用于诊断。

    设计取舍:这里只解析事件流文本,不读 opencode 的数据库/日志。opencode 的一次 session 可能
    包含多条 assistant message:先说"我去读文件",工具调用后再输出最终 JSON。因此不能在事件层
    挑最后一条或按 reason 裁剪,而要把所有正文块合并,让 extract_json 从完整文本里找最终 JSON。

    注:事件流只约束 opencode 的**输出封装**,**不**约束模型正文为 JSON;正文(可能是
    "一段话 + ```json 块")原样在 text 事件里,之后仍由 extract_json 进一步解析。
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
    session_id = ""

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
        if not session_id:
            session_id = str(ev.get("sessionID") or ev.get("session_id") or "")
        part = _event_part(ev)
        msg = _event_message(ev)
        if msg:
            mid = str(msg.get("id") or msg.get("messageID") or "")
            role = str(msg.get("role") or "")
            if mid:
                note_message(mid)
                if role:
                    message_roles[mid] = role
            if not session_id:
                session_id = str(msg.get("sessionID") or msg.get("session_id") or "")
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
        if not session_id:
            session_id = str(part.get("sessionID") or part.get("session_id") or "")
        note_part(pid, mid)
        if role and mid:
            message_roles[mid] = role

        # step_finish 带本步 tokens;最后一个(终止步)即整轮用量 → 让后写的覆盖先写的
        if etype == "step_finish" or ptype == "step-finish":
            u = _extract_usage(part) or _extract_usage(part.get("tokens") or {})
            if u:
                usage = u
        # 收集 assistant 正文 text 片段;reasoning/tool/step 等事件忽略。
        # opencode 版本间可能给累计 part.text,也可能给 delta;两种都兼容。
        if ptype == "text" or etype in ("text", "message.part.updated", "message.part.delta"):
            if isinstance(part.get("text"), str):
                part_text[pid] = part["text"]      # 同一 part 多次出现(流式累积)取最新
            delta = _text_delta(ev, part)
            if delta:
                part_text[pid] = part_text.get(pid, "") + delta
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
    # opencode 的 text 事件通常是 assistant 正文;若有明确 role=user 的 message,排除它。
    chosen = [(mid, text) for mid, text in groups if message_roles.get(mid, "assistant") != "user"]
    if not chosen:
        chosen = groups
    text = "\n".join(text for _mid, text in chosen)
    return text, usage, session_id


async def _read_stream_all_live(
    stream: Optional[asyncio.StreamReader],
    name: str,
    on_chunk: Optional[Callable[[str, str], None]],
) -> bytes:
    """持续读取 pipe 到 EOF,并把解码后的 chunk 旁路发给实时 UI。"""
    if stream is None:
        return b""
    chunks: List[bytes] = []
    decoder = None
    if on_chunk:
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        chunks.append(chunk)
        if decoder is not None and on_chunk is not None:
            text = decoder.decode(chunk, final=False)
            if text:
                try:
                    on_chunk(name, text)
                except Exception:
                    pass
    if decoder is not None and on_chunk is not None:
        text = decoder.decode(b"", final=True)
        if text:
            try:
                on_chunk(name, text)
            except Exception:
                pass
    return b"".join(chunks)


async def _drain_process(
    proc: asyncio.subprocess.Process,
    stdin_data: Optional[bytes],
    timeout_s: float,
    on_chunk: Optional[Callable[[str, str], None]] = None,
) -> Tuple[bytes, bytes]:
    """并发 drain stdout/stderr,等待进程退出且两个 pipe 都 EOF 后返回完整输出。"""
    out_task = asyncio.create_task(_read_stream_all_live(proc.stdout, "stdout", on_chunk))
    err_task = asyncio.create_task(_read_stream_all_live(proc.stderr, "stderr", on_chunk))

    async def run() -> Tuple[bytes, bytes]:
        if proc.stdin is not None:
            try:
                if stdin_data:
                    proc.stdin.write(stdin_data)
                    await proc.stdin.drain()
                proc.stdin.close()
                try:
                    await proc.stdin.wait_closed()
                except AttributeError:
                    pass
            except (BrokenPipeError, ConnectionResetError):
                pass
        out_b, err_b = await asyncio.gather(out_task, err_task)
        if proc.returncode is None:
            await proc.wait()
        return out_b, err_b

    try:
        return await asyncio.wait_for(run(), timeout=timeout_s)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=3)
        except Exception:
            pass
        for task in (out_task, err_task):
            if not task.done():
                task.cancel()
        raise


class _ProbeOutputTiming:
    """Track when the backend first exposes assistant output on stdout."""

    def __init__(self, backend: str, started: float):
        self.backend = backend
        self.started = started
        self.first_token_at: Optional[float] = None
        self._opencode_buf = ""
        self._opencode_seen_json = False

    def observe(self, stream: str, chunk: str) -> None:
        if self.first_token_at is not None or stream != "stdout":
            return
        text = strip_ansi(chunk or "")
        if not text.strip():
            return
        now = time.monotonic()
        if self.backend == "opencode":
            if self._observe_opencode(text, now):
                return
            if self._opencode_seen_json or self._opencode_buf.lstrip().startswith("{"):
                return
        self.first_token_at = now

    def _observe_opencode(self, text: str, now: float) -> bool:
        self._opencode_buf += text
        lines = self._opencode_buf.splitlines(keepends=True)
        if lines and not (lines[-1].endswith("\n") or lines[-1].endswith("\r")):
            self._opencode_buf = lines.pop()
        else:
            self._opencode_buf = ""
        if len(self._opencode_buf) > 8192:
            self._opencode_buf = self._opencode_buf[-8192:]
        pending = self._opencode_buf.strip()
        if pending.startswith("{"):
            try:
                json.loads(pending)
                lines.append(self._opencode_buf)
                self._opencode_buf = ""
            except Exception:
                pass
        for raw in lines:
            ln = raw.strip()
            if not ln.startswith("{"):
                continue
            try:
                ev = json.loads(ln)
            except Exception:
                continue
            if not isinstance(ev, dict):
                continue
            self._opencode_seen_json = True
            etype = str(ev.get("type") or "")
            part = _event_part(ev)
            if not part:
                continue
            if part.get("type") != "text" and etype not in ("text", "message.part.updated", "message.part.delta"):
                continue
            if str(part.get("text") or "").strip() or _text_delta(ev, part).strip():
                self.first_token_at = now
                return True
        return False

    def first_latency_ms(self, finished: float, has_answer: bool) -> int:
        first_at = self.first_token_at
        if first_at is None and has_answer:
            first_at = finished
        if first_at is None:
            return 0
        return max(0, int((first_at - self.started) * 1000))

    def output_tokens_per_s(self, output_tokens: int, finished: float) -> float:
        if output_tokens <= 0:
            return 0.0
        total_s = max(0.001, finished - self.started)
        if self.first_token_at is not None:
            decode_s = finished - self.first_token_at
            if decode_s >= 0.05:
                return round(max(1, output_tokens - 1) / decode_s, 2)
        return round(output_tokens / total_s, 2)


class _OpencodeServeClient:
    """One long-lived `opencode serve` process for an AgentRunner.

    Agent calls normally create a fresh opencode session and submit one prompt to
    it.  Some follow-up tasks can continue a previous session; before doing so we
    can ask opencode to summarize/compact that session to keep context bounded.
    The final session messages are converted back into opencode-like JSONL events,
    so the existing parser and Web output viewer keep working.
    """

    def __init__(self, runner: "AgentRunner"):
        self.runner = runner
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.host = "127.0.0.1"
        self.port = 0
        self.base_url = ""
        self._lock: Optional[asyncio.Lock] = None
        self._log_tasks: List[asyncio.Task] = []
        self._logs: List[str] = []

    def _ensure_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    @staticmethod
    def _pick_port(host: str) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, 0))
            return int(s.getsockname()[1])

    def _serve_command(self) -> List[str]:
        port_s = str(self.port)
        cmd = [
            tok.replace("{hostname}", self.host).replace("{host}", self.host).replace("{port}", port_s)
            for tok in (self.runner.spec.command or ["opencode", "serve"])
        ]
        if not cmd:
            cmd = ["opencode", "serve"]
        has_port = any(tok == "--port" or tok.startswith("--port=") for tok in cmd)
        has_host = any(tok == "--hostname" or tok.startswith("--hostname=") for tok in cmd)
        if not has_host:
            cmd.extend(["--hostname", self.host])
        if not has_port:
            cmd.extend(["--port", port_s])
        return cmd

    async def _drain_server_log(self, stream: Optional[asyncio.StreamReader], name: str) -> None:
        if stream is None:
            return
        while True:
            chunk = await stream.readline()
            if not chunk:
                return
            text = chunk.decode("utf-8", "replace").rstrip()
            if not text:
                continue
            self._logs.append(f"{name}: {strip_ansi(text)}")
            if len(self._logs) > 80:
                del self._logs[:-80]

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        query: Optional[Dict[str, Any]] = None,
        body: Any = None,
        timeout: float = 30.0,
    ) -> Any:
        if not self.base_url:
            raise RuntimeError("opencode serve 尚未启动")
        url = self.base_url + path
        if query:
            qs = urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
            if qs:
                url += "?" + qs
        data = None
        headers: Dict[str, str] = {}
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                if not raw:
                    return None
                text = raw.decode("utf-8", "replace")
                ctype = resp.headers.get("Content-Type", "")
                if "json" in ctype:
                    return json.loads(text) if text.strip() else None
                return text
        except urllib.error.HTTPError as e:
            raw = e.read() or b""
            detail = raw.decode("utf-8", "replace").strip()
            raise RuntimeError(f"opencode serve HTTP {e.code}: {detail or e.reason}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"opencode serve 连接失败: {e.reason}") from e

    async def _request_json_async(self, *args: Any, **kwargs: Any) -> Any:
        loop = asyncio.get_event_loop()
        fn = functools.partial(self._request_json, *args, **kwargs)
        return await loop.run_in_executor(None, fn)

    async def ensure_started(self, cwd: str) -> None:
        async with self._ensure_lock():
            if self.proc is not None and self.proc.returncode is None:
                return
            self.host = "127.0.0.1"
            self.port = self._pick_port(self.host)
            self.base_url = f"http://{self.host}:{self.port}"
            cmd = self._serve_command()
            env = dict(os.environ)
            env.update(self.runner.spec.env or {})
            # This server is private to the runner and bound to localhost; keeping it
            # unauthenticated avoids needing a secondary token plumbing path.
            env.pop("OPENCODE_SERVER_PASSWORD", None)
            self.proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
                limit=1024 * 1024,
            )
            self._log_tasks = [
                asyncio.create_task(self._drain_server_log(self.proc.stdout, "stdout")),
                asyncio.create_task(self._drain_server_log(self.proc.stderr, "stderr")),
            ]
            try:
                await self._wait_ready()
            except Exception:
                await self.close()
                raise
            self.runner.log(f"opencode serve 已启动: {self.base_url}")

    async def _wait_ready(self) -> None:
        deadline = time.monotonic() + 45.0
        last_err = ""
        while time.monotonic() < deadline:
            proc = self.proc
            if proc is not None and proc.returncode is not None:
                logs = "\n".join(self._logs[-20:])
                raise RuntimeError(f"opencode serve 启动失败(exit={proc.returncode}): {logs}")
            try:
                await self._request_json_async("GET", "/global/health", timeout=2.0)
                return
            except Exception as e:  # noqa: BLE001
                last_err = str(e)
            await asyncio.sleep(0.2)
        logs = "\n".join(self._logs[-20:])
        raise RuntimeError(f"opencode serve 启动超时: {last_err}; logs={logs}")

    @staticmethod
    def _model_ref(model: str) -> Dict[str, str]:
        provider, sep, model_id = (model or "").partition("/")
        if not sep or not provider or not model_id:
            raise RuntimeError(f"opencode serve 模式要求模型名为 provider/model,实际为: {model!r}")
        return {"providerID": provider, "modelID": model_id}

    def _agent_name(self) -> str:
        return str((self.runner.spec.env or {}).get("OPENCODE_AGENT") or os.environ.get("OPENCODE_AGENT") or "build")

    async def _create_session(self, cwd: str, label: str) -> str:
        title = (label or "pvh agent")[:120]
        obj = await self._request_json_async(
            "POST",
            "/session",
            query={"directory": cwd},
            body={"title": title},
        )
        if not isinstance(obj, dict) or not obj.get("id"):
            raise RuntimeError(f"opencode serve 创建 session 失败: {obj!r}")
        return str(obj["id"])

    async def _send_prompt(self, session_id: str, cwd: str, prompt: str, model: str) -> str:
        message_id = "msg_pvh_" + uuid.uuid4().hex
        part_id = "prt_pvh_" + uuid.uuid4().hex
        body = {
            "messageID": message_id,
            "model": self._model_ref(model),
            "agent": self._agent_name(),
            "parts": [{"id": part_id, "type": "text", "text": prompt}],
        }
        await self._request_json_async(
            "POST",
            f"/session/{urllib.parse.quote(session_id, safe='')}/prompt_async",
            query={"directory": cwd},
            body=body,
        )
        return message_id

    async def _summarize_session(self, session_id: str, cwd: str, model: str) -> bool:
        model_ref = self._model_ref(model)
        try:
            obj = await self._request_json_async(
                "POST",
                f"/session/{urllib.parse.quote(session_id, safe='')}/summarize",
                query={"directory": cwd},
                body={**model_ref, "auto": True},
                timeout=120.0,
            )
            await self._wait_idle(session_id, cwd, 120.0)
            return bool(obj) or obj is None
        except Exception as first:
            try:
                await self._request_json_async(
                    "POST",
                    f"/api/session/{urllib.parse.quote(session_id, safe='')}/compact",
                    query={"directory": cwd},
                    timeout=120.0,
                )
                await self._wait_idle(session_id, cwd, 120.0)
                return True
            except Exception:
                self.runner.log(f"⚠ opencode session 压缩失败,继续直接追加问话: {str(first)[:140]}")
                return False

    async def _abort(self, session_id: str, cwd: str) -> None:
        try:
            await self._request_json_async(
                "POST",
                f"/session/{urllib.parse.quote(session_id, safe='')}/abort",
                query={"directory": cwd},
                timeout=5.0,
            )
        except Exception:
            pass

    async def _session_status(self, cwd: str) -> Dict[str, Any]:
        obj = await self._request_json_async("GET", "/session/status", query={"directory": cwd}, timeout=5.0)
        return obj if isinstance(obj, dict) else {}

    async def _wait_idle(self, session_id: str, cwd: str, timeout_s: float) -> None:
        deadline = time.monotonic() + max(1.0, timeout_s)
        grace_until = time.monotonic() + 1.0
        seen_active = False
        while True:
            if time.monotonic() >= deadline:
                await self._abort(session_id, cwd)
                raise RuntimeError(f"timed out after {int(timeout_s)}s")
            status = await self._session_status(cwd)
            rec = status.get(session_id) if isinstance(status, dict) else None
            typ = str(rec.get("type") or "") if isinstance(rec, dict) else ""
            if rec and typ not in ("", "idle"):
                seen_active = True
            if (not rec or typ in ("", "idle")) and (seen_active or time.monotonic() >= grace_until):
                return
            await asyncio.sleep(0.5)

    async def _messages(self, session_id: str, cwd: str) -> List[Dict[str, Any]]:
        obj = await self._request_json_async(
            "GET",
            f"/session/{urllib.parse.quote(session_id, safe='')}/message",
            query={"directory": cwd},
        )
        return obj if isinstance(obj, list) else []

    async def _session(self, session_id: str, cwd: str) -> Dict[str, Any]:
        obj = await self._request_json_async(
            "GET",
            f"/session/{urllib.parse.quote(session_id, safe='')}",
            query={"directory": cwd},
        )
        return obj if isinstance(obj, dict) else {}

    @staticmethod
    def _messages_jsonl(session_id: str, messages: List[Dict[str, Any]], session: Dict[str, Any]) -> str:
        events: List[Dict[str, Any]] = []
        if session:
            events.append({"type": "session.updated", "sessionID": session_id, **session})
        for item in messages:
            if not isinstance(item, dict):
                continue
            info = item.get("info") if isinstance(item.get("info"), dict) else item.get("message")
            if isinstance(info, dict):
                events.append({"type": "message.updated", "sessionID": session_id, "message": info})
            parts = item.get("parts") if isinstance(item.get("parts"), list) else []
            for part in parts:
                if isinstance(part, dict):
                    events.append({"type": "message.part.updated", "sessionID": session_id, "part": part})
        return "\n".join(json.dumps(ev, ensure_ascii=False) for ev in events if ev) + ("\n" if events else "")

    async def invoke(
        self,
        prompt: str,
        model: str,
        cwd: str,
        timeout_s: float,
        on_output: Optional[Callable[[str, str], None]] = None,
        label: str = "",
        session_id: Optional[str] = None,
        compact_before_prompt: bool = False,
    ) -> Tuple[str, Optional[Dict[str, int]], Dict[str, Any]]:
        await self.ensure_started(cwd)
        created = False
        if session_id:
            session_id = str(session_id)
        else:
            session_id = await self._create_session(cwd, label)
            created = True
        try:
            compacted = False
            if compact_before_prompt and not created:
                compacted = await self._summarize_session(session_id, cwd, model)
            await self._send_prompt(session_id, cwd, prompt, model)
            await self._wait_idle(session_id, cwd, timeout_s)
            messages = await self._messages(session_id, cwd)
            session = await self._session(session_id, cwd)
        except asyncio.CancelledError:
            await self._abort(session_id, cwd)
            raise
        jsonl = self._messages_jsonl(session_id, messages, session)
        if on_output and jsonl:
            try:
                on_output("stdout", jsonl)
            except Exception:
                pass
        oc = _extract_opencode_text(jsonl)
        usage = _extract_usage(session)
        if oc is not None:
            text, oc_usage, _sid = oc
            usage = oc_usage or usage
            if text.strip():
                return strip_ansi(text), usage, {
                    "session_id": session_id,
                    "session_created": created,
                    "session_compacted": compacted,
                }
        logs = "\n".join(self._logs[-20:])
        raise BackendOutputError(
            "opencode serve session 未产生最终 assistant 文本",
            strip_ansi((jsonl or "") + ("\n# opencode serve logs\n" + logs if logs else "")),
        )

    async def close(self) -> None:
        proc = self.proc
        self.proc = None
        if proc is None:
            return
        try:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()
                    await asyncio.wait_for(proc.wait(), timeout=5)
        finally:
            for task in self._log_tasks:
                if not task.done():
                    task.cancel()
            if self._log_tasks:
                await asyncio.gather(*self._log_tasks, return_exceptions=True)
            self._log_tasks = []


class DynamicSemaphore:
    """容量可在运行中调整的 asyncio 信号量(用于动态增减并发)。

    语义与 asyncio.Semaphore 一致(acquire/release/locked),额外支持 set_limit(n):
      · 扩容:立即放行等量的等待者;
      · 缩容:**不打断**已持有的名额,只阻止新的获取,直到占用自然回落到新上限以下。
    缩容时内部可用计数 _value 可能暂时为负,后续 release 会把它逐步抬回正值。
    实现照搬 CPython asyncio.Semaphore 的等待者唤醒逻辑,并加上 `_value > 0` 的放行护栏。
    """

    def __init__(self, value: int = 1):
        value = max(0, int(value))
        self._value = value            # 当前可用名额(缩容后可能为负)
        self._limit = value            # 配置上限(用于自省 / 再次调整)
        self._waiters: "collections.deque[asyncio.Future]" = collections.deque()

    @property
    def limit(self) -> int:
        return self._limit

    def available(self) -> int:
        return max(0, self._value)

    def locked(self) -> bool:
        return self._value <= 0 or any(not w.cancelled() for w in self._waiters)

    async def acquire(self) -> bool:
        if not self.locked():
            self._value -= 1
            return True
        fut = asyncio.get_event_loop().create_future()
        self._waiters.append(fut)
        try:
            try:
                await fut
            finally:
                if fut in self._waiters:
                    self._waiters.remove(fut)
        except asyncio.CancelledError:
            if not fut.cancelled():
                # 已被唤醒(拿到名额)但随即被取消 → 归还并转交下一个等待者
                self._value += 1
                self._wake_next()
            raise
        if self._value > 0:
            self._wake_next()
        return True

    def release(self) -> None:
        self._value += 1
        self._wake_next()

    def _wake_next(self) -> None:
        if self._value <= 0:
            return
        for fut in self._waiters:
            if not fut.done():
                self._value -= 1
                fut.set_result(True)
                return

    def set_limit(self, value: int) -> None:
        """调整容量上限;按差值同步可用名额,扩容则立即唤醒等量等待者。"""
        value = max(0, int(value))
        delta = value - self._limit
        if not delta:
            return
        self._limit = value
        self._value += delta
        for _ in range(max(0, delta)):
            self._wake_next()

    async def __aenter__(self) -> "DynamicSemaphore":
        await self.acquire()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        self.release()


class AgentRunner:
    """封装并发门 + 重试 + 子进程调用。一个实例对应一次运行。"""

    def __init__(self, cfg: Config, logger=print,
                 usage_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
                 health_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
                 agent_sink: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.cfg = cfg
        self._sem: Optional[DynamicSemaphore] = None  # 惰性创建(避免在事件循环外构造时绑错 loop,兼容 py3.8)
        self.spec = cfg.backend_spec()
        self.log = logger
        self.usage_sink = usage_sink
        self.health_sink = health_sink
        self.agent_sink = agent_sink
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
        self._model_sems: Dict[str, DynamicSemaphore] = {}
        self._capacity_wait_s = 0.05
        self._live_prompt_files: set = set()  # 正在被子进程使用的 prompt 文件,滚动清理时必须保护
        self._artifact_seq = 0  # 临时产物单调序号:写进文件名,让滚动清理按"创建序"确定性排序(mtime 同刻度也不抖)
        self._opencode_serve: Optional[_OpencodeServeClient] = None

    async def aclose(self) -> None:
        """释放 AgentRunner 持有的长驻后端资源。"""
        if self._opencode_serve is not None:
            await self._opencode_serve.close()
            self._opencode_serve = None

    def _prune_recent(self, directory: str, primary_suffix: str, keep: int,
                      sidecar_suffixes: Tuple[str, ...] = (), protect: Optional[set] = None) -> None:
        """滚动保留:只留 directory 下最近 keep 个 primary 文件,其余 primary 及其同名 sidecar 一并删除。
        protect 中的路径视为"在用",无论新旧都保留(避免删掉正被子进程读取的文件;故实际保留数 ≥ keep)。
        keep<=0 表示不清理。所有文件操作都吞异常——清理失败绝不影响主流程。

        排序键用 (mtime, 文件名),不只看 mtime:大量文件在同一 mtime 刻度内写入时,仅按 mtime 排序会
        因同着而顺序不定 → 刚写的(受 protect 的)文件可能没落到最近 keep 内,被 protect 额外算成幸存者,
        使保留数虚高、且不确定。文件名内嵌的单调序号(见 _write_prompt_file)保证同刻度也按创建序排。"""
        if keep is None or keep <= 0:
            return
        try:
            prims = [os.path.join(directory, fn) for fn in os.listdir(directory)
                     if fn.endswith(primary_suffix)]
        except OSError:
            return
        if len(prims) <= keep:
            return
        try:
            prims.sort(key=lambda p: (os.path.getmtime(p), os.path.basename(p)))  # 旧 → 新(同刻度按创建序)
        except OSError:
            return
        survivors = set(prims[-keep:]) | set(protect or ())
        for p in prims:
            if p in survivors:
                continue
            base = p[:-len(primary_suffix)]
            for sc in (primary_suffix,) + tuple(sidecar_suffixes):
                try:
                    os.remove(base + sc)
                except OSError:
                    pass

    def _emit_agent(self, rec: Dict[str, Any]) -> None:
        if not self.agent_sink:
            return
        rec.setdefault("ts", time.time())
        try:
            self.agent_sink(dict(rec))
        except Exception:
            pass

    def _semaphore(self) -> DynamicSemaphore:
        if self._sem is None:
            self._sem = DynamicSemaphore(self.cfg.concurrency)
        return self._sem

    def _model_semaphore(self, model: str) -> DynamicSemaphore:
        if model not in self._model_sems:
            self._model_sems[model] = DynamicSemaphore(self.cfg.model_concurrency_for(model))
        return self._model_sems[model]

    @staticmethod
    def _sem_capacity(sem: DynamicSemaphore) -> int:
        return sem.available()

    def reconfigure(self, *, concurrency: Optional[int] = None,
                    model_concurrency: Optional[Any] = None) -> Dict[str, Any]:
        """运行中动态调整并发门(全局并发 + 每模型并发),就地改写 cfg 并重设已存在的信号量。

        必须在该 run 的事件循环线程内调用(经 Pipeline.reconfigure / 服务端协程)。
        模型的增删由 cfg.models 决定、调度时动态读取,无需在此处理;这里只负责并发容量。
        """
        if concurrency is not None:
            self.cfg.concurrency = max(1, int(concurrency))
            if self._sem is not None:
                self._sem.set_limit(self.cfg.concurrency)
        if model_concurrency is not None:
            self.cfg.model_concurrency = normalize_model_concurrency(model_concurrency)
        # 不论是全局并发变了(影响未单独配置的模型的默认值)还是 per-model 配置变了,
        # 都把已存在的每模型信号量按最新有效上限重设一遍。
        for model, sem in self._model_sems.items():
            sem.set_limit(self.cfg.model_concurrency_for(model))
        return {"concurrency": self.cfg.concurrency,
                "model_concurrency": dict(self.cfg.model_concurrency)}

    async def reserve_slots(self, n: int) -> int:
        """从**全局并发池**预占 n 个名额并一直持有(兼容旧的专用通道实现):
        被持有的名额计入总并发;该通道结束后用 release_slots 归还。
        取消安全:获取途中被取消会先归还已拿到的,再抛出。返回实际占到的名额数。"""
        if n <= 0:
            return 0
        sem = self._semaphore()
        got = 0
        try:
            for _ in range(n):
                await sem.acquire()
                got += 1
            return got
        except asyncio.CancelledError:
            for _ in range(got):
                sem.release()
            raise

    def release_slots(self, n: int) -> None:
        """归还此前 reserve_slots 预占的 n 个全局并发名额。"""
        if n <= 0:
            return
        sem = self._semaphore()
        for _ in range(n):
            sem.release()

    # ── 同一 role 下按模型并发加权轮换 ──
    def _next_model(self, role: str) -> str:
        models = self.cfg.model_slots_for(role)
        if not models:
            return ""
        i = self._model_cursor.get(role, 0)
        self._model_cursor[role] = i + 1
        return models[i % len(models)]

    def _ready_model(self, role: str, *, advance: bool, avoid_model: Optional[str] = None) -> str:
        """按加权轮换顺序选择一个当前有空闲 per-model 名额的模型。

        这里使用 semaphore 的即时容量做调度提示;真正执行前仍会 acquire,因此即使容量在
        同一事件循环 tick 内变化也不会越过并发上限。
        avoid_model 用于同一 agent 失败后的重试:若其它模型有即时容量,优先换模型;否则回退
        到该模型,避免单模型配置或其它模型满载时无法推进。
        """
        models = self.cfg.model_slots_for(role)
        if not models:
            return ""
        start = self._model_cursor.get(role, 0)
        fallback = ""
        fallback_idx = 0
        for off in range(len(models)):
            idx = (start + off) % len(models)
            model = models[idx]
            if self._sem_capacity(self._model_semaphore(model)) > 0:
                if avoid_model and model == avoid_model:
                    if not fallback:
                        fallback = model
                        fallback_idx = idx
                    continue
                if advance:
                    self._model_cursor[role] = idx + 1
                return model
        if fallback:
            if advance:
                self._model_cursor[role] = fallback_idx + 1
            return fallback
        return ""

    def _ready_specific_model(self, model: str) -> str:
        """返回指定模型是否当前可派发。

        用于需要固定模型身份的顺序对抗验证:仍尊重模型时间窗和 per-model 并发,
        但不参与 role 轮询。
        """
        if not model or not self.cfg.model_available_at(model):
            return ""
        if self._sem_capacity(self._model_semaphore(model)) <= 0:
            return ""
        return model

    def role_has_capacity(self, role: str, *, use_global_gate: bool = True) -> bool:
        """供上层优先级调度器做非阻塞容量判断。

        返回 False 只表示"此刻没有可立即启动的容量";调用方可以先调度队列中更靠后的
        其它 role,避免某个模型满载时把全局 worker 卡住。
        """
        if use_global_gate and self._sem_capacity(self._semaphore()) <= 0:
            return False
        return bool(self._ready_model(role, advance=False))

    def role_capacity_limit(self, role: str) -> int:
        """该 role 理论上可同时启动的模型槽数,用于上层避免同一调度 tick 过量派发。"""
        configured = self.cfg.configured_model_slots_for(role)
        if not configured:
            return self.cfg.concurrency
        slots = self.cfg.model_slots_for(role)
        if not slots:
            return 0
        return max(1, min(self.cfg.concurrency, len(slots)))

    async def _wait_capacity_tick(self, should_stop: Optional[Callable[[], bool]]) -> bool:
        if should_stop is not None and should_stop():
            return False
        await asyncio.sleep(self._capacity_wait_s)
        return should_stop is None or not should_stop()

    async def _acquire_run_capacity(
        self,
        role: str,
        *,
        use_global_gate: bool,
        should_stop: Optional[Callable[[], bool]],
        avoid_model: Optional[str] = None,
        model_override: Optional[str] = None,
    ) -> tuple[str, bool]:
        """同时取得全局名额和一个可用模型名额。

        关键点是不会在持有全局名额时等待某个已满的模型:如果当前 role 没有任何模型空位,
        会立即释放刚拿到的全局名额,让其它可运行任务继续推进。
        """
        while True:
            if should_stop is not None and should_stop():
                return "", False
            acquired_global = False
            global_sem = self._semaphore()
            if use_global_gate:
                if self._sem_capacity(global_sem) <= 0:
                    if not await self._wait_capacity_tick(should_stop):
                        return "", False
                    continue
                await global_sem.acquire()
                acquired_global = True

            if model_override:
                model = self._ready_specific_model(model_override)
            else:
                model = self._ready_model(role, advance=True, avoid_model=avoid_model)
            if model:
                await self._model_semaphore(model).acquire()
                return model, acquired_global

            if acquired_global:
                global_sem.release()
            if not await self._wait_capacity_tick(should_stop):
                return "", False

    def _release_run_capacity(self, model: str, acquired_global: bool) -> None:
        if model:
            self._model_semaphore(model).release()
        if acquired_global:
            self._semaphore().release()

    def _write_prompt_file(self, prompt: str) -> str:
        prompt_dir = os.path.join(self.cfg.out_dir, "prompts")
        os.makedirs(prompt_dir, exist_ok=True)
        # 零填充单调序号做前缀:文件名按字典序即创建序,让 _prune_recent 在 mtime 同刻度时也确定性排序。
        self._artifact_seq += 1
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".md",
            prefix=f"agent_{self._artifact_seq:09d}_",
            dir=prompt_dir,
            delete=False,
        ) as f:
            f.write(prompt)
            path = f.name
        # 标记为"在用",并滚动清理旧文件——保护在用文件,避免删掉正被并发子进程读取的 prompt。
        self._live_prompt_files.add(path)
        self._prune_recent(prompt_dir, ".md", self.cfg.artifact_retain,
                           protect=self._live_prompt_files)
        return path

    def _record_usage(self, prompt: str, output: str, *, role: str, label: str,
                      model: str, attempt: int, backend_usage: Optional[Dict[str, int]]) -> None:
        est_in = estimate_tokens(prompt)
        est_out = estimate_tokens(output)
        usage = backend_usage or {}
        input_tokens = _token_int(usage.get("input_tokens"))
        output_tokens = _token_int(usage.get("output_tokens"))
        total_tokens = _token_int(usage.get("total_tokens"))
        input_tokens = est_in if input_tokens is None else input_tokens
        output_tokens = est_out if output_tokens is None else output_tokens
        total_tokens = input_tokens + output_tokens if total_tokens is None else total_tokens
        if total_tokens < input_tokens + output_tokens:
            total_tokens = input_tokens + output_tokens
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

    # ── opencode 运行产物回收:共享热目录 + 滚动清理膨胀的 snapshot/repos ──
    def _opencode_data_root(self) -> str:
        """opencode 数据目录($XDG_DATA_HOME/opencode,默认 ~/.local/share/opencode)。
        用于定位待回收的 snapshot/repos 等运行产物。"""
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
        return os.path.join(base, "opencode")

    @staticmethod
    def _repo_recency(path: str) -> float:
        """裸 git 快照仓的"最近活跃时刻":取仓目录与其 index/HEAD/packed-refs 的最大 mtime。
        commit 会改写 index/refs,故比仅看目录 mtime 更准——避免误删仍在频繁写入的活跃 target 基线仓。"""
        best = 0.0
        for name in ("", "index", "HEAD", "packed-refs"):
            p = os.path.join(path, name) if name else path
            try:
                m = os.path.getmtime(p)
            except OSError:
                continue
            if m > best:
                best = m
        return best

    def _opencode_repo_leaves(self, parent: str) -> List[str]:
        """parent 下的裸 git 快照仓(含 HEAD 文件的目录),兼容 snapshot/<proj>/<worktree> 两级
        与 repos/<...> 一级两种布局。父目录不存在则返回空列表。"""
        leaves: List[str] = []
        try:
            firsts = os.listdir(parent)
        except OSError:
            return leaves
        for a in firsts:
            ap = os.path.join(parent, a)
            if not os.path.isdir(ap):
                continue
            if os.path.exists(os.path.join(ap, "HEAD")):
                leaves.append(ap)
                continue
            try:
                seconds = os.listdir(ap)
            except OSError:
                continue
            for b in seconds:
                bp = os.path.join(ap, b)
                if os.path.isdir(bp) and os.path.exists(os.path.join(bp, "HEAD")):
                    leaves.append(bp)
        return leaves

    @staticmethod
    def _prune_empty_dirs(parent: str) -> None:
        """回收叶子仓后,删掉 parent 下变空的中间目录(空 projectID 壳)。"""
        try:
            entries = os.listdir(parent)
        except OSError:
            return
        for a in entries:
            p = os.path.join(parent, a)
            try:
                if os.path.isdir(p) and not os.listdir(p):
                    os.rmdir(p)
            except OSError:
                pass

    def _reap_opencode_artifacts(self) -> None:
        """每次 opencode 调用收尾时回收共享数据目录里膨胀的运行产物。

        opencode 把快照(snapshot/ 裸 git 仓,每步提交整棵工作树)、storage、sqlite 库都写在
        $XDG_DATA_HOME/opencode 下;PoC 每次在独立临时 worktree 里跑,opencode 会按 cwd 新建一份
        snapshot 仓,worktree 删掉后这些 snapshot 仍以孤儿形式永久残留 → 磁盘无上限膨胀。

        这里**不**每次重建数据目录(那会让每次调用都付一次冷启动:DB 迁移 + 对整棵 target 全量
        重建快照 → 探针动辄超时),而是沿用共享热目录,只把膨胀的 snapshot/repos 裸仓按"最近活跃
        时刻"滚动保留最近 keep 个:活跃 target 的快照基线一直在写、必然最新 → 必留;PoC 临时
        worktree 残留的孤儿快照按旧→新淘汰。另顺带滚动清理旧 session_diff。

        所有文件操作吞异常,绝不拖垮主流程。仅 backend=opencode 且 ephemeral_backend_data 开启时生效。"""
        if self.cfg.backend != "opencode" or not getattr(self.cfg, "ephemeral_backend_data", True):
            return
        try:
            root = self._opencode_data_root()
            # keep 远大于同时在跑的 opencode 进程数(全局并发的若干倍),确保永不误删在用的快照仓
            keep = max(32, self.cfg.concurrency * 8)
            for sub in ("snapshot", "repos"):
                parent = os.path.join(root, sub)
                leaves = self._opencode_repo_leaves(parent)
                if len(leaves) <= keep:
                    continue
                leaves.sort(key=self._repo_recency)        # 旧 → 新
                for p in leaves[:-keep]:                    # 删最旧的孤儿,保留最近 keep 个
                    shutil.rmtree(p, ignore_errors=True)
                self._prune_empty_dirs(parent)
            self._prune_recent(os.path.join(root, "storage", "session_diff"), ".json",
                               max(self.cfg.artifact_retain, keep))
        except Exception:  # noqa: BLE001 —— 回收失败绝不影响主流程
            pass

    # ── 单次后端调用(不含重试) ──
    async def _invoke(self, prompt: str, model: str, cwd: str,
                      timeout_s: Optional[float] = None,
                      on_output: Optional[Callable[[str, str], None]] = None,
                      label: str = "",
                      invocation_meta: Optional[Dict[str, Any]] = None,
                      session_id: Optional[str] = None,
                      compact_before_prompt: bool = False) -> Tuple[str, Optional[Dict[str, int]]]:
        if self.cfg.backend == "opencode" and self.spec.prompt_mode == "serve":
            if timeout_s is None:
                timeout_s = max(1, self.cfg.retry.timeout_ms / 1000.0)
            if self._opencode_serve is None:
                self._opencode_serve = _OpencodeServeClient(self)
            try:
                text, usage, oc_meta = await self._opencode_serve.invoke(
                    prompt,
                    model,
                    cwd,
                    timeout_s,
                    on_output=on_output,
                    label=label or model,
                    session_id=session_id,
                    compact_before_prompt=compact_before_prompt,
                )
                if invocation_meta is not None:
                    invocation_meta.update(oc_meta or {})
                return text, usage
            finally:
                self._reap_opencode_artifacts()
        if self.cfg.backend == "opencode":
            raise RuntimeError("opencode 后端仅支持 prompt_mode=serve")

        prompt_file = ""
        uses_prompt_file = self.spec.prompt_mode == "file" or any(
            "{prompt_file}" in tok for tok in self.spec.command
        )
        if uses_prompt_file:
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

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
                limit=16 * 1024 * 1024,
            )
            if timeout_s is None:
                timeout_s = max(1, self.cfg.retry.timeout_ms / 1000.0)
            try:
                out_b, err_b = await _drain_process(proc, stdin_data, timeout_s, on_output)
            except asyncio.TimeoutError:
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
            usage = None
            try:
                usage = _extract_usage(json.loads(stdout))
            except Exception:
                usage = None
            return strip_ansi(stdout), usage
        finally:
            # 子进程已结束:本次 prompt 文件不再"在用",解除保护(留待滚动窗口自然淘汰)
            if prompt_file:
                self._live_prompt_files.discard(prompt_file)

    def _dump_failed_output(self, role: str, label: str, model: str, attempt: int, text: str,
                            dump_candidate: bool = False) -> str:
        """解析结构化 JSON 失败时,把后端原始输出落盘,便于排查(尤其 opencode/codex)。

        dump_candidate=True 时,在同前缀再写一个 `.jsonload.json` 文件,内容是 extract_json 真正会喂给
        json.loads 的那段候选串(由 best_json_candidate 抽取),可直接丢 json.loads/jsonlint 复现报错。"""
        try:
            dbg_dir = os.path.join(self.cfg.out_dir, "debug")
            os.makedirs(dbg_dir, exist_ok=True)
            safe = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{role}_{label}_{model}")[:80]
            base = os.path.join(dbg_dir, f"parsefail_{self.agent_count}_{attempt}_{safe}")
            path = base + ".txt"
            header = (f"# backend={self.cfg.backend} role={role} label={label} model={model} "
                      f"attempt={attempt} len={len(text or '')}\n"
                      f"# 后端输出里找不到可解析的 JSON。常见原因:opencode/codex 把工具活动/思考一并打到 stdout,"
                      f"或最终未输出 ```json 代码块。\n{'-' * 60}\n")
            with open(path, "w", encoding="utf-8") as f:
                f.write(header + (text or ""))
            if dump_candidate:
                try:
                    with open(base + ".jsonload.json", "w", encoding="utf-8") as f:
                        f.write(best_json_candidate(text))
                except Exception:
                    pass
            # 滚动清理:只保留最近 N 组转储(.txt 为锚,连同其 .jsonload.json 一起删)
            self._prune_recent(dbg_dir, ".txt", self.cfg.artifact_retain,
                               sidecar_suffixes=(".jsonload.json",))
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
                "last_first_token_latency_ms": 0, "last_output_tokens": 0,
                "last_output_tokens_per_s": 0.0,
                "checks": 0, "ok_checks": 0, "answer": "", "error": "",
                "calls": 0, "call_fails": 0, "last_call_error": "",
                "last_call_fail_ts": 0.0, "last_call_ok_ts": 0.0,
                "reason": "", "ts": time.time(),
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
        """对单个模型发一个短探针任务,据响应判定 ok/degraded/down 并记录输出性能。
        探针不计入 token 用量统计,且用独立的较短超时,避免拖慢启动。"""
        if not model:
            return None
        hc = self.cfg.health
        rec = self._health_rec(model)
        if not self.cfg.model_available_at(model):
            rec["status"] = "unavailable"
            rec["reason"] = reason
            rec["last_check_ts"] = time.time()
            rec["error"] = "当前不在模型可用时间段"
            self._emit_health(rec)
            return rec
        rec["status"] = "checking"
        rec["reason"] = reason
        self._emit_health(rec)
        cwd = os.path.abspath(os.path.expanduser(self.cfg.target))
        timeout_s = max(1, (hc.timeout_ms or self.cfg.retry.timeout_ms) / 1000.0)
        t0 = time.monotonic()
        timing = _ProbeOutputTiming(self.cfg.backend, t0)
        async with self._model_semaphore(model):
            async with self._semaphore():
                try:
                    text, _usage = await self._invoke(
                        hc.prompt,
                        model,
                        cwd,
                        timeout_s=timeout_s,
                        on_output=timing.observe,
                        label="health",
                    )
                    finished = time.monotonic()
                    latency = int((finished - t0) * 1000)
                    answer = (text or "").strip()
                    output_tokens = _token_int((_usage or {}).get("output_tokens")) or estimate_tokens(answer)
                    healthy = (hc.expect in answer) if hc.expect else bool(answer)
                    rec["checks"] += 1
                    rec["last_check_ts"] = time.time()
                    rec["last_latency_ms"] = latency
                    rec["last_first_token_latency_ms"] = timing.first_latency_ms(finished, bool(answer))
                    rec["last_output_tokens"] = output_tokens
                    rec["last_output_tokens_per_s"] = timing.output_tokens_per_s(output_tokens, finished)
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
                    finished = time.monotonic()
                    rec["checks"] += 1
                    rec["last_check_ts"] = time.time()
                    rec["last_latency_ms"] = int((finished - t0) * 1000)
                    rec["last_first_token_latency_ms"] = timing.first_latency_ms(finished, False)
                    rec["last_output_tokens"] = 0
                    rec["last_output_tokens_per_s"] = 0.0
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
        if not self.cfg.model_available_at(model):
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
        """用真实 agent 调用的成败顺带更新模型健康。

        健康探针的 answer/error 与真实任务的 last_call_error 分开存,避免 Web 把
        "后端未产出结构化 JSON"这类任务失败误显示成"最近探针答复"。
        """
        rec = self._health_rec(model)
        changed = False
        now = time.time()
        if ok:
            rec["calls"] += 1
            rec["last_ok_ts"] = now
            rec["last_call_ok_ts"] = now
            changed = True
            if rec.get("last_call_error"):
                rec["last_call_error"] = ""
            if rec["status"] in ("unknown", "down", "degraded", "checking"):
                rec["status"] = "ok"
                rec["last_check_ts"] = now
        else:
            rec["call_fails"] += 1
            rec["last_call_error"] = (err or "")[:300]
            rec["last_call_fail_ts"] = now
            changed = True
            if rec["status"] in ("ok", "unknown"):
                rec["status"] = "degraded"
        if changed:
            self._emit_health(rec)

    # ── 带重试的 agent 调用:一次后端任务执行失败(非零退出/超时/输出不可解析)即重试 ──
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
        use_global_gate: bool = True,
        retry_forever: bool = False,
        should_stop: Optional[Callable[[], bool]] = None,
        meta: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        compact_before_prompt: bool = False,
        model_override: Optional[str] = None,
    ) -> Any:
        """schema 非空 → 返回解析后的 dict/list;schema 为空 → 返回 agent 最终文本。
        meta(可选,传入一个 dict)在成功返回前回填 {"model", "attempt"},供上层把模型归因到结果。
        失败重试上限取 `retries`(未传则用 cfg.retry.max_attempts);耗尽后返回 fallback(跳过,靠续跑挽回)。
        retry_forever=True 时忽略重试上限,一直重试到成功或 should_stop() 变真。
        use_global_gate=False:本次调用不再去抢全局 concurrency 名额(仅受 per-model 信号量约束)。
        仅供已通过 reserve_slots 预占好全局名额的兼容通道使用,避免重复申请全局名额。
        """
        tag = label or role
        run_cwd = cwd or os.path.abspath(os.path.expanduser(self.cfg.target))
        self.agent_count += 1
        agent_id = self.agent_count
        agent_started = time.time()
        max_attempts = self.cfg.retry.max_attempts if retries is None else retries

        def emit_agent(status: str, **extra: Any) -> None:
            rec: Dict[str, Any] = {
                "id": agent_id,
                "role": role,
                "label": tag,
                "status": status,
                "backend": self.cfg.backend,
                "cwd": run_cwd,
            }
            rec.update(extra)
            self._emit_agent(rec)

        emit_agent("queued", prompt_chars=len(prompt or ""), schema=bool(schema))
        if not self.cfg.configured_model_slots_for(role):
            msg = f"角色 {role} 未配置模型"
            self.log(f"⚠ {tag} 后端任务无法启动: {msg}")
            emit_agent(
                "failed",
                attempt=0,
                duration_ms=int((time.time() - agent_started) * 1000),
                error=msg,
            )
            return fallback
        forced_model = (model_override or "").strip()
        if forced_model and forced_model not in self.cfg.models_for(role):
            msg = f"指定模型 {forced_model} 未配置在角色 {role}"
            self.log(f"⚠ {tag} 后端任务无法启动: {msg}")
            emit_agent(
                "failed",
                attempt=0,
                duration_ms=int((time.time() - agent_started) * 1000),
                error=msg,
            )
            return fallback

        async def retry_sleep(wait_ms: int) -> bool:
            if should_stop is None:
                await asyncio.sleep(wait_ms / 1000.0)
                return True
            end = time.time() + wait_ms / 1000.0
            while True:
                if should_stop():
                    return False
                remain = end - time.time()
                if remain <= 0:
                    return True
                await asyncio.sleep(min(1.0, remain))

        attempt = 0
        last_failed_model = ""
        while True:
            if should_stop is not None and should_stop():
                msg = "用户请求停止"
                self.log(f"⚠ {tag} 后端任务停止重试: {msg}")
                emit_agent(
                    "failed",
                    attempt=attempt,
                    duration_ms=int((time.time() - agent_started) * 1000),
                    error=msg,
                )
                return fallback
            if forced_model:
                health_model = self._ready_specific_model(forced_model)
            else:
                health_model = self._ready_model(role, advance=False, avoid_model=last_failed_model)
            while not health_model:
                if not await self._wait_capacity_tick(should_stop):
                    msg = "用户请求停止"
                    self.log(f"⚠ {tag} 后端任务停止等待模型容量: {msg}")
                    emit_agent(
                        "failed",
                        attempt=attempt,
                        duration_ms=int((time.time() - agent_started) * 1000),
                        error=msg,
                    )
                    return fallback
                if forced_model:
                    health_model = self._ready_specific_model(forced_model)
                else:
                    health_model = self._ready_model(role, advance=False, avoid_model=last_failed_model)
            await self.ensure_healthy(health_model)   # gate:调用前按需补一次健康探针(ttl 去重,不阻断)
            model, acquired_global = await self._acquire_run_capacity(
                role,
                use_global_gate=use_global_gate,
                should_stop=should_stop,
                avoid_model=last_failed_model,
                model_override=forced_model,
            )
            if not model:
                msg = "用户请求停止"
                self.log(f"⚠ {tag} 后端任务停止等待并发容量: {msg}")
                emit_agent(
                    "failed",
                    attempt=attempt,
                    duration_ms=int((time.time() - agent_started) * 1000),
                    error=msg,
                )
                return fallback
            attempt_no = attempt + 1
            attempt_started = time.time()
            emit_agent("running", model=model, attempt=attempt_no)

            def on_output(stream: str, chunk: str) -> None:
                emit_agent("output", model=model, attempt=attempt_no, stream=stream, chunk=chunk)

            try:
                invocation_meta: Dict[str, Any] = {}
                text, usage = await self._invoke(
                    prompt, model, run_cwd, on_output=on_output, label=tag,
                    invocation_meta=invocation_meta,
                    session_id=session_id,
                    compact_before_prompt=compact_before_prompt,
                )
                self._record_usage(prompt, text, role=role, label=tag, model=model,
                                   attempt=attempt_no, backend_usage=usage)
                self._note_call(model, True)
                if meta is not None:
                    meta["model"] = model
                    meta["attempt"] = attempt_no
                    meta.update(invocation_meta)
                if schema is None:
                    emit_agent(
                        "done",
                        model=model,
                        attempt=attempt_no,
                        duration_ms=int((time.time() - agent_started) * 1000),
                        attempt_ms=int((time.time() - attempt_started) * 1000),
                        output_chars=len(text or ""),
                    )
                    return text
                parsed = extract_json(text, schema)
                if parsed is None:
                    path = self._dump_failed_output(role, tag, model, attempt_no, text,
                                                    dump_candidate=True)
                    snippet = " ".join((text or "").split())[:240]
                    self.log(f"⚠ {tag} 后端输出无可解析 JSON(共 {len(text or '')} 字符)"
                             f"{(';原始输出已存 ' + path) if path else ''};前 240 字符:{snippet}")
                    raise RuntimeError("后端未产出可解析的结构化 JSON(原始输出已存到 run 目录 debug/)")
                parsed = _coerce_schema_value(parsed, schema)
                shape_error = _schema_shape_error(parsed, schema)
                if shape_error:
                    path = self._dump_failed_output(role, tag, model, attempt_no, text,
                                                    dump_candidate=True)
                    snippet = " ".join((text or "").split())[:240]
                    self.log(f"⚠ {tag} 后端 JSON 结构不符合 schema:{shape_error}"
                             f"{(';原始输出已存 ' + path) if path else ''};前 240 字符:{snippet}")
                    raise RuntimeError(f"后端结构化 JSON 形状不符合 schema:{shape_error}")
                emit_agent(
                    "done",
                    model=model,
                    attempt=attempt_no,
                    duration_ms=int((time.time() - agent_started) * 1000),
                    attempt_ms=int((time.time() - attempt_started) * 1000),
                    output_chars=len(text or ""),
                )
                return parsed
            except Exception as e:  # noqa: BLE001
                msg = str(e)
                if isinstance(e, BackendOutputError) and e.output:
                    path = self._dump_failed_output(role, tag, model, attempt_no, e.output)
                    if path:
                        msg = f"{msg}(完整 stdout 已存 {path})"
                self._note_call(model, False, msg)
                last_failed_model = model
                emit_agent(
                    "failed_attempt",
                    model=model,
                    attempt=attempt_no,
                    attempt_ms=int((time.time() - attempt_started) * 1000),
                    error=msg[:500],
                )
            finally:
                self._release_run_capacity(model, acquired_global)
            # 退避/重试在信号量之外等待(不占用并发额度)
            attempt += 1
            if (not retry_forever) and attempt > max_attempts:
                self.log(f"⚠ {tag} 后端任务连续失败 {attempt} 次,本组重试耗尽: {msg[:120]}")
                emit_agent(
                    "failed",
                    model=model,
                    attempt=attempt,
                    duration_ms=int((time.time() - agent_started) * 1000),
                    error=msg[:500],
                )
                return fallback
            wait_ms = self._backoff_ms(attempt, msg)
            limited = "(疑似限流,延长退避)" if looks_rate_limited(msg) else ""
            if retry_forever:
                retry_desc = f"第 {attempt} 次重试/不限次数{limited}"
            else:
                retry_desc = f"第 {attempt}/{max_attempts} 次重试{limited}"
            self.log(f"⚠ {tag} 后端任务失败({retry_desc}),{wait_ms // 1000}s 后重试: {msg[:100]}")
            emit_agent(
                "retrying",
                model=model,
                attempt=attempt,
                retry_in_ms=wait_ms,
                next_attempt=attempt + 1,
                error=msg[:500],
            )
            if not await retry_sleep(wait_ms):
                msg = "用户请求停止"
                self.log(f"⚠ {tag} 后端任务停止重试: {msg}")
                emit_agent(
                    "failed",
                    model=model,
                    attempt=attempt,
                    duration_ms=int((time.time() - agent_started) * 1000),
                    error=msg,
                )
                return fallback
