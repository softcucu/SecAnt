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
def _balanced_json_candidates(s: str) -> List[str]:
    """扫描出文本中所有"括号配对完整"的顶层 JSON 对象/数组子串。"""
    out: List[str] = []
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
                        out.append(s[i:j + 1])
                        break
            j += 1
        i = (j + 1) if j > i else (i + 1)
    return out


def extract_json(text: str) -> Optional[Any]:
    """从 agent 自由文本里尽力解析出一个 JSON 值。优先级:
    ```json 代码块(取最后一个) > 整段文本 > 括号配对扫描(取最后一个能解析的)。
    """
    if not text:
        return None
    # 1) fenced ```json ... ``` 代码块
    fences = re.findall(r"```(?:json|JSON)?\s*\n(.*?)```", text, re.DOTALL)
    for block in reversed(fences):
        try:
            return json.loads(block.strip())
        except Exception:
            continue
    # 2) 整段就是 JSON
    t = text.strip()
    try:
        return json.loads(t)
    except Exception:
        pass
    # 3) 括号配对扫描,取最后一个能解析的(通常是最终答案)
    cands = _balanced_json_candidates(text)
    for c in reversed(cands):
        try:
            return json.loads(c)
        except Exception:
            continue
    return None


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
        usage = None
        try:
            usage = _extract_usage(json.loads(stdout))
        except Exception:
            usage = None
        return stdout, usage

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
                        parsed = extract_json(text)
                        if parsed is None:
                            raise RuntimeError("CLI 未产出可解析的结构化 JSON")
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
