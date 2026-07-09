"""编排器:攻击树威胁分析 → 统一优先级调度(history / audit / recheck / 验证流水线) →
流式产出确认漏洞 →(高危)PoC → 汇总。断点续跑 + 并发门 + 后端任务失败重试。

结构化为主:运行期**只写结构化态**(经 RunStore 按关注点分文件落盘:checkpoint.json /
history.json / threat-analysis/graph.json /
attack-surface.json / findings/<id>.json / usage.jsonl)并发结构化事件(经 EventBus → SSE + events.jsonl);
不再在运行期写 THREAT-ANALYSIS/ATTACK-SURFACE/findings/INDEX/SARIF 这些 Markdown——它们改由 exporters.py
从结构化态**按需渲染**(Web 导出端点 / CLI `--export`)。漏洞确认即各写一个文件(流式落盘)。
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional

from . import events as EV
from . import schemas as S
from . import threat_analysis as TA
from .backends import AgentRunner
from .common import (QUALITY_FINDING_STATUS, QUALITY_FINDING_TAG, class_code,
                     finalize_findings, finding_key, is_quality_issue_finding,
                     item_key, most_severe, pad3, slim_finding)
from .config import Config, normalize_model_time_windows_with_errors, normalize_models
from .prompts import PromptBuilder
from .store import RunStore, STATUS_DONE, STATUS_ERROR, STATUS_INCOMPLETE, STATUS_RUNNING, STATUS_STOPPED

_CODE_REF_RE = re.compile(r"\S+:\d+")
_FINAL_DECISIONS = {"confirmed", "rejected", "suppressed_unproven", "needs_manual_review"}


def _noop_emit(etype: str, data: Optional[Dict[str, Any]] = None, persist: bool = True) -> None:
    return None


class Pipeline:
    def __init__(self, cfg: Config, *, store: Optional[RunStore] = None,
                 emitter: Optional[Callable[[str, Optional[Dict[str, Any]]], Any]] = None,
                 stop_event: Optional[asyncio.Event] = None):
        self.cfg = cfg
        self.pb = PromptBuilder(cfg)
        self.store = store or RunStore(cfg.out_dir).ensure()
        self._emit_cb = emitter or _noop_emit
        self._stop = stop_event   # 可为 None,惰性创建(兼容 py3.8 在事件循环外构造)
        self.runner = AgentRunner(cfg, logger=self.log, usage_sink=self.record_usage,
                                  health_sink=self.record_health, agent_sink=self.record_agent)
        self._restore_usage_counters()
        self.health_state: Dict[str, Dict[str, Any]] = {}   # model -> 最新健康记录

        # ── 运行状态(可被断点恢复) ──
        self.threat_graph: Dict[str, Any] = {}
        self.regions: List[Dict[str, Any]] = []
        self.history: List[Dict[str, Any]] = []      # 由 git 历史挖掘回灌的「历史问题模式」
        self.history_keys = set()                    # 历史模式去重(按 pattern 文本)
        self.history_done = set()                    # 已分析过的 git 提交 hash(续跑跳过)
        self._history_task: Optional[asyncio.Task] = None
        # ── 专用优先排查通道(历史变体 + 即时风险种子复查) ──
        self.pq: List[Dict[str, Any]] = []           # 优先排查队列(kind ∈ {variant, risk};variant 优先)
        self._recheck_inflight = 0                   # 正在排查 + 已 pop 待起的项数(收敛判据)
        self._restored_checkpoint = False
        self.build_hint: str = ""
        self.seq = 0
        self.start_round = 0
        self.dedup_keys = set()
        self.processed_keys = set()
        self.pending_findings: Dict[str, Dict[str, Any]] = {}
        self.seen_surface = set()
        self.completed_items = set()
        self.confirmed: List[Dict[str, Any]] = []
        self.queue: List[Dict[str, Any]] = []
        self._queue_seq = 0
        self._audit_passes: Dict[str, Dict[str, Any]] = {}
        self._history_enqueued = False
        self._retrying_past_max_rounds = False
        self._final_failed_sweep_done = False
        self._in_final_failed_sweep = False
        self._active_roles: Dict[str, int] = {}
        self._scheduler_wake: Optional[asyncio.Event] = None
        self.surface_log: List[Dict[str, Any]] = []
        self.risk_notes: List[Dict[str, Any]] = []   # 兼容旧测试 / 旧状态;新流程不再持久化风险登记
        self.risk_keys = set()                       # 本轮即时风险种子去重
        self.ledger_arr: List[Dict[str, Any]] = []
        self.ledger_map: Dict[str, Dict[str, Any]] = {}
        self.risk_seq = 0
        self.round = 0
        self.in_flight: List[asyncio.Task] = []
        self._started = time.time()
        # ── PoC 隔离工作目录(全 run 复用 + 串行) ──
        # opencode/codex 按 cwd 派生 per-project 状态(DB/快照),每个新 cwd 都要付一次冷启动
        # (一次性 DB 迁移 +「对整棵 target 全量重建快照」)。若每条 PoC 都新建一次性 worktree,
        # 就会反复冷启动,并发起来还会内存/磁盘尖峰直接拖垮 WSL。这里全 run 复用一个稳定 worktree,
        # 并用锁串行化(同时保护这个共享目录)。
        self._poc_worktree: Optional[str] = None
        self._poc_worktree_disabled = False   # 非 git 仓 / 建失败 → 回退主仓目录,且不再反复尝试
        self._poc_lock: Optional[asyncio.Lock] = None  # 惰性创建(兼容 py3.8 在事件循环外构造)

    # ──────────────────────── 日志 / 事件 ────────────────────────
    @staticmethod
    def _usage_int(v: Any) -> int:
        try:
            return max(0, int(v))
        except (TypeError, ValueError):
            return 0

    def _restore_usage_counters(self) -> None:
        """续跑时从 usage.jsonl 恢复累计 token 统计,并避免新 usage id 从 1 重新开始。"""
        if not self.cfg.resume:
            return
        try:
            rows = self.store.load_usage()
        except Exception:
            return
        if not rows:
            return
        totals = {
            "calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "estimated_calls": 0,
        }
        max_id = 0
        for rec in rows:
            if not isinstance(rec, dict):
                continue
            totals["calls"] += 1
            totals["input_tokens"] += self._usage_int(rec.get("input_tokens"))
            totals["output_tokens"] += self._usage_int(rec.get("output_tokens"))
            totals["total_tokens"] += self._usage_int(rec.get("total_tokens"))
            if rec.get("estimated"):
                totals["estimated_calls"] += 1
            max_id = max(max_id, self._usage_int(rec.get("id")))
        self.runner.usage_totals.update(totals)
        self.runner.usage_count = max(self.runner.usage_count, max_id)

    def log(self, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {msg}", flush=True)
        self.emit(EV.LOG, {"message": msg})

    def emit(self, etype: str, data: Optional[Dict[str, Any]] = None, persist: bool = True) -> None:
        try:
            self._emit_cb(etype, data or {}, persist)
        except Exception:
            pass

    def record_usage(self, rec: Dict[str, Any]) -> None:
        try:
            self.store.append_usage(rec)
        except Exception:
            pass
        self.emit(EV.USAGE, rec)
        self.emit(EV.METRICS, self._summary_snapshot(self.round))

    def record_health(self, rec: Dict[str, Any]) -> None:
        """模型健康记录更新:整体快照落盘 + 实时事件(供 Web「模型」页实时呈现)。"""
        m = rec.get("model")
        if m:
            self.health_state[m] = rec
        try:
            self.store.save_health(self.health_state)
        except Exception:
            pass
        self.emit(EV.MODEL_HEALTH, rec)

    def record_agent(self, rec: Dict[str, Any]) -> None:
        """agent 子进程状态与 stdout/stderr chunk:经 SSE 推给 Web「Agent」页。
        status=="output" 是逐字符输出流(高频大体积),只实时推、不落盘也不进事件 backlog,
        避免 events.jsonl/内存随 agent 数量无上限膨胀;其它状态事件照常持久化。"""
        is_output = rec.get("status") == "output"
        self.emit(EV.AGENT_UPDATE, rec, persist=not is_output)
        if not is_output:
            self.emit(EV.METRICS, self._summary_snapshot(self.round))

    def _reconcile_health_models(self) -> None:
        """把已落盘的 health 快照对齐到当前配置的模型集合:保留仍在用模型的既有健康记录,
        剔除已从配置移除的旧模型——避免续跑/重启后「模型」页残留上次配置里的模型。"""
        cur = set(self.cfg.active_models())
        prior = (self.store.load_health() or {}).get("models", [])
        self.health_state = {r["model"]: r for r in prior if r.get("model") in cur}
        if len(self.health_state) != len([r for r in prior if r.get("model")]):
            try:
                self.store.save_health(self.health_state)
            except Exception:
                pass

    async def health_check_all(self) -> Dict[str, Any]:
        """运行前(或按需)对当前时间窗内可用的模型各发一个 1+1 探针,实时反映健康度。"""
        all_models = self.cfg.active_models()
        if not all_models:
            self.log("⚠ 当前 run 没有需要健康检查的模型,跳过健康检查")
            self.emit(EV.HEALTH_DONE, {"total": 0, "ok": 0, "unhealthy": []})
            return {"total": 0, "ok": 0, "unhealthy": []}
        models = self.cfg.available_models(all_models)
        skipped = [m for m in all_models if m not in models]
        if not models:
            self.log("🩺 模型健康检查:当前无模型处于可用时间段,跳过探针")
            self.emit(EV.HEALTH_DONE, {"total": 0, "ok": 0, "unhealthy": [], "skipped_unavailable": skipped})
            return {"total": 0, "ok": 0, "unhealthy": [], "skipped_unavailable": skipped}
        self.emit(EV.HEALTH_START, {"models": models})
        suffix = f";跳过当前不可用 {', '.join(skipped)}" if skipped else ""
        self.log(f"🩺 模型健康检查:对 {len(models)} 个当前可用模型各发一个探针({', '.join(models)}){suffix}…")
        recs = await asyncio.gather(*[self.runner.probe_model(m, reason="startup") for m in models],
                                    return_exceptions=True)
        ok = sum(1 for r in recs if isinstance(r, dict) and r.get("status") == "ok")
        bad = [r.get("model") for r in recs if isinstance(r, dict) and r.get("status") != "ok"]
        if bad:
            self.log(f"🩺 健康检查完成:{ok}/{len(models)} 正常;异常: {', '.join(str(b) for b in bad)}"
                     f"(仍会尝试运行,失败将自动重试)")
        else:
            self.log(f"🩺 健康检查完成:{ok}/{len(models)} 全部正常")
        self.emit(EV.HEALTH_DONE, {"total": len(models), "ok": ok, "unhealthy": bad, "skipped_unavailable": skipped})
        return {"total": len(models), "ok": ok, "unhealthy": bad, "skipped_unavailable": skipped}

    def _stop_ev(self) -> asyncio.Event:
        if self._stop is None:
            self._stop = asyncio.Event()
        return self._stop

    def stop_requested(self) -> bool:
        return self._stop is not None and self._stop.is_set()

    def request_stop(self) -> None:
        self._stop_ev().set()

    # ──────────────────────── 元信息 / 路径 ────────────────────────
    def meta_dict(self) -> Dict[str, Any]:
        return {
            "target": self.cfg.target, "scope": self.cfg.scope, "threat_model": self.cfg.threat_model,
            "backend": self.cfg.backend, "run_mode": self.cfg.run_mode,
            "methods_ok": self.cfg.methods_ok(), "methods_dir": self.cfg.methods_abs,
        }

    def _abs_target(self) -> str:
        return os.path.abspath(os.path.expanduser(self.cfg.target))

    # ──────────────────────── 台账 ────────────────────────
    def ledger_rec(self, item: Dict[str, Any]) -> Dict[str, Any]:
        k = item_key(item)
        r = self.ledger_map.get(k)
        if not r:
            r = {"key": k, "kind": item.get("kind"),
                 "name": item.get("name") or item.get("objective") or item.get("pattern") or item.get("area") or "",
                 "region": item.get("region") or (item.get("name") if item.get("kind") == "region" else ""),
                 "category": item.get("category") or "", "priority": item.get("priority") or "",
                 "source": item.get("source") or "",
                 "lenses": [], "passes": 0, "candidates": 0, "surfaces": 0, "risks": 0,
                 "lastRound": 0, "status": "pending"}
            self.ledger_map[k] = r
            self.ledger_arr.append(r)
        if item.get("kind") == "risk":
            r["name"] = item.get("area") or r.get("name") or ""
            r["risk_area"] = item.get("area") or r.get("risk_area") or ""
            r["risk_note"] = item.get("note") or r.get("risk_note") or ""
            r["file"] = item.get("file") or r.get("file") or ""
            r["severity_hint"] = item.get("severity_hint") or r.get("severity_hint") or "info"
            r["callee"] = item.get("callee") or r.get("callee") or ""
            r["required_validation"] = item.get("required_validation") or r.get("required_validation") or ""
            r["good_validation_ref"] = item.get("good_validation_ref") or r.get("good_validation_ref") or ""
        return r

    # ──────────────────────── 断点(按关注点分文件)────────────────────────
    def build_checkpoint(self, rnd: int) -> Dict[str, Any]:
        """只放运行时机制态;结果产物(漏洞/风险/侦察/覆盖)各自分文件存。"""
        return {
            "v": 3, "target": self.cfg.target, "scope": self.cfg.scope,
            "round": rnd, "seq": self.seq, "risk_seq": self.risk_seq,
            "processedKeys": list(self.processed_keys),
            "seenSurface": list(self.seen_surface),
            "riskKeys": list(self.risk_keys),
            "completedItems": list(self.completed_items),
            "historyDone": list(self.history_done),
            "pendingQueue": self._checkpoint_queue(),
            "pendingPriorityQueue": self.pq,
            "pendingFindings": list(self.pending_findings.values()),
        }

    def build_attack_surface(self, rnd: int) -> Dict[str, Any]:
        n_done = sum(1 for r in self.ledger_arr if str(r.get("status")).startswith("completed"))
        n_clean = sum(1 for r in self.ledger_arr if r.get("status") == "completed-clean")
        return {
            "round": rnd, "ledger": self.ledger_arr, "surfaces": self.surface_log,
            "regions": self.regions,
            "progress": {"done": n_done, "clean": n_clean, "total": len(self.ledger_arr)},
        }

    def _summary_snapshot(self, rnd: int) -> Dict[str, Any]:
        by_sev: Dict[str, int] = {}
        for c in self.confirmed:
            sev = c.get("corrected_severity") or c.get("severity")
            by_sev[sev] = by_sev.get(sev, 0) + 1
        quality_issues = sum(1 for c in self.confirmed if is_quality_issue_finding(c))
        confirmed_real = max(0, len(self.confirmed) - quality_issues)
        return {
            "rounds": rnd, "confirmed": confirmed_real, "finding_entries": len(self.confirmed),
            "candidates": len(self.dedup_keys),
            "quality_issues": quality_issues,
            "by_severity": by_sev, "risks": 0, "surfaces": len(self.surface_log),
            "agents_spawned": self.runner.agent_count, "elapsed_s": round(time.time() - self._started, 1),
            "token_usage": dict(self.runner.usage_totals),
            "pending_findings": self._active_pending_candidate_count(),
            "failed_candidates": self._failed_candidate_count(),
            "failed_rechecks": self._failed_recheck_count(),
            "pending_queue": len(self._checkpoint_queue()),
            "pending_priority_queue": len(self.pq),
        }

    @staticmethod
    def _is_candidate_failed(f: Dict[str, Any]) -> bool:
        return f.get("verify_status") == "verify_failed"

    def _failed_candidate_count(self) -> int:
        return sum(1 for f in self.pending_findings.values() if self._is_candidate_failed(f))

    def _active_pending_candidate_count(self) -> int:
        return sum(1 for f in self.pending_findings.values() if not self._is_candidate_failed(f))

    def _failed_recheck_keys(self) -> set:
        keys = set()
        for rec in self.ledger_arr:
            if rec.get("status") == "abandoned" and rec.get("kind") in ("risk", "variant"):
                k = rec.get("key")
                if k:
                    keys.add(k)
        return keys

    def _failed_recheck_count(self) -> int:
        return len(self._failed_recheck_keys())

    def _incomplete_counts(self) -> Dict[str, int]:
        return {
            "pending_findings": self._active_pending_candidate_count(),
            "failed_candidates": self._failed_candidate_count(),
            "failed_rechecks": self._failed_recheck_count(),
            "pending_queue": len(self._checkpoint_queue()),
            "pending_priority_queue": len(self.pq),
        }

    @staticmethod
    def _has_incomplete_counts(counts: Dict[str, int]) -> bool:
        return any(int(v or 0) > 0 for v in counts.values())

    def persist_history(self) -> None:
        try:
            self.store.save_history(self.history)
        except Exception as e:  # noqa: BLE001
            self.log(f"⚠ history 写入失败(忽略继续): {str(e)[:120]}")

    def checkpoint(self, rnd: int) -> None:
        """每个检查点:刷机制态 + 攻击面/覆盖快照 + 汇总(漏洞已即时落盘)。"""
        try:
            self.store.save_checkpoint(self.build_checkpoint(rnd))
            self.store.save_attack_surface(self.build_attack_surface(rnd))
            self.store.update_summary(self._summary_snapshot(rnd))
        except Exception as e:  # noqa: BLE001
            self.log(f"⚠ 断点写入失败(忽略继续): {str(e)[:120]}")

    # ──────────────────────── 覆盖快照(供前端 Coverage 视图)────────────────────────
    def emit_coverage(self) -> None:
        n_done = sum(1 for r in self.ledger_arr if str(r.get("status")).startswith("completed"))
        n_clean = sum(1 for r in self.ledger_arr if r.get("status") == "completed-clean")
        self.emit(EV.COVERAGE_UPDATE, {
            "ledger": self.ledger_arr, "surfaces": self.surface_log, "regions": self.regions,
            "progress": {"done": n_done, "clean": n_clean, "total": len(self.ledger_arr)},
        })

    # ──────────────────────── 优先级调度队列 ────────────────────────
    _PRI_BY_AREA = {"high": 0, "medium": 1, "low": 2}
    _INTERNAL_KINDS = {"_finder", "_finding", "_history_commit", "_recheck"}

    @staticmethod
    def _runtime_clean_item(item: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in item.items() if not str(k).startswith("_")}

    def _checkpoint_queue(self) -> List[Dict[str, Any]]:
        """断点只保存可恢复的顶层审计项;运行时展开的 finder/history/finding 不写入 checkpoint。"""
        out: List[Dict[str, Any]] = []
        seen = set()
        for it in self.queue:
            if it.get("kind") in self._INTERNAL_KINDS:
                continue
            k = item_key(it)
            if k in seen or k in self.completed_items:
                continue
            seen.add(k)
            out.append(self._runtime_clean_item(it))
        for st in self._audit_passes.values():
            it = st.get("item") or {}
            k = item_key(it)
            if k in seen or k in self.completed_items:
                continue
            seen.add(k)
            out.append(self._runtime_clean_item(it))
        return out

    def _enqueue_work(self, item: Dict[str, Any]) -> None:
        self._queue_seq += 1
        item["_queue_seq"] = self._queue_seq
        self.queue.append(item)
        self._notify_scheduler()

    def _notify_scheduler(self) -> None:
        if self._scheduler_wake is not None:
            self._scheduler_wake.set()

    def _scheduler_wake_event(self) -> asyncio.Event:
        if self._scheduler_wake is None:
            self._scheduler_wake = asyncio.Event()
        return self._scheduler_wake

    async def _sleep_or_wake(self, delay_s: float) -> None:
        wake = self._scheduler_wake_event()
        if wake.is_set():
            wake.clear()
            return
        try:
            await asyncio.wait_for(wake.wait(), timeout=delay_s)
        except asyncio.TimeoutError:
            pass
        if wake.is_set():
            wake.clear()

    async def _wait_active_or_wake(self, active: List[asyncio.Task], *, may_start: bool,
                                   timeout_s: Optional[float] = None) -> None:
        if not active:
            if timeout_s is not None:
                await self._sleep_or_wake(timeout_s)
            return
        if not may_start:
            await asyncio.wait(active, return_when=asyncio.FIRST_COMPLETED)
            return

        wake = self._scheduler_wake_event()
        if wake.is_set():
            wake.clear()
            return
        wake_task = asyncio.create_task(wake.wait())
        try:
            await asyncio.wait([*active, wake_task], timeout=timeout_s,
                               return_when=asyncio.FIRST_COMPLETED)
        finally:
            if wake.is_set():
                wake.clear()
            if not wake_task.done():
                wake_task.cancel()
                await asyncio.gather(wake_task, return_exceptions=True)

    def _refresh_enqueue_order(self, item: Dict[str, Any]) -> None:
        self._queue_seq += 1
        item["_queue_seq"] = self._queue_seq

    def _ensure_queue_order(self) -> None:
        for it in self.queue:
            if not it.get("_queue_seq"):
                self._refresh_enqueue_order(it)

    def _area_rank(self, item: Dict[str, Any]) -> int:
        return self._PRI_BY_AREA.get(item.get("priority") or "medium", 1)

    def _work_priority(self, item: Dict[str, Any]) -> int:
        kind = item.get("kind")
        if kind == "_recheck":
            return 0
        if kind == "_finding":
            return 5
        if kind in ("_finder", "_history_commit"):
            return 20 + self._area_rank(item)
        if kind in ("task", "surface", "attack_method"):
            return 20 + self._area_rank(item)
        return 50

    def _work_role(self, item: Dict[str, Any]) -> Optional[str]:
        kind = item.get("kind")
        if kind == "_recheck":
            return "recheck"
        if kind == "_finding":
            return "verify"
        if kind == "_history_commit":
            return "history"
        if kind == "_finder":
            return "audit"
        return None

    def _work_sort_key(self, item: Dict[str, Any]) -> tuple[int, int]:
        return (self._work_priority(item), int(item.get("_queue_seq") or 0))

    def _recheck_concurrency_limit(self) -> int:
        """recheck 专用闸的并发上限:默认 1,逐条串行排查历史变体和风险点。"""
        return max(1, int(self.cfg.recheck.concurrency))

    def _can_dispatch_work(self, item: Dict[str, Any]) -> bool:
        if item.get("kind") == "_recheck" and self._active_roles.get("recheck", 0) >= self._recheck_concurrency_limit():
            return False
        role = self._work_role(item)
        if role is None:
            return True
        if not self.cfg.configured_model_slots_for(role):
            return True
        limit_fn = getattr(self.runner, "role_capacity_limit", None)
        role_limit = int(limit_fn(role)) if callable(limit_fn) else self.cfg.concurrency
        if role_limit <= 0:
            return False
        if self._active_roles.get(role, 0) >= max(1, role_limit):
            return False
        has_capacity = getattr(self.runner, "role_has_capacity", None)
        if not callable(has_capacity):
            return True
        return bool(has_capacity(role))

    def _enqueue_finding(self, finding: Dict[str, Any]) -> None:
        fk = finding_key(finding)
        if fk in self.processed_keys:
            return
        self._enqueue_work({"kind": "_finding", "finding_key": fk, "finding": finding})

    def _pop_dispatchable_queued_kind(self, kind: str) -> Optional[Dict[str, Any]]:
        self._ensure_queue_order()
        for idx, item in sorted(enumerate(self.queue), key=lambda x: self._work_sort_key(x[1])):
            if item.get("kind") != kind:
                continue
            if self._can_dispatch_work(item):
                return self.queue.pop(idx)
        return None

    def _enqueue_risk(self, note: Dict[str, Any]) -> None:
        """把一条即时风险种子放进优先排查队列;不登记、不落盘。"""
        self.pq.append({"kind": "risk", "id": note["id"], "area": note.get("area"),
                        "note": note.get("note"), "file": note.get("file"),
                        "severity_hint": note.get("severity_hint"), "lens": note.get("lens"),
                        "callee": note.get("callee"), "required_validation": note.get("required_validation"),
                        "good_validation_ref": note.get("good_validation_ref"),
                        "round": note.get("round")})
        self._notify_scheduler()
        self.emit(EV.RECHECK_ENQUEUED, {"kind": "risk", "id": note["id"], "area": note.get("area"),
                                        "severity_hint": note.get("severity_hint")})

    def record_risk(self, n: Dict[str, Any], lens: str, rnd: int, from_recheck: bool = False) -> bool:
        """消费 finder 的 risk_notes:直接派发一次性 recheck agent。

        risk_notes 不再代表“潜在风险登记”,也不写 risks/<id>.json / RISKS.md。
        复查 agent 自身产出的 risk_notes 不再回灌,避免自激循环。
        """
        if from_recheck or not self.cfg.recheck.enabled:
            return False
        area = (n.get("area") or "").strip()
        if not area:
            return False
        key = "::".join([
            area.lower(),
            (n.get("file") or "").strip(),
            (n.get("callee") or "").strip(),
            (n.get("required_validation") or "").strip().lower(),
        ])
        if key in self.risk_keys:
            return False
        self.risk_keys.add(key)
        self.risk_seq += 1
        note = {"id": f"RISK-{pad3(self.risk_seq)}", "area": area, "note": n.get("note") or "",
                "file": n.get("file") or "", "severity_hint": n.get("severity_hint") or "info",
                "lens": lens, "round": rnd,
                "callee": n.get("callee") or "", "required_validation": n.get("required_validation") or "",
                "good_validation_ref": n.get("good_validation_ref") or ""}
        self._enqueue_risk(note)
        return True

    def adjust_risk_severity(self, rid: str, sev: str) -> bool:
        """兼容旧 Web 接口。风险点已改为即时消费,不存在可调级的存档记录。"""
        return False

    # ──────────────────────── 运行中动态调参 ────────────────────────
    def reconfigure(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        """运行中动态调整模型与并发(供 Web 接口调用)。可含:
          · models:{role: [model, ...]} —— 增/减某角色的模型(空列表=清空该角色,会触发配置错误提示);
          · model_concurrency:{model: limit} —— 每模型并发上限;
          · model_time_windows:{model: [window, ...]} —— 每模型可用时间段;
          · concurrency:int —— 全局并发。
        就地改写 self.cfg(scheduler/各 acquire 都实时读它)并重设已存在的信号量;
        新增模型的 per-model 信号量在首次派任务时按新配置惰性创建。返回当前生效快照(含配置校验)。
        """
        patch = patch or {}
        changed: List[str] = []

        if "model_time_windows" in patch and isinstance(patch["model_time_windows"], dict):
            (self.cfg.model_time_windows,
             self.cfg._model_time_window_minutes,
             self.cfg._model_time_window_errors) = normalize_model_time_windows_with_errors(patch["model_time_windows"])
            changed.append("模型可用时间段")

        if "models" in patch and isinstance(patch["models"], dict):
            old_models = self.cfg.active_models()
            self.cfg.models = normalize_models(patch["models"])
            new_models = self.cfg.active_models()
            added = [m for m in new_models if m not in old_models]
            removed = [m for m in old_models if m not in new_models]
            if added or removed:
                bits = []
                if added:
                    bits.append("新增 " + ", ".join(added))
                if removed:
                    bits.append("移除 " + ", ".join(removed))
                changed.append("模型(" + ";".join(bits) + ")")
            else:
                changed.append("模型分配")
            # 启动健康探针只覆盖了当时配置的模型;新增的模型在后台补探一次。
            if added and self.cfg.health.enabled:
                for m in added:
                    if self.cfg.model_available_at(m):
                        asyncio.ensure_future(self.runner.probe_model(m, reason="reconfigure"))

        conc = patch.get("concurrency")
        mconc = patch.get("model_concurrency") if "model_concurrency" in patch else None
        if conc is not None:
            changed.append(f"全局并发→{max(1, int(conc))}")
        if mconc is not None:
            changed.append("每模型并发")
        if conc is not None or mconc is not None:
            self.runner.reconfigure(concurrency=conc, model_concurrency=mconc)

        # 落盘到 manifest.config:续跑沿用最新配置
        try:
            self.store.update_config({
                "models": self.cfg.models,
                "model_concurrency": self.cfg.model_concurrency,
                "model_time_windows": self.cfg.model_time_windows,
                "concurrency": self.cfg.concurrency,
            })
        except Exception:
            pass

        snapshot = self.config_snapshot()
        if changed:
            self.log("⚙ 动态调参:" + " | ".join(changed) + f"(全局并发 {self.cfg.concurrency})")
        if snapshot.get("model_config_error"):
            self.log("⚠ 当前模型配置不完整:" + snapshot["model_config_error"] + "(已派出的任务不受影响)")
        self.emit(EV.CONFIG_UPDATED, snapshot)
        return snapshot

    def config_snapshot(self) -> Dict[str, Any]:
        """当前生效的模型/并发配置快照(含逐模型实际并发上限与配置校验)。"""
        active_models = self.cfg.active_models()
        eff = {m: self.cfg.model_concurrency_for(m) for m in active_models}
        avail = {m: self.cfg.model_available_at(m) for m in active_models}
        return {
            "models": self.cfg.models,
            "model_concurrency": self.cfg.model_concurrency,
            "model_time_windows": self.cfg.model_time_windows,
            "effective_model_concurrency": eff,
            "model_availability": avail,
            "concurrency": self.cfg.concurrency,
            "model_config_error": self.cfg.model_config_error(),
        }

    @staticmethod
    def manifest_config_for(cfg: Config) -> Dict[str, Any]:
        """写入 run.json 的配置快照。"""
        return {
            "target": cfg.target, "scope": cfg.scope, "backend": cfg.backend,
            "run_mode": cfg.run_mode, "history_import_from": cfg.history_import_from,
            "models": cfg.models, "model_concurrency": cfg.model_concurrency,
            "model_time_windows": cfg.model_time_windows,
            "concurrency": cfg.concurrency, "threat_model": cfg.threat_model,
            "lenses": cfg.lenses, "finders_per_lens": cfg.finders_per_lens,
            "max_rounds": cfg.max_rounds, "dry_rounds": cfg.dry_rounds,
            "verify_votes": cfg.verify_votes, "enable_poc": cfg.enable_poc,
            "methods_dir": cfg.methods_abs, "methods_ok": cfg.methods_ok(),
        }

    def manifest_config(self) -> Dict[str, Any]:
        return self.manifest_config_for(self.cfg)

    # ──────────────────────── lens 选择 ────────────────────────
    def lenses_for(self, item: Dict[str, Any]) -> List[str]:
        active = self.cfg.lenses
        if item.get("kind") == "attack_method":
            hits = [l for l in (item.get("lens_hints") or [item.get("lens_hint")]) if l in active]
            return hits or active
        if item.get("kind") == "task":
            hits = [l for l in (item.get("lens_hints") or []) if l in active]
            return hits or active
        if item.get("kind") == "variant" and item.get("lens_hint") in active:
            return [item["lens_hint"]]
        if item.get("kind") == "surface" and item.get("lens_hint") in active:
            return [item["lens_hint"]]
        return active

    # ──────────────────────── 逐发现流水线:验证→(PoC)→报告正文 ────────────────────────
    @staticmethod
    def _candidate_payload(f: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "key": finding_key(f), "title": f.get("title"), "bug_class": f.get("bug_class"),
            "file": f.get("file"), "line": f.get("line"), "lens": f.get("lens"),
            "severity": f.get("severity"), "function": f.get("function") or "",
            "description": f.get("description") or "", "source_to_sink": f.get("source_to_sink") or "",
            "variant_of": f.get("variant_of") or "", "confidence": f.get("confidence") or "",
            "audit_model": f.get("audit_model") or "",
            "good_validation_ref": f.get("good_validation_ref") or "",
            "risk_id": f.get("risk_id") or "",
            "risk_area": f.get("risk_area") or "",
            "attack_context": f.get("attack_context") or {},
        }

    def _save_candidate_state(self, rec: Dict[str, Any]) -> None:
        try:
            self.store.save_candidate(rec)
        except Exception:
            pass

    def _candidate_failed_payload(self, f: Dict[str, Any], reason: str,
                                  votes: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        payload = {
            **self._candidate_payload(f),
            "status": "verify_failed",
            "reason": reason, "attempts": int(f.get("verify_attempts") or 0),
            "final_sweep": self._in_final_failed_sweep,
        }
        if votes:
            payload["votes"] = self._slim_verify_votes(votes)
            valid = [v for v in votes if v.get("phase") == "judge" and v.get("validation_ok", True)]
            payload["vote_total"] = len(valid)
            payload["vote_real"] = sum(1 for v in valid if self._vote_decision(v) == "confirm")
            payload["vote_false"] = sum(1 for v in valid if self._vote_decision(v) == "reject")
            payload["verify_models"] = sorted({v.get("model") for v in votes if v.get("model")})
        return payload

    def _candidate_rejected_payload(self, f: Dict[str, Any], votes: List[Dict[str, Any]],
                                    final: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        judge_votes = [v for v in votes if v.get("phase") == "judge" and v.get("validation_ok", True)]
        counted_votes = judge_votes or votes
        false_votes = [v for v in counted_votes if self._vote_decision(v) == "reject"]
        reason_bits = []
        if isinstance(final, dict):
            for key in ("rejection_reason", "final_reason", "non_issue_reason", "reasoning"):
                r = (final.get(key) or "").strip()
                if r and r not in reason_bits:
                    reason_bits.append(r)
        for v in false_votes:
            r = (v.get("non_issue_reason") or v.get("reasoning") or "").strip()
            clearing = " / ".join(self._text_list(v.get("clearing_checks")))
            if clearing:
                r = f"{r}: {clearing}" if r else clearing
            if r and r not in reason_bits:
                reason_bits.append(r)
        total = len(counted_votes)
        false_count = len(false_votes)
        summary = "终局裁判判定为非问题"
        if total:
            summary += f"(反证记录 {false_count}/{total})"
        if reason_bits:
            summary += ": " + " / ".join(reason_bits)
        slim_votes = self._slim_verify_votes(votes)
        verify_models = sorted({v["model"] for v in slim_votes if v.get("model")})
        return {
            **self._candidate_payload(f),
            "status": "rejected",
            "votes": slim_votes,
            "verify_models": verify_models,
            "vote_total": total,
            "vote_false": false_count,
            "vote_real": total - false_count,
            "rejection_reason": summary,
        }

    def _candidate_decision_payload(self, f: Dict[str, Any], status: str, votes: List[Dict[str, Any]],
                                    final: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        final = final if isinstance(final, dict) else {}
        slim_votes = self._slim_verify_votes(votes)
        verify_models = sorted({v["model"] for v in slim_votes if v.get("model")})
        reason = (final.get("final_reason") or final.get("reasoning") or final.get("residual_uncertainty")
                  or final.get("why_not_confirmed") or "").strip()
        payload = {
            **self._candidate_payload(f),
            "status": status,
            "votes": slim_votes,
            "verify_models": verify_models,
            "epistemic_verdict": final.get("epistemic_verdict") or "",
            "operational_decision": status,
            "decision_reason": reason,
            "residual_uncertainty": final.get("residual_uncertainty") or "",
            "recommended_next_action": final.get("recommended_next_action") or "",
            "vote_total": 0,
            "vote_false": 0,
            "vote_real": 0,
        }
        return payload

    def _slim_verify_votes(self, votes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [{
            "phase": v.get("phase") or "",
            "model": v.get("model") or "",
            "verify_lens": v.get("verify_lens") or "",
            "decision": self._vote_decision(v),
            "is_real": bool(v.get("is_real")),
            "validation_ok": v.get("validation_ok", True),
            "validation_reason": v.get("validation_reason") or "",
            "reachability": v.get("reachability") or "",
            "controllability": v.get("controllability") or "",
            "corrected_severity": v.get("corrected_severity") or "",
            "exploitability": v.get("exploitability") or "",
            "evidence_refs": self._text_list(v.get("evidence_refs")),
            "source_chain": self._text_list(v.get("source_chain")),
            "sink_ref": v.get("sink_ref") or "",
            "clearing_checks": self._text_list(v.get("clearing_checks")),
            "missing_evidence": v.get("missing_evidence") or "",
            "verdict_confidence": v.get("verdict_confidence") or "",
            "reasoning": v.get("reasoning") or "",
            "non_issue_reason": v.get("non_issue_reason") or "",
            "witness_complete": v.get("witness_complete"),
            "witness": v.get("witness") or "",
            "attack_preconditions": self._text_list(v.get("attack_preconditions")),
            "input_domain_constraints": self._text_list(v.get("input_domain_constraints")),
            "state_constraints": self._text_list(v.get("state_constraints")),
            "code_constraints": self._text_list(v.get("code_constraints")),
            "path_nodes": self._text_list(v.get("path_nodes")),
            "trigger_condition": v.get("trigger_condition") or "",
            "bad_result": v.get("bad_result") or "",
            "blocker_found": v.get("blocker_found"),
            "blocker_scope": v.get("blocker_scope") or "",
            "blocker_type": v.get("blocker_type") or "",
            "blocker_description": v.get("blocker_description") or "",
            "blocking_checks": self._text_list(v.get("blocking_checks")),
            "impossibility_proof": v.get("impossibility_proof") or "",
            "affected_witness": v.get("affected_witness") or "",
            "witness_verdict": v.get("witness_verdict") or "",
            "blocker_verdict": v.get("blocker_verdict") or "",
            "reviewed_checks": self._text_list(v.get("reviewed_checks")),
            "failed_checks": self._text_list(v.get("failed_checks")),
            "epistemic_verdict": v.get("epistemic_verdict") or "",
            "operational_decision": v.get("operational_decision") or "",
            "deciding_facts_checked": self._text_list(v.get("deciding_facts_checked")),
            "final_reason": v.get("final_reason") or "",
            "residual_uncertainty": v.get("residual_uncertainty") or "",
            "why_not_confirmed": v.get("why_not_confirmed") or "",
            "why_not_rejected": v.get("why_not_rejected") or "",
            "recommended_next_action": v.get("recommended_next_action") or "",
        } for v in votes]

    @staticmethod
    def _text(v: Any) -> str:
        return str(v).strip() if v is not None else ""

    @classmethod
    def _text_list(cls, v: Any) -> List[str]:
        if isinstance(v, list):
            return [cls._text(x) for x in v if cls._text(x)]
        s = cls._text(v)
        return [s] if s else []

    def _quality_finding_report_body(self, f: Dict[str, Any], final: Dict[str, Any],
                                     decision: str) -> str:
        facts = self._text_list(final.get("deciding_facts_checked"))
        reason = (final.get("final_reason") or final.get("reasoning")
                  or "对抗验证后未能闭合漏洞证据").strip()
        uncertainty = (final.get("residual_uncertainty") or "缺少足够证据证明该候选是真实可利用漏洞").strip()
        next_action = (final.get("recommended_next_action") or "按编码质量问题处理,后续结合人工代码审查补证").strip()
        decision_text = {
            "suppressed_unproven": "证据不足压制",
            "needs_manual_review": "待人工复核",
        }.get(decision, decision)
        lines = [
            "## ① 编码质量问题描述",
            f.get("description") or f.get("title") or "(无)",
            "",
            "## ② 对抗验证结论",
            "该候选经过 witness/blocker 对抗验证后未达到确认漏洞的证据门槛,也未被全局 blocker 彻底证伪。"
            f"终局工程决策为「{decision_text}」,因此保留到漏洞页,但标记为「{QUALITY_FINDING_TAG}」。",
            "",
            "## ③ 判定原因",
            reason,
            "",
            "## ④ 剩余不确定性",
            uncertainty,
            "",
            "## ⑤ 建议处理",
            next_action,
        ]
        if facts:
            lines.extend(["", "## ⑥ 已检查事实", *[f"- {x}" for x in facts]])
        return "\n".join(lines).strip() + "\n"

    def _record_quality_finding(self, f: Dict[str, Any], votes: List[Dict[str, Any]],
                                final: Dict[str, Any], decision: str) -> Dict[str, Any]:
        self.seq += 1
        fid = f"QUAL-{pad3(self.seq)}"
        verify_models = sorted({v.get("model") for v in votes if v.get("model")})
        decision_reason = (final.get("final_reason") or final.get("reasoning")
                           or final.get("residual_uncertainty") or "").strip()
        raw_tags = f.get("tags")
        tags = list(raw_tags) if isinstance(raw_tags, list) else ([str(raw_tags)] if raw_tags else [])
        if QUALITY_FINDING_TAG not in tags:
            tags.append(QUALITY_FINDING_TAG)
        rec = {
            **f,
            "id": fid,
            "corrected_severity": "info",
            "original_severity": f.get("severity") or "",
            "confidence": f.get("confidence") or "low",
            "votes": votes,
            "verify_models": verify_models,
            "tags": tags,
            "finding_status": QUALITY_FINDING_STATUS,
            "verification_status": decision,
            "epistemic_verdict": final.get("epistemic_verdict") or "unresolved",
            "operational_decision": decision,
            "decision_reason": decision_reason,
            "residual_uncertainty": final.get("residual_uncertainty") or "",
            "recommended_next_action": final.get("recommended_next_action") or "",
            "report_body": self._quality_finding_report_body(f, final, decision),
            "report_failed": False,
            "poc": None,
            "output_ts": time.time(),
        }
        self.confirmed.append(rec)
        self.store.save_finding(rec)
        self.emit(EV.FINDING_ADDED, slim_finding(rec))
        self.log(f"候选 {fid} 已作为{QUALITY_FINDING_TAG}记录到漏洞页({decision}): {rec.get('title')}")
        return rec

    @classmethod
    def _has_code_ref(cls, v: Any) -> bool:
        return any(_CODE_REF_RE.search(x) for x in cls._text_list(v))

    @staticmethod
    def _vote_decision(v: Dict[str, Any]) -> str:
        op = (v.get("operational_decision") or "").strip().lower()
        if op == "confirmed":
            return "confirm"
        if op == "rejected":
            return "reject"
        if op in ("suppressed_unproven", "needs_manual_review"):
            return "inconclusive"
        d = (v.get("decision") or "").strip().lower()
        if d in ("confirm", "reject", "inconclusive"):
            return d
        return "confirm" if v.get("is_real") else "reject"

    @classmethod
    def _normalize_judge_vote(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(v) if isinstance(v, dict) else {}
        decision = cls._vote_decision(out)
        out["decision"] = decision
        if decision == "confirm":
            out["is_real"] = True
        elif decision == "reject":
            out["is_real"] = False
        else:
            out["is_real"] = False
        return out

    @classmethod
    def _validate_verify_proof(cls, proof: Optional[Dict[str, Any]]) -> List[str]:
        if not isinstance(proof, dict):
            return ["正方无结构化输出"]
        missing = []
        if not proof.get("supports_real"):
            missing.append("正方未坐实 finding")
        if not cls._has_code_ref(proof.get("evidence_refs")):
            missing.append("正方缺少 path:line 代码证据")
        if not cls._has_code_ref(proof.get("source_chain")):
            missing.append("正方缺少 source_chain")
        if not cls._has_code_ref(proof.get("sink_ref")):
            missing.append("正方缺少 sink_ref")
        if not cls._text(proof.get("reachability")):
            missing.append("正方缺少可达性说明")
        if not cls._text(proof.get("controllability")):
            missing.append("正方缺少可控性说明")
        return missing

    @classmethod
    def _validate_verify_disproof(cls, disproof: Optional[Dict[str, Any]]) -> List[str]:
        if not isinstance(disproof, dict):
            return ["反方无结构化输出"]
        missing = []
        if not disproof.get("refutes_real"):
            missing.append("反方未证伪 finding")
        if not cls._has_code_ref(disproof.get("evidence_refs")):
            missing.append("反方缺少 path:line 代码证据")
        if not cls._has_code_ref(disproof.get("clearing_checks")):
            missing.append("反方缺少 clearing_checks")
        if not cls._text(disproof.get("non_issue_reason")):
            missing.append("反方缺少 non_issue_reason")
        return missing

    @classmethod
    def _validate_judge_vote(cls, vote: Dict[str, Any], *, proof_ok: bool, disproof_ok: bool) -> List[str]:
        decision = cls._vote_decision(vote)
        missing = []
        if decision == "inconclusive":
            missing.append("裁决不确定")
            if not cls._text(vote.get("missing_evidence") or vote.get("reasoning")):
                missing.append("未说明证据缺口")
            return missing
        if not cls._has_code_ref(vote.get("evidence_refs")):
            missing.append("裁决缺少 path:line 代码证据")
        if decision == "confirm":
            if not proof_ok:
                missing.append("正方举证不合格")
            if not cls._has_code_ref(vote.get("source_chain")):
                missing.append("确认票缺少 source_chain")
            if not cls._has_code_ref(vote.get("sink_ref")):
                missing.append("确认票缺少 sink_ref")
            if not cls._text(vote.get("reachability")):
                missing.append("确认票缺少可达性说明")
            if not cls._text(vote.get("controllability")):
                missing.append("确认票缺少可控性说明")
        elif decision == "reject":
            if not disproof_ok:
                missing.append("反方证伪不合格")
            if not cls._has_code_ref(vote.get("clearing_checks")):
                missing.append("否决票缺少 clearing_checks")
            if not cls._text(vote.get("non_issue_reason")):
                missing.append("否决票缺少 non_issue_reason")
        else:
            missing.append(f"未知裁决:{decision}")
        return missing

    @classmethod
    def _validate_witness(cls, witness: Optional[Dict[str, Any]]) -> List[str]:
        if not isinstance(witness, dict):
            return ["正方无结构化 witness 输出"]
        missing = []
        complete = bool(witness.get("witness_complete"))
        if complete:
            if not cls._text(witness.get("witness")):
                missing.append("witness_complete=true 但缺少 witness")
            if not cls._has_code_ref(witness.get("evidence_refs")):
                missing.append("witness 缺少 path:line 代码证据")
            if not cls._has_code_ref(witness.get("path_nodes")):
                missing.append("witness 缺少 path_nodes")
            if not cls._has_code_ref(witness.get("sink_ref")):
                missing.append("witness 缺少 sink_ref")
            if not cls._text(witness.get("trigger_condition")):
                missing.append("witness 缺少 trigger_condition")
            if not cls._text(witness.get("bad_result")):
                missing.append("witness 缺少 bad_result")
        elif not cls._text(witness.get("missing_evidence") or witness.get("reasoning")):
            missing.append("witness 不完整但未说明缺口")
        return missing

    @classmethod
    def _validate_blocker(cls, blocker: Optional[Dict[str, Any]]) -> List[str]:
        if not isinstance(blocker, dict):
            return ["反方无结构化 blocker 输出"]
        missing = []
        found = bool(blocker.get("blocker_found"))
        scope = (blocker.get("blocker_scope") or "").strip()
        if found:
            if scope not in ("global", "path_local", "branch_local", "config_local", "partial", "unknown"):
                missing.append("blocker_found=true 但 blocker_scope 无效")
            if not cls._has_code_ref(blocker.get("evidence_refs") or blocker.get("blocking_checks")):
                missing.append("blocker 缺少 path:line 代码证据")
            if not cls._text(blocker.get("non_issue_reason") or blocker.get("impossibility_proof")
                             or blocker.get("blocker_description")):
                missing.append("blocker 缺少非问题原因或不可满足证明")
        elif scope and scope not in ("none", "unknown"):
            missing.append("blocker_found=false 时 blocker_scope 应为 none/unknown")
        elif not cls._text(blocker.get("missing_evidence") or blocker.get("reasoning")):
            missing.append("未找到 blocker 但未说明缺口")
        return missing

    @classmethod
    def _validate_witness_review(cls, review: Optional[Dict[str, Any]]) -> List[str]:
        if not isinstance(review, dict):
            return ["witness 裁判无结构化输出"]
        verdict = (review.get("witness_verdict") or "").strip()
        if verdict not in ("accepted", "weakened", "rejected", "inconclusive"):
            return ["witness_verdict 无效"]
        missing = []
        if verdict == "accepted" and not cls._has_code_ref(review.get("evidence_refs") or review.get("reviewed_checks")):
            missing.append("accepted 缺少 path:line 复核证据")
        if verdict in ("weakened", "rejected") and not cls._text(review.get("failed_checks") or review.get("reasoning")):
            missing.append(f"{verdict} 未说明 witness 问题")
        if verdict == "inconclusive" and not cls._text(review.get("missing_evidence") or review.get("reasoning")):
            missing.append("inconclusive 未说明缺口")
        return missing

    @classmethod
    def _validate_blocker_review(cls, review: Optional[Dict[str, Any]]) -> List[str]:
        if not isinstance(review, dict):
            return ["blocker 裁判无结构化输出"]
        verdict = (review.get("blocker_verdict") or "").strip()
        if verdict not in ("global_decisive", "partial", "invalid", "unknown_scope"):
            return ["blocker_verdict 无效"]
        missing = []
        if verdict == "global_decisive" and not cls._has_code_ref(review.get("evidence_refs") or review.get("reviewed_checks")):
            missing.append("global_decisive 缺少 path:line 复核证据")
        if verdict in ("partial", "invalid") and not cls._text(review.get("failed_checks") or review.get("reasoning")):
            missing.append(f"{verdict} 未说明 blocker 作用域/有效性问题")
        if verdict == "unknown_scope" and not cls._text(review.get("missing_evidence") or review.get("reasoning")):
            missing.append("unknown_scope 未说明缺口")
        return missing

    @classmethod
    def _validate_final_adjudication(cls, final: Optional[Dict[str, Any]]) -> List[str]:
        if not isinstance(final, dict):
            return ["终局裁判无结构化输出"]
        epistemic = (final.get("epistemic_verdict") or "").strip()
        decision = (final.get("operational_decision") or "").strip()
        missing = []
        if epistemic not in ("proven_real", "proven_false", "unresolved"):
            missing.append("epistemic_verdict 无效")
        if decision not in _FINAL_DECISIONS:
            missing.append("operational_decision 无效")
        if not cls._text(final.get("reasoning") or final.get("final_reason")):
            missing.append("终局裁判缺少 reasoning/final_reason")
        if decision == "confirmed" and epistemic != "proven_real":
            missing.append("confirmed 必须对应 proven_real")
        if decision == "rejected" and epistemic != "proven_false":
            missing.append("rejected 必须对应 proven_false")
        if decision == "rejected" and not cls._text(final.get("rejection_reason") or final.get("final_reason")
                                                    or final.get("reasoning")):
            missing.append("rejected 缺少 rejection_reason")
        return missing

    @staticmethod
    def _mark_vote(v: Optional[Dict[str, Any]], *, phase: str, lens: str,
                   model: str = "", validation_errors: Optional[List[str]] = None) -> Dict[str, Any]:
        out = dict(v) if isinstance(v, dict) else {}
        out["phase"] = phase
        out["verify_lens"] = lens
        if model:
            out["model"] = model
        errs = validation_errors or []
        out["validation_ok"] = not errs
        if errs:
            out["validation_reason"] = ";".join(errs)
        return out

    @staticmethod
    def _reset_candidate_for_retry(f: Dict[str, Any]) -> None:
        f["verify_status"] = "pending"
        f["verify_attempts"] = 0
        f.pop("verify_failure_reason", None)

    def _handle_candidate_verify_failure(self, f: Dict[str, Any], reason: str,
                                         votes: Optional[List[Dict[str, Any]]] = None) -> None:
        k = finding_key(f)
        self.pending_findings[k] = f
        self.dedup_keys.add(k)
        attempts = int(f.get("verify_attempts") or 0) + 1
        f["verify_attempts"] = attempts
        f["verify_failure_reason"] = reason

        if not self._in_final_failed_sweep and attempts <= max(0, int(self.cfg.retry.max_attempts)):
            f["verify_status"] = "pending"
            payload = {**self._candidate_payload(f), "status": "pending",
                       "reason": reason, "attempts": attempts}
            if votes:
                payload["votes"] = self._slim_verify_votes(votes)
                payload["verify_models"] = sorted({v.get("model") for v in votes if v.get("model")})
            self._save_candidate_state(payload)
            self._enqueue_finding(f)
            self.log(f"候选 {k} 验证失败({reason}),第 {attempts} 次失败后放回验证队列"
                     f"(重试上限 {self.cfg.retry.max_attempts})")
            self.checkpoint(self.round)
            return

        f["verify_status"] = "verify_failed"
        payload = self._candidate_failed_payload(f, reason, votes)
        self._save_candidate_state(payload)
        self.emit(EV.CANDIDATE_FAILED, payload)
        self.log(f"候选 {k} 验证失败({reason}),标记为 verify_failed"
                 f"{'(最终补跑)' if self._in_final_failed_sweep else ''}")
        self.checkpoint(self.round)

    async def process_finding(self, f: Dict[str, Any]) -> None:
        k = finding_key(f)
        try:
            if k in self.processed_keys:
                self.pending_findings.pop(k, None)
                return
            f["verify_status"] = "pending"
            self.dedup_keys.add(k)

            title = (f.get("title") or "")[:24]
            witness_meta: Dict[str, Any] = {}
            raw_witness = await self.runner.run(
                self.pb.verify_witness(f, S.VERIFY_WITNESS_SCHEMA),
                role="verify", label=f"verify-witness:{title}",
                schema=S.VERIFY_WITNESS_SCHEMA, meta=witness_meta,
            )
            witness_errors = self._validate_witness(raw_witness)
            witness_obj = raw_witness if isinstance(raw_witness, dict) else {}
            witness_vote = self._mark_vote(raw_witness, phase="witness", lens="正方 witness",
                                           model=witness_meta.get("model") or "",
                                           validation_errors=witness_errors)
            witness_vote["decision"] = "confirm" if witness_obj.get("witness_complete") else "inconclusive"
            witness_vote["is_real"] = bool(witness_obj.get("witness_complete"))

            blocker_meta: Dict[str, Any] = {}
            raw_blocker = await self.runner.run(
                self.pb.verify_blocker(f, witness_vote, S.VERIFY_BLOCKER_SCHEMA),
                role="verify", label=f"verify-blocker:{title}",
                schema=S.VERIFY_BLOCKER_SCHEMA, meta=blocker_meta,
            )
            blocker_errors = self._validate_blocker(raw_blocker)
            blocker_obj = raw_blocker if isinstance(raw_blocker, dict) else {}
            blocker_vote = self._mark_vote(raw_blocker, phase="blocker", lens="反方 blocker",
                                           model=blocker_meta.get("model") or "",
                                           validation_errors=blocker_errors)
            blocker_vote["decision"] = "reject" if blocker_obj.get("blocker_found") else "inconclusive"
            blocker_vote["is_real"] = False
            votes = [witness_vote, blocker_vote]

            witness_judge_meta: Dict[str, Any] = {}
            blocker_judge_meta: Dict[str, Any] = {}
            raw_witness_review, raw_blocker_review = await asyncio.gather(
                self.runner.run(
                    self.pb.verify_witness_judge(f, witness_vote, blocker_vote, S.WITNESS_REVIEW_SCHEMA),
                    role="verify", label=f"verify-witness-judge:{title}",
                    schema=S.WITNESS_REVIEW_SCHEMA, meta=witness_judge_meta,
                ),
                self.runner.run(
                    self.pb.verify_blocker_judge(f, witness_vote, blocker_vote, S.BLOCKER_REVIEW_SCHEMA),
                    role="verify", label=f"verify-blocker-judge:{title}",
                    schema=S.BLOCKER_REVIEW_SCHEMA, meta=blocker_judge_meta,
                ),
            )
            witness_review_errors = self._validate_witness_review(raw_witness_review)
            witness_review_obj = raw_witness_review if isinstance(raw_witness_review, dict) else {}
            witness_review_vote = self._mark_vote(raw_witness_review, phase="witness_judge",
                                                  lens="质询 witness",
                                                  model=witness_judge_meta.get("model") or "",
                                                  validation_errors=witness_review_errors)
            wv = witness_review_obj.get("witness_verdict")
            witness_review_vote["decision"] = "confirm" if wv in ("accepted", "weakened") else ("reject" if wv == "rejected" else "inconclusive")
            witness_review_vote["is_real"] = wv in ("accepted", "weakened")

            blocker_review_errors = self._validate_blocker_review(raw_blocker_review)
            blocker_review_obj = raw_blocker_review if isinstance(raw_blocker_review, dict) else {}
            blocker_review_vote = self._mark_vote(raw_blocker_review, phase="blocker_judge",
                                                  lens="质询 blocker",
                                                  model=blocker_judge_meta.get("model") or "",
                                                  validation_errors=blocker_review_errors)
            bv = blocker_review_obj.get("blocker_verdict")
            blocker_review_vote["decision"] = "reject" if bv == "global_decisive" else "inconclusive"
            blocker_review_vote["is_real"] = False
            votes.extend([witness_review_vote, blocker_review_vote])

            final_meta: Dict[str, Any] = {}
            raw_final = await self.runner.run(
                self.pb.verify_final_adjudicator(
                    f, witness_vote, blocker_vote, witness_review_vote, blocker_review_vote,
                    S.FINAL_ADJUDICATION_SCHEMA,
                ),
                role="verify", label=f"verify-final:{title}",
                schema=S.FINAL_ADJUDICATION_SCHEMA, meta=final_meta,
            )
            final_errors = self._validate_final_adjudication(raw_final)
            final_obj = raw_final if isinstance(raw_final, dict) else {}
            final_vote = self._mark_vote(raw_final, phase="final_adjudicator", lens="终局裁判",
                                         model=final_meta.get("model") or "",
                                         validation_errors=final_errors)
            decision = (final_obj.get("operational_decision") or "").strip()
            final_vote["decision"] = "confirm" if decision == "confirmed" else ("reject" if decision == "rejected" else "inconclusive")
            final_vote["is_real"] = decision == "confirmed"
            votes.append(final_vote)
            if final_errors:
                self._handle_candidate_verify_failure(
                    f,
                    "终局裁判无有效工程决策:" + ";".join(final_errors),
                    votes,
                )
                return

            if decision == "rejected":
                self.processed_keys.add(k)
                self.pending_findings.pop(k, None)
                f["verify_status"] = "rejected"
                payload = self._candidate_rejected_payload(f, votes, final_vote)
                self._save_candidate_state(payload)
                self.emit(EV.FINDING_REJECTED, payload)
                return

            if decision in ("suppressed_unproven", "needs_manual_review"):
                self.processed_keys.add(k)
                self.pending_findings.pop(k, None)
                f["verify_status"] = decision
                quality_rec = self._record_quality_finding(f, votes, final_vote, decision)
                f["quality_finding_id"] = quality_rec.get("id")
                payload = self._candidate_decision_payload(f, decision, votes, final_vote)
                payload["id"] = quality_rec.get("id")
                payload["finding_status"] = quality_rec.get("finding_status")
                payload["tags"] = quality_rec.get("tags") or []
                payload["corrected_severity"] = quality_rec.get("corrected_severity")
                self._save_candidate_state(payload)
                self.emit(EV.CANDIDATE_DECIDED, payload)
                self.log(f"候选 {k} 终局决策:{decision} {f.get('title')}")
                self.checkpoint(self.round)
                return

            corrected = (final_vote.get("corrected_severity")
                         or witness_vote.get("corrected_severity")
                         or f.get("severity"))
            corrected = most_severe([corrected]) or f.get("severity")
            exploit = (final_vote.get("exploitability") or witness_vote.get("exploitability") or "")
            self.seq += 1
            fid = f"{class_code(f.get('bug_class'))}-{pad3(self.seq)}"
            verify_models = sorted({v["model"] for v in votes if v.get("model")})
            rec = {**f, "id": fid, "corrected_severity": corrected, "exploitability": exploit,
                   "votes": votes, "verify_models": verify_models}

            poc = None
            if self.cfg.enable_poc and corrected in ("critical", "high"):
                poc = await self.run_poc(rec)
                if poc:
                    self.emit(EV.POC_DONE, {"id": fid, "compiled": poc.get("compiled"), "triggered": poc.get("triggered")})

            body = await self.runner.run(self.pb.report_body(rec, poc),
                                         role="report", label=f"report:{fid}", schema=None, fallback=None)
            rec["report_body"] = body or ""
            rec["report_failed"] = not body
            rec["poc"] = poc
            rec["output_ts"] = time.time()
            self.confirmed.append(rec)
            self.store.save_finding(rec)            # 流式:确认即写 findings/<id>.json
            self.processed_keys.add(k)
            self.pending_findings.pop(k, None)
            cand = {**self._candidate_payload(rec), "status": "confirmed", "id": fid,
                    "severity": corrected, "corrected_severity": corrected,
                    "verify_models": verify_models}
            self._save_candidate_state(cand)
            self.emit(EV.FINDING_CONFIRMED, slim_finding(rec))
            confirmed_real = sum(1 for c in self.confirmed if not is_quality_issue_finding(c))
            self.log(f"✔ 确认漏洞 {fid} [{corrected}] {rec.get('title')} (累计 {confirmed_real})")
        except Exception as e:  # noqa: BLE001
            self.log(f"⚠ process_finding 异常,候选验证稍后重试: {str(e)[:140]}")
            try:
                self._handle_candidate_verify_failure(f, f"验证流水线异常:{str(e)[:120]}")
            except Exception:
                pass

    # ──────────────────────── PoC(隔离工作目录副本) ────────────────────────
    def _poc_lock_get(self) -> asyncio.Lock:
        if self._poc_lock is None:
            self._poc_lock = asyncio.Lock()
        return self._poc_lock

    def _reset_poc_worktree(self) -> None:
        """把复用的 PoC worktree 恢复到干净 HEAD,清掉上一条 PoC 留下的产物(含未跟踪/被忽略文件)。
        既防 worktree 自身占盘膨胀,也避免这些产物被 opencode 每步快照吞进去撑大快照仓。"""
        wt = self._poc_worktree
        if not wt or not os.path.isdir(wt):
            return
        try:
            subprocess.run(["git", "-C", wt, "reset", "--hard", "HEAD"],
                           capture_output=True, text=True)
            subprocess.run(["git", "-C", wt, "clean", "-fdx"],
                           capture_output=True, text=True)
        except Exception:  # noqa: BLE001 —— 清理失败不影响 PoC 本身
            pass

    def _ensure_poc_worktree(self) -> str:
        """惰性创建并全 run 复用一个 PoC 专用 git worktree;返回可用 cwd(失败回退主仓目录)。

        路径稳定让 opencode/codex 把它当同一个项目:一次性 DB 迁移 + 全量快照只在首条 PoC 付一次,
        后续 PoC 走增量。复用前先重置干净,保证每条 PoC 从同一基线开跑。"""
        target = self._abs_target()
        if self._poc_worktree_disabled:
            return target
        if self._poc_worktree and os.path.isdir(self._poc_worktree):
            self._reset_poc_worktree()   # 复用:先清干净
            return self._poc_worktree
        is_git = subprocess.run(["git", "-C", target, "rev-parse", "--is-inside-work-tree"],
                                capture_output=True, text=True).returncode == 0
        if not is_git:
            # 非 git 仓建不了 worktree:直接用主仓目录(opencode 仍只有一个稳定 cwd,不额外冷启动)
            self._poc_worktree_disabled = True
            return target
        try:
            wt = tempfile.mkdtemp(prefix="pvh-poc-")
            r = subprocess.run(["git", "-C", target, "worktree", "add", "--detach", wt, "HEAD"],
                               capture_output=True, text=True)
            if r.returncode == 0:
                self._poc_worktree = wt
                self.log(f"🧪 PoC 复用 worktree 就绪(全 run 共享,串行执行): {wt}")
                return wt
            self.log(f"⚠ 创建 PoC worktree 失败,PoC 退回主仓目录: {r.stderr.strip()[:120]}")
            shutil.rmtree(wt, ignore_errors=True)
        except Exception as e:  # noqa: BLE001
            self.log(f"⚠ PoC worktree 异常,退回主仓目录: {str(e)[:120]}")
        self._poc_worktree_disabled = True
        return target

    def _cleanup_poc_worktree(self) -> None:
        """run 收尾:移除复用的 PoC worktree(git 注册 + 目录),并 prune 掉历史死注册
        (含上次被 OOM 杀掉、没来得及收尾的 run 残留)。opencode 在数据目录下为该 cwd 生成的快照,
        仍由 AgentRunner._reap_opencode_artifacts 在后续 PoC 调用时按"最近活跃"滚动回收,这里不重复处理。"""
        wt = self._poc_worktree
        self._poc_worktree = None
        target = self._abs_target()
        try:
            if wt:
                subprocess.run(["git", "-C", target, "worktree", "remove", "--force", wt],
                               capture_output=True, text=True)
                shutil.rmtree(wt, ignore_errors=True)
            # 无论本 run 是否建过 worktree,都顺手 prune 一次,清掉历史残留的死注册
            subprocess.run(["git", "-C", target, "worktree", "prune"],
                           capture_output=True, text=True)
        except Exception:  # noqa: BLE001 —— 收尾失败不影响主流程
            pass

    async def run_poc(self, rec: Dict[str, Any]) -> Any:
        # 串行 + 复用同一 worktree:挡住并发冷启动的内存尖峰,并保护这个共享目录。
        async with self._poc_lock_get():
            cwd = self._ensure_poc_worktree()
            return await self.runner.run(self.pb.poc(rec, self.build_hint, S.POC_SCHEMA),
                                         role="poc", label=f"poc:{rec['id']}", schema=S.POC_SCHEMA, cwd=cwd)

    # ──────────────────────── 历史模式导入 ────────────────────────
    @staticmethod
    def _read_json_doc(path: str) -> Optional[Any]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _history_import_payload(self, source: str) -> List[Dict[str, Any]]:
        raw = os.path.abspath(os.path.expanduser(source or ""))
        if not raw:
            raise ValueError("history_import_from 为空")
        docs: List[Any] = []
        if os.path.isdir(raw):
            d = self._read_json_doc(os.path.join(raw, "history.json"))
            if d is not None:
                docs.append(d)
        elif os.path.isfile(raw):
            d = self._read_json_doc(raw)
            if d is not None:
                docs.append(d)
        else:
            raise ValueError(f"history_import_from 不存在: {source}")

        for d in docs:
            if isinstance(d, list):
                return [x for x in d if isinstance(x, dict)]
            if isinstance(d, dict) and isinstance(d.get("history"), list):
                return [x for x in d["history"] if isinstance(x, dict)]
        return []

    def _normalize_history_entry(self, raw: Dict[str, Any], *, source_hint: str = "") -> Optional[Dict[str, Any]]:
        if not isinstance(raw, dict):
            return None
        pattern = (raw.get("pattern") or "").strip()
        if not pattern:
            return None
        lens = raw.get("lens_hint") if raw.get("lens_hint") in self.cfg.lenses else "memory"
        files = raw.get("files") if isinstance(raw.get("files"), list) else []
        return {
            "pattern": pattern,
            "source": (raw.get("source") or source_hint or "imported").strip(),
            "lens_hint": lens,
            "files": [str(f) for f in files if str(f).strip()],
            "rationale": raw.get("rationale") or "",
        }

    def _record_history_entry(self, entry: Dict[str, Any], *, imported: bool = False) -> bool:
        entry = self._normalize_history_entry(entry, source_hint="imported") or {}
        pattern = (entry.get("pattern") or "").strip()
        if not pattern:
            return False
        pk = pattern.lower()
        if pk in self.history_keys:
            return False
        self.history_keys.add(pk)
        self.history.append(entry)
        self._enqueue_variant(entry)
        self.emit(EV.HISTORY_ADDED, {**entry, "total": len(self.history), "imported": imported})
        self.persist_history()
        prefix = "导入历史模式" if imported else "历史模式"
        self.log(f"🕮 {prefix} +1[{entry['lens_hint']}]:{pattern[:60]} ← {str(entry.get('source') or '')[:40]}")
        return True

    def import_history_patterns(self) -> int:
        source = self.cfg.history_import_from
        raw_items = self._history_import_payload(source)
        added = 0
        source_hint = f"imported:{os.path.basename(os.path.abspath(os.path.expanduser(source)).rstrip(os.sep)) or 'history'}"
        for raw in raw_items:
            entry = self._normalize_history_entry(raw, source_hint=source_hint)
            if entry and self._record_history_entry(entry, imported=True):
                added += 1
        if not raw_items or added == 0:
            raise ValueError(f"未能从 {source} 导入任何历史问题模式")
        self._history_enqueued = True
        self.persist_history()
        self.checkpoint(self.round)
        self.emit_coverage()
        self.log(f"🕮 已从 {source} 导入 {added} 条历史问题模式;跳过 git commit 分析")
        return added

    # ──────────────────────── 阶段 ① 威胁分析 / 断点恢复 ────────────────────────
    def restore_checkpoint(self) -> bool:
        """恢复断点机制态。成功后 history 挖掘可立即跳过已分析提交。"""
        if self._restored_checkpoint:
            return True
        ckpt = self.store.load_checkpoint() if self.cfg.resume else None
        threat_doc = self.store.load_threat_analysis() if self.cfg.resume else {}
        if ckpt and isinstance(ckpt.get("pendingQueue"), list):
            self.threat_graph = threat_doc or {}
            self.history = self.store.load_history() if self.cfg.resume else []
            self.seq = ckpt.get("seq", 0)
            self.risk_seq = ckpt.get("risk_seq", 0)
            self.start_round = ckpt.get("round", 0)
            self.confirmed = self.store.load_findings()            # 扫 findings/<id>.json 恢复
            for k in (ckpt.get("processedKeys") or []):
                self.dedup_keys.add(k)
                self.processed_keys.add(k)
            self.seen_surface.update(ckpt.get("seenSurface") or [])
            self.risk_keys.update(ckpt.get("riskKeys") or [])
            self.completed_items.update(ckpt.get("completedItems") or [])
            self.queue = ckpt.get("pendingQueue") or []
            self.pq = ckpt.get("pendingPriorityQueue") or []
            asf = self.store.load_attack_surface()
            self.surface_log = asf.get("surfaces") or []
            self.ledger_arr = asf.get("ledger") or []
            for r in self.ledger_arr:
                self.ledger_map[r["key"]] = r
            for f in (ckpt.get("pendingFindings") or []):
                fk = finding_key(f)
                self.pending_findings[fk] = f
                self.dedup_keys.add(fk)
            self.regions = asf.get("regions") or self.threat_graph.get("audit_items") or []
            for h in self.history:
                self.history_keys.add((h.get("pattern") or "").strip().lower())
            self.history_done.update(ckpt.get("historyDone") or [])
            self._enqueue_failed_rechecks()
            self.build_hint = ""
            quality_issues = sum(1 for c in self.confirmed if is_quality_issue_finding(c))
            confirmed_real = max(0, len(self.confirmed) - quality_issues)
            self.log(f"♻ 从断点恢复:已完成 {self.start_round} 轮,确认 {confirmed_real} 条,质量问题 {quality_issues} 条,待审队列 {len(self.queue)} 项,"
                     f"在途候选 {len(self.pending_findings)} 条,已处理 {len(self.processed_keys)} 个,已完成攻击面 {len(self.completed_items)} 个")
            if self.threat_graph:
                stats = self.threat_graph.get("stats") or {}
                self.emit(EV.THREAT_ANALYSIS_DONE, {"resumed": True, **stats,
                                                    "warnings": len(self.threat_graph.get("warnings") or [])})
            self.emit_coverage()
            self._restored_checkpoint = True
            return True
        return False

    async def threat_analysis(self, *, try_restore: bool = True) -> None:
        if try_restore and self.restore_checkpoint():
            return
        if self.cfg.resume:
            self.log("未找到可用断点,从头开始攻击树威胁分析")
        raw = await self.runner.run(self.pb.threat_analysis(S.THREAT_ANALYSIS_SCHEMA),
                                    role="threat", label="threat-analysis",
                                    schema=S.THREAT_ANALYSIS_SCHEMA, retry_forever=True,
                                    fallback=None, should_stop=self.stop_requested)
        if not raw and self.stop_requested():
            self.log("威胁分析阶段收到停止请求,不再继续")
            return
        if not isinstance(raw, dict):
            self.log("⚠ 威胁分析失败:未得到合法攻击树结构,本次不会产生审计项")
            raw = {"assets": [], "attack_trees": [], "code_path_mappings": []}
        graph = TA.normalize(raw)
        self.threat_graph = graph
        self.regions = sorted(graph.get("audit_items") or [],
                              key=lambda r: ({"high": 0, "medium": 1, "low": 2}).get(r.get("priority"), 3))
        self.build_hint = ""
        for item in self.regions:
            self._enqueue_work(item)
        try:
            self.store.save_threat_analysis(graph, raw=raw)
        except Exception as e:  # noqa: BLE001
            self.log(f"⚠ 威胁分析图写入失败(忽略继续): {str(e)[:120]}")
        stats = graph.get("stats") or {}
        self.log("攻击树威胁分析完成:"
                 f"资产 {stats.get('assets', 0)} 个,攻击树 {stats.get('trees', 0)} 棵,"
                 f"攻击面 {stats.get('surfaces', 0)} 个,攻击方式 {stats.get('methods', 0)} 个,"
                 f"审计项 {stats.get('audit_items', 0)} 个")
        if graph.get("warnings"):
            self.log(f"⚠ 威胁分析规范化告警 {len(graph.get('warnings') or [])} 条,详见 threat-analysis/warnings.json")
        self.emit(EV.THREAT_ANALYSIS_DONE, {**stats, "warnings": len(graph.get("warnings") or [])})
        self.checkpoint(0)
        self.emit_coverage()

    def _mark_retry_after_failure(self, item: Dict[str, Any]) -> int:
        n = int(item.get("retry_after_failure") or 0) + 1
        item["retry_after_failure"] = n
        return n

    @staticmethod
    def _clear_retry_after_failure(item: Dict[str, Any]) -> None:
        item.pop("retry_after_failure", None)

    @staticmethod
    def _queue_retry_only(queue: List[Dict[str, Any]]) -> bool:
        return bool(queue) and all(bool(it.get("retry_after_failure")) for it in queue)

    # ──────── git 历史问题模式挖掘(每条提交一个 agent,与 high audit finder 同级调度)────────
    def _collect_commits(self) -> List[Dict[str, str]]:
        """读取 git log 提交清单(hash + 标题)。非 git 仓 / 出错 → 空列表。"""
        target = self._abs_target()
        if subprocess.run(["git", "-C", target, "rev-parse", "--is-inside-work-tree"],
                          capture_output=True, text=True).returncode != 0:
            return []
        cmd = ["git", "-C", target, "log", "--no-merges", "--format=%H%x1f%s"]
        if self.cfg.history.max_commits > 0:
            cmd.append(f"-n{self.cfg.history.max_commits}")
        if self.cfg.history.since:
            cmd.append(f"--since={self.cfg.history.since}")
        paths = self.cfg.history.paths or self.cfg.scope
        if paths:
            cmd.append("--")
            cmd.extend(paths.split())
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except Exception:  # noqa: BLE001
            return []
        if r.returncode != 0:
            return []
        out: List[Dict[str, str]] = []
        for line in r.stdout.splitlines():
            h, sep, subj = line.partition("\x1f")
            h = h.strip()
            if h:
                out.append({"hash": h, "subject": subj.strip()})
        return out

    def _history_active(self) -> bool:
        return self._history_task is not None and not self._history_task.done()

    def _start_history_mining(self) -> None:
        """兼容旧调用点:现在只把 history commit 投进统一优先级队列。"""
        self._enqueue_history_commits()

    def _enqueue_history_commits(self) -> None:
        """把 git log 分析任务投进统一优先级队列,与 high audit finder 同级排队。"""
        if self.cfg.history_import_from:
            self._history_enqueued = True
            return
        if self._history_enqueued or not self.cfg.history.enabled:
            return
        self._history_enqueued = True
        commits = self._collect_commits()
        if not commits:
            self.log("🕮 git 历史挖掘:非 git 仓或无匹配提交,跳过该阶段")
            return
        todo = [c for c in commits if c["hash"] not in self.history_done]
        if not todo:
            self.log("🕮 git 历史挖掘:所有提交均已分析过(断点),跳过")
            return
        for c in todo:
            self._enqueue_work({"kind": "_history_commit", "commit": c, "priority": "high"})
        self.log(f"🕮 git 历史挖掘入队:{len(todo)}/{len(commits)} 条提交待分析"
                 "(与 high audit finder 同优先级参与统一调度)")

    async def mine_git_history(self) -> None:
        self._enqueue_history_commits()

    async def _mine_one_commit(self, c: Dict[str, str], bypass: bool = True) -> None:
        res = await self.runner.run(
            self.pb.history_commit(c, S.HISTORY_COMMIT_SCHEMA),
            role="history", label=f"history:{c['hash'][:8]}",
            schema=S.HISTORY_COMMIT_SCHEMA, retries=1, fallback=None,
            use_global_gate=not bypass)
        self.history_done.add(c["hash"])
        if not res or not res.get("security_related"):
            return
        pattern = (res.get("pattern") or "").strip()
        if not pattern:
            return
        lens = res.get("lens_hint") if res.get("lens_hint") in self.cfg.lenses else None
        source = (f"{c['hash'][:10]} {c['subject']}").strip()[:120]
        entry = {"pattern": pattern, "source": source, "lens_hint": lens or "memory",
                 "files": res.get("files") or [], "rationale": res.get("rationale") or ""}
        self._record_history_entry(entry)

    def _start_audit_pass(self, item: Dict[str, Any]) -> None:
        ik = item_key(item)
        if ik in self.completed_items:
            return
        self.round += 1
        item["pass"] = (item.get("pass") or 0) + 1
        item["newThisRound"] = 0
        item["newSurfacesThisRound"] = 0
        item["failedFinders"] = 0
        rec = self.ledger_rec(item)
        rec["passes"] = item["pass"]
        rec["lastRound"] = self.round
        rec["status"] = "in-progress"
        audit_id = f"{ik}#{item['pass']}#{self.round}"
        lenses = self.lenses_for(item)
        pending = 0
        for lens_key in lenses:
            if lens_key not in rec["lenses"]:
                rec["lenses"].append(lens_key)
            for i in range(self.cfg.finders_per_lens):
                self._enqueue_work({
                    "kind": "_finder",
                    "audit_id": audit_id,
                    "item": item,
                    "lens_key": lens_key,
                    "idx": i,
                    "priority": item.get("priority"),
                })
                pending += 1
        self._audit_passes[audit_id] = {"item": item, "rec": rec, "pending": pending}
        self.emit(EV.ROUND_START, {"round": self.round, "queue_len": len(self.queue)})
        if pending == 0:
            self._finish_audit_pass(audit_id)

    async def _run_finder_job(self, work: Dict[str, Any]) -> None:
        audit_id = work.get("audit_id")
        st = self._audit_passes.get(audit_id)
        if not st:
            return
        item = st["item"]
        rec = st["rec"]
        try:
            await self._run_finder(item, work.get("lens_key") or "memory", int(work.get("idx") or 0), rec)
        except Exception as e:  # noqa: BLE001
            item["failedFinders"] = item.get("failedFinders", 0) + 1
            self.log(f"⚠ finder 调度异常,审计项稍后重试: {str(e)[:140]}")
        finally:
            st["pending"] = max(0, int(st.get("pending") or 0) - 1)
            if st["pending"] == 0:
                self._finish_audit_pass(audit_id)

    def _finish_audit_pass(self, audit_id: str) -> None:
        st = self._audit_passes.pop(audit_id, None)
        if not st:
            return
        item = st["item"]
        rec = st["rec"]
        ik = item_key(item)
        if ik in self.completed_items:
            return
        new_findings = int(item.get("newThisRound") or 0)
        new_surfaces = int(item.get("newSurfacesThisRound") or 0)
        failed = int(item.get("failedFinders") or 0) > 0
        if failed:
            self._mark_retry_after_failure(item)
            self._refresh_enqueue_order(item)
            self.queue.append(item)
            rec["status"] = "incomplete"
            if item.get("pass", 0) >= self.cfg.max_rounds:
                self._retrying_past_max_rounds = True
            self.log("本轮有 1 个审计项因后端/结构化输出连续失败被放回队尾,稍后继续重试")
        elif new_findings > 0 and item["pass"] < self.cfg.max_rounds:
            self._clear_retry_after_failure(item)
            self._refresh_enqueue_order(item)
            self.queue.append(item)
            rec["status"] = "in-progress"
        else:
            self._clear_retry_after_failure(item)
            self.completed_items.add(ik)
            rec["status"] = "completed-findings" if rec.get("candidates", 0) > 0 else "completed-clean"
        dry_streak = 0 if (new_findings or new_surfaces) else 1
        self.log(f"轮 {self.round}: 本项新候选 {new_findings}, 新攻击面 {new_surfaces}, 队列剩 {len(self.queue)}, "
                 f"优先复查队列 {len(self.pq)}")
        self.emit(EV.ROUND_DONE, {"round": self.round, "new_findings": new_findings, "new_surfaces": new_surfaces,
                                  "queue_len": len(self.queue), "dry_streak": dry_streak, "risks": 0})
        self.emit(EV.METRICS, self._summary_snapshot(self.round))
        self.checkpoint(self.round)
        self.emit_coverage()

    def _pop_next_work(self) -> Optional[Dict[str, Any]]:
        self._ensure_queue_order()
        if self.cfg.recheck.enabled and self.pq and self._active_roles.get("recheck", 0) < self._recheck_concurrency_limit():
            probe = {"kind": "_recheck"}
            if self._can_dispatch_work(probe):
                it = self._pop_priority()
                if it is not None:
                    self._refresh_enqueue_order(probe)
                    probe["item"] = it
                    return probe

        while True:
            if not self.queue:
                return None
            ordered = sorted(enumerate(self.queue), key=lambda x: self._work_sort_key(x[1]))
            expanded = False
            for idx, item in ordered:
                kind = item.get("kind")
                if kind in ("task", "surface", "attack_method"):
                    self.queue.pop(idx)
                    self._start_audit_pass(item)
                    expanded = True
                    break
                if item_key(item) in self.completed_items and kind not in self._INTERNAL_KINDS:
                    self.queue.pop(idx)
                    expanded = True
                    break
                if self._can_dispatch_work(item):
                    return self.queue.pop(idx)
            if not expanded:
                return None

    async def _run_work(self, work: Dict[str, Any], role: Optional[str] = None) -> None:
        try:
            kind = work.get("kind")
            if kind == "_finder":
                await self._run_finder_job(work)
                return
            if kind == "_finding":
                f = work.get("finding") or {}
                if f:
                    await self.process_finding(f)
                return
            if kind == "_history_commit":
                c = work.get("commit") or {}
                if c:
                    await self._mine_one_commit(c, bypass=False)
                return
            if kind == "_recheck":
                self._recheck_inflight += 1
                try:
                    await self._run_recheck(work.get("item") or {}, use_global_gate=True)
                finally:
                    self._recheck_inflight -= 1
                return
        finally:
            if role:
                self._active_roles[role] = max(0, self._active_roles.get(role, 0) - 1)

    async def _run_scheduler(self, *, stop_when: Optional[Callable[[], bool]] = None,
                             stop_when_idle: bool = True,
                             extra_pending: Optional[Callable[[], bool]] = None) -> None:
        """统一调度循环。

        stop_when 用于威胁分析并行窗口:条件满足后不再启动新工作,但会等待已启动工作收尾;
        stop_when_idle=True 用于正式审计阶段:队列和在途项都清空后退出。
        """
        active: List[asyncio.Task] = []
        while not self.stop_requested():
            done_now = [t for t in active if t.done()]
            active = [t for t in active if not t.done()]
            for t in done_now:
                try:
                    t.result()
                except asyncio.CancelledError:
                    pass
                except Exception as e:  # noqa: BLE001
                    self.log(f"⚠ 调度工作项异常(忽略继续): {str(e)[:160]}")

            may_start = stop_when is None or not stop_when()
            made_progress = False
            while may_start and len(active) < self.cfg.concurrency:
                work = self._pop_next_work()
                if work is None:
                    break
                role = self._work_role(work)
                if role:
                    self._active_roles[role] = self._active_roles.get(role, 0) + 1
                active.append(asyncio.create_task(self._run_work(work, role)))
                made_progress = True
                may_start = stop_when is None or not stop_when()

            if active:
                timeout = 0.25 if may_start and (len(active) < self.cfg.concurrency or self.queue or self.pq) else None
                await self._wait_active_or_wake(active, may_start=may_start, timeout_s=timeout)
                continue

            if stop_when is not None and stop_when():
                break

            has_pending = bool(self.queue or self.pq or self._audit_passes or self._recheck_inflight
                               or (extra_pending is not None and extra_pending()))
            if has_pending:
                await self._sleep_or_wake(min(self.cfg.history.poll_interval_s, self.cfg.recheck.poll_interval_s, 1))
                continue
            if stop_when_idle:
                break
            await asyncio.sleep(0.1)

        if active:
            if self.stop_requested():
                for t in active:
                    t.cancel()
            await asyncio.gather(*active, return_exceptions=True)

    # ──────────────────────── 阶段 ② 审计循环 ────────────────────────
    async def audit(self) -> str:
        for f in list(self.pending_findings.values()):
            if self._is_candidate_failed(f):
                self._reset_candidate_for_retry(f)
            self._enqueue_finding(f)
        if self.pending_findings:
            self.log(f"续跑:重注入 {len(self.pending_findings)} 条在途候选到验证/报告流水线")

        self.round = self.start_round
        self._retrying_past_max_rounds = False
        self._enqueue_history_commits()

        await self._run_scheduler(stop_when_idle=True, extra_pending=self._history_active)
        final_sweep_enqueued = 0
        if not self.stop_requested():
            final_sweep_enqueued = self._enqueue_final_failed_sweep()  # 内部自标 _final_failed_sweep_done
            if final_sweep_enqueued:
                self.log(f"最终补跑:重新入队 {final_sweep_enqueued} 个失败候选/复查项")
                self._in_final_failed_sweep = True
                try:
                    await self._run_scheduler(stop_when_idle=True, extra_pending=self._history_active)
                finally:
                    self._in_final_failed_sweep = False
        else:
            self._final_failed_sweep_done = True
        if not self.queue and not self.pq and not self._audit_passes and not self._recheck_inflight:
            self.log(f"轮 {self.round}: 工作队列已空且无新攻击面回灌")

        incomplete = self._incomplete_counts()
        if self.stop_requested():
            stop_reason = "用户请求停止"
        elif self._has_incomplete_counts(incomplete):
            bits = []
            if incomplete["failed_candidates"]:
                bits.append(f"候选验证失败 {incomplete['failed_candidates']} 条")
            if incomplete["pending_findings"]:
                bits.append(f"候选仍待验证 {incomplete['pending_findings']} 条")
            if incomplete["failed_rechecks"]:
                bits.append(f"复查失败 {incomplete['failed_rechecks']} 项")
            if incomplete["pending_queue"] or incomplete["pending_priority_queue"]:
                bits.append(f"队列残留 {incomplete['pending_queue'] + incomplete['pending_priority_queue']} 项")
            stop_reason = "未完整覆盖:" + "、".join(bits)
        elif self._retrying_past_max_rounds and not self.queue:
            stop_reason = f"达到 maxRounds({self.cfg.max_rounds});失败重试队列已补审完成"
        else:
            suffix = ";失败项最终补跑完成" if final_sweep_enqueued else ""
            stop_reason = f"工作队列排空{suffix}"
        # 优先排查通道已统一并入主调度器(_run_scheduler):上面的 stop_when_idle 收敛时
        # pq 与在途复查必然已排空(失败项有上限重排后会终结),无需再单独等待专用 recheck 任务。
        self.log(f"审计循环结束:{stop_reason}。等待 {len(self.in_flight)} 条流水线(验证/PoC/报告)排空…")
        await asyncio.gather(*self.in_flight, return_exceptions=True)
        self.checkpoint(self.round)
        self.emit_coverage()
        quality_issues = sum(1 for c in self.confirmed if is_quality_issue_finding(c))
        confirmed_real = max(0, len(self.confirmed) - quality_issues)
        self.log(f"流水线排空完成:确认 {confirmed_real} 条漏洞,质量问题 {quality_issues} 条,候选去重池 {len(self.dedup_keys)} 条,"
                 f"动态攻击面 {len(self.surface_log)} 个。")
        return stop_reason

    async def _run_finder(self, item: Dict[str, Any], lens_key: str, idx: int, rec: Dict[str, Any]) -> None:
        if self.stop_requested():
            item["failedFinders"] = item.get("failedFinders", 0) + 1
            return
        meta: Dict[str, Any] = {}
        res = await self.runner.run(
            self.pb.audit(item, lens_key, idx, S.FINDINGS_SCHEMA),
            role="audit",
            label=f"audit:{str(item.get('objective') or item.get('name') or item.get('pattern') or 'item')[:20]}:{lens_key}#{item['pass']}.{idx + 1}",
            schema=S.FINDINGS_SCHEMA,
            should_stop=self.stop_requested, meta=meta)
        if not res:
            item["failedFinders"] = item.get("failedFinders", 0) + 1
            return
        self._consume(res, item, rec, lens_key, audit_model=meta.get("model"))

    @staticmethod
    def _finder_result(res: Any) -> Dict[str, Any]:
        if isinstance(res, dict):
            return res
        if isinstance(res, list):
            return {"findings": res}
        raise ValueError(f"finder 输出应为 JSON object,实际 {type(res).__name__}")

    @staticmethod
    def _finder_result_array(res: Dict[str, Any], key: str, *, required: bool = False) -> List[Dict[str, Any]]:
        if key not in res:
            if required:
                raise ValueError(f"finder 输出缺少必需字段 {key}")
            return []
        value = res.get(key)
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError(f"finder 输出字段 {key} 应为 list,实际 {type(value).__name__}")
        for i, item in enumerate(value):
            if not isinstance(item, dict):
                raise ValueError(f"finder 输出字段 {key}[{i}] 应为 object,实际 {type(item).__name__}")
        return value

    def _consume(self, res: Any, item: Dict[str, Any], rec: Dict[str, Any],
                 lens_key: str, from_recheck: bool = False, audit_model: Optional[str] = None) -> None:
        """消化一次审计 / 复查 agent 的结果:findings→验证流水线、new_surfaces→主队列、risk_notes→即时复查。
        from_recheck=True 时,产出的 risk_notes 不再二次回灌优先队列(防自激)。
        audit_model:产出该批 finding 的模型,归因到候选(随候选流转到验证/确认/报告)。"""
        res = self._finder_result(res)
        findings = self._finder_result_array(res, "findings", required=True)
        new_surfaces = self._finder_result_array(res, "new_surfaces")
        risk_notes = self._finder_result_array(res, "risk_notes")
        for f in findings:
            fk = finding_key(f)
            if fk in self.dedup_keys:
                continue
            self.dedup_keys.add(fk)
            if audit_model:
                f["audit_model"] = audit_model
            if item.get("kind") == "attack_method":
                ctx = item.get("attack_context") or {}
                f["attack_context"] = ctx
                if not (f.get("variant_of") or "").strip():
                    f["variant_of"] = "攻击树审计 " + " / ".join(
                        str(x) for x in [ctx.get("asset_name"), ctx.get("attack_goal"),
                                          ctx.get("surface"), ctx.get("method")] if x)
            # 历史问题变体排查命中:回填它"和哪个历史问题类似"(agent 未填则用模式/出处兜底)
            if from_recheck and item.get("kind") == "variant" and not (f.get("variant_of") or "").strip():
                src = (item.get("source") or "").strip()
                f["variant_of"] = (item.get("pattern") or "").strip() + (f"(出处:{src})" if src else "")
            if from_recheck and item.get("kind") == "risk":
                if item.get("id"):
                    f["risk_id"] = item.get("id")
                if item.get("area"):
                    f["risk_area"] = item.get("area")
                if not (f.get("variant_of") or "").strip():
                    f["variant_of"] = "风险点 " + " · ".join(
                        str(x) for x in [item.get("id"), item.get("area")] if x)
            item["newThisRound"] = item.get("newThisRound", 0) + 1
            rec["candidates"] = rec.get("candidates", 0) + 1
            self.pending_findings[fk] = f
            f["lens"] = lens_key
            payload = {**self._candidate_payload(f), "status": "pending"}
            self._save_candidate_state(payload)
            self.emit(EV.CANDIDATE_FOUND, payload)
            self._enqueue_finding(f)
        for s in new_surfaces:
            sk = (s.get("name") or "").strip().lower()
            if not sk or sk in self.seen_surface:
                continue
            self.seen_surface.add(sk)
            item["newSurfacesThisRound"] = item.get("newSurfacesThisRound", 0) + 1
            rec["surfaces"] = rec.get("surfaces", 0) + 1
            self._enqueue_work({"kind": "surface", "name": s.get("name"), "why": s.get("why"),
                                "files": s.get("files"), "lens_hint": s.get("lens_hint")})
            entry = {"name": s.get("name"), "why": s.get("why"), "files": s.get("files"),
                     "lens_hint": s.get("lens_hint") or lens_key, "round": self.round, "from": rec.get("name")}
            self.surface_log.append(entry)
            self.emit(EV.SURFACE_ADDED, entry)
        for n in risk_notes:
            if self.record_risk(n, lens_key, self.round, from_recheck=from_recheck):
                rec["risks"] = rec.get("risks", 0) + 1

    # ──────── 专用优先排查:历史变体 + 风险点复查(统一调度队列中的最高优先级)────────
    def _enqueue_variant(self, entry: Dict[str, Any]) -> None:
        """git 历史挖掘提炼出的问题模式 → 进优先排查队列(同类变体排查)。"""
        self.pq.append({"kind": "variant", "pattern": entry["pattern"], "source": entry["source"],
                        "files": entry["files"], "lens_hint": entry["lens_hint"]})
        self._notify_scheduler()
        self.emit(EV.RECHECK_ENQUEUED, {"kind": "variant", "pattern": entry["pattern"],
                                        "lens_hint": entry["lens_hint"]})

    def _variant_item_for_ledger(self, rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pattern = (rec.get("name") or str(rec.get("key") or "").replace("variant:", "", 1)).strip()
        if not pattern:
            return None
        hist = next((h for h in self.history
                     if (h.get("pattern") or "").strip().lower() == pattern.lower()), None)
        return {
            "kind": "variant",
            "pattern": pattern,
            "source": (hist or {}).get("source") or rec.get("source") or "",
            "files": (hist or {}).get("files") or [],
            "lens_hint": (hist or {}).get("lens_hint") or (rec.get("lenses") or ["memory"])[0],
        }

    def _risk_item_for_ledger(self, rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        rid = str(rec.get("key") or "").replace("risk:", "", 1).strip() or str(rec.get("id") or "").strip()
        area = (rec.get("risk_area") or rec.get("name") or "").strip()
        if not rid or not area:
            return None
        return {
            "kind": "risk", "id": rid, "area": area,
            "note": rec.get("risk_note") or "", "file": rec.get("file") or "",
            "severity_hint": rec.get("severity_hint") or "info",
            "lens": (rec.get("lenses") or ["memory"])[0],
            "callee": rec.get("callee") or "",
            "required_validation": rec.get("required_validation") or "",
            "good_validation_ref": rec.get("good_validation_ref") or "",
        }

    def _enqueue_failed_rechecks(self) -> int:
        enqueued = 0
        pq_keys = {item_key(it) for it in self.pq}
        for rec in self.ledger_arr:
            if rec.get("kind") not in ("risk", "variant") or rec.get("status") != "abandoned":
                continue
            item = self._variant_item_for_ledger(rec) if rec.get("kind") == "variant" else self._risk_item_for_ledger(rec)
            if not item:
                continue
            key = item_key(item)
            if key in pq_keys:
                continue
            self.completed_items.discard(key)
            rec["status"] = "pending"
            if item.get("kind") == "risk":
                self._enqueue_risk(item)
            else:
                self._enqueue_variant(item)
            pq_keys.add(key)
            enqueued += 1
        return enqueued

    def _enqueue_final_failed_sweep(self) -> int:
        if self._final_failed_sweep_done or self.stop_requested():
            return 0
        # 自身即标记本次 invocation 的 final sweep 已发起,保证“最多一次”的语义不依赖调用方,
        # 避免被重复调用时把失败项重复回灌、再次拖住流水线。
        self._final_failed_sweep_done = True
        enqueued = 0
        for f in list(self.pending_findings.values()):
            if not self._is_candidate_failed(f):
                continue
            self._reset_candidate_for_retry(f)
            self._enqueue_finding(f)
            enqueued += 1
        enqueued += self._enqueue_failed_rechecks()
        if enqueued:
            self.checkpoint(self.round)
            self.emit_coverage()
        return enqueued

    def _pop_priority(self) -> Optional[Dict[str, Any]]:
        """取下一个优先项:历史变体(variant)优先于风险点(risk);跳过已完成的。"""
        while self.pq:
            idx = next((i for i, it in enumerate(self.pq) if it.get("kind") == "variant"), 0)
            it = self.pq.pop(idx)
            if item_key(it) in self.completed_items:
                continue
            return it
        return None

    def _handle_recheck_failure(self, item: Dict[str, Any], rec: Dict[str, Any],
                                kind: Optional[str], rid: Optional[str], label: str) -> None:
        """一条优先排查项的 agent 失败后的处理:有上限地重排,超限则放弃。

        关键不变量:无论后端怎么持续失败,这一项都会在有限次后**终结**(完成或放弃),
        从而 `pq`/`_recheck_inflight` 必然清零、管线必然收敛,失败的复查不会拖住其它 agent。
        用户请求停止导致的失败不计入重试上限——保留排队态,留待续跑。
        """
        if self.stop_requested():
            rec["status"] = "incomplete"
            self.pq.append(item)
            self._notify_scheduler()
            return

        if self._in_final_failed_sweep:
            attempts = self._mark_retry_after_failure(item)
            self._abandon_recheck_item(item, rec, kind, rid, label, attempts,
                                       reason="最终补跑仍失败")
            return

        attempts = self._mark_retry_after_failure(item)
        if attempts <= max(0, self.cfg.recheck.max_retries):
            rec["status"] = "incomplete"
            self.pq.append(item)
            self._notify_scheduler()
            self.emit(EV.RECHECK_ENQUEUED, {"kind": kind, "id": rid, "pattern": item.get("pattern"),
                                            "label": label, "retry": True, "attempt": attempts})
            self.checkpoint(self.round)
            self.emit_coverage()
            self.log(f"优先排查项 {label} 第 {attempts} 次失败,放回队尾稍后重试"
                     f"(上限 {self.cfg.recheck.max_retries})")
            return

        # 超过重排上限 → 放弃该项:标记完成(后续由 final sweep 或显式续跑再补排)。
        self._abandon_recheck_item(item, rec, kind, rid, label, attempts,
                                   reason=f"超过重试上限 {self.cfg.recheck.max_retries}")

    def _abandon_recheck_item(self, item: Dict[str, Any], rec: Dict[str, Any],
                              kind: Optional[str], rid: Optional[str], label: str,
                              attempts: int, *, reason: str) -> None:
        self._clear_retry_after_failure(item)
        self.completed_items.add(item_key(item))
        rec["status"] = "abandoned"
        self.emit(EV.RECHECK_DONE, {"kind": kind, "id": rid, "pattern": item.get("pattern"),
                                    "label": label, "abandoned": True, "attempts": attempts,
                                    "reason": reason})
        self.log(f"⚠ 优先排查项 {label} 连续失败 {attempts} 次({reason}),"
                 "标记为未覆盖失败项")
        self.checkpoint(self.round)
        self.emit_coverage()

    async def _run_recheck(self, item: Dict[str, Any], *, use_global_gate: bool = True) -> None:
        if self.stop_requested():
            return
        kind = item.get("kind")
        rid = item.get("id")
        rec = self.ledger_rec(item)
        rec["status"] = "in-progress"
        rec["passes"] = rec.get("passes", 0) + 1
        rec["lastRound"] = self.round
        item["pass"] = item.get("pass", 0) + 1
        item["newThisRound"] = 0
        item["newSurfacesThisRound"] = 0
        if kind == "variant":
            lens_key = item.get("lens_hint") if item.get("lens_hint") in self.cfg.lenses else "memory"
            prompt = self.pb.audit(item, lens_key, 0, S.FINDINGS_SCHEMA)
            label = f"recheck:variant:{str(item.get('pattern') or '')[:24]}"
        else:
            lens_key = item.get("lens") if item.get("lens") in self.cfg.lenses else "memory"
            prompt = self.pb.recheck_risk(item, S.FINDINGS_SCHEMA)
            label = f"recheck:risk:{str(item.get('area') or rid or '')[:24]}"
        if lens_key not in rec["lenses"]:
            rec["lenses"].append(lens_key)
        # recheck 用「快速失败」模式跑:单次调用不在 runner 内部做长退避(retries=0),
        # 失败后的重试改由优先队列层面**有上限地**重排(见下)。这样一条卡住/失败的复查
        # 既不会在退避期间一直占着唯一的 recheck 名额、拖慢其它 agent,也不会无限重排导致管线永不收敛。
        meta: Dict[str, Any] = {}
        res = await self.runner.run(prompt, role="recheck", label=label, schema=S.FINDINGS_SCHEMA,
                                    retries=0, use_global_gate=use_global_gate,
                                    should_stop=self.stop_requested, meta=meta)
        if not res:
            self._handle_recheck_failure(item, rec, kind, rid, label)
            return
        self._clear_retry_after_failure(item)
        if res:
            self._consume(res, item, rec, lens_key, from_recheck=True, audit_model=meta.get("model"))
        self.completed_items.add(item_key(item))
        rec["status"] = "completed-findings" if rec.get("candidates", 0) > 0 else "completed-clean"
        self.checkpoint(self.round)
        self.emit_coverage()
        self.emit(EV.RECHECK_DONE, {"kind": kind, "id": rid, "pattern": item.get("pattern"), "label": label,
                                    "new_candidates": item.get("newThisRound", 0)})

    # ──────────────────────── 阶段 ③ 汇总(结构化,无文件写盘) ────────────────────────
    def synthesis(self, stop_reason: str) -> Dict[str, Any]:
        final = finalize_findings(self.confirmed)
        quality_issues = sum(1 for c in final if is_quality_issue_finding(c))
        confirmed_real = max(0, len(final) - quality_issues)
        counts: Dict[str, int] = {}
        for c in final:
            counts[c.get("bug_class")] = counts.get(c.get("bug_class"), 0) + 1
        top_sev = (final[0].get("corrected_severity") or final[0].get("severity")) if final else "none"
        incomplete_counts = self._incomplete_counts()
        has_incomplete = self._has_incomplete_counts(incomplete_counts)
        status = STATUS_STOPPED if self.stop_requested() else (STATUS_INCOMPLETE if has_incomplete else STATUS_DONE)
        converged = status == STATUS_DONE and self.round < self.cfg.max_rounds

        summary = {
            **self._summary_snapshot(self.round),
            "converged": converged, "stop_reason": stop_reason, "by_class": counts, "top_severity": top_sev,
            "confirmed": confirmed_real, "finding_entries": len(final),
            "quality_issues": quality_issues, "status": status, **incomplete_counts,
        }
        # 收尾:刷机制态 + 攻击面/覆盖快照(漏洞已即时落盘),并写最终汇总+状态
        self.store.save_checkpoint(self.build_checkpoint(self.round))
        self.store.save_attack_surface(self.build_attack_surface(self.round))
        self.store.update_summary(summary, status=status)

        result = {
            "run_id": self.store.id, "run_dir": self.store.dir,
            "target": self.cfg.target, "scope": self.cfg.scope or "(whole repo)",
            "threat_model": self.cfg.threat_model, "backend": self.cfg.backend,
            "methods_used": self.cfg.methods_ok(), "methods_dir": self.cfg.methods_abs,
            "dynamic_surfaces": len(self.surface_log), "risk_notes": 0,
            "resumed_from_round": self.start_round, "rounds": self.round,
            "converged": converged, "stop_reason": stop_reason, "candidates": len(self.dedup_keys),
            "attack_methods_total": sum(1 for r in self.ledger_arr if r.get("kind") == "attack_method"),
            "pending_findings": incomplete_counts["pending_findings"],
            "failed_candidates": incomplete_counts["failed_candidates"],
            "failed_rechecks": incomplete_counts["failed_rechecks"],
            "agents_spawned": self.runner.agent_count,
            "token_usage": dict(self.runner.usage_totals),
            "confirmed": confirmed_real, "finding_entries": len(final),
            "quality_issues": quality_issues, "by_class": counts, "status": status,
            "top_findings": [{"id": c.get("id"), "severity": c.get("corrected_severity") or c.get("severity"),
                              "bug_class": c.get("bug_class"), "title": c.get("title"),
                              "file": c.get("file"), "line": c.get("line", 0),
                              "tags": c.get("tags") or [],
                              "finding_status": c.get("finding_status") or ""} for c in final[:12]],
        }
        self.emit(EV.RUN_DONE, summary)
        return result

    # ──────────────────────── 总入口 ────────────────────────
    async def run(self) -> Dict[str, Any]:
        sn = self.pb.scope_note
        self.store.init_manifest(self.manifest_config())
        self.store.set_status(STATUS_RUNNING)
        self.emit(EV.RUN_STATUS, {"status": STATUS_RUNNING})
        self.log(f"目标={self.cfg.target}{sn} 模式={self.cfg.run_mode} 后端={self.cfg.backend} 并发={self.cfg.concurrency} "
                 f"攻击树威胁分析→攻击方式审计 每项finder={self.cfg.finders_per_lens} dryRounds={self.cfg.dry_rounds} "
                 f"maxRounds={self.cfg.max_rounds} 验证=witness/blocker(5-agent) PoC={self.cfg.enable_poc} "
                 f"resume={self.cfg.resume} 威胁模型={self.cfg.threat_model}")
        self.log(f"启用 lens: {', '.join(self.cfg.lenses)} | run 目录: {self.store.dir} | "
                 f"方法库: {self.cfg.methods_abs} ({'就绪' if self.cfg.methods_ok() else '不可用→内联兜底'})")
        history_sched: Optional[asyncio.Task] = None
        try:
            model_error = self.cfg.model_config_error()
            if model_error:
                raise ValueError(f"模型配置错误:{model_error}")
            resumed = self.restore_checkpoint()
            self._reconcile_health_models()  # 续跑/重启:剔除旧 health 快照里已不在当前配置的模型
            if self.cfg.health.enabled and self.cfg.health.on_start and not self.stop_requested():
                await self.health_check_all()
            if not resumed and self.cfg.history_import_from:
                self.import_history_patterns()

            if not resumed:
                threat_task = asyncio.create_task(self.threat_analysis(try_restore=False))
                await asyncio.sleep(0)
                self._enqueue_history_commits()
                history_sched = asyncio.create_task(
                    self._run_scheduler(stop_when=lambda: threat_task.done(), stop_when_idle=False)
                )
                self._history_task = history_sched
                try:
                    await threat_task
                except Exception:
                    if not history_sched.done():
                        history_sched.cancel()
                    await asyncio.gather(history_sched, return_exceptions=True)
                    raise
                stop_reason = await self.audit()
            else:
                stop_reason = await self.audit()
            if history_sched is not None:
                await history_sched
                if self._history_task is history_sched:
                    self._history_task = None
            result = self.synthesis(stop_reason)
            self.emit(EV.RUN_STATUS, {"status": result["status"]})
            return result
        except Exception as e:  # noqa: BLE001
            if history_sched is not None and not history_sched.done():
                history_sched.cancel()
                await asyncio.gather(history_sched, return_exceptions=True)
                if self._history_task is history_sched:
                    self._history_task = None
            self.log(f"⚠ run 异常: {str(e)[:200]}")
            self.store.set_status(STATUS_ERROR)
            self.emit(EV.ERROR, {"message": str(e)[:500]})
            self.emit(EV.RUN_STATUS, {"status": STATUS_ERROR})
            raise
        finally:
            # 收尾:移除全 run 复用的 PoC worktree(成功/失败/停止都执行)
            close_runner = getattr(self.runner, "aclose", None)
            if close_runner:
                ret = close_runner()
                if asyncio.iscoroutine(ret):
                    await ret
            self._cleanup_poc_worktree()
