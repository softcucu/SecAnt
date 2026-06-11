"""编排器:侦察 → 统一优先级调度(拆解 / history / audit / recheck / 验证流水线) →
流式产出确认漏洞 →(高危)PoC → 汇总。断点续跑 + 并发门 + CLI 任务失败重试。

结构化为主:运行期**只写结构化态**(经 RunStore 按关注点分文件落盘:checkpoint.json / recon.json /
attack-surface.json / findings/<id>.json / risks/<id>.json / usage.jsonl)并发结构化事件(经 EventBus → SSE + events.jsonl);
不再在运行期写 RECON/ATTACK-SURFACE/RISKS/findings/INDEX/SARIF 这些 Markdown——它们改由 exporters.py
从结构化态**按需渲染**(Web 导出端点 / CLI `--export`)。漏洞/风险确认即各写一个文件(流式、写一次即终态)。
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional

from . import events as EV
from . import schemas as S
from .backends import AgentRunner
from .common import (class_code, finalize_findings, finding_key, item_key,
                     most_severe, pad3, slim_finding)
from .config import Config, normalize_models
from .prompts import VERIFY_LENSES, PromptBuilder
from .store import RunStore, STATUS_DONE, STATUS_ERROR, STATUS_RUNNING, STATUS_STOPPED


def _noop_emit(etype: str, data: Optional[Dict[str, Any]] = None) -> None:
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
        self.health_state: Dict[str, Dict[str, Any]] = {}   # model -> 最新健康记录

        # ── 运行状态(可被断点恢复) ──
        self.surface_data: Dict[str, Any] = {}
        self.regions: List[Dict[str, Any]] = []
        self.history: List[Dict[str, Any]] = []      # 由 git 历史挖掘回灌的「历史问题模式」
        self.history_keys = set()                    # 历史模式去重(按 pattern 文本)
        self.history_done = set()                    # 已分析过的 git 提交 hash(续跑跳过)
        self._history_task: Optional[asyncio.Task] = None
        # ── 专用优先排查通道(历史变体 + 风险点复查) ──
        self.pq: List[Dict[str, Any]] = []           # 优先排查队列(kind ∈ {variant, risk};variant 优先)
        self.risk_by_id: Dict[str, Dict[str, Any]] = {}  # rid -> 风险记录(便于人工调级时联动入队/出队)
        self._recheck_task: Optional[asyncio.Task] = None
        self._recheck_inflight = 0                   # 正在排查 + 已 pop 待起的项数(收敛判据)
        self._recheck_stop: Optional[asyncio.Event] = None
        self._audit_done = False                     # 主审计循环是否已收敛(供 recheck_loop 收尾)
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
        self._decompose_total = 0
        self._decompose_done = 0
        self._history_enqueued = False
        self._retrying_past_max_rounds = False
        self._active_roles: Dict[str, int] = {}
        self.surface_log: List[Dict[str, Any]] = []
        self.risk_notes: List[Dict[str, Any]] = []
        self.risk_keys = set()
        self.ledger_arr: List[Dict[str, Any]] = []
        self.ledger_map: Dict[str, Dict[str, Any]] = {}
        self.risk_seq = 0
        self.round = 0
        self.in_flight: List[asyncio.Task] = []
        self._started = time.time()

    # ──────────────────────── 日志 / 事件 ────────────────────────
    def log(self, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {msg}", flush=True)
        self.emit(EV.LOG, {"message": msg})

    def emit(self, etype: str, data: Optional[Dict[str, Any]] = None) -> None:
        try:
            self._emit_cb(etype, data or {})
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
        """agent 子进程状态与 stdout/stderr chunk:经 SSE 推给 Web「Agent」页。"""
        self.emit(EV.AGENT_UPDATE, rec)
        if rec.get("status") != "output":
            self.emit(EV.METRICS, self._summary_snapshot(self.round))

    async def health_check_all(self) -> Dict[str, Any]:
        """运行前(或按需)对所有配置的模型各发一个 1+1 探针,实时反映健康度。"""
        models = self.cfg.all_models()
        if not models:
            self.log("⚠ 未配置任何模型,跳过健康检查")
            self.emit(EV.HEALTH_DONE, {"total": 0, "ok": 0, "unhealthy": []})
            return {"total": 0, "ok": 0, "unhealthy": []}
        self.emit(EV.HEALTH_START, {"models": models})
        self.log(f"🩺 模型健康检查:对 {len(models)} 个模型各发一个探针({', '.join(models)})…")
        recs = await asyncio.gather(*[self.runner.probe_model(m, reason="startup") for m in models],
                                    return_exceptions=True)
        ok = sum(1 for r in recs if isinstance(r, dict) and r.get("status") == "ok")
        bad = [r.get("model") for r in recs if isinstance(r, dict) and r.get("status") != "ok"]
        if bad:
            self.log(f"🩺 健康检查完成:{ok}/{len(models)} 正常;异常: {', '.join(str(b) for b in bad)}"
                     f"(仍会尝试运行,失败将自动重试)")
        else:
            self.log(f"🩺 健康检查完成:{ok}/{len(models)} 全部正常")
        self.emit(EV.HEALTH_DONE, {"total": len(models), "ok": ok, "unhealthy": bad})
        return {"total": len(models), "ok": ok, "unhealthy": bad}

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
            "backend": self.cfg.backend, "methods_ok": self.cfg.methods_ok(), "methods_dir": self.cfg.methods_abs,
        }

    def _abs_target(self) -> str:
        return os.path.abspath(os.path.expanduser(self.cfg.target))

    # ──────────────────────── 台账 ────────────────────────
    def ledger_rec(self, item: Dict[str, Any]) -> Dict[str, Any]:
        k = item_key(item)
        r = self.ledger_map.get(k)
        if not r:
            r = {"key": k, "kind": item.get("kind"),
                 "name": item.get("name") or item.get("objective") or item.get("pattern") or "",
                 "region": item.get("region") or (item.get("name") if item.get("kind") == "region" else ""),
                 "category": item.get("category") or "", "priority": item.get("priority") or "",
                 "source": item.get("source") or "",
                 "lenses": [], "passes": 0, "candidates": 0, "surfaces": 0, "risks": 0,
                 "lastRound": 0, "status": "pending"}
            self.ledger_map[k] = r
            self.ledger_arr.append(r)
        return r

    # ──────────────────────── 断点(按关注点分文件)────────────────────────
    def build_checkpoint(self, rnd: int) -> Dict[str, Any]:
        """只放运行时机制态;结果产物(漏洞/风险/侦察/覆盖)各自分文件存。"""
        return {
            "v": 3, "target": self.cfg.target, "scope": self.cfg.scope,
            "round": rnd, "seq": self.seq, "risk_seq": self.risk_seq,
            "processedKeys": list(self.processed_keys),
            "seenSurface": list(self.seen_surface),
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
        return {
            "rounds": rnd, "confirmed": len(self.confirmed), "candidates": len(self.dedup_keys),
            "by_severity": by_sev, "risks": len(self.risk_notes), "surfaces": len(self.surface_log),
            "agents_spawned": self.runner.agent_count, "elapsed_s": round(time.time() - self._started, 1),
            "token_usage": dict(self.runner.usage_totals),
        }

    def persist_recon(self) -> None:
        try:
            self.store.save_recon(self.surface_data)
        except Exception as e:  # noqa: BLE001
            self.log(f"⚠ recon 写入失败(忽略继续): {str(e)[:120]}")

    def checkpoint(self, rnd: int) -> None:
        """每个检查点:刷机制态 + 攻击面/覆盖快照 + 汇总(漏洞/风险已各自即时落盘)。"""
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
        if kind == "region" and self.cfg.decompose:
            return 40 + self._area_rank(item)
        if kind in ("region", "task", "surface"):
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
        if kind == "region" and self.cfg.decompose:
            return "decompose"
        return None

    def _work_sort_key(self, item: Dict[str, Any]) -> tuple[int, int]:
        return (self._work_priority(item), int(item.get("_queue_seq") or 0))

    def _can_dispatch_work(self, item: Dict[str, Any]) -> bool:
        if item.get("kind") == "_recheck" and self._active_roles.get("recheck", 0) >= max(1, self.cfg.recheck.concurrency):
            return False
        role = self._work_role(item)
        if role is None:
            return True
        if not self.cfg.model_slots_for(role):
            return True
        limit_fn = getattr(self.runner, "role_capacity_limit", None)
        role_limit = int(limit_fn(role)) if callable(limit_fn) else self.cfg.concurrency
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

    # 风险点 severity_hint 排序(用于判断是否够格自动入排查队列)
    _RISK_SEV_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}

    def _risk_sev_ok(self, sev: Optional[str]) -> bool:
        """severity_hint 是否达到自动入排查队列的阈值(cfg.recheck.risk_min_severity)。"""
        th = self.cfg.recheck.risk_min_severity
        return self._RISK_SEV_ORDER.get(sev or "info", 0) >= self._RISK_SEV_ORDER.get(th, 2)

    def _enqueue_risk(self, note: Dict[str, Any]) -> None:
        """把一条风险点放进优先排查队列(置 recheck_status=queued)。调用方负责落盘。"""
        note["recheck_status"] = "queued"
        self.pq.append({"kind": "risk", "id": note["id"], "area": note.get("area"),
                        "note": note.get("note"), "file": note.get("file"),
                        "severity_hint": note.get("severity_hint"), "lens": note.get("lens")})
        self.emit(EV.RECHECK_ENQUEUED, {"kind": "risk", "id": note["id"], "area": note.get("area"),
                                        "severity_hint": note.get("severity_hint")})

    def record_risk(self, n: Dict[str, Any], lens: str, rnd: int, from_recheck: bool = False) -> bool:
        area = (n.get("area") or "").strip()
        if not area:
            return False
        key = f"{area.lower()}::{(n.get('file') or '').strip()}"
        if key in self.risk_keys:
            return False
        self.risk_keys.add(key)
        self.risk_seq += 1
        note = {"id": f"RISK-{pad3(self.risk_seq)}", "area": area, "note": n.get("note") or "",
                "file": n.get("file") or "", "severity_hint": n.get("severity_hint") or "info",
                "lens": lens, "round": rnd, "recheck_status": "none"}
        self.risk_notes.append(note)
        self.risk_by_id[note["id"]] = note
        # 达阈值且非复查自身产出的风险点 → 自动进专用优先排查队列(防自激:复查产出的不再回灌)
        enq = self.cfg.recheck.enabled and not from_recheck and self._risk_sev_ok(note["severity_hint"])
        if enq:
            note["recheck_status"] = "queued"
        self.store.save_risk(note)            # 写一次即落盘:risks/<id>.json
        self.emit(EV.RISK_ADDED, note)
        if enq:
            self.pq.append({"kind": "risk", "id": note["id"], "area": note.get("area"),
                            "note": note.get("note"), "file": note.get("file"),
                            "severity_hint": note.get("severity_hint"), "lens": note.get("lens")})
            self.emit(EV.RECHECK_ENQUEUED, {"kind": "risk", "id": note["id"], "area": note.get("area"),
                                            "severity_hint": note.get("severity_hint")})
        return True

    def adjust_risk_severity(self, rid: str, sev: str) -> bool:
        """人工调整某条风险点的级别,并联动入队 / 出队(供 Web 接口在运行中调用)。
        升到 ≥ 阈值且尚未排查过 → 入排查队列;降到 < 阈值且仍排队未跑 → 出队。"""
        note = self.risk_by_id.get(rid)
        if not note:
            return False
        old = note.get("severity_hint")
        note["severity_hint"] = sev
        status = note.get("recheck_status") or "none"
        action = "none"
        if self._risk_sev_ok(sev):
            if status == "none":
                self._enqueue_risk(note)
                action = "enqueued"
        else:
            if status == "queued":
                self.pq = [it for it in self.pq if not (it.get("kind") == "risk" and it.get("id") == rid)]
                note["recheck_status"] = "none"
                action = "dequeued"
        self.store.save_risk(note)
        self.emit(EV.RISK_SEVERITY_CHANGED, {"id": rid, "severity_hint": sev, "old": old, "action": action})
        return True

    # ──────────────────────── 运行中动态调参 ────────────────────────
    def reconfigure(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        """运行中动态调整模型与并发(供 Web 接口调用)。可含:
          · models:{role: [model, ...]} —— 增/减某角色的模型(空列表=清空该角色,会触发配置错误提示);
          · model_concurrency:{model: limit} —— 每模型并发上限;
          · concurrency:int —— 全局并发。
        就地改写 self.cfg(scheduler/各 acquire 都实时读它)并重设已存在的信号量;
        新增模型的 per-model 信号量在首次派任务时按新配置惰性创建。返回当前生效快照(含配置校验)。
        """
        patch = patch or {}
        changed: List[str] = []

        if "models" in patch and isinstance(patch["models"], dict):
            old_models = self.cfg.all_models()
            self.cfg.models = normalize_models(patch["models"])
            new_models = self.cfg.all_models()
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
        eff = {m: self.cfg.model_concurrency_for(m) for m in self.cfg.all_models()}
        return {
            "models": self.cfg.models,
            "model_concurrency": self.cfg.model_concurrency,
            "effective_model_concurrency": eff,
            "concurrency": self.cfg.concurrency,
            "model_config_error": self.cfg.model_config_error(),
        }

    # ──────────────────────── lens 选择 ────────────────────────
    def lenses_for(self, item: Dict[str, Any]) -> List[str]:
        active = self.cfg.lenses
        if item.get("kind") == "task":
            hits = [l for l in (item.get("lens_hints") or []) if l in active]
            return hits or active
        if item.get("kind") == "variant" and item.get("lens_hint") in active:
            return [item["lens_hint"]]
        if item.get("kind") == "surface" and item.get("lens_hint") in active:
            return [item["lens_hint"]]
        return active

    # ──────────────────────── 区域拆解 ────────────────────────
    async def decompose_region(self, region: Dict[str, Any]) -> int:
        rkey = item_key(region)
        rec = self.ledger_rec(region)
        tasks: List[Dict[str, Any]] = []
        if self.cfg.decompose:
            r = await self.runner.run(
                self.pb.decompose(region, S.SUBTASKS_SCHEMA),
                role="decompose", label=f"decompose:{str(region.get('name'))[:26]}",
                schema=S.SUBTASKS_SCHEMA, retries=1, fallback=None)
            if r and isinstance(r, dict) and isinstance(r.get("subtasks"), list):
                for s in r["subtasks"][: self.cfg.max_subtasks_per_region]:
                    tasks.append({
                        "kind": "task", "region": region.get("name"), "objective": s.get("objective") or "(未命名子任务)",
                        "files": s.get("files") or region.get("files") or [],
                        "functions": s.get("functions") or [], "entry_points": s.get("entry_points") or region.get("entry_points") or [],
                        "lens_hints": s.get("lens_hints") or [], "est_lines": s.get("est_lines") or 0,
                        "category": region.get("category"), "untrusted_input": region.get("untrusted_input"),
                        "trust_boundary": region.get("trust_boundary"), "priority": region.get("priority"),
                    })
        if not tasks:
            fl = region.get("files") or []
            if len(fl) > 1:
                step = self.cfg.max_files_per_unit
                for i in range(0, len(fl), step):
                    grp = fl[i:i + step]
                    tasks.append({"kind": "task", "region": region.get("name"), "objective": f"审计文件 {', '.join(grp)}",
                                  "files": grp, "functions": [], "entry_points": region.get("entry_points") or [],
                                  "lens_hints": [], "category": region.get("category"),
                                  "untrusted_input": region.get("untrusted_input"), "trust_boundary": region.get("trust_boundary"),
                                  "priority": region.get("priority")})
                self.log(f"⚠ {region.get('name')} 拆解降级为按文件切({len(tasks)} 个子任务)")
            else:
                tasks.append({"kind": "task", "region": region.get("name"), "objective": f"审计区域 {region.get('name')}",
                              "files": fl, "functions": [], "entry_points": region.get("entry_points") or [],
                              "lens_hints": [], "category": region.get("category"),
                              "untrusted_input": region.get("untrusted_input"), "trust_boundary": region.get("trust_boundary"),
                              "priority": region.get("priority")})
        for t in tasks:
            self._enqueue_work(t)
        self.completed_items.add(rkey)
        rec["status"] = "decomposed"
        rec["subtasks"] = len(tasks)
        rec["lastRound"] = self.round
        if self._decompose_total:
            self._decompose_done += 1
            if self._decompose_done >= self._decompose_total:
                task_n = sum(1 for it in self.queue if it.get("kind") == "task")
                self.emit(EV.DECOMPOSE_DONE, {"tasks": task_n, "regions": self._decompose_done})
                self.checkpoint(self.round)
                self.emit_coverage()
        self.log(f"🧩 拆解 {region.get('name')} → {len(tasks)} 个审计子任务")
        return len(tasks)

    # ──────────────────────── 逐发现流水线:验证→(PoC)→报告正文 ────────────────────────
    async def process_finding(self, f: Dict[str, Any]) -> None:
        k = finding_key(f)
        try:
            if k in self.processed_keys:
                self.pending_findings.pop(k, None)
                return
            self.dedup_keys.add(k)

            lenses = [VERIFY_LENSES[i % len(VERIFY_LENSES)] for i in range(self.cfg.verify_votes)]
            vote_tasks = [self.runner.run(self.pb.verify(f, lens, S.VERDICT_SCHEMA),
                                          role="verify", label=f"verify:{(f.get('title') or '')[:24]}#{i + 1}",
                                          schema=S.VERDICT_SCHEMA)
                          for i, lens in enumerate(lenses)]
            votes = [v for v in await asyncio.gather(*vote_tasks) if v]
            if not votes:
                return  # 全验证失败 → 留在 pending,续跑重做
            real = sum(1 for v in votes if v.get("is_real"))
            if real < -(-len(votes) // 2):  # ceil
                self.processed_keys.add(k)
                self.pending_findings.pop(k, None)
                self.emit(EV.FINDING_REJECTED, {"key": k, "title": f.get("title"), "bug_class": f.get("bug_class")})
                return

            corrected = most_severe([v.get("corrected_severity") for v in votes]) or f.get("severity")
            exploit = next((v.get("exploitability") for v in votes if v.get("exploitability")), "")
            self.seq += 1
            fid = f"{class_code(f.get('bug_class'))}-{pad3(self.seq)}"
            rec = {**f, "id": fid, "corrected_severity": corrected, "exploitability": exploit, "votes": votes}

            poc = None
            if self.cfg.enable_poc and corrected in ("critical", "high"):
                poc = await self.run_poc(rec)
                if poc:
                    self.emit(EV.POC_DONE, {"id": fid, "compiled": poc.get("compiled"), "triggered": poc.get("triggered")})

            body = await self.runner.run(self.pb.report_body(rec, poc),
                                         role="report", label=f"report:{fid}", schema=None, fallback=None)
            rec["report_body"] = body or ""
            rec["poc"] = poc
            rec["report_failed"] = not body
            self.confirmed.append(rec)
            self.store.save_finding(rec)            # 流式:确认即写 findings/<id>.json(写一次即终态)
            self.processed_keys.add(k)
            self.pending_findings.pop(k, None)
            self.emit(EV.FINDING_CONFIRMED, slim_finding(rec))
            self.log(f"✔ 确认漏洞 {fid} [{corrected}] {rec.get('title')} (累计 {len(self.confirmed)})")
        except Exception as e:  # noqa: BLE001
            self.log(f"⚠ process_finding 异常,留待续跑重做: {str(e)[:140]}")

    # ──────────────────────── PoC(隔离工作目录副本) ────────────────────────
    async def run_poc(self, rec: Dict[str, Any]) -> Any:
        target = self._abs_target()
        wt = None
        cwd = target
        is_git = subprocess.run(["git", "-C", target, "rev-parse", "--is-inside-work-tree"],
                                capture_output=True, text=True).returncode == 0
        if is_git:
            try:
                wt = tempfile.mkdtemp(prefix="pvh-poc-")
                r = subprocess.run(["git", "-C", target, "worktree", "add", "--detach", wt, "HEAD"],
                                   capture_output=True, text=True)
                if r.returncode == 0:
                    cwd = wt
                else:
                    self.log(f"⚠ 创建 git worktree 失败,PoC 退回主仓目录: {r.stderr.strip()[:120]}")
                    shutil.rmtree(wt, ignore_errors=True)
                    wt = None
            except Exception as e:  # noqa: BLE001
                self.log(f"⚠ worktree 异常,PoC 退回主仓目录: {str(e)[:120]}")
                wt = None
        try:
            return await self.runner.run(self.pb.poc(rec, self.build_hint, S.POC_SCHEMA),
                                         role="poc", label=f"poc:{rec['id']}", schema=S.POC_SCHEMA, cwd=cwd)
        finally:
            if wt:
                subprocess.run(["git", "-C", target, "worktree", "remove", "--force", wt],
                               capture_output=True, text=True)
                shutil.rmtree(wt, ignore_errors=True)

    # ──────────────────────── 阶段 ① 侦察 / 断点恢复 ────────────────────────
    def restore_checkpoint(self) -> bool:
        """恢复断点机制态。成功后 history 挖掘可立即跳过已分析提交。"""
        if self._restored_checkpoint:
            return True
        ckpt = self.store.load_checkpoint() if self.cfg.resume else None
        recon_doc = self.store.load_recon() if self.cfg.resume else {}
        if ckpt and recon_doc and isinstance(ckpt.get("pendingQueue"), list):
            self.surface_data = recon_doc
            self.seq = ckpt.get("seq", 0)
            self.risk_seq = ckpt.get("risk_seq", 0)
            self.start_round = ckpt.get("round", 0)
            self.confirmed = self.store.load_findings()            # 扫 findings/<id>.json 恢复(写一次即终态)
            for k in (ckpt.get("processedKeys") or []):
                self.dedup_keys.add(k)
                self.processed_keys.add(k)
            self.seen_surface.update(ckpt.get("seenSurface") or [])
            self.completed_items.update(ckpt.get("completedItems") or [])
            self.queue = ckpt.get("pendingQueue") or []
            self.pq = ckpt.get("pendingPriorityQueue") or []
            # 兼容旧断点:历史变体过去落在主队列,迁移到优先排查队列
            legacy_variants = [it for it in self.queue if it.get("kind") == "variant"]
            if legacy_variants:
                self.queue = [it for it in self.queue if it.get("kind") != "variant"]
                self.pq.extend(legacy_variants)
            asf = self.store.load_attack_surface()
            self.surface_log = asf.get("surfaces") or []
            self.ledger_arr = asf.get("ledger") or []
            for r in self.ledger_arr:
                self.ledger_map[r["key"]] = r
            self.risk_notes = self.store.load_risks()              # 扫 risks/<id>.json 恢复
            pq_risk_ids = {it.get("id") for it in self.pq if it.get("kind") == "risk"}
            for r in self.risk_notes:
                self.risk_keys.add(f"{(r.get('area') or '').strip().lower()}::{(r.get('file') or '').strip()}")
                rid = r.get("id")
                if rid:
                    self.risk_by_id[rid] = r
                # 中断时正在排查 / 排队但未落进 pq 的风险点 → 重新入队补排
                st = r.get("recheck_status")
                if rid and st in ("queued", "running") and rid not in pq_risk_ids and self._risk_sev_ok(r.get("severity_hint")):
                    self._enqueue_risk(r)
                    self.store.save_risk(r)
            for f in (ckpt.get("pendingFindings") or []):
                fk = finding_key(f)
                self.pending_findings[fk] = f
                self.dedup_keys.add(fk)
            self.regions = self.surface_data.get("regions") or []
            self.history = self.surface_data.get("history") or []
            for h in self.history:
                self.history_keys.add((h.get("pattern") or "").strip().lower())
            self.history_done.update(ckpt.get("historyDone") or [])
            self.build_hint = self.surface_data.get("build_hint") or ""
            self.log(f"♻ 从断点恢复:已完成 {self.start_round} 轮,确认 {len(self.confirmed)} 条,待审队列 {len(self.queue)} 项,"
                     f"在途候选 {len(self.pending_findings)} 条,已处理 {len(self.processed_keys)} 个,已完成攻击面 {len(self.completed_items)} 个")
            self.emit(EV.RECON_DONE, {"resumed": True, "regions": len(self.regions), "history": len(self.history),
                                      "purpose": self.surface_data.get("purpose"),
                                      "threat_summary": self.surface_data.get("threat_summary")})
            self.emit_coverage()
            self._restored_checkpoint = True
            return True
        return False

    async def recon(self, *, try_restore: bool = True) -> None:
        if try_restore and self.restore_checkpoint():
            return
        if self.cfg.resume:
            self.log("未找到可用断点,从头开始侦察")
        surface = await self.runner.run(self.pb.recon(S.SURFACE_SCHEMA), role="recon", label="recon",
                                        schema=S.SURFACE_SCHEMA, retry_forever=True, fallback=None,
                                        should_stop=self.stop_requested)
        if not surface and self.stop_requested():
            self.log("侦察阶段收到停止请求,不再兜底继续")
            return
        if not surface:
            self.log("⚠ 侦察失败,使用兜底攻击面继续审计")
            surface = {
                "regions": [{"name": "全仓(侦察失败兜底)", "category": "parser",
                             "files": [self.cfg.scope] if self.cfg.scope else ["."], "entry_points": [],
                             "untrusted_input": "协议/文件/网络输入(侦察未细分)", "trust_boundary": "",
                             "crypto_apis": [], "priority": "high"}],
                "history": [], "build_hint": "", "repo_knowledge": "(侦察阶段失败,无仓库知识)",
            }
        self.surface_data = surface
        self.regions = sorted(surface.get("regions") or [], key=lambda r: ({"high": 0, "medium": 1, "low": 2}).get(r.get("priority"), 3))
        # 历史问题模式不再由侦察 agent 产出,改由 history 任务在统一队列中产出。
        self.surface_data["history"] = self.history
        self.build_hint = surface.get("build_hint") or ""
        for r in self.regions:
            self._enqueue_work({"kind": "region", **r})
        self.log(f"侦察完成:攻击面区域 {len(self.regions)} 个,build_hint {'有' if self.build_hint else '无'}"
                 f"(历史问题模式由统一调度的 git history 任务产出)")
        if surface.get("purpose"):
            self.log(f"项目用途: {str(surface['purpose'])[:120]}")
        self.emit(EV.RECON_DONE, {"resumed": False, "regions": len(self.regions),
                                  "purpose": surface.get("purpose"), "threat_summary": surface.get("threat_summary"),
                                  "build_hint": self.build_hint})
        self.persist_recon()
        self.checkpoint(0)

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
        pk = pattern.lower()
        if pk in self.history_keys:
            return
        self.history_keys.add(pk)
        lens = res.get("lens_hint") if res.get("lens_hint") in self.cfg.lenses else None
        source = (f"{c['hash'][:10]} {c['subject']}").strip()[:120]
        entry = {"pattern": pattern, "source": source, "lens_hint": lens or "memory",
                 "files": res.get("files") or [], "rationale": res.get("rationale") or ""}
        self.history.append(entry)
        self.surface_data["history"] = self.history
        # 回灌为「同类变体排查」项,放进优先排查队列(最高优先,由 recheck 角色处理)
        self._enqueue_variant(entry)
        self.emit(EV.HISTORY_ADDED, {**entry, "total": len(self.history)})
        self.persist_recon()
        self.log(f"🕮 历史模式 +1[{entry['lens_hint']}]:{pattern[:60]} ← {source[:40]}")

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
            self.log("本轮有 1 个审计项因 CLI/结构化输出连续失败被放回队尾,稍后继续重试")
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
                 f"风险登记 {len(self.risk_notes)}")
        self.emit(EV.ROUND_DONE, {"round": self.round, "new_findings": new_findings, "new_surfaces": new_surfaces,
                                  "queue_len": len(self.queue), "dry_streak": dry_streak, "risks": len(self.risk_notes)})
        self.emit(EV.METRICS, self._summary_snapshot(self.round))
        self.checkpoint(self.round)
        self.emit_coverage()

    def _pop_next_work(self) -> Optional[Dict[str, Any]]:
        self._ensure_queue_order()
        if self.cfg.recheck.enabled and self.pq and self._active_roles.get("recheck", 0) < max(1, self.cfg.recheck.concurrency):
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
                if kind == "task" or kind == "surface" or (kind == "region" and not self.cfg.decompose):
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
            if kind == "region" and self.cfg.decompose:
                await self.decompose_region(work)
        finally:
            if role:
                self._active_roles[role] = max(0, self._active_roles.get(role, 0) - 1)

    async def _run_scheduler(self, *, stop_when: Optional[Callable[[], bool]] = None,
                             stop_when_idle: bool = True) -> None:
        """统一调度循环。

        stop_when 用于 recon 并行窗口:条件满足后不再启动新工作,但会等待已启动工作收尾;
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
                if not made_progress and may_start and (self.queue or self.pq):
                    await asyncio.wait(active, timeout=0.25, return_when=asyncio.FIRST_COMPLETED)
                else:
                    await asyncio.wait(active, return_when=asyncio.FIRST_COMPLETED)
                continue

            if stop_when is not None and stop_when():
                break

            has_pending = bool(self.queue or self.pq or self._audit_passes or self._recheck_inflight)
            if has_pending:
                await asyncio.sleep(min(self.cfg.history.poll_interval_s, self.cfg.recheck.poll_interval_s, 1))
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
            self._enqueue_finding(f)
        if self.pending_findings:
            self.log(f"续跑:重注入 {len(self.pending_findings)} 条在途候选到验证/报告流水线")

        self.round = self.start_round
        self._retrying_past_max_rounds = False
        self._enqueue_history_commits()
        self._decompose_total = sum(1 for it in self.queue if it.get("kind") == "region" and item_key(it) not in self.completed_items)
        if self._decompose_total and self.cfg.decompose:
            self.log(f"区域拆解已入统一队列:{self._decompose_total} 个 region 将按优先级逐步拆解,拆出即审")

        await self._run_scheduler(stop_when_idle=True)
        if not self.queue and not self.pq and not self._audit_passes and not self._recheck_inflight:
            self.log(f"轮 {self.round}: 队列已空且无新攻击面回灌,提前收敛")

        if self.stop_requested():
            stop_reason = "用户请求停止"
        elif self._retrying_past_max_rounds and not self.queue:
            stop_reason = f"达到 maxRounds({self.cfg.max_rounds});失败重试队列已补审完成"
        else:
            stop_reason = f"收敛(连续 {self.cfg.dry_rounds} 轮无新增)"
        self._audit_done = True
        if self._recheck_task is not None:
            if self._recheck_stop is not None:
                self._recheck_stop.set()
            if not self._recheck_task.done() and self.stop_requested():
                self._recheck_task.cancel()
            if self.pq or self._recheck_inflight > 0:
                self.log(f"等待优先排查通道排空:队列 {len(self.pq)} 项、在途 {self._recheck_inflight} 项…")
            try:
                await self._recheck_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self.log(f"审计循环结束:{stop_reason}。等待 {len(self.in_flight)} 条流水线(验证/PoC/报告)排空…")
        await asyncio.gather(*self.in_flight, return_exceptions=True)
        self.checkpoint(self.round)
        self.emit_coverage()
        self.log(f"流水线排空完成:确认 {len(self.confirmed)} 条漏洞,候选去重池 {len(self.dedup_keys)} 条,"
                 f"潜在风险 {len(self.risk_notes)} 条,动态攻击面 {len(self.surface_log)} 个。")
        return stop_reason

    async def _run_finder(self, item: Dict[str, Any], lens_key: str, idx: int, rec: Dict[str, Any]) -> None:
        if self.stop_requested():
            item["failedFinders"] = item.get("failedFinders", 0) + 1
            return
        res = await self.runner.run(
            self.pb.audit(item, lens_key, idx, S.FINDINGS_SCHEMA),
            role="audit",
            label=f"audit:{str(item.get('objective') or item.get('name') or item.get('pattern') or 'item')[:20]}:{lens_key}#{item['pass']}.{idx + 1}",
            schema=S.FINDINGS_SCHEMA,
            should_stop=self.stop_requested)
        if not res:
            item["failedFinders"] = item.get("failedFinders", 0) + 1
            return
        self._consume(res, item, rec, lens_key)

    def _consume(self, res: Dict[str, Any], item: Dict[str, Any], rec: Dict[str, Any],
                 lens_key: str, from_recheck: bool = False) -> None:
        """消化一次审计 / 复查 agent 的结果:findings→验证流水线、new_surfaces→主队列、risk_notes→登记。
        from_recheck=True 时,产出的 risk_notes 不再二次回灌优先队列(防自激)。"""
        for f in (res.get("findings") or []):
            fk = finding_key(f)
            if fk in self.dedup_keys:
                continue
            self.dedup_keys.add(fk)
            item["newThisRound"] = item.get("newThisRound", 0) + 1
            rec["candidates"] = rec.get("candidates", 0) + 1
            self.pending_findings[fk] = f
            self.emit(EV.CANDIDATE_FOUND, {"key": fk, "title": f.get("title"), "bug_class": f.get("bug_class"),
                                           "file": f.get("file"), "line": f.get("line"), "lens": lens_key})
            self._enqueue_finding(f)
        for s in (res.get("new_surfaces") or []):
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
        for n in (res.get("risk_notes") or []):
            if self.record_risk(n, lens_key, self.round, from_recheck=from_recheck):
                rec["risks"] = rec.get("risks", 0) + 1

    # ──────── 专用优先排查:历史变体 + 风险点复查(统一调度队列中的最高优先级)────────
    def _recheck_active(self) -> bool:
        return self._recheck_task is not None and not self._recheck_task.done()

    def _enqueue_variant(self, entry: Dict[str, Any]) -> None:
        """git 历史挖掘提炼出的问题模式 → 进优先排查队列(同类变体排查)。"""
        self.pq.append({"kind": "variant", "pattern": entry["pattern"], "source": entry["source"],
                        "files": entry["files"], "lens_hint": entry["lens_hint"]})
        self.emit(EV.RECHECK_ENQUEUED, {"kind": "variant", "pattern": entry["pattern"],
                                        "lens_hint": entry["lens_hint"]})

    def _pop_priority(self) -> Optional[Dict[str, Any]]:
        """取下一个优先项:历史变体(variant)优先于风险点(risk);跳过已完成的。"""
        while self.pq:
            idx = next((i for i, it in enumerate(self.pq) if it.get("kind") == "variant"), 0)
            it = self.pq.pop(idx)
            if item_key(it) in self.completed_items:
                continue
            return it
        return None

    def _start_recheck(self) -> None:
        if not self.cfg.recheck.enabled or self._recheck_task is not None:
            return
        self._recheck_stop = asyncio.Event()
        self._recheck_task = asyncio.create_task(self.recheck_loop())

    async def recheck_loop(self) -> None:
        """专用排查 agent:从优先队列取项排查。并发上限 = cfg.recheck.concurrency(默认 1);
        懒占全局并发名额——有活才占、用完即还,队列空时不占用主池。"""
        sem = asyncio.Semaphore(max(1, self.cfg.recheck.concurrency))
        inflight: List[asyncio.Task] = []
        self.log(f"🔁 优先排查通道就绪(并发上限 {self.cfg.recheck.concurrency},"
                 f"风险点入队阈值 ≥{self.cfg.recheck.risk_min_severity};历史变体与风险点复查优先处理)")

        async def worker(it: Dict[str, Any]) -> None:
            try:
                async with sem:
                    if self.stop_requested():
                        return
                    got = await self.runner.reserve_slots(1)   # 懒占:用时才占 1 个全局名额
                    try:
                        await self._run_recheck(it, use_global_gate=False)
                    finally:
                        self.runner.release_slots(got)          # 用完即还,主池回满
            finally:
                self._recheck_inflight -= 1

        while not self.stop_requested():
            inflight = [t for t in inflight if not t.done()]
            it = self._pop_priority()
            if it is None:
                if (self._recheck_stop and self._recheck_stop.is_set()
                        and self._recheck_inflight == 0 and not inflight):
                    break
                await asyncio.sleep(self.cfg.recheck.poll_interval_s)
                continue
            self._recheck_inflight += 1                          # pop 与计数之间无 await,原子
            inflight.append(asyncio.create_task(worker(it)))
        await asyncio.gather(*inflight, return_exceptions=True)

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
        if kind == "risk" and rid in self.risk_by_id:
            self.risk_by_id[rid]["recheck_status"] = "running"
            self.store.save_risk(self.risk_by_id[rid])
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
        res = await self.runner.run(prompt, role="recheck", label=label, schema=S.FINDINGS_SCHEMA,
                                    use_global_gate=use_global_gate,
                                    should_stop=self.stop_requested)
        if not res:
            self._mark_retry_after_failure(item)
            rec["status"] = "incomplete"
            if kind == "risk" and rid in self.risk_by_id:
                self.risk_by_id[rid]["recheck_status"] = "queued"
                self.store.save_risk(self.risk_by_id[rid])
            self.pq.append(item)
            self.emit(EV.RECHECK_ENQUEUED, {"kind": kind, "id": rid, "pattern": item.get("pattern"),
                                            "label": label, "retry": True})
            self.checkpoint(self.round)
            self.emit_coverage()
            self.log(f"优先排查项 {label} 连续失败,已放回队尾稍后重试")
            return
        self._clear_retry_after_failure(item)
        if res:
            self._consume(res, item, rec, lens_key, from_recheck=True)
        self.completed_items.add(item_key(item))
        rec["status"] = "completed-findings" if rec.get("candidates", 0) > 0 else "completed-clean"
        if kind == "risk" and rid in self.risk_by_id:
            self.risk_by_id[rid]["recheck_status"] = "done"
            self.store.save_risk(self.risk_by_id[rid])
        self.checkpoint(self.round)
        self.emit_coverage()
        self.emit(EV.RECHECK_DONE, {"kind": kind, "id": rid, "pattern": item.get("pattern"), "label": label,
                                    "new_candidates": item.get("newThisRound", 0)})

    # ──────────────────────── 阶段 ③ 汇总(结构化,无文件写盘) ────────────────────────
    def synthesis(self, stop_reason: str) -> Dict[str, Any]:
        final = finalize_findings(self.confirmed)
        counts: Dict[str, int] = {}
        for c in final:
            counts[c.get("bug_class")] = counts.get(c.get("bug_class"), 0) + 1
        top_sev = (final[0].get("corrected_severity") or final[0].get("severity")) if final else "none"
        converged = self.round < self.cfg.max_rounds and not self.stop_requested()

        summary = {
            **self._summary_snapshot(self.round),
            "converged": converged, "stop_reason": stop_reason, "by_class": counts, "top_severity": top_sev,
            "confirmed": len(final),
        }
        status = STATUS_STOPPED if self.stop_requested() else STATUS_DONE
        # 收尾:刷机制态 + 攻击面/覆盖快照(漏洞/风险已各自即时落盘),并写最终汇总+状态
        self.store.save_checkpoint(self.build_checkpoint(self.round))
        self.store.save_attack_surface(self.build_attack_surface(self.round))
        self.store.update_summary(summary, status=status)

        result = {
            "run_id": self.store.id, "run_dir": self.store.dir,
            "target": self.cfg.target, "scope": self.cfg.scope or "(whole repo)",
            "threat_model": self.cfg.threat_model, "backend": self.cfg.backend,
            "methods_used": self.cfg.methods_ok(), "methods_dir": self.cfg.methods_abs,
            "dynamic_surfaces": len(self.surface_log), "risk_notes": len(self.risk_notes),
            "resumed_from_round": self.start_round, "rounds": self.round,
            "converged": converged, "stop_reason": stop_reason, "candidates": len(self.dedup_keys),
            "subtasks_total": sum(1 for r in self.ledger_arr if r.get("kind") == "task"),
            "regions_decomposed": sum(1 for r in self.ledger_arr if r.get("status") == "decomposed"),
            "pending_findings": len(self.pending_findings), "agents_spawned": self.runner.agent_count,
            "token_usage": dict(self.runner.usage_totals),
            "confirmed": len(final), "by_class": counts, "status": status,
            "top_findings": [{"id": c.get("id"), "severity": c.get("corrected_severity") or c.get("severity"),
                              "bug_class": c.get("bug_class"), "title": c.get("title"),
                              "file": c.get("file"), "line": c.get("line", 0)} for c in final[:12]],
        }
        self.emit(EV.RUN_DONE, summary)
        return result

    # ──────────────────────── 总入口 ────────────────────────
    async def run(self) -> Dict[str, Any]:
        sn = self.pb.scope_note
        self.store.init_manifest({
            "target": self.cfg.target, "scope": self.cfg.scope, "backend": self.cfg.backend,
            "models": self.cfg.models, "model_concurrency": self.cfg.model_concurrency,
            "concurrency": self.cfg.concurrency, "threat_model": self.cfg.threat_model,
            "lenses": self.cfg.lenses, "finders_per_lens": self.cfg.finders_per_lens,
            "max_rounds": self.cfg.max_rounds, "dry_rounds": self.cfg.dry_rounds,
            "verify_votes": self.cfg.verify_votes, "enable_poc": self.cfg.enable_poc, "decompose": self.cfg.decompose,
            "methods_dir": self.cfg.methods_abs, "methods_ok": self.cfg.methods_ok(),
        })
        self.store.set_status(STATUS_RUNNING)
        self.emit(EV.RUN_STATUS, {"status": STATUS_RUNNING})
        self.log(f"目标={self.cfg.target}{sn} 后端={self.cfg.backend} 并发={self.cfg.concurrency} "
                 f"每lens finder={self.cfg.finders_per_lens} dryRounds={self.cfg.dry_rounds} "
                 f"maxRounds={self.cfg.max_rounds} 验证票={self.cfg.verify_votes} PoC={self.cfg.enable_poc} "
                 f"resume={self.cfg.resume} 威胁模型={self.cfg.threat_model}")
        self.log(f"启用 lens: {', '.join(self.cfg.lenses)} | run 目录: {self.store.dir} | "
                 f"方法库: {self.cfg.methods_abs} ({'就绪' if self.cfg.methods_ok() else '不可用→内联兜底'})")
        try:
            model_error = self.cfg.model_config_error()
            if model_error:
                raise ValueError(f"模型配置错误:{model_error}")
            resumed = self.restore_checkpoint()
            if self.cfg.health.enabled and self.cfg.health.on_start and not self.stop_requested():
                await self.health_check_all()
            if not resumed:
                recon_task = asyncio.create_task(self.recon(try_restore=False))
                await asyncio.sleep(0)
                self._enqueue_history_commits()
                history_sched = asyncio.create_task(
                    self._run_scheduler(stop_when=lambda: recon_task.done(), stop_when_idle=False)
                )
                try:
                    await recon_task
                finally:
                    await history_sched
            stop_reason = await self.audit()
            result = self.synthesis(stop_reason)
            self.emit(EV.RUN_STATUS, {"status": result["status"]})
            return result
        except Exception as e:  # noqa: BLE001
            self.log(f"⚠ run 异常: {str(e)[:200]}")
            self.store.set_status(STATUS_ERROR)
            self.emit(EV.ERROR, {"message": str(e)[:500]})
            self.emit(EV.RUN_STATUS, {"status": STATUS_ERROR})
            raise
