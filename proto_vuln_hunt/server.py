"""Web 控制台后端(FastAPI):REST + SSE + 静态 SPA。

fastapi/uvicorn 惰性 import —— 纯 CLI(`run`)环境无需安装它们也能用。

注意:本文件**不能**用 `from __future__ import annotations`。否则注解会变成字符串,FastAPI 解析路由
处理函数的 `request: Request` 时只在模块全局里找 `Request`,而它是在 create_app 内惰性 import 的局部名,
解析失败会把 request 误当查询参数。去掉 future 注解后,注解在 def 执行时(此时 Request 在作用域内)求值。
"""
import asyncio
import dataclasses
import json
import os
from typing import Any, Dict, List, Optional

from . import exporters
from .common import finalize_findings, slim_finding
from .config import ALL_LENSES, DEFAULT_BACKENDS, ROLES, Config
from .events import EventBus
from .store import (RunRegistry, RunStore, STATUS_INTERRUPTED, STATUS_QUEUED, STATUS_RUNNING)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "static")

# 允许从 Web 表单覆盖的 Config 字段(白名单,防注入任意字段)
_RUN_FIELDS = {
    "target", "scope", "backend", "concurrency", "threat_model", "lenses",
    "finders_per_lens", "max_rounds", "dry_rounds", "verify_votes",
    "enable_poc", "decompose", "methods_dir", "models", "model_concurrency", "resume", "fresh",
}


def _meta_from_manifest(m: Dict[str, Any]) -> Dict[str, Any]:
    cfg = (m or {}).get("config") or {}
    return {"target": cfg.get("target"), "scope": cfg.get("scope") or "", "threat_model": cfg.get("threat_model"),
            "backend": cfg.get("backend"), "methods_ok": cfg.get("methods_ok"), "methods_dir": cfg.get("methods_dir")}


def build_run_config(base: Config, payload: Dict[str, Any]) -> Config:
    """以服务端基础配置为模板,套用 Web 表单的白名单覆盖,生成一次 run 的 Config。"""
    overrides = {k: v for k, v in (payload or {}).items() if k in _RUN_FIELDS and v is not None}
    if "lenses" in overrides:
        overrides["lenses"] = [l for l in overrides["lenses"] if l in ALL_LENSES] or list(base.lenses)
    if "models" in overrides and not isinstance(overrides["models"], dict):
        overrides.pop("models")
    if "model_concurrency" in overrides and not isinstance(overrides["model_concurrency"], dict):
        overrides.pop("model_concurrency")
    overrides.setdefault("resume", False)   # 新建 run 默认从头(run 目录本来就是空的)
    return dataclasses.replace(base, **overrides)


class RunManager:
    """管理并发运行的 run:每个 run 一个 asyncio.Task + EventBus + stop Event。"""

    def __init__(self, base: Config, registry: RunRegistry):
        self.base = base
        self.registry = registry
        self.active: Dict[str, Dict[str, Any]] = {}   # run_id -> {task, pipeline, bus, stop}

    def get_bus(self, run_id: str) -> Optional[EventBus]:
        rec = self.active.get(run_id)
        return rec["bus"] if rec else None

    def is_running(self, run_id: str) -> bool:
        rec = self.active.get(run_id)
        return bool(rec and not rec["task"].done())

    def _launch(self, cfg: Config, store: RunStore) -> str:
        from .pipeline import Pipeline  # 惰性,避免循环 import
        bus = EventBus(sink=store.append_event)
        stop = asyncio.Event()
        pipe = Pipeline(cfg, store=store, emitter=bus.emit, stop_event=stop)
        task = asyncio.create_task(pipe.run())
        self.active[store.id] = {"task": task, "pipeline": pipe, "bus": bus, "stop": stop}

        def _done(_t):
            # 任务结束:保留 bus 供已连接客户端收尾,但标记非运行
            pass
        task.add_done_callback(_done)
        return store.id

    def create_and_launch(self, payload: Dict[str, Any]) -> str:
        cfg = build_run_config(self.base, payload)
        store = self.registry.create()
        return self._launch(cfg, store)

    def resume(self, run_id: str) -> bool:
        store = self.registry.get(run_id)
        if not store or self.is_running(run_id):
            return False
        m = store.load_manifest() or {}
        saved = m.get("config") or {}
        cfg = build_run_config(self.base, {**saved, "resume": True, "fresh": False})
        self._launch(cfg, store)
        return True

    def stop(self, run_id: str) -> bool:
        rec = self.active.get(run_id)
        if not rec:
            return False
        rec["stop"].set()
        return True

    def recheck_health(self, run_id: str) -> bool:
        """对正在运行的 run 触发一次全模型健康复检(后台任务,实时经 SSE 回传)。"""
        rec = self.active.get(run_id)
        if not rec or rec["task"].done():
            return False
        asyncio.create_task(rec["pipeline"].health_check_all())
        return True

    def reconcile_on_startup(self) -> None:
        """服务重启:把"清单写着 running 但其实没有任务在跑"的 run 标记为 interrupted。"""
        for info in self.registry.list_runs():
            if info.get("status") in (STATUS_RUNNING, STATUS_QUEUED) and not self.is_running(info["id"]):
                store = self.registry.get(info["id"])
                if store:
                    store.set_status(STATUS_INTERRUPTED)


def _sse(ev: Dict[str, Any]) -> str:
    return f"id: {ev['seq']}\nevent: {ev['type']}\ndata: {json.dumps(ev, ensure_ascii=False)}\n\n"


def create_app(cfg: Config):
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
    from fastapi.staticfiles import StaticFiles

    registry = RunRegistry(cfg.runs_dir).ensure()
    manager = RunManager(cfg, registry)
    app = FastAPI(title="proto-vuln-hunt", version="0.2.0")

    @app.on_event("startup")
    async def _startup():
        manager.reconcile_on_startup()

    def _store_or_404(run_id: str) -> RunStore:
        store = registry.get(run_id)
        if not store or not store.exists():
            raise HTTPException(404, "run not found")
        return store

    # ── 元信息:填充新建表单 ──
    @app.get("/api/meta")
    async def meta():
        return {
            "backends": sorted(set(list(DEFAULT_BACKENDS) + list(cfg.backends))),
            "lenses": ALL_LENSES, "roles": ROLES,
            "defaults": {
                "backend": cfg.backend, "concurrency": cfg.concurrency, "models": cfg.models,
                "model_concurrency": cfg.model_concurrency,
                "threat_model": cfg.threat_model, "lenses": cfg.lenses,
                "finders_per_lens": cfg.finders_per_lens, "max_rounds": cfg.max_rounds,
                "dry_rounds": cfg.dry_rounds, "verify_votes": cfg.verify_votes,
                "enable_poc": cfg.enable_poc, "decompose": cfg.decompose, "methods_dir": cfg.methods_abs,
                "health": {"enabled": cfg.health.enabled, "on_start": cfg.health.on_start,
                           "gate": cfg.health.gate, "ttl_s": cfg.health.ttl_s},
            },
        }

    # ── runs 列表 / 新建 ──
    @app.get("/api/runs")
    async def list_runs():
        runs = registry.list_runs()
        for r in runs:
            r["running"] = manager.is_running(r["id"])
        return runs

    @app.post("/api/runs")
    async def create_run(req: Request):
        payload = await req.json()
        if not (payload.get("target") or cfg.target):
            raise HTTPException(400, "target is required")
        run_id = manager.create_and_launch(payload)
        return {"run_id": run_id}

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str):
        store = _store_or_404(run_id)
        m = store.load_manifest() or {}
        m["running"] = manager.is_running(run_id)
        return m

    @app.post("/api/runs/{run_id}/stop")
    async def stop_run(run_id: str):
        return {"ok": manager.stop(run_id)}

    @app.post("/api/runs/{run_id}/resume")
    async def resume_run(run_id: str):
        return {"ok": manager.resume(run_id)}

    # ── 结果读取(各读各的分文件) ──
    @app.get("/api/runs/{run_id}/findings")
    async def findings(run_id: str):
        store = _store_or_404(run_id)
        return [slim_finding(c) for c in finalize_findings(store.load_findings())]

    @app.get("/api/runs/{run_id}/findings/{fid}")
    async def finding(run_id: str, fid: str):
        store = _store_or_404(run_id)
        rec = store.load_finding(fid)
        if not rec:
            raise HTTPException(404, "finding not found")
        return rec

    @app.get("/api/runs/{run_id}/coverage")
    async def coverage(run_id: str):
        store = _store_or_404(run_id)
        asf = store.load_attack_surface()
        regions = asf.get("regions") or (store.load_recon() or {}).get("regions") or []
        return {"ledger": asf.get("ledger") or [], "surfaces": asf.get("surfaces") or [],
                "regions": regions, "progress": asf.get("progress") or {"done": 0, "clean": 0, "total": 0}}

    @app.get("/api/runs/{run_id}/risks")
    async def risks(run_id: str):
        return _store_or_404(run_id).load_risks()

    @app.get("/api/runs/{run_id}/recon")
    async def recon(run_id: str):
        return _store_or_404(run_id).load_recon()

    # ── 模型健康 ──
    @app.get("/api/runs/{run_id}/health")
    async def health(run_id: str):
        h = _store_or_404(run_id).load_health()
        h["running"] = manager.is_running(run_id)
        return h

    @app.post("/api/runs/{run_id}/health/check")
    async def health_check(run_id: str):
        _store_or_404(run_id)
        return {"ok": manager.recheck_health(run_id)}

    # ── 导出 ──
    @app.get("/api/runs/{run_id}/export/sarif")
    async def export_sarif(run_id: str):
        store = _store_or_404(run_id)
        meta = _meta_from_manifest(store.load_manifest() or {})
        return JSONResponse(exporters.build_sarif(store.load_full_state(), meta))

    @app.get("/api/runs/{run_id}/export/index.md")
    async def export_index(run_id: str):
        store = _store_or_404(run_id)
        meta = _meta_from_manifest(store.load_manifest() or {})
        return PlainTextResponse(exporters.render_index_md(store.load_full_state(), meta), media_type="text/markdown")

    @app.get("/api/runs/{run_id}/export/finding/{fid}.md")
    async def export_finding(run_id: str, fid: str):
        store = _store_or_404(run_id)
        rec = store.load_finding(fid)
        if not rec:
            raise HTTPException(404, "finding not found")
        return PlainTextResponse(exporters.render_finding_md(rec), media_type="text/markdown")

    @app.post("/api/runs/{run_id}/export/all")
    async def export_all(run_id: str):
        store = _store_or_404(run_id)
        meta = _meta_from_manifest(store.load_manifest() or {})
        written = exporters.export_all(store.export_dir, store.load_full_state(), meta)
        return {"dir": store.export_dir, "files": sorted(os.path.basename(p) for p in written.values())}

    # ── SSE 实时事件流 ──
    @app.get("/api/runs/{run_id}/events")
    async def events_stream(run_id: str, request: Request):
        store = _store_or_404(run_id)
        try:
            last_id = int(request.headers.get("last-event-id") or request.query_params.get("last_id") or 0)
        except ValueError:
            last_id = 0

        async def gen():
            sent = last_id
            # 1) 先从磁盘补齐已落盘的历史事件
            for ev in store.read_events(sent):
                if ev.get("seq", 0) > sent:
                    yield _sse(ev)
                    sent = ev["seq"]
            # 2) 若 run 仍在跑,接活动流(内存 backlog>sent 部分 + 实时)
            bus = manager.get_bus(run_id)
            if bus:
                async for ev in bus.stream(sent):
                    if await request.is_disconnected():
                        break
                    if ev.get("seq", 0) > sent:
                        yield _sse(ev)
                        sent = ev["seq"]

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ── 静态 SPA(放最后,兜底 /) ──
    if os.path.isdir(STATIC_DIR):
        app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")

    app.state.manager = manager
    app.state.registry = registry
    return app
