"""事件总线:Pipeline 发结构化事件,Web 经 SSE 实时消费;同时由 RunStore 落 events.jsonl。

每个 run 一个 EventBus(由 RunManager 创建):内存里保留该 run 的事件 backlog(供新订阅者补齐),
并通过 sink 回调把事件追加到磁盘 events.jsonl(供 SSE 重放 / 服务重启后回看)。
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Callable, Dict, List, Optional

# ── 事件类型常量(与 pipeline.emit 一一对应) ──
RUN_STATUS = "run_status"          # {status}
LOG = "log"                        # {level, message}
RECON_DONE = "recon_done"          # {purpose, threat_summary, regions, history, build_hint}
DECOMPOSE_DONE = "decompose_done"  # {tasks, regions}
ROUND_START = "round_start"        # {round}
ROUND_DONE = "round_done"          # {round, new_findings, new_surfaces, queue_len, dry_streak, risks}
CANDIDATE_FOUND = "candidate_found"    # {key, title, bug_class, file, line}
FINDING_CONFIRMED = "finding_confirmed"  # {finding ...}
FINDING_REJECTED = "finding_rejected"    # {key, title}
SURFACE_ADDED = "surface_added"    # {name, why, files, lens_hint, round, from}
RISK_ADDED = "risk_added"          # {area, note, file, severity_hint, lens, round}
POC_DONE = "poc_done"              # {id, compiled, triggered}
COVERAGE_UPDATE = "coverage_update"  # {ledger, surfaces, progress}
METRICS = "metrics"                # {agents_spawned, in_flight, confirmed, candidates}
USAGE = "usage"                    # {role, label, model, input_tokens, output_tokens, total_tokens, estimated}
HEALTH_START = "health_check_start"  # {models}
HEALTH_DONE = "health_check_done"    # {total, ok, unhealthy}
MODEL_HEALTH = "model_health"        # {model, status, last_latency_ms, answer, error, checks, calls, ...}
RUN_DONE = "run_done"              # {summary}
ERROR = "error"                    # {message}


def now_ms() -> int:
    return int(time.time() * 1000)


class EventBus:
    """单个 run 的事件总线。线程模型:全部在该 run 的事件循环里运行,无需加锁。"""

    def __init__(self, sink: Optional[Callable[[Dict[str, Any]], None]] = None,
                 backlog: Optional[List[Dict[str, Any]]] = None):
        self.events: List[Dict[str, Any]] = list(backlog or [])
        self._seq = self.events[-1]["seq"] if self.events else 0
        self._subscribers: List[asyncio.Queue] = []
        self._sink = sink           # 持久化回调:store.append_event(event)
        self.closed = False

    @property
    def last_seq(self) -> int:
        return self._seq

    def emit(self, etype: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._seq += 1
        ev = {"seq": self._seq, "ts": now_ms(), "type": etype, "data": data or {}}
        self.events.append(ev)
        if self._sink:
            try:
                self._sink(ev)
            except Exception:
                pass  # 持久化失败不影响运行
        for q in list(self._subscribers):
            try:
                q.put_nowait(ev)
            except Exception:
                pass
        return ev

    def close(self) -> None:
        """标记 run 结束;唤醒所有订阅者使其 stream 自然退出。"""
        self.closed = True
        for q in list(self._subscribers):
            try:
                q.put_nowait(None)  # 哨兵
            except Exception:
                pass

    async def stream(self, last_id: int = 0):
        """异步生成器:先补发 seq>last_id 的 backlog,再实时转发新事件。
        客户端断开 → 外层取消本协程,finally 注销订阅。"""
        # 1) backlog 补齐
        for ev in self.events:
            if ev["seq"] > last_id:
                yield ev
        if self.closed:
            return
        # 2) 实时
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.append(q)
        try:
            while True:
                ev = await q.get()
                if ev is None:  # close() 哨兵
                    return
                if ev["seq"] > last_id:
                    yield ev
        finally:
            if q in self._subscribers:
                self._subscribers.remove(q)
