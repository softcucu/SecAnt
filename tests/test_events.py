import asyncio
import builtins
import os
import tempfile
import unittest
from unittest import mock

from proto_vuln_hunt import events as EV
from proto_vuln_hunt.events import EventBus
from proto_vuln_hunt.pipeline import Pipeline
from proto_vuln_hunt.config import Config
from proto_vuln_hunt.server import _candidate_snapshot_from_events, _dashboard_snapshot, _response_findings
from proto_vuln_hunt.store import RunStore


class EventBusPersistTests(unittest.TestCase):
    def _bus(self):
        sunk = []
        bus = EventBus(sink=sunk.append)
        return bus, sunk

    def test_persisted_event_goes_to_sink_and_backlog(self):
        bus, sunk = self._bus()
        bus.emit(EV.ROUND_START, {"round": 1})  # 默认 persist=True
        self.assertEqual(len(sunk), 1)
        self.assertEqual(len(bus.events), 1)

    def test_output_chunk_not_persisted_and_not_in_backlog(self):
        bus, sunk = self._bus()
        bus.emit(EV.AGENT_UPDATE, {"status": "output", "chunk": "x" * 100000}, persist=False)
        # 不落盘、不进内存 backlog
        self.assertEqual(sunk, [])
        self.assertEqual(bus.events, [])
        # 但 seq 仍递增(实时推送可用)
        self.assertEqual(bus.last_seq, 1)

    def test_start_seq_continues_monotonically_on_resume(self):
        # 续跑:bus 必须从磁盘已落盘的最大 seq 续接,否则重号会被 SSE 的 seq>sent 过滤掉。
        bus = EventBus(sink=lambda ev: None, start_seq=5000)
        ev = bus.emit(EV.ROUND_START, {"round": 9})
        self.assertEqual(ev["seq"], 5001)
        self.assertGreater(bus.last_seq, 5000)

    def test_run_store_tracks_last_event_seq(self):
        with tempfile.TemporaryDirectory() as td:
            store = RunStore(td).ensure()
            store.append_event({"seq": 7, "ts": 0, "type": EV.LOG, "data": {}})
            self.assertEqual(store.last_event_seq(), 7)

    def test_iter_events_skips_events_file_when_after_seq_reaches_tail(self):
        with tempfile.TemporaryDirectory() as td:
            store = RunStore(td).ensure()
            store.append_event({"seq": 1, "ts": 0, "type": EV.LOG, "data": {}})
            events_path = os.path.abspath(store.events_path)
            real_open = builtins.open

            def guarded_open(path, *args, **kwargs):
                if os.path.abspath(path) == events_path:
                    raise AssertionError("events.jsonl should not be opened when after_seq is current")
                return real_open(path, *args, **kwargs)

            with mock.patch("builtins.open", guarded_open):
                self.assertEqual(list(store.iter_events(1)), [])

    def test_dashboard_snapshot_limits_usage_rows(self):
        with tempfile.TemporaryDirectory() as td:
            store = RunStore(td).ensure()
            store.init_manifest({"target": "."})
            for i in range(100):
                store.append_usage({"id": i, "role": "audit", "input_tokens": i})

            snap = _dashboard_snapshot(store, running=False, last_seq=0)
            self.assertEqual(len(snap["usage"]), 80)
            self.assertEqual(snap["usage"][0]["id"], 20)

    def test_lite_dashboard_snapshot_skips_heavy_rows(self):
        with tempfile.TemporaryDirectory() as td:
            store = RunStore(td).ensure()
            store.init_manifest({"target": "."})
            store.update_summary({"candidates": 3, "risks": 2, "token_usage": {"calls": 100}})
            store.save_candidate({"key": "a.c::1::memory", "status": "pending"})
            store.append_usage({"id": 1, "role": "audit"})

            snap = _dashboard_snapshot(store, running=True, last_seq=0, lite=True)
            self.assertEqual(snap["candidates"], [])
            self.assertEqual(snap["usage"], [])
            self.assertEqual(snap["counts"]["candidates"], 3)
            self.assertEqual(snap["counts"]["risks"], 2)
            self.assertEqual(snap["counts"]["usage"], 100)

    def test_start_seq_respects_higher_backlog_tail(self):
        # start_seq 与 backlog 尾部取较大者,二者都给时不回退。
        backlog = [{"seq": 42, "ts": 0, "type": EV.LOG, "data": {}}]
        bus = EventBus(backlog=backlog, start_seq=10)
        self.assertEqual(bus.emit(EV.LOG)["seq"], 43)

    def test_non_persisted_event_still_reaches_live_subscriber(self):
        async def run():
            bus, _sunk = self._bus()
            received = []

            async def consume():
                async for ev in bus.stream(last_id=0):
                    received.append(ev)
                    if ev["type"] == EV.AGENT_UPDATE:
                        return

            task = asyncio.create_task(consume())
            await asyncio.sleep(0.01)  # 让订阅者先挂上
            bus.emit(EV.AGENT_UPDATE, {"status": "output", "chunk": "live"}, persist=False)
            await asyncio.wait_for(task, timeout=1.0)
            return received

        received = asyncio.run(run())
        self.assertTrue(any(ev["type"] == EV.AGENT_UPDATE for ev in received))


class RecordAgentWiringTests(unittest.TestCase):
    def _pipeline(self):
        captured = []
        cfg = Config(target=".", models={"audit": ["m"]})
        cfg.health.enabled = False
        pipe = Pipeline(cfg, emitter=lambda etype, data, persist=True: captured.append((etype, persist)))
        return pipe, captured

    def test_output_status_is_not_persisted(self):
        pipe, captured = self._pipeline()
        pipe.record_agent({"id": "a1", "status": "output", "chunk": "abc"})
        # 只发一条 AGENT_UPDATE,persist=False,且不附带 METRICS
        self.assertEqual(captured, [(EV.AGENT_UPDATE, False)])

    def test_non_output_status_is_persisted(self):
        pipe, captured = self._pipeline()
        pipe.record_agent({"id": "a1", "status": "done"})
        # AGENT_UPDATE 持久化,且跟一条 METRICS
        self.assertIn((EV.AGENT_UPDATE, True), captured)
        self.assertTrue(any(etype == EV.METRICS for etype, _ in captured))


class SnapshotMigrationTests(unittest.TestCase):
    def test_response_findings_include_feedback_and_legacy_output_time(self):
        with tempfile.TemporaryDirectory() as td:
            store = RunStore(td).ensure()
            store.save_finding({
                "id": "MEM-001", "title": "t", "bug_class": "memory",
                "file": "a.c", "line": 10, "severity": "high",
            })
            store.append_event({"seq": 1, "ts": 12345000, "type": EV.FINDING_CONFIRMED, "data": {
                "id": "MEM-001",
            }})
            updated = store.update_finding_feedback("MEM-001", {"status": "confirmed", "updated_at": 200.0})

            self.assertEqual(updated["manual_feedback"]["status"], "confirmed")
            rows = _response_findings(store)
            self.assertEqual(rows[0]["manual_feedback"]["status"], "confirmed")
            self.assertEqual(rows[0]["output_ts"], 12345.0)

    def test_legacy_events_migrate_rejected_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            store = RunStore(td).ensure()
            store.append_event({"seq": 1, "ts": 0, "type": EV.CANDIDATE_FOUND, "data": {
                "key": "a.c::10::memory", "title": "t", "bug_class": "memory",
                "file": "a.c", "line": 10, "severity": "high",
                "description": "candidate reason",
            }})
            store.append_event({"seq": 2, "ts": 0, "type": EV.FINDING_REJECTED, "data": {
                "key": "a.c::10::memory", "title": "t", "bug_class": "memory",
                "vote_false": 2, "vote_total": 3, "rejection_reason": "多数验证票判定为非问题",
                "votes": [{"is_real": False, "reasoning": "已被上游夹紧"}],
            }})

            cands = _candidate_snapshot_from_events(store)
            self.assertEqual(len(cands), 1)
            self.assertEqual(cands[0]["status"], "rejected")
            self.assertEqual(cands[0]["vote_false"], 2)
            self.assertEqual(store.load_candidates()[0]["status"], "rejected")


if __name__ == "__main__":
    unittest.main()
