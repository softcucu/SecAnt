import os
import sys
import tempfile
import asyncio
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proto_vuln_hunt.config import Config, HistorySpec, RecheckSpec
from proto_vuln_hunt.pipeline import Pipeline
from proto_vuln_hunt.store import RunStore


def _pipe(tmp, **overrides):
    vals = {
        "target": tmp,
        "out_dir": os.path.join(tmp, "out"),
        "lenses": ["memory"],
        "finders_per_lens": 1,
        "concurrency": 1,
        "models": {
            "recon": ["unit-model"],
            "history": ["unit-model"],
            "recheck": ["unit-model"],
            "decompose": ["unit-model"],
            "audit": ["unit-model"],
            "verify": ["unit-model"],
            "report": ["unit-model"],
            "poc": ["unit-model"],
        },
        "history": HistorySpec(enabled=False),
        "recheck": RecheckSpec(enabled=False),
    }
    vals.update(overrides)
    cfg = Config(
        **vals,
    )
    store = RunStore(cfg.out_dir).ensure()
    return Pipeline(cfg, store=store)


class TestUnifiedScheduler(unittest.IsolatedAsyncioTestCase):
    async def test_history_commit_starts_while_recon_is_running(self):
        class DummyRunner:
            def __init__(self):
                self.events = []
                self.agent_count = 0
                self.usage_totals = {
                    "calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "estimated_calls": 0,
                }

            async def run(self, *_args, **kwargs):
                role = kwargs.get("role")
                if role == "recon":
                    self.events.append("recon-start")
                    await asyncio.sleep(0.05)
                    self.events.append("recon-end")
                    return {"regions": [], "history": [], "build_hint": "", "repo_knowledge": ""}
                if role == "history":
                    self.events.append("history")
                    return {"security_related": False}
                return {"findings": [], "new_surfaces": [], "risk_notes": []}

        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(
                tmp,
                decompose=False,
                enable_poc=False,
                history=HistorySpec(enabled=True),
                recheck=RecheckSpec(enabled=False),
            )
            p.cfg.health.enabled = False
            p._collect_commits = lambda: [{"hash": "abc123", "subject": "fix"}]
            runner = DummyRunner()
            p.runner = runner

            await p.run()

            self.assertLess(runner.events.index("recon-start"), runner.events.index("history"))
            self.assertLess(runner.events.index("history"), runner.events.index("recon-end"))

    async def test_audit_starts_after_first_region_decomposes(self):
        class DummyRunner:
            def __init__(self):
                self.order = []
                self.agent_count = 0
                self.usage_totals = {
                    "calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "estimated_calls": 0,
                }

            async def run(self, *_args, **kwargs):
                role = kwargs.get("role")
                label = kwargs.get("label") or role
                self.order.append((role, label))
                if role == "decompose":
                    name = label.split(":", 1)[1]
                    return {"subtasks": [{"objective": f"audit-{name}", "files": []}]}
                return {"findings": [], "new_surfaces": [], "risk_notes": []}

        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp, decompose=True)
            runner = DummyRunner()
            p.runner = runner
            p._enqueue_work({"kind": "region", "name": "r1", "priority": "high", "files": []})
            p._enqueue_work({"kind": "region", "name": "r2", "priority": "high", "files": []})

            await p.audit()

            roles = [r for r, _ in runner.order]
            self.assertEqual(roles, ["decompose", "audit", "decompose", "audit"])

    async def test_recon_completion_does_not_wait_for_active_history_before_decompose(self):
        class DummyRunner:
            def __init__(self):
                self.events = []
                self.agent_count = 0
                self.usage_totals = {
                    "calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "estimated_calls": 0,
                }

            async def run(self, *_args, **kwargs):
                role = kwargs.get("role")
                if role == "recon":
                    self.events.append("recon-start")
                    await asyncio.sleep(0.02)
                    self.events.append("recon-end")
                    return {
                        "regions": [{"name": "r1", "priority": "high", "files": []}],
                        "history": [],
                        "build_hint": "",
                        "repo_knowledge": "",
                    }
                if role == "history":
                    self.events.append("history-start")
                    await asyncio.sleep(0.15)
                    self.events.append("history-end")
                    return {"security_related": False}
                if role == "decompose":
                    self.events.append("decompose-start")
                    return {"subtasks": [{"objective": "audit-r1", "files": []}]}
                if role == "audit":
                    self.events.append("audit")
                return {"findings": [], "new_surfaces": [], "risk_notes": []}

        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(
                tmp,
                concurrency=2,
                decompose=True,
                enable_poc=False,
                history=HistorySpec(enabled=True),
                recheck=RecheckSpec(enabled=False),
            )
            p.cfg.health.enabled = False
            p._collect_commits = lambda: [{"hash": "abc123", "subject": "fix"}]
            runner = DummyRunner()
            p.runner = runner

            await p.run()

            self.assertLess(runner.events.index("history-start"), runner.events.index("recon-end"))
            self.assertLess(runner.events.index("recon-end"), runner.events.index("decompose-start"))
            self.assertLess(runner.events.index("decompose-start"), runner.events.index("history-end"))

    async def test_recheck_spawned_when_history_finishes_during_decompose(self):
        class DummyRunner:
            def __init__(self):
                self.events = []
                self.agent_count = 0
                self.usage_totals = {
                    "calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "estimated_calls": 0,
                }

            async def run(self, *_args, **kwargs):
                role = kwargs.get("role")
                if role == "recon":
                    self.events.append("recon-start")
                    await asyncio.sleep(0.02)
                    self.events.append("recon-end")
                    return {
                        "regions": [{"name": "r1", "priority": "high", "files": []}],
                        "history": [],
                        "build_hint": "",
                        "repo_knowledge": "",
                    }
                if role == "history":
                    self.events.append("history-start")
                    await asyncio.sleep(0.08)
                    self.events.append("history-end")
                    return {
                        "security_related": True,
                        "pattern": "missing bounds check",
                        "lens_hint": "memory",
                        "files": [],
                        "rationale": "unit",
                    }
                if role == "decompose":
                    self.events.append("decompose-start")
                    await asyncio.sleep(0.35)
                    self.events.append("decompose-end")
                    return {"subtasks": [{"objective": "audit-r1", "files": []}]}
                if role == "recheck":
                    self.events.append("recheck-start")
                    return {"findings": [], "new_surfaces": [], "risk_notes": []}
                if role == "audit":
                    self.events.append("audit")
                return {"findings": [], "new_surfaces": [], "risk_notes": []}

        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(
                tmp,
                concurrency=3,
                decompose=True,
                enable_poc=False,
                history=HistorySpec(enabled=True),
                recheck=RecheckSpec(enabled=True),
            )
            p.cfg.health.enabled = False
            p._collect_commits = lambda: [{"hash": "abc123", "subject": "security fix"}]
            runner = DummyRunner()
            p.runner = runner

            await p.run()

            self.assertLess(runner.events.index("decompose-start"), runner.events.index("history-end"))
            self.assertLess(runner.events.index("history-end"), runner.events.index("recheck-start"))
            self.assertLess(runner.events.index("recheck-start"), runner.events.index("decompose-end"))


class TestSchedulerPriority(unittest.TestCase):
    def test_recheck_work_is_selected_before_audit_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp, recheck=RecheckSpec(enabled=True))
            p.pq.append({"kind": "risk", "id": "RISK-001", "area": "x", "severity_hint": "high"})
            p._enqueue_work({"kind": "task", "objective": "audit", "files": [], "priority": "high"})

            work = p._pop_next_work()

            self.assertEqual(work["kind"], "_recheck")
            self.assertEqual(work["item"]["id"], "RISK-001")

    def test_history_and_audit_share_priority_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            history = {"kind": "_history_commit", "commit": {"hash": "abc", "subject": "s"}, "priority": "high"}
            audit = {"kind": "_finder", "audit_id": "a", "item": {}, "lens_key": "memory", "idx": 0, "priority": "high"}

            self.assertEqual(p._work_priority(history), p._work_priority(audit))

    def test_history_commit_is_above_medium_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            history = {"kind": "_history_commit", "commit": {"hash": "abc", "subject": "s"}, "priority": "high"}
            audit = {"kind": "_finder", "audit_id": "a", "item": {}, "lens_key": "memory", "idx": 0, "priority": "medium"}

            self.assertLess(p._work_priority(history), p._work_priority(audit))

    def test_unavailable_front_role_does_not_block_later_ready_role(self):
        class CapacityRunner:
            def role_has_capacity(self, role):
                return role == "history"

        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            p.runner = CapacityRunner()
            p._enqueue_work({"kind": "_finder", "audit_id": "a", "item": {}, "lens_key": "memory",
                             "idx": 0, "priority": "high"})
            p._enqueue_work({"kind": "_history_commit", "commit": {"hash": "abc", "subject": "s"},
                             "priority": "medium"})

            work = p._pop_next_work()

            self.assertEqual(work["kind"], "_history_commit")


if __name__ == "__main__":
    unittest.main()
