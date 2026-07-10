import os
import sys
import tempfile
import asyncio
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proto_vuln_hunt.backends import AgentRunner
from proto_vuln_hunt.config import Config, HistorySpec, RecheckSpec
from proto_vuln_hunt.pipeline import Pipeline
from proto_vuln_hunt.store import RunStore
from proto_vuln_hunt import threat_analysis as TA


def _pipe(tmp, **overrides):
    vals = {
        "target": tmp,
        "out_dir": os.path.join(tmp, "out"),
        "lenses": ["memory"],
        "finders_per_lens": 1,
        "concurrency": 1,
        "models": {
            "threat": ["unit-model"],
            "history": ["unit-model"],
            "recheck": ["unit-model"],
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


def _threat_raw():
    return {
        "schema_version": "1.0",
        "analysis_id": "unit",
        "sources": {"repositories": ["."], "documents": []},
        "assets": [{
            "asset_id": "ASSET-001",
            "name": "服务",
            "asset_type": "service",
            "criticality": "critical",
            "risks": [{
                "risk_id": "RISK-001",
                "name": "服务不可用",
                "security_property": "availability",
                "description": "服务中断",
            }],
        }],
        "attack_trees": [{
            "tree_id": "TREE-001",
            "asset_id": "ASSET-001",
            "risk_id": "RISK-001",
            "attack_goal": "造成服务中断",
            "root_node_id": "NODE-001",
            "nodes": [
                {"node_id": "NODE-001", "parent_id": None, "node_type": "goal", "name": "造成服务中断", "order": 1, "basis": []},
                {"node_id": "NODE-002", "parent_id": "NODE-001", "node_type": "domain", "name": "协议栈", "order": 1, "basis": []},
                {"node_id": "NODE-003", "parent_id": "NODE-002", "node_type": "surface", "name": "协议入口", "surface_type": "protocol", "order": 1, "basis": []},
                {"node_id": "NODE-004", "parent_id": "NODE-003", "node_type": "method", "name": "畸形消息", "order": 1, "basis": [], "preconditions": []},
            ],
        }],
        "code_path_mappings": [{"surface_node_id": "NODE-003", "code_paths": [{"path": "src", "description": "入口"}]}],
    }


def _future_hour_window():
    now = time.localtime()
    start = (now.tm_hour + 1) % 24
    end = (start + 1) % 24
    return f"{start:02d}:00~{end:02d}:00"


class TestUnifiedScheduler(unittest.IsolatedAsyncioTestCase):
    async def test_health_check_skips_time_window_unavailable_models(self):
        class DummyRunner:
            async def probe_model(self, model, *, reason="startup"):
                seen.append(model)
                return {"model": model, "status": "ok"}

        seen = []
        models = {
            "threat": ["ready-model"],
            "history": ["ready-model"],
            "recheck": ["ready-model"],
            "audit": ["closed-model", "ready-model"],
            "verify": ["ready-model"],
            "report": ["ready-model"],
            "poc": ["ready-model"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(
                tmp,
                models=models,
                model_concurrency={"default": 1},
                model_time_windows={"closed-model": _future_hour_window()},
            )
            p.runner = DummyRunner()

            result = await p.health_check_all()

            self.assertEqual(seen, ["ready-model"])
            self.assertEqual(result["ok"], 1)
            self.assertIn("closed-model", result["skipped_unavailable"])

    async def test_health_check_only_probes_active_run_models(self):
        class DummyRunner:
            async def probe_model(self, model, *, reason="startup"):
                seen.append(model)
                return {"model": model, "status": "ok"}

        seen = []
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(
                tmp,
                models={
                    "threat": ["active-threat"],
                    "history": ["unused-history"],
                    "recheck": ["unused-recheck"],
                    "audit": ["active-audit"],
                    "verify": ["active-verify"],
                    "report": ["active-report"],
                    "poc": ["unused-poc"],
                },
                enable_poc=False,
                history=HistorySpec(enabled=False),
                recheck=RecheckSpec(enabled=False),
                model_time_windows={
                    "unused-history": _future_hour_window(),
                    "unused-recheck": _future_hour_window(),
                    "unused-poc": _future_hour_window(),
                },
            )
            p.runner = DummyRunner()

            result = await p.health_check_all()

            self.assertEqual(seen, ["active-threat", "active-audit", "active-verify", "active-report"])
            self.assertEqual(result["total"], 4)
            self.assertEqual(result["skipped_unavailable"], [])

    async def test_history_commit_starts_while_threat_analysis_is_running(self):
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
                if role == "threat":
                    self.events.append("threat-start")
                    await asyncio.sleep(0.05)
                    self.events.append("threat-end")
                    return {"assets": [], "attack_trees": [], "code_path_mappings": []}
                if role == "history":
                    self.events.append("history")
                    return {"security_related": False}
                return {"findings": [], "new_surfaces": [], "risk_notes": []}

        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(
                tmp,
                enable_poc=False,
                history=HistorySpec(enabled=True),
                recheck=RecheckSpec(enabled=False),
            )
            p.cfg.health.enabled = False
            p._collect_commits = lambda: [{"hash": "abc123", "subject": "fix"}]
            runner = DummyRunner()
            p.runner = runner

            await p.run()

            self.assertLess(runner.events.index("threat-start"), runner.events.index("history"))
            self.assertLess(runner.events.index("history"), runner.events.index("threat-end"))

    async def test_attack_methods_audit_directly(self):
        class DummyRunner:
            def __init__(self):
                self.order = []
                self.prompts = []
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
                self.prompts.append(_args[0] if _args else "")
                return {"findings": [], "new_surfaces": [], "risk_notes": []}

        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            runner = DummyRunner()
            p.runner = runner
            p._enqueue_work({"kind": "attack_method", "id": "a1", "name": "m1", "priority": "high", "files": []})
            p._enqueue_work({"kind": "attack_method", "id": "a2", "name": "m2", "priority": "high", "files": []})

            await p.audit()

            roles = [r for r, _ in runner.order]
            self.assertEqual(roles, ["audit", "audit"])
            self.assertTrue(all("请分析代码实现是否存在" in p for p in runner.prompts))
            self.assertTrue(all("未找到与当前攻击面/攻击方式强相关的专用 skill" not in p for p in runner.prompts))
            self.assertTrue(all("只查这一个 lens" not in p for p in runner.prompts))

    def test_threat_attack_method_items_do_not_get_lens_hints(self):
        graph = TA.normalize(_threat_raw())
        items = graph["audit_items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["kind"], "attack_method")
        self.assertNotIn("lens_hint", items[0])
        self.assertNotIn("lens_hints", items[0])

    def test_attack_method_pass_uses_audit_profile_not_lens_expansion(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp, lenses=["memory", "integer", "dos"], finders_per_lens=2)
            item = {"kind": "attack_method", "id": "a1", "name": "畸形消息", "priority": "high", "files": []}
            p._start_audit_pass(item)

            finders = [w for w in p.queue if w.get("kind") == "_finder"]
            self.assertEqual(len(finders), 2)
            self.assertTrue(all(w.get("audit_key") == "generic-attack-method" for w in finders))
            self.assertTrue(all("lens_key" not in w for w in finders))

    def test_attack_method_pass_uses_strongly_relevant_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp, lenses=["memory", "integer", "dos"], finders_per_lens=1)
            item = {"kind": "attack_method", "id": "a1", "name": "认证绕过", "priority": "high", "files": []}
            p._start_audit_pass(item)

            finders = [w for w in p.queue if w.get("kind") == "_finder"]
            self.assertEqual(len(finders), 1)
            self.assertEqual(finders[0].get("audit_key"), "skill:authn")
            self.assertEqual(finders[0].get("audit_profile", {}).get("kind"), "skill")

    def test_generic_attack_method_template_composes_surface_and_method(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            item = {
                "kind": "attack_method",
                "name": "认证绕过",
                "attack_context": {
                    "surface": "IPSec协议",
                    "method": "认证绕过",
                    "preconditions": ["远程攻击者可发送协商报文"],
                },
            }

            text = p.pb.attack_method_instruction(item, {"kind": "generic"})

            self.assertIn("请分析代码实现是否存在IPSec协议认证绕过问题。", text)
            self.assertIn("攻击方式成立前提:远程攻击者可发送协商报文", text)
            self.assertNotIn("未找到与当前攻击面/攻击方式强相关的专用 skill", text)

    async def test_threat_completion_does_not_wait_for_active_history_before_audit(self):
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
                if role == "threat":
                    self.events.append("threat-start")
                    await asyncio.sleep(0.02)
                    self.events.append("threat-end")
                    return _threat_raw()
                if role == "history":
                    self.events.append("history-start")
                    await asyncio.sleep(0.15)
                    self.events.append("history-end")
                    return {"security_related": False}
                if role == "audit":
                    self.events.append("audit")
                return {"findings": [], "new_surfaces": [], "risk_notes": []}

        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(
                tmp,
                concurrency=2,
                enable_poc=False,
                history=HistorySpec(enabled=True),
                recheck=RecheckSpec(enabled=False),
            )
            p.cfg.health.enabled = False
            p._collect_commits = lambda: [{"hash": "abc123", "subject": "fix"}]
            runner = DummyRunner()
            p.runner = runner

            await p.run()

            self.assertLess(runner.events.index("history-start"), runner.events.index("threat-end"))
            self.assertLess(runner.events.index("threat-end"), runner.events.index("audit"))
            self.assertLess(runner.events.index("audit"), runner.events.index("history-end"))

    async def test_recheck_spawned_when_history_finishes_during_attack_method_audit(self):
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
                if role == "threat":
                    self.events.append("threat-start")
                    await asyncio.sleep(0.02)
                    self.events.append("threat-end")
                    return _threat_raw()
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
                if role == "audit":
                    self.events.append("audit-start")
                    await asyncio.sleep(0.35)
                    self.events.append("audit-end")
                    return {"findings": [], "new_surfaces": [], "risk_notes": []}
                if role == "recheck":
                    self.events.append("recheck-start")
                    return {"findings": [], "new_surfaces": [], "risk_notes": []}
                return {"findings": [], "new_surfaces": [], "risk_notes": []}

        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(
                tmp,
                concurrency=3,
                enable_poc=False,
                history=HistorySpec(enabled=True),
                recheck=RecheckSpec(enabled=True),
            )
            p.cfg.health.enabled = False
            p._collect_commits = lambda: [{"hash": "abc123", "subject": "security fix"}]
            runner = DummyRunner()
            p.runner = runner

            await p.run()

            self.assertLess(runner.events.index("audit-start"), runner.events.index("history-end"))
            self.assertLess(runner.events.index("history-end"), runner.events.index("recheck-start"))
            self.assertLess(runner.events.index("recheck-start"), runner.events.index("audit-end"))


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

    def test_time_window_unavailable_model_does_not_dispatch_role(self):
        models = {
            "threat": ["ready-model"],
            "history": ["ready-model"],
            "recheck": ["ready-model"],
            "audit": ["closed-model"],
            "verify": ["ready-model"],
            "report": ["ready-model"],
            "poc": ["ready-model"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(
                tmp,
                concurrency=2,
                models=models,
                model_concurrency={"default": 1},
                model_time_windows={"closed-model": _future_hour_window()},
            )
            p.runner = AgentRunner(p.cfg, logger=lambda *_a, **_k: None)

            self.assertEqual(p.runner.role_capacity_limit("audit"), 0)
            self.assertFalse(p.runner.role_has_capacity("audit"))

    def test_time_window_unavailable_front_work_does_not_block_ready_work(self):
        models = {
            "threat": ["ready-model"],
            "history": ["ready-model"],
            "recheck": ["ready-model"],
            "audit": ["closed-model"],
            "verify": ["ready-model"],
            "report": ["ready-model"],
            "poc": ["ready-model"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(
                tmp,
                concurrency=2,
                models=models,
                model_concurrency={"default": 1},
                model_time_windows={"closed-model": _future_hour_window()},
            )
            p.runner = AgentRunner(p.cfg, logger=lambda *_a, **_k: None)
            p._enqueue_work({"kind": "_finder", "audit_id": "a", "item": {}, "lens_key": "memory",
                             "idx": 0, "priority": "high"})
            p._enqueue_work({"kind": "_history_commit", "commit": {"hash": "abc", "subject": "s"},
                             "priority": "medium"})

            work = p._pop_next_work()

            self.assertEqual(work["kind"], "_history_commit")

class TestFinderResultShape(unittest.TestCase):
    def test_consume_accepts_top_level_finding_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            item = {"kind": "task", "objective": "audit", "newThisRound": 0}
            rec = p.ledger_rec(item)
            finding = {
                "title": "t",
                "bug_class": "memory",
                "file": "a.c",
                "function": "f",
                "description": "d",
                "severity": "high",
                "confidence": "medium",
            }

            p._consume([finding], item, rec, "memory")

            self.assertEqual(item["newThisRound"], 1)
            self.assertEqual(rec["candidates"], 1)
            self.assertEqual(len(p.pending_findings), 1)

    def test_consume_rejects_non_object_finding_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            item = {"kind": "task", "objective": "audit", "newThisRound": 0}
            rec = p.ledger_rec(item)

            with self.assertRaisesRegex(ValueError, r"findings\[0\] 应为 object"):
                p._consume({"findings": [[]]}, item, rec, "memory")


if __name__ == "__main__":
    unittest.main()
