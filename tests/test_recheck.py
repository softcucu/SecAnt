"""专用优先排查通道(历史变体 + 风险点复查)的纯逻辑测试:
入队阈值、优先级排序、人工调级联动入队/出队、配置解析。不涉及子进程 / agent 调用。"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proto_vuln_hunt.config import Config, RecheckSpec, load_config
from proto_vuln_hunt.common import item_key
from proto_vuln_hunt.pipeline import Pipeline
from proto_vuln_hunt.store import RunStore


def _pipe(tmp, **recheck):
    cfg = Config(target=tmp, out_dir=os.path.join(tmp, "out"))
    if recheck:
        cfg.recheck = RecheckSpec(**recheck)
    store = RunStore(cfg.out_dir).ensure()
    return Pipeline(cfg, store=store)


class TestRiskEnqueueThreshold(unittest.TestCase):
    def test_high_and_medium_enqueue_low_info_do_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            p.record_risk({"area": "a-high", "note": "n", "severity_hint": "high"}, "memory", 1)
            p.record_risk({"area": "a-med", "note": "n", "severity_hint": "medium"}, "memory", 1)
            p.record_risk({"area": "a-low", "note": "n", "severity_hint": "low"}, "memory", 1)
            p.record_risk({"area": "a-info", "note": "n", "severity_hint": "info"}, "memory", 1)
            kinds = [(it["kind"], it["severity_hint"]) for it in p.pq]
            self.assertEqual(sorted(s for _, s in kinds), ["high", "medium"])
            # low/info 仍登记,只是 recheck_status=none
            statuses = {r["area"]: r["recheck_status"] for r in p.risk_notes}
            self.assertEqual(statuses["a-low"], "none")
            self.assertEqual(statuses["a-high"], "queued")

    def test_threshold_high_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp, risk_min_severity="high")
            p.record_risk({"area": "m", "note": "n", "severity_hint": "medium"}, "memory", 1)
            p.record_risk({"area": "h", "note": "n", "severity_hint": "high"}, "memory", 1)
            self.assertEqual([it["severity_hint"] for it in p.pq], ["high"])

    def test_from_recheck_does_not_reenqueue(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            p.record_risk({"area": "x", "note": "n", "severity_hint": "high"}, "memory", 1, from_recheck=True)
            self.assertEqual(p.pq, [])
            self.assertEqual(p.risk_notes[0]["recheck_status"], "none")


class TestPriorityOrdering(unittest.TestCase):
    def test_variant_pops_before_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            p.record_risk({"area": "r1", "note": "n", "severity_hint": "high"}, "memory", 1)
            p._enqueue_variant({"pattern": "v1", "source": "c1", "files": [], "lens_hint": "memory"})
            p.record_risk({"area": "r2", "note": "n", "severity_hint": "high"}, "memory", 1)
            first = p._pop_priority()
            self.assertEqual(first["kind"], "variant")
            rest = [p._pop_priority()["kind"], p._pop_priority()["kind"]]
            self.assertEqual(rest, ["risk", "risk"])


class TestAuditRetryQueue(unittest.IsolatedAsyncioTestCase):
    async def test_failed_audit_item_retries_past_max_rounds_until_success(self):
        class DummyRunner:
            def __init__(self):
                self.calls = 0
                self.agent_count = 0
                self.usage_totals = {
                    "calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "estimated_calls": 0,
                }

            async def run(self, *_args, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    return None
                return {"findings": [], "new_surfaces": [], "risk_notes": []}

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(
                target=tmp,
                out_dir=os.path.join(tmp, "out"),
                lenses=["memory"],
                finders_per_lens=1,
                max_rounds=1,
                dry_rounds=1,
                decompose=False,
            )
            store = RunStore(cfg.out_dir).ensure()
            p = Pipeline(cfg, store=store)
            runner = DummyRunner()
            p.runner = runner
            item = {"kind": "task", "region": "r", "objective": "o", "files": []}
            p.queue.append(item)

            stop_reason = await p.audit()

            self.assertEqual(runner.calls, 2)
            self.assertEqual(p.queue, [])
            self.assertIn(item_key(item), p.completed_items)
            self.assertNotIn("retry_after_failure", item)
            self.assertIn("失败重试队列已补审完成", stop_reason)


class TestRecheckRetryQueue(unittest.IsolatedAsyncioTestCase):
    async def test_failed_recheck_item_is_requeued_not_completed(self):
        class DummyRunner:
            agent_count = 0
            usage_totals = {
                "calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "estimated_calls": 0,
            }

            async def run(self, *_args, **_kwargs):
                return None

        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            p.runner = DummyRunner()
            p.round = 1
            item = {"kind": "variant", "pattern": "v1", "source": "c1", "files": [], "lens_hint": "memory"}

            await p._run_recheck(item)

            self.assertEqual(p.pq, [item])
            self.assertEqual(item.get("retry_after_failure"), 1)
            self.assertNotIn(item_key(item), p.completed_items)
            self.assertEqual(p.ledger_rec(item)["status"], "incomplete")


class TestAdjustSeverity(unittest.TestCase):
    def test_upgrade_enqueues(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            p.record_risk({"area": "x", "note": "n", "severity_hint": "low"}, "memory", 1)
            rid = p.risk_notes[0]["id"]
            self.assertEqual(p.pq, [])
            self.assertTrue(p.adjust_risk_severity(rid, "high"))
            self.assertEqual([it["id"] for it in p.pq], [rid])
            self.assertEqual(p.risk_by_id[rid]["recheck_status"], "queued")

    def test_downgrade_dequeues_when_still_queued(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            p.record_risk({"area": "x", "note": "n", "severity_hint": "high"}, "memory", 1)
            rid = p.risk_notes[0]["id"]
            self.assertEqual(len(p.pq), 1)
            self.assertTrue(p.adjust_risk_severity(rid, "low"))
            self.assertEqual(p.pq, [])
            self.assertEqual(p.risk_by_id[rid]["recheck_status"], "none")

    def test_downgrade_after_done_does_not_touch_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            p.record_risk({"area": "x", "note": "n", "severity_hint": "high"}, "memory", 1)
            rid = p.risk_notes[0]["id"]
            p.pq.clear()
            p.risk_by_id[rid]["recheck_status"] = "done"
            self.assertTrue(p.adjust_risk_severity(rid, "low"))
            self.assertEqual(p.pq, [])
            self.assertEqual(p.risk_by_id[rid]["recheck_status"], "done")

    def test_unknown_id_returns_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp)
            self.assertFalse(p.adjust_risk_severity("RISK-999", "high"))


class TestConfig(unittest.TestCase):
    def test_recheck_defaults(self):
        cfg = Config()
        self.assertTrue(cfg.recheck.enabled)
        self.assertEqual(cfg.recheck.concurrency, 1)
        self.assertEqual(cfg.recheck.risk_min_severity, "medium")

    def test_recheck_parsed_and_clamped(self):
        import json
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"recheck": {"concurrency": 0, "risk_min_severity": "bogus", "poll_interval_s": 9}}, f)
            path = f.name
        try:
            cfg = load_config(path)
            self.assertEqual(cfg.recheck.concurrency, 1)             # clamped to >=1
            self.assertEqual(cfg.recheck.risk_min_severity, "medium")  # invalid → default
            self.assertEqual(cfg.recheck.poll_interval_s, 9)
        finally:
            os.unlink(path)

    def test_recheck_role_registered(self):
        from proto_vuln_hunt.config import ROLES
        self.assertIn("recheck", ROLES)

    def test_models_default_is_not_a_role_fallback(self):
        cfg = Config(models={"default": ["m"]}, decompose=False, enable_poc=False)
        cfg.history.enabled = False
        cfg.recheck.enabled = False
        self.assertEqual(cfg.models_for("audit"), [])
        self.assertIn("models.default 已不支持", cfg.model_config_error())
        self.assertIn("audit", cfg.missing_model_roles())

    def test_required_roles_accept_explicit_models(self):
        cfg = Config(
            models={
                "recon": ["m"],
                "audit": ["m"],
                "verify": ["m"],
                "report": ["m"],
            },
            decompose=False,
            enable_poc=False,
        )
        cfg.history.enabled = False
        cfg.recheck.enabled = False
        self.assertEqual(cfg.model_config_error(), "")


if __name__ == "__main__":
    unittest.main()
