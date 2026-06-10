"""专用优先排查通道(历史变体 + 风险点复查)的纯逻辑测试:
入队阈值、优先级排序、人工调级联动入队/出队、配置解析。不涉及子进程 / agent 调用。"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proto_vuln_hunt.config import Config, RecheckSpec, load_config
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


if __name__ == "__main__":
    unittest.main()
