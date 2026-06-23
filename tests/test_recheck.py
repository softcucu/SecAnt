"""专用优先排查通道(历史变体 + 风险点复查)的纯逻辑测试:
入队阈值、优先级排序、人工调级联动入队/出队、配置解析。不涉及子进程 / agent 调用。"""
import os
import sys
import tempfile
import time
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


class TestRecheckGivesUp(unittest.IsolatedAsyncioTestCase):
    """持续失败的优先排查项必须在 max_retries 次后放弃,而不是无限回灌优先队列。
    这是修复“跑完 recon 后只剩 1 个 recheck、其它 agent 全停”死循环的关键不变量。"""

    class _FailRunner:
        agent_count = 0
        usage_totals = {"calls": 0, "input_tokens": 0, "output_tokens": 0,
                        "total_tokens": 0, "estimated_calls": 0}

        async def run(self, *_args, **_kwargs):
            return None  # 后端持续失败

    async def test_recheck_abandoned_after_exceeding_max_retries(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _pipe(tmp, enabled=True, max_retries=2)
            p.runner = self._FailRunner()
            p.round = 1
            item = {"kind": "variant", "pattern": "v1", "source": "c1", "files": [], "lens_hint": "memory"}

            # 前 max_retries 次失败 → 仍回灌重排
            for expected in (1, 2):
                p.pq.clear()
                await p._run_recheck(item)
                self.assertEqual(p.pq, [item])
                self.assertEqual(item["retry_after_failure"], expected)
                self.assertNotIn(item_key(item), p.completed_items)

            # 第 max_retries+1 次失败 → 放弃:不再回灌、标记完成、状态 abandoned
            p.pq.clear()
            await p._run_recheck(item)
            self.assertEqual(p.pq, [])
            self.assertIn(item_key(item), p.completed_items)
            self.assertEqual(p.ledger_rec(item)["status"], "abandoned")

    async def test_persistently_failing_recheck_does_not_hang_audit(self):
        """端到端:audit() 在 recheck 永久失败时仍必须收敛(不再死循环),
        且普通 audit 工作照常完成——recheck 失败不拖住其它 agent。"""
        class MixedRunner:
            agent_count = 0
            usage_totals = {"calls": 0, "input_tokens": 0, "output_tokens": 0,
                            "total_tokens": 0, "estimated_calls": 0}

            def __init__(self):
                self.audit_calls = 0

            async def run(self, *_args, **kwargs):
                if kwargs.get("role") == "recheck":
                    return None  # 复查永久失败
                self.audit_calls += 1
                return {"findings": [], "new_surfaces": [], "risk_notes": []}

        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(target=tmp, out_dir=os.path.join(tmp, "out"), lenses=["memory"],
                         finders_per_lens=1, max_rounds=1, dry_rounds=1, decompose=False)
            cfg.recheck = RecheckSpec(enabled=True, max_retries=1)
            store = RunStore(cfg.out_dir).ensure()
            p = Pipeline(cfg, store=store)
            p.runner = MixedRunner()
            p._enqueue_variant({"pattern": "v1", "source": "c1", "files": [], "lens_hint": "memory"})
            p.queue.append({"kind": "task", "region": "r", "objective": "o", "files": []})

            import asyncio
            # 修复前这里会永久挂起;加超时把回归坐死。
            await asyncio.wait_for(p.audit(), timeout=10)

            self.assertEqual(p.pq, [])
            self.assertEqual(p._recheck_inflight, 0)
            self.assertIn("variant:v1", p.completed_items)   # 失败的复查被放弃
            self.assertGreaterEqual(p.runner.audit_calls, 1)  # 普通审计照常完成


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

    def test_active_models_only_include_required_roles(self):
        cfg = Config(
            models={
                "recon": ["recon-m"],
                "history": ["unused-history-m"],
                "recheck": ["unused-recheck-m"],
                "decompose": ["unused-decompose-m"],
                "audit": ["audit-m"],
                "verify": ["verify-m"],
                "report": ["report-m"],
                "poc": ["unused-poc-m"],
            },
            decompose=False,
            enable_poc=False,
        )
        cfg.history.enabled = False
        cfg.recheck.enabled = False

        self.assertEqual(cfg.active_models(), ["recon-m", "audit-m", "verify-m", "report-m"])
        self.assertIn("unused-history-m", cfg.all_models())
        self.assertIn("unused-poc-m", cfg.all_models())

    def test_model_time_windows_default_to_all_day(self):
        ts = time.mktime((2026, 1, 2, 12, 0, 0, 0, 0, -1))
        cfg = Config(models={"audit": ["m"]}, model_concurrency={"default": 1})

        self.assertTrue(cfg.model_available_at("m", ts))
        self.assertEqual(cfg.model_slots_for("audit", ts), ["m"])

    def test_model_time_windows_filter_slots(self):
        at_0100 = time.mktime((2026, 1, 2, 1, 0, 0, 0, 0, -1))
        at_0700 = time.mktime((2026, 1, 2, 7, 0, 0, 0, 0, -1))
        cfg = Config(
            models={"audit": ["night", "always"]},
            model_concurrency={"default": 1},
            model_time_windows={"night": "00:00~06:00"},
        )

        self.assertTrue(cfg.model_available_at("night", at_0100))
        self.assertFalse(cfg.model_available_at("night", at_0700))
        self.assertTrue(cfg.model_available_at("always", at_0700))
        self.assertEqual(cfg.model_slots_for("audit", at_0100), ["night", "always"])
        self.assertEqual(cfg.model_slots_for("audit", at_0700), ["always"])

    def test_model_time_windows_support_cross_midnight(self):
        at_2300 = time.mktime((2026, 1, 2, 23, 0, 0, 0, 0, -1))
        at_0100 = time.mktime((2026, 1, 3, 1, 0, 0, 0, 0, -1))
        at_1200 = time.mktime((2026, 1, 3, 12, 0, 0, 0, 0, -1))
        cfg = Config(models={"audit": ["m"]}, model_time_windows={"m": "22:00~02:00"})

        self.assertTrue(cfg.model_available_at("m", at_2300))
        self.assertTrue(cfg.model_available_at("m", at_0100))
        self.assertFalse(cfg.model_available_at("m", at_1200))

    def test_invalid_model_time_windows_report_config_error(self):
        cfg = Config(models={"audit": ["m"]}, model_time_windows={"m": "bad-window"})

        self.assertIn("模型可用时间段配置错误", cfg.model_config_error())


if __name__ == "__main__":
    unittest.main()
