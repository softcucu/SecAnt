import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proto_vuln_hunt.config import Config, HistorySpec, RecheckSpec
from proto_vuln_hunt.pipeline import Pipeline
from proto_vuln_hunt.server import build_run_config
from proto_vuln_hunt.store import RunStore


_ALL_MODELS = {
    "history": ["unit-model"],
    "recheck": ["unit-model"],
    "verify": ["unit-model"],
    "report": ["unit-model"],
    "poc": ["unit-model"],
}


def _history_only_cfg(tmp, **overrides):
    vals = {
        "target": tmp,
        "out_dir": os.path.join(tmp, "out"),
        "run_mode": "history_only",
        "history_import_from": "",
        "lenses": ["memory"],
        "finders_per_lens": 1,
        "concurrency": 2,
        "enable_poc": False,
        "models": dict(_ALL_MODELS),
        "history": HistorySpec(enabled=True),
        "recheck": RecheckSpec(enabled=True, max_retries=0),
    }
    vals.update(overrides)
    cfg = Config(**vals)
    cfg.health.enabled = False
    return cfg


class HistoryOnlyConfigTests(unittest.TestCase):
    def test_imported_history_only_does_not_require_history_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _history_only_cfg(
                tmp,
                history_import_from=os.path.join(tmp, "old-run"),
                models={"recheck": ["m"], "verify": ["m"], "report": ["m"]},
            )
            self.assertEqual(cfg.required_model_roles(), ["recheck", "verify", "report"])
            self.assertEqual(cfg.model_config_error(), "")

    def test_non_imported_history_only_requires_history_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _history_only_cfg(tmp, models={"recheck": ["m"], "verify": ["m"], "report": ["m"]})
            self.assertIn("models.history", cfg.model_config_error())

    def test_build_run_config_preserves_history_only_fields(self):
        base = Config(target=".", models=dict(_ALL_MODELS))
        cfg = build_run_config(base, {
            "run_mode": "history_only",
            "history_import_from": "/tmp/source-run",
        })
        self.assertEqual(cfg.run_mode, "history_only")
        self.assertEqual(cfg.history_import_from, "/tmp/source-run")


class HistoryOnlyImportTests(unittest.IsolatedAsyncioTestCase):
    async def test_imported_patterns_skip_history_commit_analysis_and_run_recheck(self):
        class Runner:
            agent_count = 0
            usage_totals = {"calls": 0, "input_tokens": 0, "output_tokens": 0,
                            "total_tokens": 0, "estimated_calls": 0}

            def __init__(self):
                self.roles = []

            async def run(self, *_args, **kwargs):
                role = kwargs.get("role")
                self.roles.append(role)
                if role in {"history", "recon", "audit", "decompose"}:
                    raise AssertionError(f"unexpected role: {role}")
                if role == "recheck":
                    return {"findings": [], "new_surfaces": [], "risk_notes": []}
                return {}

        with tempfile.TemporaryDirectory() as tmp:
            src = RunStore(os.path.join(tmp, "src")).ensure()
            src.save_recon({"history": [{
                "pattern": "missing bounds check before memcpy",
                "source": "abc123 fix overflow",
                "lens_hint": "memory",
                "files": ["a.c"],
                "rationale": "unit",
            }]})
            cfg = _history_only_cfg(tmp, history_import_from=src.dir)
            store = RunStore(cfg.out_dir).ensure()
            pipe = Pipeline(cfg, store=store)
            runner = Runner()
            pipe.runner = runner

            result = await pipe.run()

            self.assertEqual(result["status"], "done")
            self.assertEqual(runner.roles, ["recheck"])
            self.assertEqual(store.load_recon()["history"][0]["pattern"], "missing bounds check before memcpy")
            ledger = store.load_attack_surface()["ledger"]
            self.assertEqual(ledger[0]["kind"], "variant")

    async def test_imported_recheck_candidate_goes_through_verify_and_report(self):
        class Runner:
            agent_count = 0
            usage_totals = {"calls": 0, "input_tokens": 0, "output_tokens": 0,
                            "total_tokens": 0, "estimated_calls": 0}

            async def run(self, *_args, **kwargs):
                role = kwargs.get("role")
                label = kwargs.get("label") or ""
                if role == "recheck":
                    return {"findings": [{
                        "title": "overflow variant",
                        "bug_class": "memory",
                        "file": "a.c",
                        "line": 10,
                        "function": "parse",
                        "severity": "high",
                        "confidence": "high",
                        "description": "copy length is unchecked",
                        "source_to_sink": "a.c:1 -> a.c:10",
                    }], "new_surfaces": [], "risk_notes": []}
                if role == "verify" and "witness:" in label:
                    return {
                        "witness_complete": True,
                        "witness": "len=512",
                        "evidence_refs": ["a.c:10"],
                        "path_nodes": ["a.c:1", "a.c:10"],
                        "sink_ref": "a.c:10",
                        "trigger_condition": "len > dst",
                        "bad_result": "overflow",
                        "corrected_severity": "high",
                        "reasoning": "witness",
                    }
                if role == "verify" and "blocker:" in label:
                    return {
                        "blocker_found": False,
                        "blocker_scope": "none",
                        "evidence_refs": [],
                        "missing_evidence": "none",
                        "reasoning": "not refuted",
                    }
                if role == "verify" and "witness-judge" in label:
                    return {
                        "witness_verdict": "accepted",
                        "evidence_refs": ["a.c:10"],
                        "reviewed_checks": ["a.c:10"],
                        "reasoning": "accepted",
                    }
                if role == "verify" and "blocker-judge" in label:
                    return {
                        "blocker_verdict": "invalid",
                        "evidence_refs": ["a.c:10"],
                        "failed_checks": ["no blocker"],
                        "reasoning": "invalid",
                    }
                if role == "verify" and "final" in label:
                    return {
                        "epistemic_verdict": "proven_real",
                        "operational_decision": "confirmed",
                        "deciding_facts_checked": ["a.c:10"],
                        "final_reason": "confirmed",
                        "corrected_severity": "high",
                        "exploitability": "remote",
                        "verdict_confidence": "high",
                        "reasoning": "confirmed",
                    }
                if role == "report":
                    return "## 漏洞描述\nconfirmed"
                raise AssertionError(f"unexpected role: {role}")

        with tempfile.TemporaryDirectory() as tmp:
            src = RunStore(os.path.join(tmp, "src")).ensure()
            src.save_recon({"history": [{
                "pattern": "missing bounds check before memcpy",
                "source": "abc123 fix overflow",
                "lens_hint": "memory",
                "files": ["a.c"],
            }]})
            cfg = _history_only_cfg(tmp, history_import_from=src.dir, verify_votes=1)
            store = RunStore(cfg.out_dir).ensure()
            pipe = Pipeline(cfg, store=store)
            pipe.runner = Runner()

            result = await pipe.run()

            self.assertEqual(result["confirmed"], 1)
            finding = store.load_findings()[0]
            self.assertEqual(finding["variant_of"], "missing bounds check before memcpy(出处:abc123 fix overflow)")
            self.assertEqual(finding["corrected_severity"], "high")

    async def test_empty_import_source_fails_instead_of_falling_back_to_commits(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = RunStore(os.path.join(tmp, "src")).ensure()
            src.save_recon({"history": []})
            cfg = _history_only_cfg(tmp, history_import_from=src.dir)
            pipe = Pipeline(cfg, store=RunStore(cfg.out_dir).ensure())
            pipe._collect_commits = lambda: [{"hash": "abc", "subject": "security fix"}]

            with self.assertRaises(ValueError):
                await pipe.run()


if __name__ == "__main__":
    unittest.main()
