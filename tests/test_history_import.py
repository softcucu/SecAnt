import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proto_vuln_hunt.config import Config, HistorySpec, RecheckSpec
from proto_vuln_hunt.pipeline import Pipeline
from proto_vuln_hunt.server import build_run_config
from proto_vuln_hunt.store import RunStore


_MODELS = {
    "threat": ["unit-model"],
    "recheck": ["unit-model"],
    "audit": ["unit-model"],
    "verify": ["unit-model"],
    "report": ["unit-model"],
    "poc": ["unit-model"],
}


def _cfg(tmp, **overrides):
    vals = {
        "target": tmp,
        "out_dir": os.path.join(tmp, "out"),
        "finders_per_item": 1,
        "concurrency": 2,
        "enable_poc": False,
        "models": dict(_MODELS),
        "history": HistorySpec(enabled=True),
        "recheck": RecheckSpec(enabled=True, max_retries=0),
    }
    vals.update(overrides)
    cfg = Config(**vals)
    cfg.health.enabled = False
    return cfg


def _threat_raw():
    return {
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
                {"node_id": "NODE-001", "node_type": "goal", "name": "造成服务中断", "order": 1},
                {"node_id": "NODE-002", "parent_id": "NODE-001", "node_type": "domain", "name": "协议栈", "order": 1},
                {"node_id": "NODE-003", "parent_id": "NODE-002", "node_type": "surface", "name": "协议入口", "surface_type": "protocol", "order": 1},
                {"node_id": "NODE-004", "parent_id": "NODE-003", "node_type": "method", "name": "畸形消息", "order": 1},
            ],
        }],
        "code_path_mappings": [{"surface_node_id": "NODE-003", "code_paths": [{"path": "src", "description": "入口"}]}],
    }


class HistoryImportConfigTests(unittest.TestCase):
    def test_imported_history_does_not_require_history_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(
                tmp,
                history_import_from=os.path.join(tmp, "old-run"),
                models={"threat": ["m"], "recheck": ["m"], "audit": ["m"], "verify": ["m"], "report": ["m"]},
            )
            self.assertEqual(cfg.required_model_roles(), ["threat", "recheck", "audit", "verify", "report"])
            self.assertEqual(cfg.model_config_error(), "")

    def test_build_run_config_ignores_removed_mode_payload(self):
        base = Config(target=".", models=dict(_MODELS))
        cfg = build_run_config(base, {
            "run_mode": "removed-mode",
            "history_import_from": "/tmp/source-run",
        })
        self.assertEqual(cfg.run_mode, "full")
        self.assertEqual(cfg.history_import_from, "/tmp/source-run")


class HistoryImportPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_imported_patterns_skip_history_commit_analysis_and_run_full_pipeline(self):
        class Runner:
            agent_count = 0
            usage_totals = {"calls": 0, "input_tokens": 0, "output_tokens": 0,
                            "total_tokens": 0, "estimated_calls": 0}

            def __init__(self):
                self.roles = []

            async def run(self, *_args, **kwargs):
                role = kwargs.get("role")
                self.roles.append(role)
                if role == "history":
                    raise AssertionError("history role should be skipped when importing history.json")
                if role == "threat":
                    return _threat_raw()
                return {"findings": [], "new_surfaces": [], "risk_notes": []}

        with tempfile.TemporaryDirectory() as tmp:
            src = RunStore(os.path.join(tmp, "src")).ensure()
            src.save_history([{
                "pattern": "missing bounds check before memcpy",
                "source": "abc123 fix overflow",
                "files": ["a.c"],
                "rationale": "unit",
            }])
            cfg = _cfg(tmp, history_import_from=src.dir)
            store = RunStore(cfg.out_dir).ensure()
            pipe = Pipeline(cfg, store=store)
            runner = Runner()
            pipe.runner = runner

            result = await pipe.run()

            self.assertEqual(result["status"], "done")
            self.assertIn("threat", runner.roles)
            self.assertIn("recheck", runner.roles)
            self.assertIn("audit", runner.roles)
            self.assertEqual(store.load_history()[0]["pattern"], "missing bounds check before memcpy")
            kinds = {r["kind"] for r in store.load_attack_surface()["ledger"]}
            self.assertIn("variant", kinds)
            self.assertIn("attack_method", kinds)

    async def test_empty_import_source_fails_instead_of_falling_back_to_commits(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = RunStore(os.path.join(tmp, "src")).ensure()
            src.save_history([])
            cfg = _cfg(tmp, history_import_from=src.dir)
            pipe = Pipeline(cfg, store=RunStore(cfg.out_dir).ensure())
            pipe._collect_commits = lambda: [{"hash": "abc", "subject": "security fix"}]

            with self.assertRaises(ValueError):
                await pipe.run()


if __name__ == "__main__":
    unittest.main()
