"""续跑历史任务时,后端/模型相关配置应改用本次启动的最新基础配置(self.base),
而不沿用 run 首次创建时落盘到 manifest 的旧快照。"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proto_vuln_hunt.config import Config, load_config
from proto_vuln_hunt.pipeline import Pipeline
from proto_vuln_hunt.server import RunManager
from proto_vuln_hunt.store import RunRegistry, RunStore


_ROLES = ["recon", "history", "recheck", "decompose", "audit", "verify", "report", "poc"]


def _models(name):
    return {r: [name] for r in _ROLES}


class ResumeConfigTest(unittest.TestCase):
    def _manager(self, tmp, base_model):
        base = Config(
            target=tmp,
            runs_dir=os.path.join(tmp, "runs"),
            backend="claude",
            models=_models(base_model),
            model_concurrency={base_model: 2},
        )
        registry = RunRegistry(base.runs_dir).ensure()
        return RunManager(base, registry), registry

    def _stale_run(self, registry, tmp):
        store = registry.create()
        # 模拟该 run 首次创建时落盘的旧模型快照
        store.init_manifest({
            "target": tmp, "backend": "codex",
            "models": _models("old-stale-model"),
            "model_concurrency": {"old-stale-model": 9},
            "max_rounds": 3,
        })
        return store

    def test_resume_uses_startup_model_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, registry = self._manager(tmp, "new-startup-model")
            store = self._stale_run(registry, tmp)

            launched = {}
            manager._launch = lambda cfg, st: launched.setdefault("cfg", cfg) or st.id

            self.assertTrue(manager.resume(store.id))
            cfg = launched["cfg"]

            # 后端/模型相关 → 取本次启动的最新基础配置
            self.assertEqual(cfg.backend, "claude")
            self.assertEqual(cfg.models["audit"], ["new-startup-model"])
            self.assertEqual(cfg.model_concurrency, {"new-startup-model": 2})
            # 非模型字段 → 仍沿用 run 的旧快照
            self.assertEqual(cfg.max_rounds, 3)
            # 续跑标志生效
            self.assertTrue(cfg.resume)
            self.assertFalse(cfg.fresh)

    def test_resume_rereads_config_file(self):
        """编辑配置文件后无需重启进程:续跑应读到文件里的最新模型。"""
        import json as _json
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = os.path.join(tmp, "cfg.json")
            # 服务启动时:配置文件里是 file-model-v1
            with open(cfg_path, "w") as f:
                _json.dump({"target": tmp, "runs_dir": os.path.join(tmp, "runs"),
                            "models": _models("file-model-v1")}, f)
            base = load_config(cfg_path)
            registry = RunRegistry(base.runs_dir).ensure()
            manager = RunManager(base, registry, config_path=cfg_path)
            store = self._stale_run(registry, tmp)

            # 用户在不重启进程的情况下编辑了配置文件 → file-model-v2
            with open(cfg_path, "w") as f:
                _json.dump({"target": tmp, "runs_dir": os.path.join(tmp, "runs"),
                            "models": _models("file-model-v2")}, f)

            launched = {}
            manager._launch = lambda c, st: launched.setdefault("cfg", c) or st.id
            self.assertTrue(manager.resume(store.id))

            self.assertEqual(launched["cfg"].models["audit"], ["file-model-v2"])


class HealthPruneTest(unittest.TestCase):
    def test_reconcile_drops_stale_models(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(target=tmp, out_dir=os.path.join(tmp, "out"),
                         models=_models("kept-model"))
            store = RunStore(cfg.out_dir).ensure()
            # 旧 health 快照里既有现配置的模型,也有已移除的旧模型
            store.save_health({
                "kept-model": {"model": "kept-model", "status": "ok"},
                "removed-model": {"model": "removed-model", "status": "ok"},
            })
            pipe = Pipeline(cfg, store=store)
            pipe._reconcile_health_models()

            models = [r["model"] for r in store.load_health()["models"]]
            self.assertIn("kept-model", models)
            self.assertNotIn("removed-model", models)


class UsageResumeTest(unittest.TestCase):
    def test_resume_restores_usage_totals_and_next_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(target=tmp, out_dir=os.path.join(tmp, "out"),
                         models=_models("m"), resume=True)
            store = RunStore(cfg.out_dir).ensure()
            store.append_usage({
                "id": 1, "input_tokens": 10, "output_tokens": 5,
                "total_tokens": 15, "estimated": True,
            })
            store.append_usage({
                "id": 7, "input_tokens": 20, "output_tokens": 8,
                "total_tokens": 28, "estimated": False,
            })

            pipe = Pipeline(cfg, store=store)

            self.assertEqual(pipe.runner.usage_count, 7)
            self.assertEqual(pipe.runner.usage_totals, {
                "calls": 2,
                "input_tokens": 30,
                "output_tokens": 13,
                "total_tokens": 43,
                "estimated_calls": 1,
            })

            pipe.runner._record_usage(
                "prompt", "output", role="audit", label="audit:unit",
                model="m", attempt=1,
                backend_usage={"input_tokens": 3, "output_tokens": 2, "total_tokens": 5},
            )

            rows = store.load_usage()
            self.assertEqual(rows[-1]["id"], 8)
            self.assertEqual(pipe.runner.usage_totals["calls"], 3)
            self.assertEqual(pipe.runner.usage_totals["total_tokens"], 48)


if __name__ == "__main__":
    unittest.main()
