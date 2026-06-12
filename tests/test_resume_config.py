"""续跑历史任务时,后端/模型相关配置应改用本次启动的最新基础配置(self.base),
而不沿用 run 首次创建时落盘到 manifest 的旧快照。"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proto_vuln_hunt.config import Config
from proto_vuln_hunt.server import RunManager
from proto_vuln_hunt.store import RunRegistry


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

    def test_resume_uses_startup_model_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager, registry = self._manager(tmp, "new-startup-model")
            store = registry.create()
            # 模拟该 run 首次创建时落盘的旧模型快照
            store.init_manifest({
                "target": tmp, "backend": "codex",
                "models": _models("old-stale-model"),
                "model_concurrency": {"old-stale-model": 9},
                "max_rounds": 3,
            })

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


if __name__ == "__main__":
    unittest.main()
