"""结构化 run 存储:一个 run = 一个目录。按"数据生命周期"分文件存(而非塞进一个 state.json):

  run.json             —— 清单:id / 时间戳 / 状态 / 配置快照 / 汇总(runs 列表与 dashboard 头部读它)
  checkpoint.json      —— 运行时机制态(round/seq/processed/pending/dedup…),高频小幅刷
  history.json         —— git 历史安全修复提炼出的历史问题模式
  threat-analysis/graph.json —— 基于攻击树的威胁分析图(资产/风险/goal/domain/surface/method)
  attack-surface.json  —— 攻击面(初始+动态)+ 覆盖台账 + progress,每轮整体快照(状态持续演变)
  candidates/<hash>.json —— 每条候选/非问题的当前状态(候选、已确认、已否决、验证失败)
  findings/<id>.json   —— 每条确认漏洞一个文件,确认即写;人工反馈可追加更新
  risks/<id>.json      —— 每条风险一个文件,登记即写、写一次即终态
  usage.jsonl          —— 每次 agent 调用的 token 使用记录(真实 usage 或轻量估算)
  events.jsonl         —— append-only 事件日志(SSE 重放 / 服务重启回看)
  exports/             —— 按需生成的 MD / SARIF(由 exporters.py 渲染)

判据:会演变的(攻击面/覆盖)单文件快照;漏洞/风险多文件独立寻址;威胁分析与历史模式独立存储。
Web 的 run 放在 runs_root/<run_id>/;CLI 仍可用 <out_dir>/ 当 run 目录(resume 行为不变)。
"""
from __future__ import annotations

import json
import os
import random
import hashlib
import shutil
import time
from collections import deque
from typing import Any, Dict, Iterator, List, Optional

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_STOPPED = "stopped"
STATUS_INCOMPLETE = "incomplete"
STATUS_ERROR = "error"
STATUS_INTERRUPTED = "interrupted"   # 服务重启时发现"running 但任务已不在"


def _atomic_write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


class RunStore:
    def __init__(self, run_dir: str):
        self.dir = os.path.abspath(os.path.expanduser(run_dir))
        self.id = os.path.basename(self.dir.rstrip("/"))

    # ── 路径 ──
    @property
    def manifest_path(self) -> str:
        return os.path.join(self.dir, "run.json")

    @property
    def checkpoint_path(self) -> str:            # 运行时机制态(高频小幅刷)
        return os.path.join(self.dir, "checkpoint.json")

    @property
    def history_path(self) -> str:
        return os.path.join(self.dir, "history.json")

    @property
    def threat_analysis_dir(self) -> str:
        return os.path.join(self.dir, "threat-analysis")

    @property
    def threat_analysis_raw_path(self) -> str:
        return os.path.join(self.threat_analysis_dir, "raw.json")

    @property
    def threat_analysis_path(self) -> str:
        return os.path.join(self.threat_analysis_dir, "graph.json")

    @property
    def threat_analysis_warnings_path(self) -> str:
        return os.path.join(self.threat_analysis_dir, "warnings.json")

    @property
    def attack_surface_path(self) -> str:        # 攻击面(初始+动态)+ 覆盖台账(每轮快照)
        return os.path.join(self.dir, "attack-surface.json")

    @property
    def findings_dir(self) -> str:               # 每条确认漏洞一个 <id>.json(人工反馈可追加更新)
        return os.path.join(self.dir, "findings")

    @property
    def candidates_dir(self) -> str:              # 候选/非问题当前态:按 key 哈希成文件名
        return os.path.join(self.dir, "candidates")

    @property
    def risks_dir(self) -> str:                  # 每条风险一个 <id>.json(写一次即终态)
        return os.path.join(self.dir, "risks")

    @property
    def health_path(self) -> str:                # 各模型健康检查快照(整体覆盖刷)
        return os.path.join(self.dir, "health.json")

    @property
    def events_path(self) -> str:
        return os.path.join(self.dir, "events.jsonl")

    @property
    def event_seq_path(self) -> str:
        return os.path.join(self.dir, "event-seq.txt")

    @property
    def usage_path(self) -> str:
        return os.path.join(self.dir, "usage.jsonl")

    @property
    def export_dir(self) -> str:
        return os.path.join(self.dir, "exports")

    def ensure(self) -> "RunStore":
        os.makedirs(self.dir, exist_ok=True)
        return self

    def exists(self) -> bool:
        return (os.path.isfile(self.manifest_path) or os.path.isfile(self.checkpoint_path)
                or os.path.isfile(self.threat_analysis_path) or os.path.isfile(self.attack_surface_path))

    def delete(self) -> bool:
        """整目录删除该 run(不可逆)。目录不存在视为已删除,返回 False。"""
        if not os.path.isdir(self.dir):
            return False
        shutil.rmtree(self.dir, ignore_errors=True)
        return not os.path.isdir(self.dir)

    # ── 清单 ──
    def load_manifest(self) -> Optional[Dict[str, Any]]:
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def save_manifest(self, manifest: Dict[str, Any]) -> None:
        manifest["updated_at"] = time.time()
        _atomic_write(self.manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2))

    def init_manifest(self, config: Dict[str, Any]) -> Dict[str, Any]:
        m = self.load_manifest() or {}
        m.setdefault("id", self.id)
        m.setdefault("created_at", time.time())
        m["config"] = config
        m.setdefault("status", STATUS_QUEUED)
        m.setdefault("summary", {})
        self.save_manifest(m)
        return m

    def set_status(self, status: str) -> None:
        m = self.load_manifest() or {"id": self.id, "created_at": time.time(), "config": {}, "summary": {}}
        m["status"] = status
        self.save_manifest(m)

    def update_summary(self, summary: Dict[str, Any], status: Optional[str] = None) -> None:
        m = self.load_manifest() or {"id": self.id, "created_at": time.time(), "config": {}}
        m["summary"] = {**(m.get("summary") or {}), **summary}
        if status:
            m["status"] = status
        self.save_manifest(m)

    def update_config(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        """把若干字段合并进 manifest.config(供运行中动态调参 / 续跑时沿用)。返回更新后的 config。"""
        m = self.load_manifest() or {"id": self.id, "created_at": time.time(), "config": {}, "summary": {}}
        cfg = {**(m.get("config") or {}), **(patch or {})}
        m["config"] = cfg
        self.save_manifest(m)
        return cfg

    # ── 结构化态(按关注点分文件) ──
    @staticmethod
    def _read_json(path: str) -> Optional[Any]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    @staticmethod
    def _safe_id(fid: str) -> bool:
        return bool(fid) and "/" not in fid and "\\" not in fid and not fid.startswith(".")

    # checkpoint:运行时机制态
    def save_checkpoint(self, d: Dict[str, Any]) -> None:
        _atomic_write(self.checkpoint_path, json.dumps(d, ensure_ascii=False))

    def load_checkpoint(self) -> Optional[Dict[str, Any]]:
        d = self._read_json(self.checkpoint_path)
        return d if isinstance(d, dict) else None

    # history:历史安全修复提炼出的模式库
    def save_history(self, items: List[Dict[str, Any]]) -> None:
        _atomic_write(self.history_path, json.dumps(items or [], ensure_ascii=False, indent=2))

    def load_history(self) -> List[Dict[str, Any]]:
        d = self._read_json(self.history_path)
        return d if isinstance(d, list) else []

    # threat-analysis:攻击树威胁分析图
    def save_threat_analysis(self, graph: Dict[str, Any], raw: Optional[Dict[str, Any]] = None) -> None:
        os.makedirs(self.threat_analysis_dir, exist_ok=True)
        if raw is not None:
            _atomic_write(self.threat_analysis_raw_path, json.dumps(raw, ensure_ascii=False, indent=2))
        _atomic_write(self.threat_analysis_path, json.dumps(graph, ensure_ascii=False, indent=2))
        warnings = graph.get("warnings") if isinstance(graph, dict) else []
        _atomic_write(self.threat_analysis_warnings_path, json.dumps(warnings or [], ensure_ascii=False, indent=2))

    def load_threat_analysis(self) -> Dict[str, Any]:
        d = self._read_json(self.threat_analysis_path)
        return d if isinstance(d, dict) else {}

    # attack-surface:攻击面(初始+动态)+ 覆盖台账 + progress
    def save_attack_surface(self, d: Dict[str, Any]) -> None:
        _atomic_write(self.attack_surface_path, json.dumps(d, ensure_ascii=False, indent=2))

    def load_attack_surface(self) -> Dict[str, Any]:
        d = self._read_json(self.attack_surface_path)
        if isinstance(d, dict):
            return d
        return {"round": 0, "ledger": [], "surfaces": [], "regions": [],
                "progress": {"done": 0, "clean": 0, "total": 0}}

    # findings:每条确认漏洞一个文件
    def save_finding(self, rec: Dict[str, Any]) -> None:
        if not rec.get("id"):
            return
        os.makedirs(self.findings_dir, exist_ok=True)
        _atomic_write(os.path.join(self.findings_dir, f"{rec['id']}.json"), json.dumps(rec, ensure_ascii=False, indent=2))

    def load_finding(self, fid: str) -> Optional[Dict[str, Any]]:
        if not self._safe_id(fid):
            return None
        d = self._read_json(os.path.join(self.findings_dir, f"{fid}.json"))
        if isinstance(d, dict):
            return d
        return None

    def update_finding_feedback(self, fid: str, feedback: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """保存人工确认反馈。只更新 finding 记录,不改变流水线的自动验证结论。"""
        if not self._safe_id(fid):
            return None
        d = self.load_finding(fid)
        if not d:
            return None
        d["manual_feedback"] = feedback
        if not d.get("output_ts"):
            d["output_ts"] = d.get("confirmed_at") or d.get("created_at") or 0
        self.save_finding(d)
        return d

    def load_findings(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if os.path.isdir(self.findings_dir):
            for fn in sorted(os.listdir(self.findings_dir)):
                if fn.endswith(".json"):
                    d = self._read_json(os.path.join(self.findings_dir, fn))
                    if d:
                        out.append(d)
        if out:
            return out
        return []

    # candidates:候选 / 已确认 / 已否决 / 验证失败的当前态
    @staticmethod
    def _candidate_file_id(key: str) -> str:
        return hashlib.sha1(key.encode("utf-8", errors="ignore")).hexdigest()

    def save_candidate(self, rec: Dict[str, Any]) -> None:
        key = rec.get("key")
        if not key:
            return
        os.makedirs(self.candidates_dir, exist_ok=True)
        path = os.path.join(self.candidates_dir, f"{self._candidate_file_id(str(key))}.json")
        _atomic_write(path, json.dumps(rec, ensure_ascii=False, indent=2))

    def load_candidates(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if os.path.isdir(self.candidates_dir):
            for fn in sorted(os.listdir(self.candidates_dir)):
                if fn.endswith(".json"):
                    d = self._read_json(os.path.join(self.candidates_dir, fn))
                    if d:
                        out.append(d)
        return out

    # risks:每条风险一个文件
    def save_risk(self, rec: Dict[str, Any]) -> None:
        if not rec.get("id"):
            return
        os.makedirs(self.risks_dir, exist_ok=True)
        _atomic_write(os.path.join(self.risks_dir, f"{rec['id']}.json"), json.dumps(rec, ensure_ascii=False, indent=2))

    def update_risk_severity(self, rid: str, severity: str) -> Optional[Dict[str, Any]]:
        """直接改写某条风险文件的 severity_hint(供运行已结束时的人工调级)。返回更新后的记录或 None。"""
        if not self._safe_id(rid):
            return None
        path = os.path.join(self.risks_dir, f"{rid}.json")
        d = self._read_json(path)
        if not d:
            return None
        d["severity_hint"] = severity
        _atomic_write(path, json.dumps(d, ensure_ascii=False, indent=2))
        return d

    def load_risks(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if os.path.isdir(self.risks_dir):
            for fn in sorted(os.listdir(self.risks_dir)):
                if fn.endswith(".json"):
                    d = self._read_json(os.path.join(self.risks_dir, fn))
                    if d:
                        out.append(d)
        if out:
            return out
        return []

    # 聚合成 exporters 期望的 state 形状(供导出与兜底)
    def load_full_state(self) -> Dict[str, Any]:
        asf = self.load_attack_surface()
        ck = self.load_checkpoint() or {}
        m = self.load_manifest() or {}
        return {
            "round": asf.get("round") or ck.get("round") or 0,
            "history": self.load_history(),
            "threatAnalysis": self.load_threat_analysis(),
            "surfaceLog": asf.get("surfaces", []),
            "auditLedger": asf.get("ledger", []),
            "riskNotes": self.load_risks(),
            "confirmed": self.load_findings(),
            "usage": self.load_usage(),
            "summary": m.get("summary", {}),
        }

    # health:各模型健康检查快照(model -> 记录;整体覆盖刷)
    def save_health(self, models: Dict[str, Any]) -> None:
        payload = {"models": list(models.values()), "updated_at": time.time()}
        _atomic_write(self.health_path, json.dumps(payload, ensure_ascii=False, indent=2))

    def load_health(self) -> Dict[str, Any]:
        d = self._read_json(self.health_path)
        if isinstance(d, dict) and isinstance(d.get("models"), list):
            return d
        return {"models": [], "updated_at": 0}

    # usage:每次 agent 调用一行 JSONL
    def append_usage(self, rec: Dict[str, Any]) -> None:
        os.makedirs(self.dir, exist_ok=True)
        with open(self.usage_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def load_usage(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        max_rows: Optional[int] = None
        if limit is not None:
            try:
                max_rows = max(0, int(limit))
            except (TypeError, ValueError):
                max_rows = None
        if max_rows == 0:
            return []
        out = deque(maxlen=max_rows) if max_rows else []
        if not os.path.isfile(self.usage_path):
            return []
        with open(self.usage_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
        return list(out)

    # ── 事件 ──
    def append_event(self, ev: Dict[str, Any]) -> None:
        os.makedirs(self.dir, exist_ok=True)
        with open(self.events_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        try:
            with open(self.event_seq_path, "w", encoding="utf-8") as f:
                f.write(str(int(ev.get("seq", 0) or 0)))
        except Exception:
            pass

    def last_event_seq(self) -> int:
        """已落盘事件里的最大 seq(0 表示无)。续跑时用来让 EventBus 的 seq 单调续接,
        避免重号导致 SSE `seq>sent` 把续跑后的所有事件过滤掉。"""
        try:
            with open(self.event_seq_path, "r", encoding="utf-8") as f:
                return max(0, int((f.read() or "0").strip() or "0"))
        except Exception:
            pass
        last = 0
        if not os.path.isfile(self.events_path):
            return last
        with open(self.events_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    seq = int(json.loads(line).get("seq", 0))
                except Exception:
                    continue
                if seq > last:
                    last = seq
        if last:
            try:
                with open(self.event_seq_path, "w", encoding="utf-8") as f:
                    f.write(str(last))
            except Exception:
                pass
        return last

    def iter_events(self, after_seq: int = 0) -> Iterator[Dict[str, Any]]:
        try:
            after_seq = max(0, int(after_seq or 0))
        except (TypeError, ValueError):
            after_seq = 0
        if after_seq and after_seq >= self.last_event_seq():
            return
        if not os.path.isfile(self.events_path):
            return
        with open(self.events_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                try:
                    seq = int(ev.get("seq", 0) or 0)
                except (TypeError, ValueError):
                    continue
                if seq > after_seq:
                    yield ev

    def read_events(self, after_seq: int = 0) -> List[Dict[str, Any]]:
        return list(self.iter_events(after_seq))


class RunRegistry:
    """管理 runs_root 下的所有 run。"""

    def __init__(self, runs_root: str):
        self.root = os.path.abspath(os.path.expanduser(runs_root))

    def ensure(self) -> "RunRegistry":
        os.makedirs(self.root, exist_ok=True)
        return self

    def new_run_id(self) -> str:
        lt = time.localtime()
        stamp = time.strftime("%Y%m%d-%H%M%S", lt)
        suffix = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(4))
        return f"{stamp}-{suffix}"

    def create(self, run_id: Optional[str] = None) -> RunStore:
        rid = run_id or self.new_run_id()
        return RunStore(os.path.join(self.root, rid)).ensure()

    def get(self, run_id: str) -> Optional[RunStore]:
        # 防目录穿越
        if not run_id or "/" in run_id or "\\" in run_id or run_id.startswith("."):
            return None
        d = os.path.join(self.root, run_id)
        if not os.path.isdir(d):
            return None
        return RunStore(d)

    def delete(self, run_id: str) -> bool:
        store = self.get(run_id)
        if not store:
            return False
        return store.delete()

    def list_runs(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not os.path.isdir(self.root):
            return out
        for name in os.listdir(self.root):
            store = RunStore(os.path.join(self.root, name))
            if not os.path.isdir(store.dir):
                continue
            m = store.load_manifest()
            if not m:
                continue
            cfg = m.get("config") or {}
            history_count = len(store.load_history())
            out.append({
                "id": m.get("id", name), "status": m.get("status"),
                "created_at": m.get("created_at"), "updated_at": m.get("updated_at"),
                "target": cfg.get("target"), "scope": cfg.get("scope"),
                "backend": cfg.get("backend"), "run_mode": cfg.get("run_mode"),
                "history_count": history_count, "summary": m.get("summary") or {},
            })
        out.sort(key=lambda r: r.get("created_at") or 0, reverse=True)
        return out
