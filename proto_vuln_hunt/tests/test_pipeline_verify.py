"""process_finding 同 session claim 辩论验证 + final failed sweep 的单元测试。

不触碰真实后端 CLI:用 FakeRunner 直接喂 O1/P1/O2/P2/A1/报告正文,
用临时目录里的真实 RunStore 落盘(避免再去 stub 一堆 store 方法)。

运行:  python3 -m unittest proto_vuln_hunt.tests.test_pipeline_verify
"""
import tempfile
import unittest

from proto_vuln_hunt import events as EV
from proto_vuln_hunt.common import QUALITY_FINDING_STATUS, QUALITY_FINDING_TAG, finding_key
from proto_vuln_hunt.config import Config
from proto_vuln_hunt.pipeline import Pipeline
from proto_vuln_hunt.store import RunStore


class FakeRunner:
    """按 role 分发的假 AgentRunner:verify 逐个弹出(None=CLI/解析失败),report 返回正文。"""

    def __init__(self):
        self.verify_responses = []
        self.report_response = "REPORT BODY"
        self.agent_count = 0
        self.usage_totals = {}
        self.calls = []

    async def run(self, prompt, role=None, label=None, schema=None, fallback=None, **kwargs):
        self.calls.append({"role": role, "label": label, "schema": schema, "kwargs": kwargs})
        meta = kwargs.get("meta")
        if isinstance(meta, dict):
            meta["model"] = kwargs.get("model_override") or "unit-verify"
            if role == "verify":
                meta["session_id"] = kwargs.get("session_id") or "verify-session-1"
        if role == "verify":
            return self.verify_responses.pop(0) if self.verify_responses else None
        if role == "report":
            return self.report_response
        return None


def _finding(**over):
    f = {"title": "t", "bug_class": "memory", "file": "a.c", "line": 10,
         "audit_unit": "unit-test", "severity": "high", "function": "fn"}
    f.update(over)
    return f


def _witness(complete=True, sev="high", **over):
    if complete:
        v = {
            "witness_complete": True,
            "witness": "len=512 reaches memcpy with dst_size=128",
            "attack_preconditions": ["a.c:1 - REMOTE packet controls len"],
            "input_domain_constraints": ["a.c:2 - len is uint16, 0..65535"],
            "state_constraints": ["a.c:3 - authenticated state is not required"],
            "code_constraints": ["a.c:4 - no clamp before call"],
            "path_nodes": ["a.c:1 - recv_packet", "a.c:8 - fn passes len", "a.c:10 - memcpy"],
            "trigger_condition": "512 > sizeof(dst)=128",
            "bad_result": "stack buffer overflow",
            "sink_ref": "a.c:10 - memcpy(dst, src, len)",
            "evidence_refs": ["a.c:1 - recv 读入攻击者长度", "a.c:10 - memcpy 使用该长度"],
            "corrected_severity": sev,
            "exploitability": "exploitable",
            "verdict_confidence": "high",
            "reasoning": "合法输入能触发越界写",
        }
    else:
        v = {"witness_complete": False, "evidence_refs": [], "missing_evidence": "未找到真实入口",
             "reasoning": "正方无法构造合法 witness"}
    v.update(over)
    return v


def _blocker(found=False, scope="none", **over):
    if found:
        v = {
            "blocker_found": True,
            "blocker_scope": scope,
            "blocker_type": "guard_dominance",
            "blocker_description": "入口已把长度夹紧到缓冲区容量以内",
            "evidence_refs": ["a.c:4 - len 被夹紧到缓冲区容量以内"],
            "blocking_checks": ["a.c:4 - if (len > sizeof(dst)) return -1"],
            "impossibility_proof": "所有到 memcpy 的路径均先执行该检查",
            "non_issue_reason": "入口已把长度夹紧到缓冲区容量以内",
            "verdict_confidence": "high",
            "reasoning": "caller trace 证伪可达危险长度",
        }
    else:
        v = {"blocker_found": False, "blocker_scope": "none", "evidence_refs": [],
             "missing_evidence": "未找到上游证伪点", "reasoning": "反方未能证伪"}
    v.update(over)
    return v


def _witness_review(verdict="accepted", **over):
    if verdict == "accepted":
        v = {
            "witness_verdict": "accepted",
            "evidence_refs": ["a.c:10 - memcpy 使用 len"],
            "reviewed_checks": ["a.c:1 - len 来自报文", "a.c:10 - sink 可达"],
            "verdict_confidence": "high",
            "reasoning": "witness 满足关键约束",
        }
    elif verdict == "rejected":
        v = {
            "witness_verdict": "rejected",
            "evidence_refs": ["a.c:2 - len 最大只有 64"],
            "failed_checks": ["witness 的 len=512 不合法"],
            "verdict_confidence": "high",
            "reasoning": "witness 违反协议约束",
        }
    else:
        v = {
            "witness_verdict": verdict,
            "evidence_refs": ["a.c:10 - 仅核对到 sink"],
            "missing_evidence": "输入域未闭合",
            "reasoning": "证据不足",
        }
    v.update(over)
    return v


def _blocker_review(verdict="invalid", **over):
    if verdict == "global_decisive":
        v = {
            "blocker_verdict": "global_decisive",
            "evidence_refs": ["a.c:4 - if (len > sizeof(dst)) return -1"],
            "reviewed_checks": ["a.c:4 - guard 支配 memcpy"],
            "verdict_confidence": "high",
            "reasoning": "blocker 覆盖所有路径",
        }
    elif verdict == "invalid":
        v = {
            "blocker_verdict": "invalid",
            "evidence_refs": ["a.c:4 - guard 只在另一个分支"],
            "failed_checks": ["guard 不支配 witness 路径"],
            "verdict_confidence": "high",
            "reasoning": "反方 blocker 无效",
        }
    else:
        v = {
            "blocker_verdict": verdict,
            "evidence_refs": ["a.c:4 - 找到局部 guard"],
            "failed_checks": ["作用域不是全局"],
            "missing_evidence": "无法证明支配所有路径",
            "reasoning": "blocker 作用域不足",
        }
    v.update(over)
    return v


def _final(decision="confirmed", sev="high", **over):
    if decision == "confirmed":
        v = {
            "epistemic_verdict": "proven_real",
            "operational_decision": "confirmed",
            "deciding_facts_checked": ["a.c:10 - memcpy 使用 witness 长度"],
            "final_reason": "witness 被接受且 blocker 无效",
            "corrected_severity": sev,
            "exploitability": "exploitable",
            "verdict_confidence": "high",
            "reasoning": "可作为静态确认漏洞",
        }
    elif decision == "rejected":
        v = {
            "epistemic_verdict": "proven_false",
            "operational_decision": "rejected",
            "deciding_facts_checked": ["a.c:4 - guard 支配 sink"],
            "final_reason": "global blocker 成立",
            "rejection_reason": "入口已把长度夹紧到缓冲区容量以内",
            "verdict_confidence": "high",
            "reasoning": "坏条件不可满足",
        }
    else:
        v = {
            "epistemic_verdict": "unresolved",
            "operational_decision": decision,
            "deciding_facts_checked": ["a.c:10 - sink 存在但 witness 未闭合"],
            "final_reason": "witness 不完整且 blocker 不决定性",
            "residual_uncertainty": "输入域未闭合",
            "recommended_next_action": "后续变体排查",
            "reasoning": "不确认也不强否决",
        }
        if decision == "needs_manual_review":
            v["final_reason"] = "高危潜在影响但正反证据冲突"
    v.update(over)
    return v

class _PipelineTestBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def make_pipeline(self, **cfg_over):
        cfg_vals = {"out_dir": self._tmp.name, "enable_poc": False}
        cfg_vals.update(cfg_over)
        cfg = Config(**cfg_vals)
        events = []
        p = Pipeline(cfg, store=RunStore(self._tmp.name).ensure(),
                     emitter=lambda etype, data, persist=True: events.append((etype, data)))
        p.runner = FakeRunner()
        p.pb.verify_opponent_opening = lambda *a, **k: "O1_PROMPT"
        p.pb.verify_proponent_response = lambda *a, **k: "P_PROMPT"
        p.pb.verify_opponent_response = lambda *a, **k: "O2_PROMPT"
        p.pb.verify_debate_final_adjudicator = lambda *a, **k: "FINAL_PROMPT"
        p.pb.report_body = lambda *a, **k: "REPORT_PROMPT"
        p.events = events
        return p

    @staticmethod
    def _event_types(p):
        return [e[0] for e in p.events]

    @staticmethod
    def _last_event(p, etype):
        return next((data for t, data in reversed(p.events) if t == etype), None)


class TestAdversarialVerify(_PipelineTestBase):
    async def test_verified_witness_and_invalid_blocker_confirms(self):
        """witness 被接受 + blocker 无效 + 终局 confirmed → 确认为漏洞。"""
        p = self.make_pipeline(verify_votes=3)
        p.runner.verify_responses = [_blocker(False), _witness(), _blocker(False), _witness(), _final("confirmed")]
        f = _finding()
        await p.process_finding(f)

        self.assertEqual(len(p.confirmed), 1)
        self.assertIn(finding_key(f), p.processed_keys)
        self.assertEqual(p.pending_findings, {})
        self.assertIn(EV.FINDING_CONFIRMED, self._event_types(p))
        cands = p.store.load_candidates()
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["status"], "confirmed")
        self.assertEqual(cands[0]["id"], "MEM-001")
        self.assertEqual(len(p.confirmed[0]["votes"]), 5)
        self.assertTrue(any(v.get("phase") == "proponent_closing" for v in p.confirmed[0]["votes"]))

    async def test_no_poc_components_skip_poc_for_high_finding(self):
        """enable_poc=true 但组件列表为空时,高危确认项不派 PoC agent。"""
        p = self.make_pipeline(
            enable_poc=True,
            poc_components=[],
            models={"threat": ["m"], "audit": ["m"], "verify": ["m"], "report": ["m"]},
        )
        p.runner.verify_responses = [_blocker(False), _witness(), _blocker(False), _witness(), _final("confirmed")]
        await p.process_finding(_finding())

        self.assertEqual(len(p.confirmed), 1)
        self.assertIsNone(p.confirmed[0]["poc"])
        self.assertNotIn("poc", [c["role"] for c in p.runner.calls])
        self.assertNotIn(EV.POC_DONE, self._event_types(p))

    async def test_debate_uses_configured_models_and_one_session(self):
        """O/P/A 按三个 verify 模型发言,后续轮次复用 O1 session,终局前压缩。"""
        p = self.make_pipeline(
            models={
                "threat": ["threat-m"],
                "audit": ["audit-m"],
                "verify": ["opp-m", "prop-m", "judge-m"],
                "report": ["report-m"],
            },
        )
        p.runner.verify_responses = [_blocker(False), _witness(), _blocker(False), _witness(), _final("confirmed")]

        await p.process_finding(_finding())

        verify_calls = [c for c in p.runner.calls if c["role"] == "verify"]
        self.assertEqual(
            [c["kwargs"].get("model_override") for c in verify_calls],
            ["opp-m", "prop-m", "opp-m", "prop-m", "judge-m"],
        )
        self.assertEqual(
            [c["kwargs"].get("session_id") for c in verify_calls],
            [None, "verify-session-1", "verify-session-1", "verify-session-1", "verify-session-1"],
        )
        self.assertFalse(verify_calls[1]["kwargs"].get("compact_before_prompt", False))
        self.assertTrue(verify_calls[4]["kwargs"].get("compact_before_prompt"))
        self.assertEqual(
            [v.get("model") for v in p.confirmed[0]["votes"]],
            ["opp-m", "prop-m", "opp-m", "prop-m", "judge-m"],
        )

    async def test_global_blocker_rejects(self):
        """global blocker 被终局确认 → 标记 rejected,不入 confirmed。"""
        p = self.make_pipeline(verify_votes=3)
        p.runner.verify_responses = [
            _blocker(True, "global"),
            _witness(False),
            _blocker(True, "global"),
            _witness(False),
            _final("rejected"),
        ]
        f = _finding(description="候选声称长度可控导致溢出", source_to_sink="recv len -> copy")
        await p.process_finding(f)

        self.assertEqual(p.confirmed, [])
        self.assertIn(finding_key(f), p.processed_keys)
        self.assertEqual(p.pending_findings, {})
        self.assertIn(EV.FINDING_REJECTED, self._event_types(p))
        self.assertNotIn(EV.CANDIDATE_FAILED, self._event_types(p))
        payload = self._last_event(p, EV.FINDING_REJECTED)
        self.assertEqual(payload["description"], "候选声称长度可控导致溢出")
        self.assertEqual(payload["source_to_sink"], "recv len -> copy")
        self.assertEqual(len(payload["votes"]), 5)
        self.assertEqual(payload["votes"][2]["phase"], "opponent_rebuttal")
        self.assertIn("入口已把长度夹紧", payload["rejection_reason"])
        cands = p.store.load_candidates()
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["status"], "rejected")

    async def test_suppressed_unproven_records_quality_finding(self):
        """witness 不完整 + blocker 不决定性 + 终局压制 → 漏洞页质量问题条目。"""
        p = self.make_pipeline(verify_votes=3)
        p.runner.verify_responses = [
            _blocker(True, "partial"),
            _witness(False),
            _blocker(True, "partial"),
            _witness(False),
            _final("suppressed_unproven"),
        ]
        f = _finding()
        await p.process_finding(f)

        self.assertEqual(len(p.confirmed), 1)
        self.assertIn(finding_key(f), p.processed_keys)
        self.assertEqual(p.pending_findings, {})
        self.assertEqual(f["verify_status"], "suppressed_unproven")
        self.assertEqual(p.risk_notes, [])
        self.assertNotIn(EV.CANDIDATE_FAILED, self._event_types(p))
        self.assertIn(EV.FINDING_ADDED, self._event_types(p))
        self.assertIn(EV.CANDIDATE_DECIDED, self._event_types(p))
        finding = p.store.load_findings()[0]
        self.assertEqual(finding["id"], "QUAL-001")
        self.assertEqual(finding["finding_status"], QUALITY_FINDING_STATUS)
        self.assertIn(QUALITY_FINDING_TAG, finding["tags"])
        self.assertEqual(finding["corrected_severity"], "info")
        self.assertIn("编码质量问题", finding["report_body"])
        cand = p.store.load_candidates()[0]
        self.assertEqual(cand["status"], "suppressed_unproven")
        self.assertEqual(cand["id"], "QUAL-001")
        self.assertIn(QUALITY_FINDING_TAG, cand["tags"])

    async def test_high_conflict_needs_manual_review_is_terminal(self):
        """高危冲突无法闭合 → 漏洞页质量问题条目,候选保持 needs_manual_review。"""
        p = self.make_pipeline(verify_votes=3)
        p.runner.verify_responses = [
            _blocker(True, "unknown"),
            _witness(),
            _blocker(True, "unknown"),
            _witness(),
            _final("needs_manual_review"),
        ]
        f = _finding()
        await p.process_finding(f)

        self.assertEqual(len(p.confirmed), 1)
        self.assertIn(finding_key(f), p.processed_keys)
        self.assertIn(EV.FINDING_ADDED, self._event_types(p))
        self.assertIn(EV.CANDIDATE_DECIDED, self._event_types(p))
        finding = p.store.load_findings()[0]
        self.assertEqual(finding["id"], "QUAL-001")
        self.assertEqual(finding["finding_status"], QUALITY_FINDING_STATUS)
        self.assertEqual(finding["verification_status"], "needs_manual_review")
        self.assertIn(QUALITY_FINDING_TAG, finding["tags"])
        self.assertIn("编码质量问题", finding["report_body"])
        self.assertIn("待人工复核", finding["report_body"])
        cand = p.store.load_candidates()[0]
        self.assertEqual(cand["status"], "needs_manual_review")
        self.assertEqual(cand["id"], "QUAL-001")
        self.assertIn(QUALITY_FINDING_TAG, cand["tags"])

    async def test_final_adjudicator_parse_failure_retries_then_verify_failed(self):
        """终局裁判无结构化输出,耗尽 retry.max_attempts 后 → verify_failed。"""
        p = self.make_pipeline(verify_votes=2)
        p.cfg.retry.max_attempts = 1   # 总共允许 1 次失败回队,第 2 次失败即终态
        f = _finding()

        p.runner.verify_responses = [_blocker(False), _witness(), _blocker(False), _witness(), None]
        await p.process_finding(f)                        # 第 1 次:回队
        self.assertEqual(f["verify_status"], "pending")
        self.assertEqual(f["verify_attempts"], 1)
        self.assertNotIn(EV.CANDIDATE_FAILED, self._event_types(p))

        p.runner.verify_responses = [_blocker(False), _witness(), _blocker(False), _witness(), None]
        await p.process_finding(f)                        # 第 2 次:超限 → verify_failed
        self.assertEqual(f["verify_status"], "verify_failed")
        self.assertEqual(f["verify_attempts"], 2)
        self.assertIn(finding_key(f), p.pending_findings)
        self.assertNotIn(finding_key(f), p.processed_keys)
        self.assertIn(EV.CANDIDATE_FAILED, self._event_types(p))
        self.assertEqual(p._failed_candidate_count(), 1)

    async def test_final_sweep_failure_is_immediately_terminal(self):
        """final sweep 模式:一次额外机会,失败即终态 verify_failed(不再回队重试)。"""
        p = self.make_pipeline(verify_votes=2)
        p._in_final_failed_sweep = True
        p.runner.verify_responses = [_blocker(False), _witness(), _blocker(False), _witness(), None]
        f = _finding()
        await p.process_finding(f)

        self.assertEqual(f["verify_status"], "verify_failed")
        self.assertEqual(f["verify_attempts"], 1)         # 仅这一次,没有回队再攒
        self.assertFalse(any(it.get("kind") == "_finding" for it in p.queue))
        payload = self._last_event(p, EV.CANDIDATE_FAILED)
        self.assertIsNotNone(payload)
        self.assertTrue(payload["final_sweep"])


class TestFinalFailedSweep(_PipelineTestBase):
    def test_enqueue_reinjects_failed_items_once(self):
        """final sweep:把 verify_failed 候选 + abandoned risk 复查重新入队,且每次 invocation 只执行一次。"""
        p = self.make_pipeline(verify_votes=3)

        f = _finding(severity="high")
        k = finding_key(f)
        f["verify_status"] = "verify_failed"
        f["verify_attempts"] = 3
        p.pending_findings[k] = f

        risk = {"kind": "risk", "id": "R1", "area": "auth", "file": "b.c", "severity_hint": "high",
                "note": "n"}
        rec = p.ledger_rec(risk)
        rec["status"] = "abandoned"
        p.completed_items.add("risk:R1")   # 之前被放弃时标过完成

        n = p._enqueue_final_failed_sweep()

        self.assertEqual(n, 2)
        self.assertEqual(f["verify_status"], "pending")   # 候选被重置以便重试
        self.assertEqual(f["verify_attempts"], 0)
        self.assertTrue(any(it.get("kind") == "_finding" for it in p.queue))
        self.assertTrue(any(it.get("kind") == "risk" and it.get("id") == "R1" for it in p.pq))
        self.assertNotIn("risk:R1", p.completed_items)    # 重新打开
        self.assertTrue(p._final_failed_sweep_done)

        # 同一 invocation 内再调用 → 不再重复入队(防失败项无限循环)
        self.assertEqual(p._enqueue_final_failed_sweep(), 0)

    def test_low_severity_risk_is_swept_because_threshold_no_longer_applies(self):
        """即时风险种子不再按 risk_min_severity 过滤,失败后 final sweep 会补跑一次。"""
        p = self.make_pipeline(verify_votes=3)
        risk = {"kind": "risk", "id": "R2", "area": "x", "severity_hint": "low", "note": "n"}
        rec = p.ledger_rec(risk)
        rec["status"] = "abandoned"
        p.completed_items.add("risk:R2")

        self.assertEqual(p._enqueue_final_failed_sweep(), 1)
        self.assertTrue(any(it.get("kind") == "risk" and it.get("id") == "R2" for it in p.pq))
        self.assertNotIn("risk:R2", p.completed_items)


class TestIncompleteCounts(_PipelineTestBase):
    def test_clean_run_is_complete(self):
        p = self.make_pipeline()
        self.assertFalse(p._has_incomplete_counts(p._incomplete_counts()))

    def test_verify_failed_candidate_blocks_completion(self):
        p = self.make_pipeline()
        f = _finding()
        f["verify_status"] = "verify_failed"
        p.pending_findings[finding_key(f)] = f

        counts = p._incomplete_counts()
        self.assertEqual(counts["failed_candidates"], 1)
        self.assertEqual(counts["pending_findings"], 0)   # verify_failed 不算“待验证”
        self.assertTrue(p._has_incomplete_counts(counts))

    def test_failed_recheck_counts_risk_and_variant(self):
        p = self.make_pipeline()
        p.ledger_arr.append({"key": "risk:R1", "kind": "risk", "status": "abandoned"})
        p.ledger_arr.append({"key": "variant:foo", "kind": "variant", "status": "abandoned"})
        self.assertEqual(p._failed_recheck_count(), 2)


if __name__ == "__main__":
    unittest.main()
