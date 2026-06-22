"""process_finding witness/blocker 对抗验证 + final failed sweep 的单元测试。

不触碰真实后端 CLI:用 FakeRunner 直接喂 witness/blocker/裁判/终局裁判/报告正文,
用临时目录里的真实 RunStore 落盘(避免再去 stub 一堆 store 方法)。

运行:  python3 -m unittest proto_vuln_hunt.tests.test_pipeline_verify
"""
import tempfile
import unittest

from proto_vuln_hunt import events as EV
from proto_vuln_hunt.common import finding_key
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

    async def run(self, prompt, role=None, label=None, schema=None, fallback=None, **kwargs):
        if role == "verify":
            return self.verify_responses.pop(0) if self.verify_responses else None
        if role == "report":
            return self.report_response
        return None


def _finding(**over):
    f = {"title": "t", "bug_class": "memory", "file": "a.c", "line": 10,
         "lens": "memory", "severity": "high", "function": "fn"}
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
        if decision == "promoted_to_risk":
            v["risk_note"] = "共享 helper 依赖调用方校验,值得变体排查"
        if decision == "needs_manual_review":
            v["final_reason"] = "高危潜在影响但正反证据冲突"
    v.update(over)
    return v

class _PipelineTestBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def make_pipeline(self, **cfg_over):
        cfg = Config(out_dir=self._tmp.name, enable_poc=False, **cfg_over)
        events = []
        p = Pipeline(cfg, store=RunStore(self._tmp.name).ensure(),
                     emitter=lambda etype, data, persist=True: events.append((etype, data)))
        p.runner = FakeRunner()
        p.pb.verify_witness = lambda *a, **k: "WITNESS_PROMPT"
        p.pb.verify_blocker = lambda *a, **k: "BLOCKER_PROMPT"
        p.pb.verify_witness_judge = lambda *a, **k: "WITNESS_JUDGE_PROMPT"
        p.pb.verify_blocker_judge = lambda *a, **k: "BLOCKER_JUDGE_PROMPT"
        p.pb.verify_final_adjudicator = lambda *a, **k: "FINAL_PROMPT"
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
        p.runner.verify_responses = [_witness(), _blocker(False), _witness_review("accepted"), _blocker_review("invalid"), _final("confirmed")]
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
        self.assertTrue(any(v.get("phase") == "witness" for v in p.confirmed[0]["votes"]))

    async def test_global_blocker_rejects(self):
        """global blocker 被终局确认 → 标记 rejected,不入 confirmed。"""
        p = self.make_pipeline(verify_votes=3)
        p.runner.verify_responses = [
            _witness(False),
            _blocker(True, "global"),
            _witness_review("rejected"),
            _blocker_review("global_decisive"),
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
        self.assertEqual(payload["votes"][2]["phase"], "witness_judge")
        self.assertIn("入口已把长度夹紧", payload["rejection_reason"])
        cands = p.store.load_candidates()
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["status"], "rejected")

    async def test_suppressed_unproven_is_terminal_candidate(self):
        """witness 不完整 + blocker 不决定性 + 终局压制 → 不回队、不确认。"""
        p = self.make_pipeline(verify_votes=3)
        p.runner.verify_responses = [
            _witness(False),
            _blocker(True, "partial"),
            _witness_review("inconclusive"),
            _blocker_review("partial"),
            _final("suppressed_unproven"),
        ]
        f = _finding()
        await p.process_finding(f)

        self.assertEqual(p.confirmed, [])
        self.assertIn(finding_key(f), p.processed_keys)
        self.assertEqual(p.pending_findings, {})
        self.assertEqual(f["verify_status"], "suppressed_unproven")
        self.assertNotIn(EV.CANDIDATE_FAILED, self._event_types(p))
        self.assertIn(EV.CANDIDATE_DECIDED, self._event_types(p))
        self.assertEqual(p.store.load_candidates()[0]["status"], "suppressed_unproven")

    async def test_promoted_to_risk_records_risk(self):
        """终局 promoted_to_risk → 候选终态 + 风险登记。"""
        p = self.make_pipeline(verify_votes=3)
        p.runner.verify_responses = [
            _witness(False),
            _blocker(False),
            _witness_review("inconclusive"),
            _blocker_review("unknown_scope"),
            _final("promoted_to_risk"),
        ]
        f = _finding()
        await p.process_finding(f)

        self.assertEqual(p.confirmed, [])
        self.assertIn(finding_key(f), p.processed_keys)
        self.assertEqual(p.store.load_candidates()[0]["status"], "promoted_to_risk")
        self.assertEqual(len(p.risk_notes), 1)
        self.assertIn("共享 helper", p.risk_notes[0]["note"])

    async def test_high_conflict_needs_manual_review_is_terminal(self):
        """高危冲突无法闭合 → needs_manual_review 终态,不确认不否决。"""
        p = self.make_pipeline(verify_votes=3)
        p.runner.verify_responses = [
            _witness(),
            _blocker(True, "unknown"),
            _witness_review("accepted"),
            _blocker_review("unknown_scope"),
            _final("needs_manual_review"),
        ]
        f = _finding()
        await p.process_finding(f)

        self.assertEqual(p.confirmed, [])
        self.assertIn(finding_key(f), p.processed_keys)
        self.assertEqual(p.store.load_candidates()[0]["status"], "needs_manual_review")

    async def test_final_adjudicator_parse_failure_retries_then_verify_failed(self):
        """终局裁判无结构化输出,耗尽 retry.max_attempts 后 → verify_failed。"""
        p = self.make_pipeline(verify_votes=2)
        p.cfg.retry.max_attempts = 1   # 总共允许 1 次失败回队,第 2 次失败即终态
        f = _finding()

        p.runner.verify_responses = [_witness(), _blocker(False), _witness_review("accepted"), _blocker_review("invalid"), None]
        await p.process_finding(f)                        # 第 1 次:回队
        self.assertEqual(f["verify_status"], "pending")
        self.assertEqual(f["verify_attempts"], 1)
        self.assertNotIn(EV.CANDIDATE_FAILED, self._event_types(p))

        p.runner.verify_responses = [_witness(), _blocker(False), _witness_review("accepted"), _blocker_review("invalid"), None]
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
        p.runner.verify_responses = [_witness(), _blocker(False), _witness_review("accepted"), _blocker_review("invalid"), None]
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
        """final sweep:把 verify_failed 候选 + failed risk 复查重新入队,且每次 invocation 只执行一次。"""
        p = self.make_pipeline(verify_votes=3)

        f = _finding(severity="high")
        k = finding_key(f)
        f["verify_status"] = "verify_failed"
        f["verify_attempts"] = 3
        p.pending_findings[k] = f

        risk = {"id": "R1", "area": "auth", "file": "b.c", "severity_hint": "high",
                "lens": "authn", "recheck_status": "failed"}
        p.risk_notes.append(risk)
        p.risk_by_id["R1"] = risk
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

    def test_low_severity_risk_not_swept(self):
        """低于 risk_min_severity 的 low/info 风险即便 failed 也不入最终补跑。"""
        p = self.make_pipeline(verify_votes=3)
        risk = {"id": "R2", "area": "x", "severity_hint": "low", "recheck_status": "failed"}
        p.risk_notes.append(risk)
        p.risk_by_id["R2"] = risk

        self.assertEqual(p._enqueue_final_failed_sweep(), 0)
        self.assertFalse(p.pq)
        # low/info 风险也不计入“复查失败”阻塞完成统计
        self.assertEqual(p._failed_recheck_count(), 1)  # 仍登记为 failed(只是不补跑)


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
        p.risk_notes.append({"id": "R1", "recheck_status": "failed", "severity_hint": "high"})
        p.ledger_arr.append({"key": "variant:foo", "kind": "variant", "status": "abandoned"})
        self.assertEqual(p._failed_recheck_count(), 2)


if __name__ == "__main__":
    unittest.main()
