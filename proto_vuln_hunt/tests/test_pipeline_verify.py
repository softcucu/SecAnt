"""process_finding 对抗举证/裁决 + final failed sweep 的单元测试。

不触碰真实后端 CLI:用 FakeRunner 直接喂正方/反方/裁决票/报告正文,
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


def _proof(ok=True, sev="high", **over):
    if ok:
        v = {
            "supports_real": True,
            "evidence_refs": ["a.c:1 - recv 读入攻击者长度", "a.c:10 - memcpy 使用该长度"],
            "source_chain": ["a.c:1 - recv_packet", "a.c:8 - fn 传入 len", "a.c:10 - memcpy"],
            "sink_ref": "a.c:10 - memcpy(dst, src, len)",
            "reachability": "REMOTE 入口可达 fn",
            "controllability": "len 由报文字段控制且未夹紧",
            "corrected_severity": sev,
            "exploitability": "exploitable",
            "verdict_confidence": "high",
            "reasoning": "source 到 sink 链路完整且缺校验",
        }
    else:
        v = {"supports_real": False, "evidence_refs": [], "source_chain": [], "sink_ref": "",
             "missing_evidence": "未找到真实入口", "reasoning": "正方无法坐实"}
    v.update(over)
    return v


def _disproof(refutes=False, **over):
    if refutes:
        v = {
            "refutes_real": True,
            "evidence_refs": ["a.c:4 - len 被夹紧到缓冲区容量以内"],
            "clearing_checks": ["a.c:4 - if (len > sizeof(dst)) return -1"],
            "non_issue_reason": "入口已把长度夹紧到缓冲区容量以内",
            "verdict_confidence": "high",
            "reasoning": "caller trace 证伪可达危险长度",
        }
    else:
        v = {"refutes_real": False, "evidence_refs": [], "clearing_checks": [],
             "missing_evidence": "未找到上游证伪点", "reasoning": "反方未能证伪"}
    v.update(over)
    return v


def _judge(decision="confirm", sev="high", **over):
    if decision == "confirm":
        v = {
            "decision": "confirm",
            "is_real": True,
            "evidence_refs": ["a.c:1 - recv 读入攻击者长度", "a.c:10 - memcpy 使用该长度"],
            "source_chain": ["a.c:1 - recv_packet", "a.c:8 - fn 传入 len", "a.c:10 - memcpy"],
            "sink_ref": "a.c:10 - memcpy(dst, src, len)",
            "reachability": "REMOTE 入口可达 fn",
            "controllability": "len 由报文字段控制且未夹紧",
            "corrected_severity": sev,
            "exploitability": "exploitable",
            "verdict_confidence": "high",
            "reasoning": "正方证据完整,反方未证伪",
        }
    elif decision == "reject":
        v = {
            "decision": "reject",
            "is_real": False,
            "evidence_refs": ["a.c:4 - len 被夹紧到缓冲区容量以内"],
            "clearing_checks": ["a.c:4 - if (len > sizeof(dst)) return -1"],
            "non_issue_reason": "入口已把长度夹紧到缓冲区容量以内",
            "verdict_confidence": "high",
            "reasoning": "反方证伪点成立",
        }
    else:
        v = {
            "decision": "inconclusive",
            "is_real": False,
            "evidence_refs": ["a.c:10 - 仅定位到 sink"],
            "missing_evidence": "source_chain 和 clearing_checks 均不足",
            "reasoning": "证据不足",
        }
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
        p.pb.verify_prover = lambda *a, **k: "PROVER_PROMPT"
        p.pb.verify_disprover = lambda *a, **k: "DISPROVER_PROMPT"
        p.pb.verify_judge = lambda *a, **k: "JUDGE_PROMPT"
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
    async def test_majority_confirm_judges_confirm(self):
        """正方证据合格 + 3 张裁决票里 2 confirm → 确认为漏洞。"""
        p = self.make_pipeline(verify_votes=3)
        p.runner.verify_responses = [_proof(), _disproof(False), _judge("confirm"), _judge("confirm"), _judge("inconclusive")]
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
        self.assertTrue(any(v.get("phase") == "prover" for v in p.confirmed[0]["votes"]))

    async def test_majority_reject_judges_rejects(self):
        """反方证伪合格 + 3 张裁决票里 3 reject → 标记 rejected,不入 confirmed。"""
        p = self.make_pipeline(verify_votes=3)
        p.runner.verify_responses = [
            _proof(False),
            _disproof(True),
            _judge("reject"),
            _judge("reject"),
            _judge("reject"),
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
        self.assertEqual(payload["vote_false"], 3)
        self.assertEqual(len(payload["votes"]), 5)
        self.assertEqual(payload["votes"][2]["phase"], "judge")
        self.assertIn("入口已把长度夹紧", payload["rejection_reason"])
        cands = p.store.load_candidates()
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["status"], "rejected")
        self.assertEqual(cands[0]["vote_false"], 3)

    async def test_tie_no_majority_is_not_a_rejection(self):
        """偶数裁决票打平(1 confirm / 1 reject)→ 正常阶段回队重试。"""
        p = self.make_pipeline(verify_votes=2)
        p.runner.verify_responses = [_proof(), _disproof(True), _judge("confirm"), _judge("reject")]
        f = _finding()
        await p.process_finding(f)

        self.assertEqual(p.confirmed, [])
        self.assertNotIn(finding_key(f), p.processed_keys)       # 未终结
        self.assertIn(finding_key(f), p.pending_findings)        # 留在候选池
        self.assertEqual(f["verify_status"], "pending")
        self.assertEqual(f["verify_attempts"], 1)
        self.assertTrue(any(it.get("kind") == "_finding" for it in p.queue))  # 已回队
        self.assertNotIn(EV.CANDIDATE_FAILED, self._event_types(p))
        self.assertNotIn(EV.FINDING_REJECTED, self._event_types(p))

    async def test_insufficient_valid_votes_is_not_a_rejection(self):
        """3 张裁决票里仅 1 张有效(2 张 CLI/解析失败)→ 票数不足 → 回队重试。"""
        p = self.make_pipeline(verify_votes=3)
        p.runner.verify_responses = [_proof(), _disproof(False), _judge("confirm"), None, None]
        f = _finding()
        await p.process_finding(f)

        self.assertEqual(p.confirmed, [])
        self.assertNotIn(finding_key(f), p.processed_keys)
        self.assertEqual(f["verify_attempts"], 1)
        self.assertIn("裁决票不足", f.get("verify_failure_reason", ""))
        self.assertNotIn(EV.FINDING_REJECTED, self._event_types(p))

    async def test_confirm_judge_without_source_chain_is_invalid(self):
        """confirm 裁决缺 source_chain → 无证据票不算票。"""
        p = self.make_pipeline(verify_votes=1)
        p.runner.verify_responses = [_proof(), _disproof(False), _judge("confirm", source_chain=[])]
        f = _finding()
        await p.process_finding(f)

        self.assertEqual(p.confirmed, [])
        self.assertNotIn(finding_key(f), p.processed_keys)
        self.assertIn("有效裁决票不足", f.get("verify_failure_reason", ""))
        self.assertIn("source_chain", f.get("verify_failure_reason", ""))

    async def test_reject_judge_without_clearing_check_is_invalid(self):
        """reject 裁决缺 clearing_checks → 无证据票不算票。"""
        p = self.make_pipeline(verify_votes=1)
        p.runner.verify_responses = [_proof(False), _disproof(True), _judge("reject", clearing_checks=[])]
        f = _finding()
        await p.process_finding(f)

        self.assertEqual(p.confirmed, [])
        self.assertNotIn(finding_key(f), p.processed_keys)
        self.assertIn("有效裁决票不足", f.get("verify_failure_reason", ""))
        self.assertIn("clearing_checks", f.get("verify_failure_reason", ""))

    async def test_retry_exhaustion_marks_verify_failed(self):
        """连续打平,耗尽 retry.max_attempts 后 → 终态 verify_failed + 发 CANDIDATE_FAILED。"""
        p = self.make_pipeline(verify_votes=2)
        p.cfg.retry.max_attempts = 1   # 总共允许 1 次失败回队,第 2 次失败即终态
        f = _finding()

        p.runner.verify_responses = [_proof(), _disproof(True), _judge("confirm"), _judge("reject")]
        await p.process_finding(f)                        # 第 1 次:回队
        self.assertEqual(f["verify_status"], "pending")
        self.assertEqual(f["verify_attempts"], 1)
        self.assertNotIn(EV.CANDIDATE_FAILED, self._event_types(p))

        p.runner.verify_responses = [_proof(), _disproof(True), _judge("confirm"), _judge("reject")]
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
        p.runner.verify_responses = [_proof(), _disproof(True), _judge("confirm"), _judge("reject")]
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
