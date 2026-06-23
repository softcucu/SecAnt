"""共享纯函数/常量,供 pipeline 与 exporters 复用(避免互相 import 形成环)。"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
QUALITY_FINDING_STATUS = "unproven_quality_issue"
QUALITY_FINDING_TAG = "编码质量问题"

LEDGER_STATUS = {
    "decomposed": "🧩 已拆解为子任务", "completed-clean": "✅ 已完成(未发现)",
    "completed-findings": "⚠️ 已完成(有候选)", "in-progress": "🔄 进行中(将续审)",
    "incomplete": "⛔ 未审完(agent故障,待重审)", "pending": "⏳ 待审",
    "abandoned": "⛔ 复查失败(未覆盖)",
}


def most_severe(arr: List[Optional[str]]) -> Optional[str]:
    vals = [a for a in arr if a]
    if not vals:
        return None
    return sorted(vals, key=lambda a: SEV_RANK.get(a, 9))[0]


def class_code(bc: str) -> str:
    s = (bc or "").lower()
    if re.search(r"info.?leak|infoleak|information.?disclosure|disclosure|uninitialized|uninit|padding.?leak|address.?leak|\baslr\b|mem(ory)?.?disclosure", s):
        return "LEAK"
    if re.search(r"uaf|use-after|double-free|overflow|oob|memory|buffer|stack|heap", s) and not re.search(r"integer|int-", s):
        return "MEM"
    if re.search(r"integer|int-overflow|truncat|signed", s):
        return "INT"
    if re.search(r"type-confusion|type_conf", s):
        return "TYPE"
    if re.search(r"race|toctou|double-fetch|concurren", s):
        return "RACE"
    if re.search(r"inject|format-string|path|symlink|command", s):
        return "INJ"
    if re.search(r"deser", s):
        return "DESER"
    if re.search(r"auth|credential|bypass|downgrade", s):
        return "AUTH"
    if re.search(r"crypto|cipher|tls|cert|random|nonce|iv\b", s):
        return "CRYPTO"
    if re.search(r"dos|denial|exhaust|recursion|deadlock|resource|starv|watchdog|priority.?inversion|rtos|real.?time|timer.?storm|pool.?exhaust|task.?stack|stack.?exhaust", s):
        return "DOS"
    return "VULN"


def finding_key(f: Dict[str, Any]) -> str:
    return f"{(f.get('file') or '').strip()}::{f.get('line') or 0}::{(f.get('bug_class') or '').strip().lower()}"


def item_key(it: Dict[str, Any]) -> str:
    k = it.get("kind")
    if k == "region":
        return f"region:{it.get('name')}"
    if k == "variant":
        return f"variant:{it.get('pattern')}"
    if k == "risk":
        return f"risk:{it.get('id')}"
    if k == "task":
        return f"task:{it.get('region') or ''}:{it.get('objective') or it.get('name')}"
    return f"surface:{it.get('name')}"


def pad3(n: int) -> str:
    return str(n).zfill(3)


def sev_to_level(s: str) -> str:
    return "error" if s in ("critical", "high") else ("warning" if s == "medium" else "note")


def slim_finding(c: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": c.get("id"), "title": c.get("title"), "bug_class": c.get("bug_class"),
        "description": c.get("description") or c.get("title"),
        "corrected_severity": c.get("corrected_severity") or c.get("severity"),
        "confidence": c.get("confidence") or "medium",
        "file": c.get("file"), "line": c.get("line") or 0, "function": c.get("function") or "",
        "exploitability": c.get("exploitability") or "", "variant_of": c.get("variant_of") or "",
        "audit_model": c.get("audit_model") or "", "verify_models": c.get("verify_models") or [],
        "output_ts": c.get("output_ts") or c.get("confirmed_at") or c.get("created_at") or 0,
        "manual_feedback": c.get("manual_feedback") or {},
        "tags": c.get("tags") if isinstance(c.get("tags"), list) else [],
        "finding_status": c.get("finding_status") or "",
        "verification_status": c.get("verification_status") or "",
        "original_severity": c.get("original_severity") or "",
        "epistemic_verdict": c.get("epistemic_verdict") or "",
        "operational_decision": c.get("operational_decision") or "",
        "decision_reason": c.get("decision_reason") or "",
        "residual_uncertainty": c.get("residual_uncertainty") or "",
        "recommended_next_action": c.get("recommended_next_action") or "",
    }


def finding_tags(c: Dict[str, Any]) -> List[str]:
    tags = c.get("tags")
    if not isinstance(tags, list):
        return []
    return [str(t) for t in tags if str(t).strip()]


def is_quality_issue_finding(c: Dict[str, Any]) -> bool:
    return c.get("finding_status") == QUALITY_FINDING_STATUS or QUALITY_FINDING_TAG in finding_tags(c)


def finalize_findings(confirmed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """按 file::line::bug_class 去重(保留更严重者),按严重度排序。输入为完整或精简的确认记录。"""
    loc_seen: Dict[str, Dict[str, Any]] = {}
    for c in confirmed:
        sev = c.get("corrected_severity") or c.get("severity")
        lk = f"{(c.get('file') or '').strip()}::{c.get('line') or 0}::{(c.get('bug_class') or '').strip().lower()}"
        ex = loc_seen.get(lk)
        cur_rank = (1 if is_quality_issue_finding(c) else 0, SEV_RANK.get(sev, 9))
        ex_sev = (ex.get("corrected_severity") or ex.get("severity")) if ex else None
        ex_rank = (1 if ex and is_quality_issue_finding(ex) else 0, SEV_RANK.get(ex_sev, 9))
        if not ex or cur_rank < ex_rank:
            loc_seen[lk] = c
    return sorted(loc_seen.values(),
                  key=lambda c: (1 if is_quality_issue_finding(c) else 0,
                                 SEV_RANK.get(c.get("corrected_severity") or c.get("severity"), 9)))
