"""共享纯函数/常量,供 pipeline 与 exporters 复用(避免互相 import 形成环)。"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

LEDGER_STATUS = {
    "decomposed": "🧩 已拆解为子任务", "completed-clean": "✅ 已完成(未发现)",
    "completed-findings": "⚠️ 已完成(有候选)", "in-progress": "🔄 进行中(将续审)",
    "incomplete": "⛔ 未审完(agent故障,待重审)", "pending": "⏳ 待审",
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
    if re.search(r"dos|denial|exhaust|recursion|deadlock", s):
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
    }


def finalize_findings(confirmed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """按 file::line::bug_class 去重(保留更严重者),按严重度排序。输入为完整或精简的确认记录。"""
    loc_seen: Dict[str, Dict[str, Any]] = {}
    for c in confirmed:
        sev = c.get("corrected_severity") or c.get("severity")
        lk = f"{(c.get('file') or '').strip()}::{c.get('line') or 0}::{(c.get('bug_class') or '').strip().lower()}"
        ex = loc_seen.get(lk)
        if not ex or SEV_RANK.get(sev, 9) < SEV_RANK.get(ex.get("corrected_severity") or ex.get("severity"), 9):
            loc_seen[lk] = c
    return sorted(loc_seen.values(),
                  key=lambda c: SEV_RANK.get(c.get("corrected_severity") or c.get("severity"), 9))
