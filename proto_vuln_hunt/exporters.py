"""从结构化 run 态按需渲染 Markdown / SARIF(不在 run 过程中写盘)。

输入是 RunStore.load_full_state() 聚合出的 state(其 threatAnalysis / history / auditLedger / surfaceLog / riskNotes / confirmed)
加一个 meta(target / scope / threat_model / methods / backend)。供 Web 导出端点与 CLI `--export` 复用。
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from .common import LEDGER_STATUS, SEV_RANK, finalize_findings, finding_tags, is_quality_issue_finding, sev_to_level


def _scope_note(meta: Dict[str, Any]) -> str:
    return f"(仅审子路径:{meta.get('scope')})" if meta.get("scope") else ""


def _nl(s: Optional[str]) -> str:
    return (s or "").replace("\n", " ")


def _as_md(v: Any, empty: str = "(无)") -> str:
    """把"字符串或字符串列表"渲染为 Markdown:列表 → 逐条 bullet;字符串 → 原样。"""
    if isinstance(v, (list, tuple)):
        items = [f"- {_nl(str(x))}" for x in v if str(x).strip()]
        return "\n".join(items) if items else empty
    return str(v) if v else empty


# ──────────────────────── THREAT-ANALYSIS.md ────────────────────────
def render_threat_analysis_md(state: Dict[str, Any], meta: Dict[str, Any]) -> str:
    graph = state.get("threatAnalysis") or {}
    sn = _scope_note(meta)
    assets = graph.get("assets") or []
    audit_items = graph.get("audit_items") or []
    stats = graph.get("stats") or {}
    if assets:
        rows = ["| 关键资产 | 类型 | 重要性 | 关键风险 |", "|---|---|---|---|"]
        for a in assets:
            risks = "；".join(r.get("name") or "" for r in (a.get("risks") or []))
            rows.append(f"| {a.get('name') or ''} | {a.get('asset_type') or ''} | {a.get('criticality') or ''} | {_nl(risks)} |")
        asset_table = "\n".join(rows)
    else:
        asset_table = "(威胁分析未识别关键资产)"
    if audit_items:
        rows = ["| 优先级 | 关键资产 | 攻击目标 | 攻击域 | 攻击面 | 攻击方式 | 代码路径 |", "|---|---|---|---|---|---|---|"]
        for it in audit_items:
            ctx = it.get("attack_context") or {}
            rows.append(f"| {it.get('priority') or ''} | {ctx.get('asset_name') or ''} | {ctx.get('attack_goal') or ''} | "
                        f"{ctx.get('domain') or ''} | {ctx.get('surface') or ''} | {ctx.get('method') or it.get('name') or ''} | "
                        f"{', '.join(it.get('files') or []) or '—'} |")
        item_table = "\n".join(rows)
    else:
        item_table = "(威胁分析未生成审计项)"
    hist = state.get("history") or []
    if hist:
        rows = ["| 历史问题模式 | 出处 | 相关 lens | 涉及文件 |", "|---|---|---|---|"]
        for h in hist:
            rows.append(f"| {_nl(h.get('pattern'))} | {h.get('source') or ''} | {h.get('lens_hint') or ''} | {', '.join(h.get('files') or [])} |")
        hist_table = "\n".join(rows)
    else:
        hist_table = "(未提炼到历史问题模式)"
    return (
        f"# 攻击树威胁分析 — {meta.get('target')}{sn}\n\n"
        f"**威胁模型**: {meta.get('threat_model')}　|　资产 {stats.get('assets', 0)} 个,攻击树 {stats.get('trees', 0)} 棵,"
        f"攻击面 {stats.get('surfaces', 0)} 个,攻击方式 {stats.get('methods', 0)} 个。\n\n"
        f"## 1. 关键资产\n{asset_table}\n\n"
        f"## 2. 攻击方式审计清单\n{item_table}\n\n"
        f"## 3. 历史问题模式(同类变体排查种子)\n{hist_table}\n\n"
        "---\n*由 proto-vuln-hunt(python) 从结构化态导出。*\n"
    )


# ──────────────────────── ATTACK-SURFACE.md ────────────────────────
def render_attack_surface_md(state: Dict[str, Any], meta: Dict[str, Any]) -> str:
    sn = _scope_note(meta)
    attack_items = (state.get("threatAnalysis") or {}).get("audit_items") or []
    surface_log = state.get("surfaceLog") or []
    ledger = state.get("auditLedger") or []
    led_by_key = {r.get("key"): r for r in ledger}

    def label(key: str) -> str:
        rec = led_by_key.get(key)
        return LEDGER_STATUS.get(rec["status"] if rec else "pending", "⏳ 待审")

    init = sorted(attack_items, key=lambda r: SEV_RANK.get(r.get("priority"), 3))
    if init:
        rows = ["| 状态 | 优先级 | 资产 | 攻击目标 | 攻击面 | 攻击方式 | 涉及文件 |", "|---|---|---|---|---|---|---|"]
        for r in init:
            ctx = r.get("attack_context") or {}
            rows.append(f"| {label('attack_method:' + str(r.get('id') or r.get('name')))} | {r.get('priority') or '?'} | "
                        f"{ctx.get('asset_name') or ''} | {ctx.get('attack_goal') or ''} | {ctx.get('surface') or ''} | "
                        f"{ctx.get('method') or r.get('name') or ''} | {', '.join(r.get('files') or []) or '—'} |")
        init_table = "\n".join(rows)
    else:
        init_table = "(无)"
    if surface_log:
        rows = ["| 状态 | 轮次 | 新增攻击面 | 来自 | 为何可疑 | 相关 lens | 涉及文件 |", "|---|---|---|---|---|---|---|"]
        for s in surface_log:
            rows.append(f"| {label('surface:' + str(s.get('name')))} | r{s.get('round') or '?'} | {s.get('name') or ''} | "
                        f"{s.get('from') or ''} | {_nl(s.get('why'))} | {s.get('lens_hint') or ''} | {', '.join(s.get('files') or [])} |")
        dyn_table = "\n".join(rows)
    else:
        dyn_table = "(本次审计未动态发现新的攻击面)"
    ord_map = {"completed-findings": 0, "in-progress": 1, "completed-clean": 2, "pending": 3}
    led = sorted(ledger, key=lambda r: ord_map.get(r.get("status"), 9))
    if led:
        rows = ["| 状态 | 工作项 | 类型 | 审计轮数(passes) | 覆盖 lens | 候选数 | 新攻击面 | 风险登记 | 末轮 |",
                "|---|---|---|---|---|---|---|---|---|"]
        for r in led:
            rows.append(f"| {LEDGER_STATUS.get(r.get('status'), r.get('status'))} | {r.get('name') or ''} | {r.get('kind') or ''} | "
                        f"{r.get('passes') or 0} | {'/'.join(r.get('lenses') or [])} | {r.get('candidates') or 0} | "
                        f"{r.get('surfaces') or 0} | {r.get('risks') or 0} | r{r.get('lastRound') or 0} |")
        led_table = "\n".join(rows)
    else:
        led_table = "(尚无审计记录)"
    n_done = sum(1 for r in ledger if str(r.get("status")).startswith("completed"))
    n_clean = sum(1 for r in ledger if r.get("status") == "completed-clean")
    return (
        f"# 攻击面(初始 + 审计中动态扩展)+ 审计覆盖 — {meta.get('target')}{sn}\n\n"
        f"**威胁模型**: {meta.get('threat_model')}　|　详见 THREAT-ANALYSIS.md。\n"
        f"**状态图例**: {'　'.join(LEDGER_STATUS.values())}\n"
        f"**进度**: 已完成 {n_done} 项(其中未发现漏洞 {n_clean} 项),台账共 {len(ledger)} 项。\n\n"
        f"## A. 攻击树审计项\n{init_table}\n\n"
        f"## B. 审计中动态新增的攻击面\n{dyn_table}\n\n"
        f"## C. 审计覆盖台账(每个工作项的结果,含\"审过但未发现漏洞\")\n{led_table}\n\n"
        "---\n*由 proto-vuln-hunt(python) 从结构化态导出。*\n"
    )


# ──────────────────────── RISKS.md ────────────────────────
def render_risks_md(state: Dict[str, Any], meta: Dict[str, Any]) -> str:
    sn = _scope_note(meta)
    rows_data = sorted(state.get("riskNotes") or [], key=lambda r: SEV_RANK.get(r.get("severity_hint"), 9))
    if rows_data:
        rows = ["| 风险高低 | 主题 | 位置 | 说明 | lens | 轮次 | 排查 |", "|---|---|---|---|---|---|---|"]
        _rc_label = {"none": "—", "queued": "排队中", "running": "排查中", "done": "已排查", "failed": "排查失败"}
        for r in rows_data:
            rc = _rc_label.get(r.get("recheck_status") or "none", r.get("recheck_status") or "—")
            rows.append(f"| {r.get('severity_hint') or 'info'} | {r.get('area') or ''} | {r.get('file') or '—'} | "
                        f"{_nl(r.get('note'))} | {r.get('lens') or ''} | r{r.get('round') or '?'} | {rc} |")
        table = "\n".join(rows)
    else:
        table = "(本次审计未登记潜在风险)"
    return (
        f"# 潜在安全风险登记 — {meta.get('target')}{sn}\n\n"
        "> 这些是审计中发现、**可疑但未确认为漏洞**的隐患/可加固点(未经对抗验证确认)。\n"
        f"**威胁模型**: {meta.get('threat_model')}　|　共 {len(rows_data)} 条\n\n"
        f"{table}\n\n---\n*由 proto-vuln-hunt(python) 从结构化态导出。*\n"
    )


# ──────────────────────── finding/<id>.md ────────────────────────
def _render_verify_votes_md(votes: List[Dict[str, Any]]) -> str:
    if not votes:
        return ""
    rows = ["\n\n## 对抗验证记录\n"]
    for i, v in enumerate(votes, 1):
        phase = v.get("phase") or "verify"
        decision = v.get("decision") or ("confirm" if v.get("is_real") else "reject")
        valid = "合格" if v.get("validation_ok", True) else f"无效: {v.get('validation_reason') or '未通过证据门槛'}"
        meta = " / ".join(x for x in [phase, decision, v.get("verify_lens") or "", v.get("model") or ""] if x)
        rows.append(f"\n### 验证记录 {i}: {meta}\n\n")
        rows.append(f"- 证据有效性: {valid}\n")
        if v.get("verdict_confidence"):
            rows.append(f"- 置信度: {v.get('verdict_confidence')}\n")
        if v.get("operational_decision"):
            rows.append(f"- 工程决策: {v.get('operational_decision')}\n")
        if v.get("epistemic_verdict"):
            rows.append(f"- 证据结论: {v.get('epistemic_verdict')}\n")
        if v.get("witness"):
            rows.append(f"- Witness: {_nl(str(v.get('witness')))}\n")
        if v.get("attack_preconditions"):
            rows.append(f"- 攻击前置条件:\n{_as_md(v.get('attack_preconditions'))}\n")
        if v.get("input_domain_constraints"):
            rows.append(f"- 输入域约束:\n{_as_md(v.get('input_domain_constraints'))}\n")
        if v.get("state_constraints"):
            rows.append(f"- 状态约束:\n{_as_md(v.get('state_constraints'))}\n")
        if v.get("code_constraints"):
            rows.append(f"- 代码约束:\n{_as_md(v.get('code_constraints'))}\n")
        if v.get("path_nodes"):
            rows.append(f"- 路径节点:\n{_as_md(v.get('path_nodes'))}\n")
        if v.get("trigger_condition"):
            rows.append(f"- 触发条件: {_nl(str(v.get('trigger_condition')))}\n")
        if v.get("bad_result"):
            rows.append(f"- 坏结果: {_nl(str(v.get('bad_result')))}\n")
        if v.get("blocker_description") or v.get("impossibility_proof"):
            rows.append(f"- Blocker: {_nl(str(v.get('blocker_description') or v.get('impossibility_proof')))}\n")
        if v.get("blocker_scope"):
            rows.append(f"- Blocker 作用域: {v.get('blocker_scope')}\n")
        if v.get("blocking_checks"):
            rows.append(f"- 阻断点:\n{_as_md(v.get('blocking_checks'))}\n")
        if v.get("witness_verdict"):
            rows.append(f"- Witness 裁决: {v.get('witness_verdict')}\n")
        if v.get("blocker_verdict"):
            rows.append(f"- Blocker 裁决: {v.get('blocker_verdict')}\n")
        if v.get("reviewed_checks"):
            rows.append(f"- 已复核事实:\n{_as_md(v.get('reviewed_checks'))}\n")
        if v.get("failed_checks"):
            rows.append(f"- 失败/削弱点:\n{_as_md(v.get('failed_checks'))}\n")
        if v.get("deciding_facts_checked"):
            rows.append(f"- 终局补查事实:\n{_as_md(v.get('deciding_facts_checked'))}\n")
        if v.get("evidence_refs"):
            rows.append(f"- 代码证据:\n{_as_md(v.get('evidence_refs'))}\n")
        if v.get("source_chain"):
            rows.append(f"- 调用链:\n{_as_md(v.get('source_chain'))}\n")
        if v.get("sink_ref"):
            rows.append(f"- Sink: {_nl(str(v.get('sink_ref')))}\n")
        if v.get("clearing_checks"):
            rows.append(f"- 证伪点:\n{_as_md(v.get('clearing_checks'))}\n")
        if v.get("reachability"):
            rows.append(f"- 可达性: {_nl(str(v.get('reachability')))}\n")
        if v.get("controllability"):
            rows.append(f"- 可控性: {_nl(str(v.get('controllability')))}\n")
        reason = v.get("non_issue_reason") or v.get("reasoning")
        if reason:
            rows.append(f"- 理由: {_nl(str(reason))}\n")
        if v.get("missing_evidence"):
            rows.append(f"- 缺失证据: {_nl(str(v.get('missing_evidence')))}\n")
        if v.get("residual_uncertainty"):
            rows.append(f"- 剩余不确定性: {_nl(str(v.get('residual_uncertainty')))}\n")
        if v.get("why_not_confirmed"):
            rows.append(f"- 为何不确认: {_nl(str(v.get('why_not_confirmed')))}\n")
        if v.get("why_not_rejected"):
            rows.append(f"- 为何不否决: {_nl(str(v.get('why_not_rejected')))}\n")
        if v.get("recommended_next_action"):
            rows.append(f"- 建议动作: {_nl(str(v.get('recommended_next_action')))}\n")
        if v.get("risk_note"):
            rows.append(f"- 风险说明: {_nl(str(v.get('risk_note')))}\n")
    return "".join(rows)


def render_finding_md(finding: Dict[str, Any]) -> str:
    fm = {
        "id": finding.get("id"), "title": finding.get("title"), "bug_class": finding.get("bug_class"),
        "severity": finding.get("corrected_severity") or finding.get("severity"),
        "file": finding.get("file"), "line": finding.get("line") or 0,
        "function": finding.get("function"), "confidence": finding.get("confidence"),
        "variant_of": finding.get("variant_of") or "",
        "tags": finding_tags(finding),
        "finding_status": finding.get("finding_status") or "",
        "verification_status": finding.get("verification_status") or "",
    }
    fm_lines = "\n".join(f"{k}: {json.dumps(v, ensure_ascii=False) if isinstance(v, str) else v}" for k, v in fm.items())
    body = (finding.get("report_body") or "").strip()
    if not body:
        poc = finding.get("poc")
        body = (f"## ① 漏洞描述\n{finding.get('description') or finding.get('title')}\n\n"
                f"## ⑦ PoC / 验证结果\n{json.dumps(poc, ensure_ascii=False) if poc else '(无)'}\n")
    body += _render_verify_votes_md(finding.get("votes") or [])
    return f"---\n{fm_lines}\n---\n\n{body}\n"


# ──────────────────────── INDEX.md(确定性,无需 agent) ────────────────────────
def _index_status_line(summary: Dict[str, Any]) -> str:
    status = summary.get("status") or ("done" if summary.get("converged") else "incomplete")
    if status != "incomplete":
        label = {"done": "✅ 完整完成", "stopped": "⏹ 用户停止"}.get(status, status)
        return f"- 运行状态: {label}"
    bits = []
    if summary.get("failed_candidates"):
        bits.append(f"候选验证失败 {summary['failed_candidates']} 条")
    if summary.get("pending_findings"):
        bits.append(f"候选仍待验证 {summary['pending_findings']} 条")
    if summary.get("failed_rechecks"):
        bits.append(f"风险/变体复查失败 {summary['failed_rechecks']} 项")
    detail = ("(" + "、".join(bits) + ")") if bits else ""
    return f"- 运行状态: ⛔ 未完整覆盖{detail} —— 续跑可对失败项重新补审"


def render_index_md(state: Dict[str, Any], meta: Dict[str, Any]) -> str:
    sn = _scope_note(meta)
    final = finalize_findings(state.get("confirmed") or [])
    quality_count = sum(1 for c in final if is_quality_issue_finding(c))
    counts: Dict[str, int] = {}
    for c in final:
        counts[c.get("bug_class")] = counts.get(c.get("bug_class"), 0) + 1
    top_sev = (final[0].get("corrected_severity") or final[0].get("severity")) if final else "none"
    summary = state.get("summary") or {}
    attack_items = (state.get("threatAnalysis") or {}).get("audit_items") or []
    history = state.get("history") or []
    lines = [
        f"# 漏洞挖掘汇总 — {meta.get('target')}{sn}", "",
        f"- 威胁模型: {meta.get('threat_model')}　|　后端: {meta.get('backend')}　|　"
        f"方法库: {'已用(' + str(meta.get('methods_dir')) + ')' if meta.get('methods_ok') else '内联兜底'}",
        f"- 漏洞条目: {len(final)} 条;其中编码质量问题: {quality_count} 条;最高危等级: {top_sev};审计轮数: {summary.get('rounds', state.get('round', 0))};"
        f"候选去重池: {summary.get('candidates', '?')}",
        f"- 收敛: {'是' if summary.get('converged') else '否 —— ' + str(summary.get('stop_reason', ''))}",
        _index_status_line(summary),
        f"- 按 bug_class 计数: {json.dumps(counts, ensure_ascii=False)}", "",
        "## 漏洞索引(severity 从高到低)", "",
        "| ID | 严重度 | 类型 | 标签 | 标题 | 位置 | 报告 |", "|---|---|---|---|---|---|---|",
    ]
    for c in final:
        sev = c.get("corrected_severity") or c.get("severity")
        tags = "、".join(finding_tags(c)) or "—"
        lines.append(f"| {c.get('id')} | {sev} | {c.get('bug_class')} | {tags} | {c.get('title')} | "
                     f"{c.get('file')}:{c.get('line') or 0} | [findings/{c.get('id')}.md](findings/{c.get('id')}.md) |")
    if not final:
        lines.append("| — | — | — | — | (本次未确认漏洞) | — | — |")
    # 攻击树审计项 + 历史模式提要
    lines += ["", "## 攻击树审计项(精炼)", ""]
    for it in attack_items:
        ctx = it.get("attack_context") or {}
        lines.append(f"- **{ctx.get('surface') or it.get('name')} / {ctx.get('method') or it.get('name')}** "
                     f"({it.get('priority')}, {ctx.get('asset_name') or ''}) — {_nl(ctx.get('attack_goal'))}")
    if history:
        lines += ["", "## 历史问题模式", ""]
        for h in history:
            lines.append(f"- {_nl(h.get('pattern'))} ({h.get('source') or ''})")
    return "\n".join(lines) + "\n"


# ──────────────────────── REPORT.sarif ────────────────────────
def build_sarif(state: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    final = finalize_findings(state.get("confirmed") or [])
    rule_ids = list(dict.fromkeys(c.get("bug_class") for c in final))
    return {
        "version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "proto-vuln-hunt-py", "informationUri": "https://anthropic.com",
                                "rules": [{"id": r, "name": r} for r in rule_ids]}},
            "results": [{
                "ruleId": c.get("bug_class"),
                "level": sev_to_level(c.get("corrected_severity") or c.get("severity")),
                "message": {"text": f"[{c.get('id')}] {c.get('title')} — {c.get('description', '')}"[:2000]},
                "properties": {"severity": c.get("corrected_severity") or c.get("severity"),
                               "confidence": c.get("confidence"), "exploitability": c.get("exploitability") or "",
                               "variant_of": c.get("variant_of") or "", "report": f"findings/{c.get('id')}.md"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": c.get("file")},
                                                    "region": {"startLine": max(1, c.get("line") or 1)}}}],
            } for c in final],
        }],
    }


# ──────────────────────── 批量导出到磁盘 ────────────────────────
def export_all(out_dir: str, state: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, str]:
    """把所有 MD/SARIF 渲染并写入 out_dir(含 findings/ 子目录)。返回写出的路径表。"""
    out_dir = os.path.abspath(os.path.expanduser(out_dir))
    find_dir = os.path.join(out_dir, "findings")
    os.makedirs(find_dir, exist_ok=True)
    written: Dict[str, str] = {}

    def w(name: str, text: str) -> None:
        path = os.path.join(out_dir, name)
        os.makedirs(os.path.dirname(path) or out_dir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        written[name] = path

    w("THREAT-ANALYSIS.md", render_threat_analysis_md(state, meta))
    w("ATTACK-SURFACE.md", render_attack_surface_md(state, meta))
    w("RISKS.md", render_risks_md(state, meta))
    w("INDEX.md", render_index_md(state, meta))
    w("REPORT.sarif", json.dumps(build_sarif(state, meta), ensure_ascii=False, indent=2))
    for finding in finalize_findings(state.get("confirmed") or []):
        if finding.get("id"):
            w(f"findings/{finding['id']}.md", render_finding_md(finding))
    return written
