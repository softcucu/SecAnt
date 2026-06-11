"""从结构化 run 态按需渲染 Markdown / SARIF(不在 run 过程中写盘)。

输入是 RunStore.load_full_state() 聚合出的 state(其 recon / auditLedger / surfaceLog / riskNotes / confirmed)
加一个 meta(target / scope / threat_model / methods / backend)。供 Web 导出端点与 CLI `--export` 复用。
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from .common import LEDGER_STATUS, SEV_RANK, finalize_findings, sev_to_level


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


# ──────────────────────── RECON.md ────────────────────────
def render_recon_md(state: Dict[str, Any], meta: Dict[str, Any]) -> str:
    sd = state.get("recon") or {}
    sn = _scope_note(meta)
    rg = sorted(sd.get("regions") or [], key=lambda r: SEV_RANK.get(r.get("priority"), 3))
    if rg:
        rows = ["| 优先级 | 攻击面区域 | 类别 | 不可信输入 | 信任边界 | 涉及文件 |", "|---|---|---|---|---|---|"]
        for r in rg:
            rows.append(f"| {r.get('priority') or '?'} | {r.get('name') or ''} | {r.get('category') or ''} | "
                        f"{_nl(r.get('untrusted_input'))} | {_nl(r.get('trust_boundary')) or '—'} | {', '.join(r.get('files') or [])} |")
        reg_table = "\n".join(rows)
    else:
        reg_table = "(无)"
    hist = sd.get("history") or []
    if hist:
        rows = ["| 历史问题模式 | 出处 | 相关 lens | 涉及文件 |", "|---|---|---|---|"]
        for h in hist:
            rows.append(f"| {_nl(h.get('pattern'))} | {h.get('source') or ''} | {h.get('lens_hint') or ''} | {', '.join(h.get('files') or [])} |")
        hist_table = "\n".join(rows)
    else:
        hist_table = "(未提炼到历史问题模式)"
    return (
        f"# 侦察 / 威胁建模报告 — {meta.get('target')}{sn}\n\n"
        f"**威胁模型**: {meta.get('threat_model')}　|　**生成阶段**: Recon\n\n"
        f"## 1. 项目用途与目标(它是做什么的)\n{sd.get('purpose') or '(侦察未归纳)'}\n\n"
        f"## 2. 威胁分析\n{_as_md(sd.get('threat_summary'), '(侦察未给出)')}\n\n"
        f"## 3. 仓库知识与安全背景\n{_as_md(sd.get('repo_knowledge'))}\n\n"
        f"## 4. 攻击面地图(按优先级)\n{reg_table}\n\n"
        f"## 5. 历史问题模式(由统一调度的 git history 任务提炼,同类变体排查种子)\n{hist_table}\n\n"
        f"## 6. 编译提示(供 PoC)\n{sd.get('build_hint') or '(未识别)'}\n\n"
        "---\n*由 proto-vuln-hunt(python) 从结构化态导出。*\n"
    )


# ──────────────────────── ATTACK-SURFACE.md ────────────────────────
def render_attack_surface_md(state: Dict[str, Any], meta: Dict[str, Any]) -> str:
    sn = _scope_note(meta)
    regions = (state.get("recon") or {}).get("regions") or []
    surface_log = state.get("surfaceLog") or []
    ledger = state.get("auditLedger") or []
    led_by_key = {r.get("key"): r for r in ledger}

    def label(key: str) -> str:
        rec = led_by_key.get(key)
        return LEDGER_STATUS.get(rec["status"] if rec else "pending", "⏳ 待审")

    init = sorted(regions, key=lambda r: SEV_RANK.get(r.get("priority"), 3))
    if init:
        rows = ["| 状态 | 优先级 | 区域 | 类别 | 不可信输入 | 涉及文件 |", "|---|---|---|---|---|---|"]
        for r in init:
            rows.append(f"| {label('region:' + str(r.get('name')))} | {r.get('priority') or '?'} | {r.get('name') or ''} | "
                        f"{r.get('category') or ''} | {_nl(r.get('untrusted_input'))} | {', '.join(r.get('files') or [])} |")
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
        f"**威胁模型**: {meta.get('threat_model')}　|　详见 RECON.md。\n"
        f"**状态图例**: {'　'.join(LEDGER_STATUS.values())}\n"
        f"**进度**: 已完成 {n_done} 项(其中未发现漏洞 {n_clean} 项),台账共 {len(ledger)} 项。\n\n"
        f"## A. 初始攻击面(侦察阶段)\n{init_table}\n\n"
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
        _rc_label = {"none": "—", "queued": "排队中", "running": "排查中", "done": "已排查"}
        for r in rows_data:
            rc = _rc_label.get(r.get("recheck_status") or "none", r.get("recheck_status") or "—")
            rows.append(f"| {r.get('severity_hint') or 'info'} | {r.get('area') or ''} | {r.get('file') or '—'} | "
                        f"{_nl(r.get('note'))} | {r.get('lens') or ''} | r{r.get('round') or '?'} | {rc} |")
        table = "\n".join(rows)
    else:
        table = "(本次审计未登记潜在风险)"
    return (
        f"# 潜在安全风险登记 — {meta.get('target')}{sn}\n\n"
        "> 这些是审计中发现、**可疑但未确认为漏洞**的隐患/可加固点(未经多票验证)。\n"
        f"**威胁模型**: {meta.get('threat_model')}　|　共 {len(rows_data)} 条\n\n"
        f"{table}\n\n---\n*由 proto-vuln-hunt(python) 从结构化态导出。*\n"
    )


# ──────────────────────── finding/<id>.md ────────────────────────
def render_finding_md(finding: Dict[str, Any]) -> str:
    fm = {
        "id": finding.get("id"), "title": finding.get("title"), "bug_class": finding.get("bug_class"),
        "severity": finding.get("corrected_severity") or finding.get("severity"),
        "file": finding.get("file"), "line": finding.get("line") or 0,
        "function": finding.get("function"), "confidence": finding.get("confidence"),
        "variant_of": finding.get("variant_of") or "",
    }
    fm_lines = "\n".join(f"{k}: {json.dumps(v, ensure_ascii=False) if isinstance(v, str) else v}" for k, v in fm.items())
    body = (finding.get("report_body") or "").strip()
    if not body:
        poc = finding.get("poc")
        body = (f"## ① 漏洞描述\n{finding.get('description') or finding.get('title')}\n\n"
                f"## ⑦ PoC / 验证结果\n{json.dumps(poc, ensure_ascii=False) if poc else '(无)'}\n")
    return f"---\n{fm_lines}\n---\n\n{body}\n"


# ──────────────────────── INDEX.md(确定性,无需 agent) ────────────────────────
def render_index_md(state: Dict[str, Any], meta: Dict[str, Any]) -> str:
    sn = _scope_note(meta)
    final = finalize_findings(state.get("confirmed") or [])
    counts: Dict[str, int] = {}
    for c in final:
        counts[c.get("bug_class")] = counts.get(c.get("bug_class"), 0) + 1
    top_sev = (final[0].get("corrected_severity") or final[0].get("severity")) if final else "none"
    summary = state.get("summary") or {}
    regions = (state.get("recon") or {}).get("regions") or []
    history = (state.get("recon") or {}).get("history") or []
    lines = [
        f"# 漏洞挖掘汇总 — {meta.get('target')}{sn}", "",
        f"- 威胁模型: {meta.get('threat_model')}　|　后端: {meta.get('backend')}　|　"
        f"方法库: {'已用(' + str(meta.get('methods_dir')) + ')' if meta.get('methods_ok') else '内联兜底'}",
        f"- 确认漏洞: {len(final)} 条;最高危等级: {top_sev};审计轮数: {summary.get('rounds', state.get('round', 0))};"
        f"候选去重池: {summary.get('candidates', '?')}",
        f"- 收敛: {'是' if summary.get('converged') else '否 —— ' + str(summary.get('stop_reason', ''))}",
        f"- 按 bug_class 计数: {json.dumps(counts, ensure_ascii=False)}", "",
        "## 漏洞索引(severity 从高到低)", "",
        "| ID | 严重度 | 类型 | 标题 | 位置 | 报告 |", "|---|---|---|---|---|---|",
    ]
    for c in final:
        sev = c.get("corrected_severity") or c.get("severity")
        lines.append(f"| {c.get('id')} | {sev} | {c.get('bug_class')} | {c.get('title')} | "
                     f"{c.get('file')}:{c.get('line') or 0} | [findings/{c.get('id')}.md](findings/{c.get('id')}.md) |")
    if not final:
        lines.append("| — | — | — | (本次未确认漏洞) | — | — |")
    # 攻击面地图 + 历史模式提要
    lines += ["", "## 攻击面地图(精炼)", ""]
    for r in regions:
        lines.append(f"- **{r.get('name')}** ({r.get('category')}, {r.get('priority')}) — {_nl(r.get('untrusted_input'))}")
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

    w("RECON.md", render_recon_md(state, meta))
    w("ATTACK-SURFACE.md", render_attack_surface_md(state, meta))
    w("RISKS.md", render_risks_md(state, meta))
    w("INDEX.md", render_index_md(state, meta))
    w("REPORT.sarif", json.dumps(build_sarif(state, meta), ensure_ascii=False, indent=2))
    for finding in finalize_findings(state.get("confirmed") or []):
        if finding.get("id"):
            w(f"findings/{finding['id']}.md", render_finding_md(finding))
    return written
