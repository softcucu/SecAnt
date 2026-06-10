"use strict";
// ──────────────────────── helpers ────────────────────────
const app = document.getElementById("app");
const SEVS = ["critical", "high", "medium", "low", "info"];
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else if (k === "html") e.innerHTML = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) e.setAttribute(k, v);
  }
  for (const k of kids) { if (k == null) continue; e.append(k.nodeType ? k : document.createTextNode(k)); }
  return e;
}
async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
}
function flash(msg) { const f = el("div", { class: "flash" }, msg); document.body.append(f); setTimeout(() => f.remove(), 4200); }
function fmtTs(t) { if (!t) return "—"; const d = new Date(t * 1000); return d.toLocaleString(); }
function fmtClock(t) { if (!t) return "—"; const d = new Date(t * 1000); return d.toLocaleTimeString(); }
function fmtMs(ms) { ms = Number(ms || 0); if (!ms) return "—"; return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(ms < 10000 ? 1 : 0)}s`; }
function sevPill(s) { return el("span", { class: "pill sev-" + (s || "none") }, s || "none"); }
function stPill(s) { return el("span", { class: "pill st-" + (s || "queued") }, s || "queued"); }
function fmtNum(n) { return Number(n || 0).toLocaleString(); }
function cssKey(s) { return String(s || "unknown").replace(/[^a-z0-9-]+/gi, "-").toLowerCase(); }
function modelText(v) { return Array.isArray(v) ? v.join(", ") : (v || ""); }
function splitModels(v) { return String(v || "").split(",").map(s => s.trim()).filter(Boolean); }
function kvText(obj) { return Object.entries(obj || {}).map(([k, v]) => `${k}=${v}`).join(", "); }
function parseKvInts(v) {
  const out = {};
  for (const part of String(v || "").split(",")) {
    const i = part.indexOf("=");
    if (i < 1) continue;
    const k = part.slice(0, i).trim();
    const n = parseInt(part.slice(i + 1).trim(), 10);
    if (k && Number.isFinite(n) && n > 0) out[k] = n;
  }
  return out;
}
function emptyUsage() { return { calls: 0, input_tokens: 0, output_tokens: 0, total_tokens: 0, estimated_calls: 0 }; }
function addUsage(total, rec) {
  total.calls += 1;
  total.input_tokens += Number(rec.input_tokens || 0);
  total.output_tokens += Number(rec.output_tokens || 0);
  total.total_tokens += Number(rec.total_tokens || 0);
  if (rec.estimated) total.estimated_calls += 1;
}
function setUsage(total, src) {
  total.calls = Number(src?.calls || 0);
  total.input_tokens = Number(src?.input_tokens || 0);
  total.output_tokens = Number(src?.output_tokens || 0);
  total.total_tokens = Number(src?.total_tokens || 0);
  total.estimated_calls = Number(src?.estimated_calls || 0);
}

// ──────────────────────── mini markdown ────────────────────────
function inlineMd(s) {
  s = esc(s);
  s = s.replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`);
  s = s.replace(/\*\*([^*]+)\*\*/g, (_, c) => `<strong>${c}</strong>`);
  s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, t, u) => `<a href="${esc(u)}" target="_blank" rel="noopener">${t}</a>`);
  return s;
}
function mdToHtml(md) {
  if (!md) return "";
  const parts = String(md).split(/```/);
  let out = "";
  parts.forEach((seg, i) => {
    if (i % 2 === 1) { // fenced code
      const nl = seg.indexOf("\n");
      const code = nl >= 0 ? seg.slice(nl + 1) : seg;
      out += `<pre><code>${esc(code.replace(/\n$/, ""))}</code></pre>`;
      return;
    }
    const lines = seg.split("\n");
    let i2 = 0, inList = false, inTable = false;
    const closeList = () => { if (inList) { out += "</ul>"; inList = false; } };
    while (i2 < lines.length) {
      let ln = lines[i2];
      const h = ln.match(/^(#{1,4})\s+(.*)$/);
      const isTableRow = /^\s*\|.*\|\s*$/.test(ln);
      if (isTableRow && /\|/.test(lines[i2 + 1] || "") && /^[\s|:-]+$/.test(lines[i2 + 1] || "")) {
        closeList();
        const cells = (r) => r.trim().replace(/^\||\|$/g, "").split("|").map(c => c.trim());
        const head = cells(ln); i2 += 2;
        out += "<table><thead><tr>" + head.map(c => `<th>${inlineMd(c)}</th>`).join("") + "</tr></thead><tbody>";
        while (i2 < lines.length && /^\s*\|.*\|\s*$/.test(lines[i2])) {
          out += "<tr>" + cells(lines[i2]).map(c => `<td>${inlineMd(c)}</td>`).join("") + "</tr>"; i2++;
        }
        out += "</tbody></table>"; continue;
      }
      if (h) { closeList(); out += `<h${h[1].length}>${inlineMd(h[2])}</h${h[1].length}>`; i2++; continue; }
      if (/^\s*[-*]\s+/.test(ln)) { if (!inList) { out += "<ul>"; inList = true; } out += `<li>${inlineMd(ln.replace(/^\s*[-*]\s+/, ""))}</li>`; i2++; continue; }
      if (/^\s*>\s?/.test(ln)) { closeList(); out += `<blockquote>${inlineMd(ln.replace(/^\s*>\s?/, ""))}</blockquote>`; i2++; continue; }
      if (ln.trim() === "") { closeList(); i2++; continue; }
      closeList(); out += `<p>${inlineMd(ln)}</p>`; i2++;
    }
    closeList();
  });
  return out;
}

// ──────────────────────── router ────────────────────────
window.addEventListener("hashchange", route);
window.addEventListener("DOMContentLoaded", route);
function route() {
  if (window._es) { window._es.close(); window._es = null; }
  const h = location.hash || "#/";
  const m = h.match(/^#\/run\/(.+)$/);
  if (m) return viewDashboard(decodeURIComponent(m[1]));
  if (h === "#/new") return viewNew();
  return viewRuns();
}

// ──────────────────────── view: runs list ────────────────────────
async function viewRuns() {
  app.innerHTML = "";
  const head = el("div", { class: "row", style: "justify-content:space-between" },
    el("h2", {}, "运行列表"),
    el("a", { class: "btn", href: "#/new" }, "+ 新建审计"));
  app.append(head);
  let runs = [];
  try { runs = await api("GET", "/api/runs"); } catch (e) { app.append(el("div", { class: "empty" }, "加载失败: " + e.message)); return; }
  if (!runs.length) { app.append(el("div", { class: "panel empty" }, "还没有运行。点击「新建审计」开始。")); return; }
  const tbl = el("table", {}, el("thead", {}, el("tr", {},
    el("th", {}, "状态"), el("th", {}, "目标"), el("th", {}, "后端"),
    el("th", {}, "确认"), el("th", {}, "轮数"), el("th", {}, "创建时间"), el("th", {}, ""))));
  const tb = el("tbody");
  for (const r of runs) {
    const s = r.summary || {};
    tb.append(el("tr", {},
      el("td", {}, stPill(r.running ? "running" : r.status)),
      el("td", { html: `<a href="#/run/${encodeURIComponent(r.id)}">${esc(r.target || r.id)}</a>` + (r.scope ? `<div class="muted" style="font-size:12px">${esc(r.scope)}</div>` : "")}),
      el("td", {}, r.backend || "—"),
      el("td", {}, String(s.confirmed ?? 0)),
      el("td", {}, String(s.rounds ?? 0)),
      el("td", {}, fmtTs(r.created_at)),
      el("td", { html: `<a href="#/run/${encodeURIComponent(r.id)}">查看 →</a>` })));
  }
  tbl.append(tb);
  app.append(el("div", { class: "panel" }, tbl));
}

// ──────────────────────── view: new run ────────────────────────
async function viewNew() {
  app.innerHTML = "";
  let meta;
  try { meta = await api("GET", "/api/meta"); } catch (e) { app.append(el("div", { class: "empty" }, "加载失败: " + e.message)); return; }
  const d = meta.defaults;
  const f = (label, node) => el("label", { class: "field" }, el("span", {}, label), node);
  const inp = (id, val, type = "text") => el("input", { id, type, value: val == null ? "" : val });
  const num = (id, val) => inp(id, val, "number");

  const backendSel = el("select", { id: "backend" }, ...meta.backends.map(b => el("option", { value: b, selected: b === d.backend ? "" : null }, b)));
  const tmSel = el("select", { id: "threat_model" }, ...["REMOTE", "LOCAL_UNPRIVILEGED", "BOTH"].map(t => el("option", { value: t, selected: t === d.threat_model ? "" : null }, t)));
  const lensChecks = el("div", { class: "checks" }, ...meta.lenses.map(l =>
    el("label", {}, el("input", { type: "checkbox", value: l, class: "lens", checked: (d.lenses || []).includes(l) ? "" : null }), l)));
  const modelRows = el("div", { class: "grid" }, ...["default", ...meta.roles].map(role =>
    f("模型 · " + role, inp("model_" + role, modelText((d.models || {})[role]), "text"))));

  const left = el("div", {},
    f("目标源码根目录 *", inp("target", "")),
    f("子路径 scope(可选)", inp("scope", "")),
    f("后端 CLI", backendSel),
    f("并发数", num("concurrency", d.concurrency)),
    f("威胁模型", tmSel),
    el("label", { class: "field" }, el("span", {}, "lens(攻击面镜头)"), lensChecks),
  );
  const right = el("div", {},
    f("每 lens finder 数", num("finders_per_lens", d.finders_per_lens)),
    f("最大轮数 max_rounds", num("max_rounds", d.max_rounds)),
    f("收敛空轮 dry_rounds", num("dry_rounds", d.dry_rounds)),
    f("验证票数 verify_votes", num("verify_votes", d.verify_votes)),
    el("div", { class: "checks", style: "margin:8px 0 14px" },
      el("label", {}, el("input", { type: "checkbox", id: "enable_poc", checked: d.enable_poc ? "" : null }), "启用 PoC"),
      el("label", {}, el("input", { type: "checkbox", id: "decompose", checked: d.decompose ? "" : null }), "区域拆解")),
    el("div", { class: "panel", style: "padding:10px" },
      el("div", { class: "muted", style: "margin-bottom:6px" }, "每角色模型(留空=用 default)"),
      modelRows,
      f("模型并发 model=limit", inp("model_concurrency", kvText(d.model_concurrency), "text"))),
  );

  const submit = el("button", { class: "btn" }, "🚀 启动审计");
  submit.addEventListener("click", async () => {
    const target = document.getElementById("target").value.trim();
    if (!target) { flash("请填写目标目录"); return; }
    const models = {};
    for (const role of ["default", ...meta.roles]) {
      const vals = splitModels(document.getElementById("model_" + role).value);
      if (vals.length) models[role] = vals;
    }
    const lenses = [...document.querySelectorAll(".lens:checked")].map(c => c.value);
    const payload = {
      target, scope: document.getElementById("scope").value.trim(),
      backend: document.getElementById("backend").value, concurrency: +document.getElementById("concurrency").value,
      threat_model: document.getElementById("threat_model").value, lenses,
      finders_per_lens: +document.getElementById("finders_per_lens").value, max_rounds: +document.getElementById("max_rounds").value,
      dry_rounds: +document.getElementById("dry_rounds").value, verify_votes: +document.getElementById("verify_votes").value,
      enable_poc: document.getElementById("enable_poc").checked, decompose: document.getElementById("decompose").checked,
      models, model_concurrency: parseKvInts(document.getElementById("model_concurrency").value),
    };
    submit.disabled = true;
    try { const r = await api("POST", "/api/runs", payload); location.hash = "#/run/" + encodeURIComponent(r.run_id); }
    catch (e) { flash("启动失败: " + e.message); submit.disabled = false; }
  });

  app.append(el("h2", {}, "新建审计"),
    el("div", { class: "panel" }, el("div", { class: "cols" }, left, right), el("div", { style: "margin-top:8px" }, submit)));
}

// ──────────────────────── view: dashboard ────────────────────────
function viewDashboard(runId) {
  app.innerHTML = "";
  const S = { findings: new Map(), risks: new Map(), health: new Map(), agentMap: new Map(), coverage: null, recon: null, log: [], usageRows: [], usage: emptyUsage(), manifest: null, candidates: 0, status: "queued", round: 0, dry: 0, agents: 0, elapsed: 0 };
  let activeTab = "findings";

  const header = el("div", { class: "panel" });
  const tabsBar = el("div", { class: "tabs" });
  const tabBody = el("div", { id: "tabbody" });
  app.append(el("div", { class: "row", style: "justify-content:space-between" },
    el("h2", {}, "审计 ", el("span", { class: "muted", style: "font-size:13px" }, runId)),
    el("div", { class: "row" },
      el("button", { class: "btn danger", onclick: stop }, "停止"),
      el("button", { class: "btn secondary", onclick: resume }, "续跑"),
      el("a", { class: "btn secondary", href: "#/" }, "返回"))));
  app.append(header, tabsBar, tabBody);

  async function stop() { try { await api("POST", `/api/runs/${encodeURIComponent(runId)}/stop`); flash("已请求停止"); } catch (e) { flash(e.message); } }
  async function resume() { try { const r = await api("POST", `/api/runs/${encodeURIComponent(runId)}/resume`); flash(r.ok ? "已续跑" : "无法续跑(可能正在运行)"); } catch (e) { flash(e.message); } }

  function renderHeader() {
    const bySev = {}; for (const f of S.findings.values()) bySev[f.corrected_severity] = (bySev[f.corrected_severity] || 0) + 1;
    header.innerHTML = "";
    const m = S.manifest || {}; const cfg = m.config || {};
    header.append(el("div", { class: "row", style: "justify-content:space-between;margin-bottom:10px" },
      el("div", { class: "row" }, stPill(S.status),
        el("span", { class: "muted" }, `${esc(cfg.target || "")}${cfg.scope ? " · " + esc(cfg.scope) : ""}`),
        el("span", { class: "muted" }, `后端 ${esc(cfg.backend || "?")} · 威胁 ${esc(cfg.threat_model || "?")}`)),
      el("div", { class: "muted" }, `轮 ${S.round}/${cfg.max_rounds ?? "?"} · dry ${S.dry} · 用时 ${Math.round(S.elapsed)}s`)));
    const stats = el("div", { class: "stats" },
      el("div", { class: "stat" }, el("div", { class: "n" }, String(S.findings.size)), el("div", { class: "l" }, "确认漏洞")),
      ...SEVS.map(s => el("div", { class: "stat" }, el("div", { class: "n sev-" + s, style: "color:var(--" + (s === "critical" ? "crit" : s === "high" ? "high" : s === "medium" ? "med" : s === "low" ? "low" : "info") + ")" }, String(bySev[s] || 0)), el("div", { class: "l" }, s))),
      el("div", { class: "stat" }, el("div", { class: "n" }, String(S.candidates)), el("div", { class: "l" }, "候选")),
      el("div", { class: "stat" }, el("div", { class: "n" }, String(S.risks.size)), el("div", { class: "l" }, "风险登记")),
      el("div", { class: "stat" }, el("div", { class: "n" }, String(S.agents)), el("div", { class: "l" }, "agent 调用")),
      el("div", { class: "stat" }, el("div", { class: "n" }, fmtNum(S.usage.input_tokens)), el("div", { class: "l" }, "输入 token")),
      el("div", { class: "stat" }, el("div", { class: "n" }, fmtNum(S.usage.output_tokens)), el("div", { class: "l" }, "输出 token")),
      el("div", { class: "stat" }, el("div", { class: "n" }, fmtNum(S.usage.total_tokens)), el("div", { class: "l" }, "总 token")));
    header.append(stats);
  }

  const TABS = [["findings", "漏洞"], ["agents", "Agent"], ["health", "模型"], ["coverage", "覆盖"], ["risks", "风险"], ["usage", "用量"], ["recon", "侦察"], ["activity", "活动"], ["exports", "导出"]];
  function renderTabs() {
    tabsBar.innerHTML = "";
    const activeAgents = [...S.agentMap.values()].filter(isAgentActive).length;
    const counts = { findings: S.findings.size, risks: S.risks.size, usage: S.usageRows.length, health: S.health.size, agents: activeAgents || S.agentMap.size };
    for (const [key, label] of TABS) {
      const t = el("div", { class: "tab" + (key === activeTab ? " active" : "") }, label);
      if (counts[key]) t.append(el("span", { class: "tabcount" }, String(counts[key])));
      t.addEventListener("click", () => { activeTab = key; renderTabs(); renderTab(); });
      tabsBar.append(t);
    }
  }

  function renderTab() {
    tabBody.innerHTML = "";
    if (activeTab === "findings") return renderFindings();
    if (activeTab === "agents") return renderAgents();
    if (activeTab === "health") return renderModels();
    if (activeTab === "coverage") return renderCoverage();
    if (activeTab === "risks") return renderRisks();
    if (activeTab === "usage") return renderUsage();
    if (activeTab === "recon") return renderRecon();
    if (activeTab === "activity") return renderActivity();
    if (activeTab === "exports") return renderExports();
  }

  function renderFindings() {
    const list = [...S.findings.values()].sort((a, b) => SEVS.indexOf(a.corrected_severity) - SEVS.indexOf(b.corrected_severity));
    if (!list.length) { tabBody.append(el("div", { class: "panel empty" }, "暂无确认漏洞(审计进行中会实时出现)。")); return; }
    for (const f of list) {
      const head = el("div", { class: "head" }, sevPill(f.corrected_severity),
        el("span", { class: "title" }, f.title || f.id),
        el("span", { class: "muted" }, f.bug_class || ""),
        el("span", { class: "loc" }, `${f.file || ""}:${f.line || 0}`));
      const body = el("div", { class: "body md" }, el("div", { class: "muted" }, "加载详情…"));
      const card = el("div", { class: "finding" }, head, body);
      head.addEventListener("click", async () => {
        card.classList.toggle("open");
        if (card.classList.contains("open") && !body.dataset.loaded) {
          try {
            const full = await api("GET", `/api/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(f.id)}`);
            body.dataset.loaded = "1";
            body.innerHTML = mdToHtml(full.report_body || "(无正文)");
            if (full.exploitability) body.prepend(el("p", { html: "<strong>可利用性:</strong> " + esc(full.exploitability) }));
            body.append(el("p", { style: "margin-top:10px" }, el("a", { href: `/api/runs/${encodeURIComponent(runId)}/export/finding/${encodeURIComponent(f.id)}.md`, target: "_blank" }, "下载该条报告 .md")));
          } catch (e) { body.innerHTML = "加载失败: " + esc(e.message); }
        }
      });
      tabBody.append(card);
    }
  }

  const HEALTH_TXT = { ok: "✅ 正常", down: "⛔ 不可达", degraded: "⚠️ 异常", checking: "⏳ 检查中", unknown: "· 未检查" };
  function healthPill(s) { return el("span", { class: "pill health-" + (s || "unknown") }, HEALTH_TXT[s] || s || "未检查"); }
  function isCallErrorText(s) { return /CLI 未产出|后端输出无可解析 JSON|结构化 JSON|parsefail|stdout 已存/.test(String(s || "")); }
  function renderModels() {
    const list = [...S.health.values()];
    const bar = el("div", { class: "row", style: "justify-content:space-between;margin-bottom:6px" },
      el("strong", {}, "各模型健康度"),
      el("button", { class: "btn secondary", onclick: recheckHealth }, "🩺 重新检查"));
    tabBody.append(el("div", { class: "panel" }, bar,
      el("p", { class: "muted", style: "margin:0" },
        "运行开始前会对每个配置的模型发一个 1+1 探针;调用某模型前若健康状态陈旧/异常会自动补检。状态实时更新。")));
    if (!list.length) { tabBody.append(el("div", { class: "panel empty" }, "暂无模型健康数据(开始运行后会自动检测)。")); return; }
    const order = { checking: 0, down: 1, degraded: 2, unknown: 3, ok: 4 };
    list.sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9) || String(a.model).localeCompare(String(b.model)));
    const tbl = el("table", {}, el("thead", {}, el("tr", {},
      el("th", {}, "状态"), el("th", {}, "模型"), el("th", {}, "延迟"), el("th", {}, "探针(正常/总)"),
      el("th", {}, "成功调用"), el("th", {}, "失败"), el("th", {}, "最近探针答复"), el("th", {}, "最近调用异常"), el("th", {}, "最近检查"))));
    const tb = el("tbody");
    for (const h of list) {
      const legacyCallErr = (!h.last_call_error && isCallErrorText(h.error)) ? h.error : "";
      const probeErr = h.error && !legacyCallErr ? h.error : "";
      const ans = h.answer ? h.answer : (probeErr ? el("span", { class: "muted", title: probeErr }, "⚠ " + probeErr) : "—");
      const callErrText = h.last_call_error || legacyCallErr;
      const callErr = callErrText ? el("span", { class: "muted", title: callErrText }, "⚠ " + callErrText) : "—";
      tb.append(el("tr", {},
        el("td", {}, healthPill(h.status)),
        el("td", { class: "loc" }, h.model || "—"),
        el("td", {}, h.last_latency_ms ? Math.round(h.last_latency_ms) + " ms" : "—"),
        el("td", {}, `${h.ok_checks || 0}/${h.checks || 0}`),
        el("td", {}, String(h.calls || 0)),
        el("td", {}, String(h.call_fails || 0)),
        el("td", {}, ans),
        el("td", {}, callErr),
        el("td", {}, h.last_check_ts ? fmtTs(h.last_check_ts) : "—")));
    }
    tbl.append(tb);
    tabBody.append(el("div", { class: "panel" }, tbl));
  }
  async function recheckHealth() {
    try { const r = await api("POST", `/api/runs/${encodeURIComponent(runId)}/health/check`); flash(r.ok ? "已触发健康复检" : "无法复检(run 未在运行)"); }
    catch (e) { flash(e.message); }
  }

  const AGENT_TXT = {
    queued: "排队中",
    running: "运行中",
    retrying: "等待重试",
    failed_attempt: "本次失败",
    done: "完成",
    failed: "失败",
  };
  function isAgentActive(a) { return ["queued", "running", "retrying", "failed_attempt"].includes(a.status); }
  function agentPill(s) { return el("span", { class: "pill agent-" + cssKey(s) }, AGENT_TXT[s] || s || "unknown"); }
  function agentSort(a, b) {
    const live = Number(isAgentActive(b)) - Number(isAgentActive(a));
    if (live) return live;
    return Number(b.updated_ts || b.ts || b.id || 0) - Number(a.updated_ts || a.ts || a.id || 0);
  }
  function renderAgents() {
    const all = [...S.agentMap.values()].sort(agentSort);
    const running = all.filter(isAgentActive);
    const done = all.length - running.length;
    tabBody.append(el("div", { class: "panel agent-summary" },
      el("div", { class: "row", style: "justify-content:space-between" },
        el("strong", {}, "Agent 实时输出"),
        el("span", { class: "muted" }, `运行中 ${running.length} · 已结束 ${done}`)),
      el("p", { class: "muted", style: "margin:6px 0 0" },
        "这里显示每个 agent 子进程的 stdout/stderr，按 agent 分开，输出会随 opencode/后端 CLI 实时追加。")));
    if (!all.length) { tabBody.append(el("div", { class: "panel empty" }, "暂无 agent 输出。运行开始后这里会出现每个 agent 的实时 stdout/stderr。")); return; }
    const shown = all.slice(0, 80);
    for (const a of shown) {
      const title = `${a.role || "agent"} · ${a.label || ""}`.replace(/\s+$/, "");
      const meta = [
        `#${a.id}`,
        a.model ? `model ${a.model}` : "",
        a.attempt ? `attempt ${a.attempt}` : "",
        a.duration_ms ? `耗时 ${fmtMs(a.duration_ms)}` : "",
        a.retry_in_ms ? `重试等待 ${fmtMs(a.retry_in_ms)}` : "",
        a.updated_ts || a.ts ? `更新 ${fmtClock(a.updated_ts || a.ts)}` : "",
      ].filter(Boolean).join(" · ");
      const out = el("pre", { class: "agent-output" }, a.output || "(暂未收到 stdout/stderr)");
      const card = el("div", { class: "agent-card " + (isAgentActive(a) ? "active" : "") },
        el("div", { class: "agent-head" },
          agentPill(a.status),
          el("span", { class: "agent-title" }, title),
          el("span", { class: "muted" }, meta)),
        el("div", { class: "agent-meta" },
          el("span", {}, a.cwd || ""),
          a.error ? el("span", { class: "agent-error" }, a.error) : null),
        out);
      tabBody.append(card);
      if (isAgentActive(a)) setTimeout(() => { out.scrollTop = out.scrollHeight; }, 0);
    }
  }

  function subtaskRow(t) {
    const meta = [
      (t.lenses || []).length ? (t.lenses || []).join("/") : "",
      t.passes ? `${t.passes} 轮` : "",
      t.candidates ? `候选 ${t.candidates}` : "",
      t.risks ? `风险 ${t.risks}` : "",
    ].filter(Boolean).join(" · ");
    return el("div", { class: "subtask pri-" + cssKey(t.priority || "info") },
      statusBadge(t.status),
      el("span", { class: "sobj" }, t.name || "(未命名子任务)"),
      el("span", { class: "smeta" }, meta));
  }

  function renderCoverage() {
    const c = S.coverage;
    if (!c) { tabBody.append(el("div", { class: "panel empty" }, "暂无覆盖数据(运行开始后会出现攻击面审计进度与拆解的子任务)。")); return; }
    const p = c.progress || { done: 0, clean: 0, total: 0 };
    const pct = p.total ? Math.round(100 * p.done / p.total) : 0;
    tabBody.append(el("div", { class: "panel" },
      el("div", { class: "row", style: "justify-content:space-between" },
        el("strong", {}, `审计覆盖:${p.done}/${p.total} 工作项已完成(其中未发现漏洞 ${p.clean})`),
        el("span", { class: "muted" }, pct + "%")),
      el("div", { class: "bar" }, el("span", { style: `width:${pct}%;background:var(--ok)` }))));

    const ledger = c.ledger || [];
    const regionRecs = ledger.filter(r => r.kind === "region");
    const tasks = ledger.filter(r => r.kind === "task");
    const variants = ledger.filter(r => r.kind === "variant");
    const tasksByRegion = new Map();
    for (const t of tasks) {
      const k = t.region || "(未归类子任务)";
      if (!tasksByRegion.has(k)) tasksByRegion.set(k, []);
      tasksByRegion.get(k).push(t);
    }

    // 攻击面 × 拆解的子任务(region 卡片,内嵌子任务)
    const regionNames = new Set(regionRecs.map(r => r.name));
    if (regionRecs.length || tasks.length) {
      tabBody.append(el("h3", { class: "section-title" }, "攻击面审计进度(区域 → 拆解的子任务)"));
      for (const rg of regionRecs) {
        const subs = tasksByRegion.get(rg.name) || [];
        const card = el("div", { class: "region" },
          el("div", { class: "region-head" },
            rg.priority ? sevPill(PRI_PILL[rg.priority] || "info") : null,
            el("span", { class: "rname" }, rg.name || ""),
            rg.category ? el("span", { class: "tag" }, rg.category) : null,
            statusBadge(rg.status),
            el("span", { class: "rmeta" }, `${subs.length} 个子任务 · 候选 ${rg.candidates || 0} · 风险 ${rg.risks || 0}`)),
          subs.length ? el("div", { class: "subtasks" }, ...subs.map(subtaskRow)) : null);
        tabBody.append(card);
      }
      // 区域记录里没有的 region(兜底:子任务的 region 名不在 region 台账里)
      for (const [rname, subs] of tasksByRegion) {
        if (regionNames.has(rname)) continue;
        tabBody.append(el("div", { class: "region" },
          el("div", { class: "region-head" }, el("span", { class: "rname" }, rname),
            el("span", { class: "rmeta" }, `${subs.length} 个子任务`)),
          el("div", { class: "subtasks" }, ...subs.map(subtaskRow))));
      }
    }

    // 历史模式排查(variant 工作项)
    if (variants.length) {
      tabBody.append(el("h3", { class: "section-title" }, "历史模式同类变体排查"));
      const vt = el("table", {}, el("thead", {}, el("tr", {},
        el("th", {}, "状态"), el("th", {}, "问题模式"), el("th", {}, "出处"), el("th", {}, "轮"), el("th", {}, "候选"))));
      const vtb = el("tbody");
      for (const v of variants) vtb.append(el("tr", {}, el("td", {}, statusBadge(v.status)), el("td", {}, v.name || ""),
        el("td", {}, v.source || "—"), el("td", {}, String(v.passes || 0)), el("td", {}, String(v.candidates || 0))));
      vt.append(vtb);
      tabBody.append(el("div", { class: "panel" }, vt));
    }

    // 审计中动态新增的攻击面
    if ((c.surfaces || []).length) {
      tabBody.append(el("h3", { class: "section-title" }, "审计中动态新增的攻击面"));
      const st = el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "轮"), el("th", {}, "动态新增攻击面"), el("th", {}, "来自"), el("th", {}, "为何可疑"))));
      const stb = el("tbody");
      for (const s of c.surfaces) stb.append(el("tr", {}, el("td", {}, "r" + (s.round || "?")), el("td", {}, s.name || ""), el("td", {}, s.from || ""), el("td", {}, s.why || "")));
      st.append(stb);
      tabBody.append(el("div", { class: "panel" }, st));
    }
  }
  const STATUS_TXT = { "decomposed": "🧩 已拆解", "completed-clean": "✅ 未发现", "completed-findings": "⚠️ 有候选", "in-progress": "🔄 进行中", "incomplete": "⛔ 未审完", "pending": "⏳ 待审" };
  function statusBadge(s) { return el("span", {}, STATUS_TXT[s] || s || "?"); }

  function renderRisks() {
    const list = [...S.risks.values()].sort((a, b) => SEVS.indexOf(a.severity_hint) - SEVS.indexOf(b.severity_hint));
    if (!list.length) { tabBody.append(el("div", { class: "panel empty" }, "暂无风险登记。")); return; }
    const tbl = el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "风险"), el("th", {}, "主题"), el("th", {}, "位置"), el("th", {}, "说明"), el("th", {}, "lens"))));
    const tb = el("tbody");
    for (const r of list) tb.append(el("tr", {}, el("td", {}, sevPill(r.severity_hint)), el("td", {}, r.area || ""), el("td", { class: "loc" }, r.file || "—"), el("td", {}, r.note || ""), el("td", {}, r.lens || "")));
    tbl.append(tb);
    tabBody.append(el("div", { class: "panel" }, tbl));
  }

  const PRI_PILL = { high: "high", medium: "medium", low: "low" };
  function renderRecon() {
    const r = S.recon;
    if (!r) { tabBody.append(el("div", { class: "panel empty" }, "侦察数据加载中…(运行开始后侦察 agent 会产出项目用途、攻击面地图与历史问题模式)")); return; }
    const sec = (t, b) => el("div", { class: "panel" }, el("h3", {}, t), el("div", { class: "md", html: mdToHtml(b || "(无)") }));
    tabBody.append(sec("项目用途", r.purpose), sec("威胁分析", r.threat_summary), sec("仓库知识", r.repo_knowledge));
    if (r.build_hint) tabBody.append(sec("编译提示 build_hint", r.build_hint));

    // 攻击面地图(recon 识别的初始攻击面区域)
    const regions = r.regions || [];
    if (regions.length) {
      tabBody.append(el("h3", { class: "section-title" }, `攻击面地图 · ${regions.length} 个区域`));
      for (const rg of [...regions].sort((a, b) => (({ high: 0, medium: 1, low: 2 })[a.priority] ?? 3) - (({ high: 0, medium: 1, low: 2 })[b.priority] ?? 3))) {
        const card = el("div", { class: "region" },
          el("div", { class: "region-head" },
            sevPill(PRI_PILL[rg.priority] || "info"),
            el("span", { class: "rname" }, rg.name || "(未命名)"),
            el("span", { class: "tag" }, rg.category || "other"),
            rg.trust_boundary ? el("span", { class: "rmeta" }, "信任边界:" + rg.trust_boundary) : null),
          rg.untrusted_input ? el("div", { class: "region-why" }, el("strong", {}, "不可信输入:"), " " + rg.untrusted_input) : null,
          (rg.entry_points || []).length ? el("div", { class: "region-why" }, el("strong", {}, "入口:"), " " + rg.entry_points.join(", ")) : null,
          (rg.crypto_apis || []).length ? el("div", { class: "region-why" }, el("strong", {}, "crypto API:"), " " + rg.crypto_apis.join(", ")) : null,
          (rg.files || []).length ? el("div", { class: "region-files" }, (rg.files || []).join("  ·  ")) : null);
        tabBody.append(card);
      }
    } else {
      tabBody.append(el("div", { class: "panel empty" }, "尚无攻击面区域(侦察未完成或失败)。"));
    }

    // 历史问题模式(同类变体排查种子)
    const hist = r.history || [];
    tabBody.append(el("h3", { class: "section-title" }, `历史问题模式 · ${hist.length} 条`));
    if (hist.length) {
      const tbl = el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "lens"), el("th", {}, "问题模式"), el("th", {}, "出处"), el("th", {}, "相关文件"))));
      const tb = el("tbody");
      for (const h of hist) tb.append(el("tr", {},
        el("td", {}, el("span", { class: "tag" }, h.lens_hint || "—")),
        el("td", {}, h.pattern || ""),
        el("td", {}, h.source || "—"),
        el("td", { class: "loc" }, (h.files || []).join(", ") || "—")));
      tbl.append(tb);
      tabBody.append(el("div", { class: "panel" }, tbl,
        el("p", { class: "muted", style: "margin:8px 0 0" }, "每条历史模式会作为「同类变体排查」种子,派 agent 在全仓搜索同类代码模式。")));
    } else {
      tabBody.append(el("div", { class: "panel empty" }, "未提取到历史问题模式。"));
    }
  }

  function renderUsage() {
    const rows = [...S.usageRows].slice(-80).reverse();
    if (!rows.length) { tabBody.append(el("div", { class: "panel empty" }, "暂无 token 用量数据。")); return; }
    const tbl = el("table", {}, el("thead", {}, el("tr", {},
      el("th", {}, "#"), el("th", {}, "role"), el("th", {}, "模型"), el("th", {}, "输入"), el("th", {}, "输出"), el("th", {}, "总计"), el("th", {}, "来源"))));
    const tb = el("tbody");
    for (const u of rows) tb.append(el("tr", {},
      el("td", {}, String(u.id || "")), el("td", {}, u.label || u.role || ""), el("td", {}, u.model || ""),
      el("td", {}, fmtNum(u.input_tokens)), el("td", {}, fmtNum(u.output_tokens)), el("td", {}, fmtNum(u.total_tokens)),
      el("td", {}, u.estimated ? "估算" : "后端")));
    tbl.append(tb);
    tabBody.append(el("div", { class: "panel" }, el("h3", {}, "Token 使用(最近 80 次 agent 调用)"), tbl));
  }

  function renderActivity() {
    tabBody.append(el("div", { class: "panel" }, el("div", { class: "log" }, S.log.join("\n") || "(暂无日志)")));
  }

  function renderExports() {
    const base = `/api/runs/${encodeURIComponent(runId)}/export`;
    const allBtn = el("button", { class: "btn secondary" }, "导出全部到 run 目录");
    allBtn.addEventListener("click", async () => { try { const r = await api("POST", base + "/all"); flash("已导出 " + r.files.length + " 个文件到 " + r.dir); } catch (e) { flash(e.message); } });
    tabBody.append(el("div", { class: "panel" },
      el("h3", {}, "导出"),
      el("div", { class: "row" },
        el("a", { class: "btn secondary", href: base + "/sarif", target: "_blank" }, "REPORT.sarif"),
        el("a", { class: "btn secondary", href: base + "/index.md", target: "_blank" }, "INDEX.md"),
        allBtn),
      el("p", { class: "muted", style: "margin-top:8px" }, "Markdown / SARIF 由结构化结果按需渲染。")));
  }

  // ── SSE 驱动 ──
  function applyAgentUpdate(d) {
    const id = String(d.id || "");
    if (!id) return;
    const now = Date.now() / 1000;
    const a = S.agentMap.get(id) || { id, status: "queued", output: "", stdout_chars: 0, stderr_chars: 0, created_ts: d.ts || now };
    if (d.status === "output") {
      const chunk = String(d.chunk == null ? "" : d.chunk);
      a.output += chunk;
      if (d.stream === "stderr") a.stderr_chars += chunk.length;
      else a.stdout_chars += chunk.length;
      a.model = d.model || a.model;
      a.attempt = d.attempt || a.attempt;
      a.updated_ts = d.ts || now;
      if (!a.status || a.status === "queued") a.status = "running";
    } else {
      for (const [k, v] of Object.entries(d)) {
        if (k !== "chunk") a[k] = v;
      }
      a.updated_ts = d.ts || now;
    }
    S.agentMap.set(id, a);
  }
  function applyEvent(ev) {
    const d = ev.data || {};
    switch (ev.type) {
      case "run_status": S.status = d.status; renderHeader(); break;
      case "metrics": S.agents = d.agents_spawned ?? S.agents; S.elapsed = d.elapsed_s ?? S.elapsed; S.candidates = d.candidates ?? S.candidates; if (d.token_usage) setUsage(S.usage, d.token_usage); renderHeader(); break;
      case "usage": S.usageRows.push(d); addUsage(S.usage, d); renderHeader(); renderTabs(); if (activeTab === "usage") renderTab(); break;
      case "agent_update": applyAgentUpdate(d); renderTabs(); if (activeTab === "agents") renderTab(); break;
      case "candidate_found": S.candidates++; renderHeader(); break;
      case "finding_confirmed":
        if (d.id && !S.findings.has(d.id)) { S.findings.set(d.id, d); flash("✔ 确认漏洞 " + d.id + " [" + d.corrected_severity + "]"); }
        else if (d.id) S.findings.set(d.id, d);
        renderHeader(); renderTabs(); if (activeTab === "findings") renderTab(); break;
      case "risk_added": { const k = (d.area || "") + "::" + (d.file || ""); S.risks.set(k, d); renderHeader(); renderTabs(); if (activeTab === "risks") renderTab(); break; }
      case "surface_added": case "coverage_update":
        if (ev.type === "coverage_update") S.coverage = Object.assign({}, S.coverage, d);
        if (activeTab === "coverage") renderTab(); break;
      case "round_start": S.round = d.round; renderHeader(); break;
      case "round_done": S.round = d.round; S.dry = d.dry_streak; renderHeader(); break;
      case "recon_done": if (d.purpose != null || d.threat_summary != null) { S.recon = Object.assign({}, S.recon, d); } fetchRecon(); break;
      case "run_done": S.status = "done"; renderHeader(); break;
      case "model_health": if (d.model) { S.health.set(d.model, d); renderTabs(); if (activeTab === "health") renderTab(); } break;
      case "health_check_start": if (Array.isArray(d.models)) for (const m of d.models) if (!S.health.has(m)) S.health.set(m, { model: m, status: "checking" }); renderTabs(); if (activeTab === "health") renderTab(); break;
      case "health_check_done": flash(`🩺 健康检查:${d.ok}/${d.total} 正常` + ((d.unhealthy || []).length ? `,异常 ${d.unhealthy.join(", ")}` : "")); if (activeTab === "health") renderTab(); break;
      case "log": S.log.push(d.message); if (S.log.length > 600) S.log.shift(); if (activeTab === "activity") renderTab(); break;
    }
  }
  async function fetchRecon() { try { S.recon = await api("GET", `/api/runs/${encodeURIComponent(runId)}/recon`); if (activeTab === "recon") renderTab(); } catch (e) {} }
  async function fetchCoverage() { try { const c = await api("GET", `/api/runs/${encodeURIComponent(runId)}/coverage`); if (c) { S.coverage = Object.assign({}, S.coverage, c); if (activeTab === "coverage") renderTab(); } } catch (e) {} }
  async function fetchRisks() { try { const list = await api("GET", `/api/runs/${encodeURIComponent(runId)}/risks`); for (const r of (list || [])) { const k = (r.area || "") + "::" + (r.file || ""); if (!S.risks.has(k)) S.risks.set(k, r); } renderHeader(); renderTabs(); if (activeTab === "risks") renderTab(); } catch (e) {} }
  async function fetchHealth() { try { const h = await api("GET", `/api/runs/${encodeURIComponent(runId)}/health`); for (const r of (h.models || [])) if (r.model) S.health.set(r.model, r); renderTabs(); if (activeTab === "health") renderTab(); } catch (e) {} }

  async function boot() {
    try { S.manifest = await api("GET", `/api/runs/${encodeURIComponent(runId)}`); S.status = S.manifest.running ? "running" : S.manifest.status; } catch (e) {}
    renderHeader(); renderTabs(); renderTab();
    fetchRecon(); fetchHealth(); fetchCoverage(); fetchRisks();
    // SSE:从 seq 0 重放历史事件(重建 findings/coverage/risks/log)再接实时;EventSource 断线自动带 Last-Event-ID 续传
    const es = new EventSource(`/api/runs/${encodeURIComponent(runId)}/events`);
    window._es = es;
    const TYPES = ["run_status", "metrics", "usage", "agent_update", "candidate_found", "finding_confirmed", "risk_added", "surface_added", "coverage_update", "round_start", "round_done", "recon_done", "run_done", "log", "decompose_done", "poc_done", "error", "model_health", "health_check_start", "health_check_done"];
    for (const t of TYPES) es.addEventListener(t, (e) => { try { applyEvent(JSON.parse(e.data)); } catch (_) {} });
    es.onerror = () => { /* EventSource 自动重连 */ };
  }
  boot();
}
