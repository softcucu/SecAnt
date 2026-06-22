"use strict";
// ──────────────────────── helpers ────────────────────────
const app = document.getElementById("app");
const SEVS = ["critical", "high", "medium", "low", "info"];
const RELATED_CANDIDATE_RENDER_LIMIT = 80;
const FINDING_FEEDBACK_OPTIONS = [
  ["unreviewed", "未确认"],
  ["confirmed", "确认漏洞"],
  ["false_positive", "误报"],
  ["needs_review", "待复核"],
];
const FINDING_SOURCE_OPTIONS = [
  ["history", "历史问题排查"],
  ["risk", "潜在风险点审计"],
  ["coverage", "攻击面覆盖审计"],
];
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
function fmtPct(num, den) { if (!den) return "0%"; const v = (num / den) * 100; return `${v >= 10 ? v.toFixed(1) : v.toFixed(2)}%`; }
function fmtMs(ms) { ms = Number(ms || 0); if (!ms) return "—"; return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(ms < 10000 ? 1 : 0)}s`; }
function fmtTps(v) { const n = Number(v || 0); if (!Number.isFinite(n) || n <= 0) return "—"; return `${n >= 10 ? Math.round(n) : n.toFixed(1)} tok/s`; }
function sevPill(s) { return el("span", { class: "pill sev-" + (s || "none") }, s || "none"); }
function stPill(s) { return el("span", { class: "pill st-" + (s || "queued") }, s || "queued"); }
function tokenCount(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : 0;
}
function fmtNum(n) { return tokenCount(n).toLocaleString(); }
function fmtTok(n) {
  n = tokenCount(n);
  if (n >= 1e6) return (n / 1e6).toFixed(n < 1e7 ? 2 : 1) + "M";
  if (n >= 1e4) return (n / 1e3).toFixed(n < 1e5 ? 1 : 0) + "K";
  return n.toLocaleString();
}
function cssKey(s) { return String(s || "unknown").replace(/[^a-z0-9-]+/gi, "-").toLowerCase(); }
function findingFeedbackStatus(f) { return (f && f.manual_feedback && f.manual_feedback.status) || "unreviewed"; }
function modelText(v) { return Array.isArray(v) ? v.join(", ") : (v || ""); }
function splitModels(v) { return String(v || "").split(",").map(s => s.trim()).filter(Boolean); }
function kvText(obj) { return Object.entries(obj || {}).map(([k, v]) => `${k}=${v}`).join(", "); }
function modelWindowsText(obj) {
  return Object.entries(obj || {}).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : v}`).join("\n");
}
function shortJson(v, max = 420) {
  let s;
  try { s = typeof v === "string" ? v : JSON.stringify(v, null, 2); }
  catch (_) { s = String(v); }
  if (s == null) return "";
  s = String(s);
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}
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
function parseModelWindows(v) {
  const out = {};
  for (const rawLine of String(v || "").split(/\n+/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const i = line.indexOf("=");
    if (i < 1) continue;
    const model = line.slice(0, i).trim();
    const windows = line.slice(i + 1).split("|").map(s => s.trim()).filter(Boolean);
    if (model && windows.length) out[model] = windows.length === 1 ? windows[0] : windows;
  }
  return out;
}
function emptyUsage() { return { calls: 0, input_tokens: 0, output_tokens: 0, total_tokens: 0, estimated_calls: 0 }; }
function cleanUsage(rec) {
  const input = tokenCount(rec?.input_tokens);
  const output = tokenCount(rec?.output_tokens);
  const total = Math.max(tokenCount(rec?.total_tokens), input + output);
  return Object.assign({}, rec || {}, { input_tokens: input, output_tokens: output, total_tokens: total });
}
function addUsage(total, rec) {
  rec = cleanUsage(rec);
  total.calls += 1;
  total.input_tokens += rec.input_tokens;
  total.output_tokens += rec.output_tokens;
  total.total_tokens += rec.total_tokens;
  if (rec.estimated) total.estimated_calls += 1;
}
function setUsage(total, src) {
  const rec = cleanUsage(src);
  total.calls = tokenCount(src?.calls);
  total.input_tokens = rec.input_tokens;
  total.output_tokens = rec.output_tokens;
  total.total_tokens = rec.total_tokens;
  total.estimated_calls = tokenCount(src?.estimated_calls);
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
  const tbl = el("table", { class: "data-table run-table" }, el("thead", {}, el("tr", {},
    el("th", {}, "状态"), el("th", {}, "目标"), el("th", {}, "模式"), el("th", {}, "后端"),
    el("th", {}, "确认"), el("th", {}, "轮数"), el("th", {}, "创建时间"), el("th", {}, ""))));
  const tb = el("tbody");
  for (const r of runs) {
    const s = r.summary || {};
    tb.append(el("tr", {},
      el("td", {}, stPill(r.running ? "running" : r.status)),
      el("td", { html: `<a href="#/run/${encodeURIComponent(r.id)}">${esc(r.target || r.id)}</a>` + (r.scope ? `<div class="muted" style="font-size:12px">${esc(r.scope)}</div>` : "")}),
      el("td", {}, r.run_mode === "history_only" ? "仅历史" : "完整"),
      el("td", {}, r.backend || "—"),
      el("td", {}, String(s.confirmed ?? 0)),
      el("td", {}, String(s.rounds ?? 0)),
      el("td", {}, fmtTs(r.created_at)),
      el("td", { html: `<a href="#/run/${encodeURIComponent(r.id)}">查看 →</a>` })));
  }
  tbl.append(tb);
  app.append(el("div", { class: "panel" }, el("div", { class: "table-wrap" }, tbl)));
}

// ──────────────────────── view: new run ────────────────────────
async function viewNew() {
  app.innerHTML = "";
  let meta;
  let runs = [];
  try { meta = await api("GET", "/api/meta"); } catch (e) { app.append(el("div", { class: "empty" }, "加载失败: " + e.message)); return; }
  try { runs = await api("GET", "/api/runs"); } catch (_) { runs = []; }
  const d = meta.defaults;
  const f = (label, node) => el("label", { class: "field" }, el("span", {}, label), node);
  const inp = (id, val, type = "text") => el("input", { id, type, value: val == null ? "" : val });
  const area = (id, val, rows = 3) => el("textarea", { id, rows }, val == null ? "" : val);
  const num = (id, val) => inp(id, val, "number");

  const runModeSel = el("select", { id: "run_mode" },
    el("option", { value: "full", selected: (d.run_mode || "full") === "full" ? "" : null }, "完整审计"),
    el("option", { value: "history_only", selected: d.run_mode === "history_only" ? "" : null }, "仅历史漏洞排查"));
  const backendSel = el("select", { id: "backend" }, ...meta.backends.map(b => el("option", { value: b, selected: b === d.backend ? "" : null }, b)));
  const tmSel = el("select", { id: "threat_model" }, ...["REMOTE", "LOCAL_UNPRIVILEGED", "BOTH"].map(t => el("option", { value: t, selected: t === d.threat_model ? "" : null }, t)));
  const lensChecks = el("div", { class: "checks" }, ...meta.lenses.map(l =>
    el("label", {}, el("input", { type: "checkbox", value: l, class: "lens", checked: (d.lenses || []).includes(l) ? "" : null }), l)));
  const modelRoles = meta.roles.filter(role => role !== "synthesis" && role !== "util");
  // history_only 模式只用 recheck/verify/report(+可选 history/poc),其余角色与攻击面相关配置无关
  const HISTORY_ONLY_HIDDEN_ROLES = new Set(["recon", "audit", "decompose"]);
  const modelFieldByRole = {};
  modelRoles.forEach(role => {
    modelFieldByRole[role] = f("模型 · " + role, inp("model_" + role, modelText((d.models || {})[role]), "text"));
  });
  const modelRows = el("div", { class: "grid" }, ...modelRoles.map(role => modelFieldByRole[role]));
  const historyRuns = runs.filter(r => (r.history_count || 0) > 0);
  const historyRunSel = el("select", { id: "history_import_run_id" },
    el("option", { value: "" }, "不导入,重新分析 git commits"),
    ...historyRuns.map(r => el("option", { value: r.id },
      `${r.id} · 历史 ${r.history_count || 0} · ${r.target || ""}`)));
  const historyImportBox = el("div", { id: "history_import_box" },
    f("导入已有历史模式 run", historyRunSel),
    f("或导入 run 目录 / recon.json", inp("history_import_from", d.history_import_from || "", "text")));

  const lensField = el("label", { class: "field" }, el("span", {}, "lens(攻击面镜头)"), lensChecks);
  const findersField = f("每 lens finder 数", num("finders_per_lens", d.finders_per_lens));
  const decomposeLabel = el("label", {}, el("input", { type: "checkbox", id: "decompose", checked: d.decompose ? "" : null }), "区域拆解");
  const left = el("div", {},
    f("目标源码根目录 *", inp("target", "")),
    f("子路径 scope(可选)", inp("scope", "")),
    f("运行模式", runModeSel),
    historyImportBox,
    f("后端 CLI", backendSel),
    f("并发数", num("concurrency", d.concurrency)),
    f("威胁模型", tmSel),
    lensField,
  );
  const right = el("div", {},
    findersField,
    f("最大轮数 max_rounds", num("max_rounds", d.max_rounds)),
    f("收敛空轮 dry_rounds", num("dry_rounds", d.dry_rounds)),
    f("兼容参数 verify_votes", num("verify_votes", d.verify_votes)),
    el("div", { class: "checks", style: "margin:8px 0 14px" },
      el("label", {}, el("input", { type: "checkbox", id: "enable_poc", checked: d.enable_poc ? "" : null }), "启用 PoC"),
      decomposeLabel),
    el("div", { class: "panel", style: "padding:10px" },
      el("div", { class: "muted", style: "margin-bottom:6px" }, "每角色模型(运行中的角色必须填写)"),
      modelRows,
      f("模型并发 model=limit", inp("model_concurrency", kvText(d.model_concurrency), "text")),
      f("模型可用时间段 model=00:00~06:00", area("model_time_windows", modelWindowsText(d.model_time_windows), 4))),
  );

  const submit = el("button", { class: "btn" }, "🚀 启动审计");
  function syncRunMode() {
    const historyOnly = runModeSel.value === "history_only";
    historyImportBox.style.display = historyOnly ? "" : "none";
    // 仅历史模式下隐藏攻击面相关配置(lens / finder 数 / 区域拆解)及不参与的模型角色
    lensField.style.display = historyOnly ? "none" : "";
    findersField.style.display = historyOnly ? "none" : "";
    decomposeLabel.style.display = historyOnly ? "none" : "";
    modelRoles.forEach(role => {
      modelFieldByRole[role].style.display = (historyOnly && HISTORY_ONLY_HIDDEN_ROLES.has(role)) ? "none" : "";
    });
    submit.textContent = historyOnly ? "启动历史排查" : "🚀 启动审计";
  }
  runModeSel.addEventListener("change", syncRunMode);
  syncRunMode();
  submit.addEventListener("click", async () => {
    const target = document.getElementById("target").value.trim();
    if (!target) { flash("请填写目标目录"); return; }
    const models = {};
    for (const role of modelRoles) {
      const vals = splitModels(document.getElementById("model_" + role).value);
      if (vals.length) models[role] = vals;
    }
    const lenses = [...document.querySelectorAll(".lens:checked")].map(c => c.value);
    const payload = {
      target, scope: document.getElementById("scope").value.trim(),
      backend: document.getElementById("backend").value, concurrency: +document.getElementById("concurrency").value,
      run_mode: document.getElementById("run_mode").value,
      threat_model: document.getElementById("threat_model").value, lenses,
      finders_per_lens: +document.getElementById("finders_per_lens").value, max_rounds: +document.getElementById("max_rounds").value,
      dry_rounds: +document.getElementById("dry_rounds").value, verify_votes: +document.getElementById("verify_votes").value,
      enable_poc: document.getElementById("enable_poc").checked, decompose: document.getElementById("decompose").checked,
      models, model_concurrency: parseKvInts(document.getElementById("model_concurrency").value),
      model_time_windows: parseModelWindows(document.getElementById("model_time_windows").value),
    };
    const importRunId = document.getElementById("history_import_run_id").value;
    const importPath = document.getElementById("history_import_from").value.trim();
    if (payload.run_mode === "history_only" && importRunId) payload.history_import_run_id = importRunId;
    else if (payload.run_mode === "history_only" && importPath) payload.history_import_from = importPath;
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
  const S = { findings: new Map(), risks: new Map(), health: new Map(), agentMap: new Map(), candidateMap: new Map(), nonIssueMap: new Map(), coverage: null, recon: null, log: [], usageRows: [], usageIds: new Set(), usage: emptyUsage(), manifest: null, meta: null, candidates: 0, candidateTotal: 0, nonIssueTotal: 0, usageTotal: 0, riskTotal: 0, status: "queued", round: 0, dry: 0, agents: 0, elapsed: 0 };
  let activeTab = "findings";
  let initialModeTabApplied = false;
  const nonIssueOpenKeys = new Set();
  let tabRenderTimer = null;
  let pendingFocus = null;
  // 大列表分页:每页只建一页 DOM,切页签与 SSE 重渲都只重建当页,与总量无关。
  const PAGE_SIZE = { findings: 40, candidates: 100, nonissues: 40, history: 50, risks: 50 };
  const pageState = { findings: 1, candidates: 1, nonissues: 1, history: 1, risks: 1 };
  let findingAuditModelFilter = "all"; // 漏洞页按审计模型筛选
  let findingSourceFilter = "all";      // 漏洞页按来源筛选
  let findingFeedbackFilter = "all";   // 漏洞页按人工确认状态筛选
  let candStatusFilter = "all";   // 候选页按状态筛选
  let histStatusFilter = "all";   // 历史问题页按排查状态筛选
  let riskStatusFilter = "all";   // 风险页按排查状态筛选
  function clampPage(p, total) { return Math.min(Math.max(1, p | 0 || 1), Math.max(1, total)); }
  // 返回当前页应渲染的切片;若 pendingFocus 命中某条,则翻到它所在页。
  function paginate(tabKey, list, focusIndex = -1) {
    const size = PAGE_SIZE[tabKey] || 50;
    const pages = Math.max(1, Math.ceil(list.length / size));
    let page = pageState[tabKey] || 1;
    if (focusIndex >= 0) page = Math.floor(focusIndex / size) + 1;
    page = clampPage(page, pages);
    pageState[tabKey] = page;
    const start = (page - 1) * size;
    return { items: list.slice(start, start + size), page, pages, size, total: list.length, start };
  }
  function pagerBar(tabKey, info) {
    if (info.pages <= 1) return null;
    const go = (p) => {
      pageState[tabKey] = clampPage(p, info.pages);
      renderTab();
      tabBody.scrollIntoView({ block: "start", behavior: "smooth" });
    };
    const prev = el("button", { type: "button", class: "btn secondary", disabled: info.page <= 1 ? "" : null, onclick: () => go(info.page - 1) }, "← 上一页");
    const next = el("button", { type: "button", class: "btn secondary", disabled: info.page >= info.pages ? "" : null, onclick: () => go(info.page + 1) }, "下一页 →");
    const label = el("span", { class: "muted" },
      `第 ${info.page}/${info.pages} 页 · 显示 ${info.start + 1}–${info.start + info.items.length} / 共 ${info.total}`);
    return el("div", { class: "pager row", style: "justify-content:space-between;align-items:center;margin:8px 0" },
      prev, label, next);
  }
  let agentOutputMode = localStorage.getItem("pvh.agentOutputMode") === "raw" ? "raw" : "pretty";
  const agentGroupStoreKey = `pvh.agentGroupsCollapsed:${runId}`;
  const agentOutputStoreKey = `pvh.agentOutputsExpanded:${runId}`;
  let collapsedAgentGroups = loadLocalSet(agentGroupStoreKey);
  let expandedAgentOutputs = loadLocalSet(agentOutputStoreKey);
  let candidatesLoaded = false;
  let candidatesLoading = null;
  let usageLoaded = false;
  let usageLoading = null;
  let elapsedBase = 0;
  let elapsedBaseAt = Date.now();
  // 候选列表缓存:仅在新增/清空候选时失效,渲染期间复用同一数组,
  // 避免 renderHistory/renderRisks/renderCoverage 每行都 [...S.candidateMap.values()]。
  let candListCache = null;
  function candidateList() { return candListCache || (candListCache = [...S.candidateMap.values()]); }
  function invalidateCandIndex() { candListCache = null; }

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
  async function resume() { try { const r = await api("POST", `/api/runs/${encodeURIComponent(runId)}/resume`); flash(r.ok ? "已续跑" : "无法续跑(可能正在运行)"); if (r.ok) boot(); } catch (e) { flash(e.message); } }

  function finiteNumber(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }
  function isRunClockActive(status = S.status) {
    return status === "queued" || status === "running";
  }
  function currentElapsed() {
    if (!isRunClockActive()) return finiteNumber(S.elapsed) || 0;
    return Math.max(finiteNumber(S.elapsed) || 0, elapsedBase + (Date.now() - elapsedBaseAt) / 1000);
  }
  function runConfig() { return (S.manifest && S.manifest.config) || {}; }
  function isHistoryOnly() { return runConfig().run_mode === "history_only"; }
  function historyVariantLedger() {
    return (((S.coverage || {}).ledger || []).filter(r => r.kind === "variant"));
  }
  function historyModeStats() {
    const hist = (S.recon || {}).history || [];
    const variants = historyVariantLedger();
    const counts = {};
    for (const v of variants) counts[v.status || "pending"] = (counts[v.status || "pending"] || 0) + 1;
    const completedClean = counts["completed-clean"] || 0;
    const completedFindings = counts["completed-findings"] || 0;
    const failed = (counts.incomplete || 0) + (counts.abandoned || 0);
    const running = counts["in-progress"] || 0;
    const pending = (counts.pending || 0) + Math.max(0, hist.length - variants.length);
    const total = Math.max(hist.length, variants.length);
    return {
      total,
      pending,
      running,
      completed: completedClean + completedFindings,
      clean: completedClean,
      hits: completedFindings,
      failed,
    };
  }
  function resetElapsedClock(seconds) {
    const n = finiteNumber(seconds);
    S.elapsed = Math.max(0, n == null ? (finiteNumber(S.elapsed) || 0) : n);
    elapsedBase = S.elapsed;
    elapsedBaseAt = Date.now();
  }
  function applyMetrics(d) {
    if (!d) return;
    const agents = finiteNumber(d.agents_spawned);
    if (agents != null) S.agents = Math.max(S.agents || 0, agents);
    const elapsed = finiteNumber(d.elapsed_s);
    if (elapsed != null) resetElapsedClock(elapsed);
    if (d.candidates != null) {
      S.candidates = d.candidates;
      S.candidateTotal = Math.max(S.candidateTotal || 0, tokenCount(d.candidates));
    }
    if (d.risks != null) S.riskTotal = Math.max(S.riskTotal || 0, tokenCount(d.risks));
    if (d.token_usage) setUsage(S.usage, d.token_usage);
  }
  function setRunStatus(status) {
    if (!status) return;
    const wasActive = isRunClockActive();
    const nextActive = isRunClockActive(status);
    if (wasActive && !nextActive) S.elapsed = currentElapsed();
    S.status = status;
    resetElapsedClock(S.elapsed);
  }

  function renderHeader() {
    const bySev = {}; for (const f of S.findings.values()) bySev[f.corrected_severity] = (bySev[f.corrected_severity] || 0) + 1;
    const suspectedCount = S.findings.size;
    const manualConfirmed = [...S.findings.values()].filter(f => findingFeedbackStatus(f) === "confirmed").length;
    header.innerHTML = "";
    const cfg = runConfig();
    const agentCount = Math.max(S.agents || 0, S.agentMap.size, S.usageRows.length);
    const elapsed = Math.round(currentElapsed());
    if (isHistoryOnly()) {
      const hs = historyModeStats();
      const source = cfg.history_import_from ? `导入 ${cfg.history_import_from}` : "git commit";
      header.append(el("div", { class: "row", style: "justify-content:space-between;margin-bottom:10px" },
        el("div", { class: "row" }, stPill(S.status),
          el("span", { class: "muted" }, `${esc(cfg.target || "")}${cfg.scope ? " · " + esc(cfg.scope) : ""}`),
          el("span", { class: "muted" }, `仅历史漏洞排查 · ${esc(source)} · 后端 ${esc(cfg.backend || "?")}`)),
        el("div", { class: "muted" }, `排查 ${hs.completed}/${hs.total || "?"} · 用时 ${elapsed}s`)));
      header.append(el("div", { class: "stats history-stats" },
        el("div", { class: "stat" }, el("div", { class: "n" }, String(hs.total)), el("div", { class: "l" }, "历史模式")),
        el("div", { class: "stat" }, el("div", { class: "n" }, String(hs.completed)), el("div", { class: "l" }, "已排查")),
        el("div", { class: "stat" }, el("div", { class: "n" }, String(hs.hits)), el("div", { class: "l" }, "命中模式")),
        el("div", { class: "stat" }, el("div", { class: "n" }, String(hs.failed)), el("div", { class: "l" }, "失败/未覆盖")),
        el("div", { class: "stat" }, el("div", { class: "n" }, String(S.candidates)), el("div", { class: "l" }, "候选")),
        el("div", { class: "stat" }, el("div", { class: "n" }, String(S.findings.size)), el("div", { class: "l" }, "确认漏洞")),
        el("div", { class: "stat" }, el("div", { class: "n" }, String(agentCount)), el("div", { class: "l" }, "agent 调用")),
        el("div", { class: "stat" }, el("div", { class: "n" }, fmtTok(S.usage.total_tokens)), el("div", { class: "l" }, "总 token"))));
      return;
    }
    header.append(el("div", { class: "row", style: "justify-content:space-between;margin-bottom:10px" },
      el("div", { class: "row" }, stPill(S.status),
        el("span", { class: "muted" }, `${esc(cfg.target || "")}${cfg.scope ? " · " + esc(cfg.scope) : ""}`),
        el("span", { class: "muted" }, `模式 ${cfg.run_mode === "history_only" ? "仅历史" : "完整"} · 后端 ${esc(cfg.backend || "?")} · 威胁 ${esc(cfg.threat_model || "?")}`)),
      el("div", { class: "muted" }, `轮 ${S.round}/${cfg.max_rounds ?? "?"} · dry ${S.dry} · 用时 ${elapsed}s`)));
    const stats = el("div", { class: "stats" },
      el("div", { class: "stat" }, el("div", { class: "n" }, String(suspectedCount)), el("div", { class: "l" }, "疑似漏洞")),
      el("div", { class: "stat" }, el("div", { class: "n" }, String(manualConfirmed)), el("div", { class: "l" }, "确认漏洞")),
      el("div", { class: "stat" }, el("div", { class: "n" }, fmtPct(manualConfirmed, suspectedCount)), el("div", { class: "l" }, "准确率")),
      ...SEVS.map(s => el("div", { class: "stat" }, el("div", { class: "n", style: "color:var(--" + (s === "critical" ? "crit" : s === "high" ? "high" : s === "medium" ? "med" : s === "low" ? "low" : "info") + ")" }, String(bySev[s] || 0)), el("div", { class: "l" }, s))),
      el("div", { class: "stat" }, el("div", { class: "n" }, String(S.candidates)), el("div", { class: "l" }, "候选")),
      el("div", { class: "stat" }, el("div", { class: "n" }, String(S.risks.size)), el("div", { class: "l" }, "风险登记")),
      el("div", { class: "stat" }, el("div", { class: "n" }, String(agentCount)), el("div", { class: "l" }, "agent 调用")),
      el("div", { class: "stat" }, el("div", { class: "n" }, fmtTok(S.usage.input_tokens)), el("div", { class: "l" }, "输入 token")),
      el("div", { class: "stat" }, el("div", { class: "n" }, fmtTok(S.usage.output_tokens)), el("div", { class: "l" }, "输出 token")),
      el("div", { class: "stat" }, el("div", { class: "n" }, fmtTok(S.usage.total_tokens)), el("div", { class: "l" }, "总 token")));
    header.append(stats);
  }

  const FULL_TABS = [["findings", "漏洞"], ["candidates", "候选"], ["nonissues", "非问题"], ["agents", "实时Agent"], ["health", "模型"], ["coverage", "攻击面覆盖"], ["history", "历史问题"], ["risks", "潜在风险点"], ["usage", "历史任务"], ["recon", "侦察"], ["activity", "活动"], ["exports", "导出"]];
  function visibleTabs() {
    if (!isHistoryOnly()) return FULL_TABS;
    const tabs = [["coverage", "排查进度"], ["history", "历史模式"], ["findings", "漏洞"], ["candidates", "候选"], ["nonissues", "非问题"], ["agents", "实时Agent"], ["health", "模型"]];
    if ((S.riskTotal || 0) > 0 || S.risks.size) tabs.push(["risks", "风险线索"]);
    tabs.push(["usage", "调用记录"], ["activity", "活动"], ["exports", "导出"]);
    return tabs;
  }
  function renderTabs() {
    tabsBar.innerHTML = "";
    const tabs = visibleTabs();
    if (!tabs.some(([key]) => key === activeTab)) activeTab = tabs[0][0];
    const activeAgents = [...S.agentMap.values()].filter(a => isAgentActive(a) && isVisibleAgentCategory(agentCategory(a))).length;
    const counts = {
      findings: S.findings.size,
      candidates: Math.max(S.candidateTotal || 0, S.candidateMap.size),
      nonissues: Math.max(S.nonIssueTotal || 0, S.nonIssueMap.size),
      risks: Math.max(S.riskTotal || 0, S.risks.size),
      usage: Math.max(S.usageTotal || 0, S.usageRows.length),
      health: S.health.size,
      agents: activeAgents,
      history: (S.recon?.history || []).length,
      coverage: isHistoryOnly() ? historyModeStats().total : 0,
    };
    for (const [key, label] of tabs) {
      const t = el("div", { class: "tab" + (key === activeTab ? " active" : "") }, label);
      if (counts[key]) t.append(el("span", { class: "tabcount" }, String(counts[key])));
      t.addEventListener("click", () => { activeTab = key; renderTabs(); renderTab(); });
      tabsBar.append(t);
    }
  }

  function renderTab() {
    if (tabRenderTimer) {
      clearTimeout(tabRenderTimer);
      tabRenderTimer = null;
    }
    tabBody.innerHTML = "";
    let rendered;
    if (activeTab === "findings") rendered = renderFindings();
    else if (activeTab === "candidates") rendered = renderCandidates();
    else if (activeTab === "nonissues") rendered = renderNonIssues();
    else if (activeTab === "agents") rendered = renderAgents();
    else if (activeTab === "health") rendered = renderModels();
    else if (activeTab === "coverage") rendered = renderCoverage();
    else if (activeTab === "history") rendered = renderHistory();
    else if (activeTab === "risks") rendered = renderRisks();
    else if (activeTab === "usage") rendered = renderUsage();
    else if (activeTab === "recon") rendered = renderRecon();
    else if (activeTab === "activity") rendered = renderActivity();
    else if (activeTab === "exports") rendered = renderExports();
    requestAnimationFrame(applyPendingFocus);
    return rendered;
  }
  function scheduleRenderTab(delay = 120) {
    if (tabRenderTimer) return;
    tabRenderTimer = setTimeout(() => {
      tabRenderTimer = null;
      renderTab();
    }, delay);
  }
  // agent_update 在流式输出时频率极高(每个 chunk 一次),合并到 ~150ms 一帧统一刷新,
  // 避免 header/tabs/tab 被逐 token 全量重建造成持续卡顿。
  let agentRefreshTimer = null;
  function scheduleAgentRefresh(delay = 150) {
    if (agentRefreshTimer) return;
    agentRefreshTimer = setTimeout(() => {
      agentRefreshTimer = null;
      renderHeader();
      renderTabs();
      if (activeTab === "agents" || activeTab === "health") renderTab();
    }, delay);
  }
  function showTab(key, focus = null) {
    activeTab = key;
    pendingFocus = focus;
    renderTabs();
    renderTab();
  }
  function findByData(name, value) {
    if (!value) return null;
    for (const n of tabBody.querySelectorAll(`[data-${name}]`)) {
      if (n.getAttribute(`data-${name}`) === String(value)) return n;
    }
    return null;
  }
  function highlightNode(node) {
    if (!node) return;
    for (const n of tabBody.querySelectorAll(".target-hit")) n.classList.remove("target-hit");
    node.classList.add("target-hit");
    node.scrollIntoView({ block: "center", behavior: "smooth" });
    setTimeout(() => node.classList.remove("target-hit"), 2600);
  }
  function applyPendingFocus() {
    if (!pendingFocus) return;
    const focus = pendingFocus;
    pendingFocus = null;
    let node = null;
    if (focus.type === "finding") {
      node = findByData("finding-id", focus.id);
      if (node && !node.classList.contains("open")) {
        const head = node.querySelector(".head");
        if (head) head.click();
      }
    } else if (focus.type === "candidate") {
      node = findByData("cand-key", focus.key);
    }
    highlightNode(node);
  }
  function jumpToFinding(fid) {
    if (!fid) return;
    showTab("findings", { type: "finding", id: fid });
  }
  function jumpToNonIssue(key) {
    if (!key) return;
    nonIssueOpenKeys.add(key);
    showTab("nonissues", { type: "candidate", key });
  }
  function jumpToCandidate(c) {
    if (!c) return;
    if (c.status === "confirmed" && c.id) return jumpToFinding(c.id);
    if (c.status === "rejected") return jumpToNonIssue(c.key || candKeyOf(c));
    showTab("candidates", { type: "candidate", key: c.key || candKeyOf(c) });
  }
  function jumpToCandidateKey(key) {
    const c = S.candidateMap.get(key);
    if (c) return jumpToCandidate(c);
    showTab("candidates", { type: "candidate", key });
  }

  function applyFindingManualStatus(f, status, feedback = null) {
    f.manual_feedback = feedback || Object.assign({}, f.manual_feedback || {}, {
      status,
      updated_at: Date.now() / 1000,
    });
    S.findings.set(f.id, f);
    renderHeader();
    renderTabs();
  }
  function refreshFindingsTab() {
    if (activeTab === "findings") renderTab();
  }

  function renderFindingFeedback(f) {
    const select = el("select", { class: "feedback-select", title: "人工确认反馈" },
      ...FINDING_FEEDBACK_OPTIONS.map(([value, label]) =>
        el("option", { value, selected: value === findingFeedbackStatus(f) ? "" : null }, label)));
    const saveBtn = el("button", { type: "button", class: "feedback-save", title: "保存人工确认反馈" }, "保存");
    const state = el("span", { class: "muted feedback-state" }, "");
    const wrap = el("div", { class: "feedback-control" },
      el("span", { class: "muted" }, "人工确认"),
      select,
      saveBtn,
      state);
    wrap.addEventListener("click", e => e.stopPropagation());
    let saving = false;
    let stateTimer = null;
    const setState = (text) => {
      if (stateTimer) clearTimeout(stateTimer);
      state.textContent = text || "";
      if (text === "已保存") stateTimer = setTimeout(() => { state.textContent = ""; }, 1800);
    };
    const save = async (e) => {
      e.stopPropagation();
      if (saving || !f.id) return;
      saving = true;
      const previousFeedback = Object.assign({}, f.manual_feedback || {});
      const previousStatus = findingFeedbackStatus(f);
      const status = select.value;
      applyFindingManualStatus(f, status);
      select.disabled = true;
      saveBtn.disabled = true;
      setState("保存中…");
      try {
        const r = await api("POST", `/api/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(f.id)}/feedback`, { status });
        if (r.finding) {
          Object.assign(f, r.finding);
          S.findings.set(f.id, f);
        } else {
          applyFindingManualStatus(f, status);
        }
        renderHeader();
        renderTabs();
        setState("已保存");
        flash("人工确认反馈已保存");
        refreshFindingsTab();
      } catch (err) {
        f.manual_feedback = previousFeedback;
        S.findings.set(f.id, f);
        select.value = previousStatus;
        renderHeader();
        renderTabs();
        setState("保存失败");
        flash("保存反馈失败: " + err.message);
        refreshFindingsTab();
      } finally {
        saving = false;
        select.disabled = false;
        saveBtn.disabled = false;
      }
    };
    select.addEventListener("change", save);
    saveBtn.addEventListener("click", save);
    return wrap;
  }

  const MISSING_AUDIT_MODEL = "__missing_audit_model__";
  function auditModelKey(f) {
    const m = String((f && f.audit_model) || "").trim();
    return m || MISSING_AUDIT_MODEL;
  }
  function auditModelLabel(key) {
    return key === MISSING_AUDIT_MODEL ? "未记录" : key;
  }
  function findingAuditModelItems(list) {
    const counts = new Map();
    for (const f of list) {
      const k = auditModelKey(f);
      counts.set(k, (counts.get(k) || 0) + 1);
    }
    return [...counts.entries()].sort((a, b) =>
      String(auditModelLabel(a[0])).localeCompare(String(auditModelLabel(b[0])), undefined, { numeric: true }));
  }
  function findingFeedbackCounts(list) {
    const counts = {};
    for (const f of list) {
      const s = findingFeedbackStatus(f);
      counts[s] = (counts[s] || 0) + 1;
    }
    return counts;
  }
  function findingSourceRecord(f) {
    const k = candKeyOf(f);
    let c = S.candidateMap.get(k);
    if (!c && f && f.id) c = candidateList().find(x => String(x.id) === String(f.id));
    return c || f || {};
  }
  function findingSourceKey(f) {
    const c = findingSourceRecord(f);
    const variant = String(c.variant_of || f?.variant_of || "").trim();
    if (c.risk_id || c.risk_area || c.good_validation_ref || variant.startsWith("风险点")) return "risk";
    if (variant) return "history";
    return "coverage";
  }
  function findingSourceCounts(list) {
    const counts = {};
    for (const f of list) {
      const s = findingSourceKey(f);
      counts[s] = (counts[s] || 0) + 1;
    }
    return counts;
  }
  function findingFilterPanel(all, modelFiltered, sourceFiltered, filtered) {
    const modelSelect = el("select", { title: "按审计模型筛选漏洞" },
      el("option", { value: "all", selected: findingAuditModelFilter === "all" ? "" : null }, `全部模型 (${all.length})`),
      ...findingAuditModelItems(all).map(([value, n]) =>
        el("option", { value, selected: findingAuditModelFilter === value ? "" : null },
          `${auditModelLabel(value)} (${n})`)));
    modelSelect.addEventListener("change", () => {
      findingAuditModelFilter = modelSelect.value || "all";
      pageState.findings = 1;
      renderTab();
    });

    const sourceCounts = findingSourceCounts(modelFiltered);
    const sourceSelect = el("select", { title: "按来源筛选漏洞" },
      el("option", { value: "all", selected: findingSourceFilter === "all" ? "" : null },
        `全部来源 (${modelFiltered.length})`),
      ...FINDING_SOURCE_OPTIONS.map(([value, label]) =>
        el("option", { value, selected: findingSourceFilter === value ? "" : null },
          `${label} (${sourceCounts[value] || 0})`)));
    sourceSelect.addEventListener("change", () => {
      findingSourceFilter = sourceSelect.value || "all";
      pageState.findings = 1;
      renderTab();
    });

    const feedbackCounts = findingFeedbackCounts(sourceFiltered);
    const feedbackOptions = [
      el("option", { value: "all", selected: findingFeedbackFilter === "all" ? "" : null },
        `全部结果 (${sourceFiltered.length})`),
      ...FINDING_FEEDBACK_OPTIONS.map(([value, label]) => {
        const n = feedbackCounts[value] || 0;
        return el("option", { value, selected: findingFeedbackFilter === value ? "" : null },
          `${label} (${n})`);
      }),
    ];
    const feedbackSelect = el("select", { title: "按人工确认结果筛选漏洞" }, ...feedbackOptions);
    feedbackSelect.addEventListener("change", () => {
      findingFeedbackFilter = feedbackSelect.value || "all";
      pageState.findings = 1;
      renderTab();
    });

    const clearBtn = el("button", {
      type: "button",
      class: "btn secondary finding-filter-clear",
      disabled: findingAuditModelFilter === "all" && findingSourceFilter === "all" && findingFeedbackFilter === "all" ? "" : null,
    }, "清除筛选");
    clearBtn.addEventListener("click", () => {
      if (findingAuditModelFilter === "all" && findingSourceFilter === "all" && findingFeedbackFilter === "all") return;
      findingAuditModelFilter = "all";
      findingSourceFilter = "all";
      findingFeedbackFilter = "all";
      pageState.findings = 1;
      renderTab();
    });

    return el("div", { class: "panel finding-filter-panel" },
      el("div", { class: "row finding-filter-row" },
        el("strong", {}, "漏洞筛选"),
        el("label", { class: "filter-field" }, el("span", {}, "审计模型"), modelSelect),
        el("label", { class: "filter-field" }, el("span", {}, "来源"), sourceSelect),
        el("label", { class: "filter-field" }, el("span", {}, "人工确认结果"), feedbackSelect),
        clearBtn,
        el("span", { class: "muted filter-summary" }, `显示 ${filtered.length} / ${all.length}`)));
  }

  function renderFindings() {
    if (!candidatesLoaded) fetchCandidates();
    const all = [...S.findings.values()].sort((a, b) => SEVS.indexOf(a.corrected_severity) - SEVS.indexOf(b.corrected_severity));
    const focusId = pendingFocus?.type === "finding" ? pendingFocus.id : null;
    if (all.length && focusId && (findingAuditModelFilter !== "all" || findingSourceFilter !== "all" || findingFeedbackFilter !== "all")) {
      const target = all.find(f => String(f.id) === String(focusId));
      if (target && findingAuditModelFilter !== "all" && auditModelKey(target) !== findingAuditModelFilter) findingAuditModelFilter = "all";
      if (target && findingSourceFilter !== "all" && findingSourceKey(target) !== findingSourceFilter) findingSourceFilter = "all";
      if (target && findingFeedbackFilter !== "all" && findingFeedbackStatus(target) !== findingFeedbackFilter) findingFeedbackFilter = "all";
    }
    const modelFiltered = findingAuditModelFilter === "all" ? all : all.filter(f => auditModelKey(f) === findingAuditModelFilter);
    const sourceFiltered = findingSourceFilter === "all" ? modelFiltered : modelFiltered.filter(f => findingSourceKey(f) === findingSourceFilter);
    const list = findingFeedbackFilter === "all" ? sourceFiltered : sourceFiltered.filter(f => findingFeedbackStatus(f) === findingFeedbackFilter);
    tabBody.append(findingFilterPanel(all, modelFiltered, sourceFiltered, list));
    if (!all.length) { tabBody.append(el("div", { class: "panel empty" }, "暂无疑似漏洞(审计进行中会实时出现)。")); return; }
    if (!list.length) { tabBody.append(el("div", { class: "panel empty" }, "当前筛选下暂无疑似漏洞。")); return; }
    const focusIdx = pendingFocus?.type === "finding" ? list.findIndex(f => String(f.id) === String(pendingFocus.id)) : -1;
    const info = paginate("findings", list, focusIdx);
    const topPager = pagerBar("findings", info);
    if (topPager) tabBody.append(topPager);
    const frag = document.createDocumentFragment();
    for (const f of info.items) {
      const vmodels = Array.isArray(f.verify_models) ? f.verify_models : [];
      const modelBits = [];
      if (f.audit_model) modelBits.push("审计 " + f.audit_model);
      if (vmodels.length) modelBits.push("验证 " + vmodels.join("/"));
      const outputTs = f.output_ts || f.confirmed_at || f.created_at || 0;
      const head = el("div", { class: "head" }, sevPill(f.corrected_severity),
        el("span", { class: "title" }, f.title || f.id),
        el("span", { class: "muted" }, f.bug_class || ""),
        el("span", { class: "loc" }, `${f.file || ""}:${f.line || 0}`),
        el("span", { class: "muted output-time" }, `输出 ${fmtTs(outputTs)}`),
        renderFindingFeedback(f),
        modelBits.length ? el("span", { class: "muted model-attr" }, "🧠 " + modelBits.join(" · ")) : null);
      const body = el("div", { class: "body md" }, el("div", { class: "muted" }, "加载详情…"));
      const card = el("div", { class: "finding", "data-finding-id": f.id }, head, body);
      head.addEventListener("click", async () => {
        card.classList.toggle("open");
        if (card.classList.contains("open") && !body.dataset.loaded) {
          try {
            const full = await api("GET", `/api/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(f.id)}`);
            Object.assign(f, {
              output_ts: full.output_ts || f.output_ts,
              manual_feedback: full.manual_feedback || f.manual_feedback || {},
            });
            body.dataset.loaded = "1";
            body.innerHTML = mdToHtml(full.report_body || "(无正文)");
            const votes = Array.isArray(full.votes) ? full.votes : [];
            const finalVote = votes.find(v => (v.phase || "") === "final_adjudicator");
            const countedVotes = votes.filter(v => v.validation_ok !== false);
            const voteTxt = finalVote
              ? `终局决策 ${finalVote.operational_decision || finalVote.decision || "?"} / 证据 ${finalVote.epistemic_verdict || "?"}`
              : (countedVotes.length ? `验证记录 ${countedVotes.length}/${votes.length} 合格` : votes.map(v => `${v.model || "?"}${v.is_real ? "✓" : "✗"}`).join("、"));
            const attrBits = [];
            if (full.output_ts) attrBits.push("<strong>输出时间:</strong> " + esc(fmtTs(full.output_ts)));
            if (full.audit_model) attrBits.push("<strong>审计模型:</strong> " + esc(full.audit_model));
            if (voteTxt) attrBits.push("<strong>验证裁决:</strong> " + esc(voteTxt));
            else if ((full.verify_models || []).length) attrBits.push("<strong>验证模型:</strong> " + esc(full.verify_models.join("、")));
            if (attrBits.length) body.prepend(el("p", { class: "model-attr", html: "🧠 " + attrBits.join("　|　") }));
            if (full.exploitability) body.prepend(el("p", { html: "<strong>可利用性:</strong> " + esc(full.exploitability) }));
            if (votes.length) {
              body.append(el("h3", {}, "对抗验证记录"));
              body.append(el("div", { class: "vote-list" }, ...votes.map(renderVoteCard)));
            }
            body.append(el("p", { style: "margin-top:10px" }, el("a", { href: `/api/runs/${encodeURIComponent(runId)}/export/finding/${encodeURIComponent(f.id)}.md`, target: "_blank" }, "下载该条报告 .md")));
          } catch (e) { body.innerHTML = "加载失败: " + esc(e.message); }
        }
      });
      frag.append(card);
    }
    tabBody.append(frag);
    const bottomPager = pagerBar("findings", info);
    if (bottomPager) tabBody.append(bottomPager);
  }

  const CAND_STATUS_TXT = {
    pending: "验证中", confirmed: "已确认", rejected: "已否决", verify_failed: "验证失败",
    suppressed_unproven: "证据不足压制", promoted_to_risk: "转风险", needs_manual_review: "待人工复核"
  };
  function candPill(s) { return el("span", { class: "pill cand-" + cssKey(s) }, CAND_STATUS_TXT[s] || s || "?"); }
  function candKeyOf(d) {
    return d.key || `${(d.file || "").trim()}::${d.line || 0}::${(d.bug_class || "").trim().toLowerCase()}`;
  }
  const CAND_FIELDS = ["title", "bug_class", "file", "line", "lens", "severity", "function", "description",
    "source_to_sink", "variant_of", "confidence", "audit_model", "good_validation_ref", "risk_id", "risk_area",
    "epistemic_verdict", "operational_decision", "decision_reason", "residual_uncertainty", "recommended_next_action",
    "risk_note"];
  function mergeCandidateFields(c, d) {
    for (const k of CAND_FIELDS) {
      if (d[k] !== undefined && d[k] !== null && d[k] !== "") c[k] = d[k];
    }
    c._relText = undefined; c._varNorm = undefined;   // 关联文本缓存随字段变动失效
    return c;
  }
  function upsertCandidate(d) {
    const k = candKeyOf(d);
    const ex = S.candidateMap.get(k);
    if (ex) {
      // 仅补全字段,不覆盖已有状态(confirmed/rejected 优先级高于 pending)
      return mergeCandidateFields(ex, d);
    }
    const c = { key: k, status: "pending", seq: S.candidateMap.size };
    mergeCandidateFields(c, d);
    c.function = c.function || "";
    S.candidateMap.set(k, c);
    invalidateCandIndex();
    return c;
  }
  function upsertNonIssue(d) {
    const c = upsertCandidate(d);
    c.status = "rejected";
    if (Array.isArray(d.votes)) c.votes = d.votes;
    if (Array.isArray(d.verify_models)) c.verify_models = d.verify_models;
    for (const k of ["rejection_reason", "vote_total", "vote_false", "vote_real", "epistemic_verdict", "operational_decision", "decision_reason"]) {
      if (d[k] !== undefined && d[k] !== null && d[k] !== "") c[k] = d[k];
    }
    S.nonIssueMap.set(c.key, c);
    return c;
  }
  function linkButton(label, onClick, title = "") {
    return el("button", { type: "button", class: "link-btn", title, onclick: onClick }, label);
  }
  function normRel(s) {
    return String(s || "").trim().toLowerCase();
  }
  function candidateVarNorm(c) {
    if (c._varNorm === undefined) c._varNorm = normRel(c.variant_of);
    return c._varNorm;
  }
  function candidateRelText(c) {
    if (c._relText === undefined)
      c._relText = normRel([c.variant_of, c.risk_id, c.risk_area, c.title, c.description, c.source_to_sink, c.file].filter(Boolean).join("\n"));
    return c._relText;
  }
  function candidateActionLabel(c) {
    if (c.status === "confirmed" && c.id) return "查看漏洞";
    if (c.status === "rejected") return "查看非问题";
    if (["suppressed_unproven", "promoted_to_risk", "needs_manual_review", "verify_failed"].includes(c.status)) return "查看候选";
    return "定位候选";
  }
  function candidateSummaryLine(c) {
    const loc = `${c.file || ""}:${c.line || 0}`;
    return [c.title || c.key, c.bug_class, loc !== ":0" ? loc : ""].filter(Boolean).join(" · ");
  }
  function candidatesForHistory(h) {
    if (!candidatesLoaded) return [];
    const pattern = normRel(h.pattern);
    const source = normRel(h.source);
    if (!pattern && !source) return [];
    return candidateList().filter(c => {
      const v = candidateVarNorm(c);
      return (pattern && v.includes(pattern)) || (source && v.includes(source));
    });
  }
  function candidatesForRisk(r) {
    if (!candidatesLoaded) return [];
    const rid = normRel(r.id);
    const area = normRel(r.area);
    return candidateList().filter(c => {
      if (rid && normRel(c.risk_id) === rid) return true;
      const text = candidateRelText(c);
      if (rid && text.includes(rid)) return true;
      if (area && normRel(c.risk_area) === area) return true;
      const v = candidateVarNorm(c);
      return area && v.includes("风险") && v.includes(area);
    });
  }
  function ledgerByKey(key) {
    return (((S.coverage || {}).ledger || []).find(r => r.key === key)) || null;
  }
  function renderRelatedCandidates(cands, emptyText = "无关联候选") {
    const uniq = [];
    const seen = new Set();
    for (const c of cands || []) {
      const k = c.key || candKeyOf(c);
      if (!k || seen.has(k)) continue;
      seen.add(k);
      uniq.push(c);
    }
    if (!uniq.length) return el("span", { class: "muted" }, emptyText);
    const list = el("div", { class: "related-list" });
    let rendered = false;
    const renderList = () => {
      if (rendered) return;
      rendered = true;
      const shown = uniq.slice(0, RELATED_CANDIDATE_RENDER_LIMIT);
      const frag = document.createDocumentFragment();
      for (const c of shown) {
        frag.append(el("div", { class: "related-item" },
          candPill(c.status),
          el("span", { class: "related-title" }, candidateSummaryLine(c)),
          linkButton(candidateActionLabel(c), () => jumpToCandidate(c))));
      }
      if (uniq.length > shown.length) {
        frag.append(el("div", { class: "related-more muted" },
          `仅显示前 ${shown.length} 条，另有 ${uniq.length - shown.length} 条可到候选页查看`));
      }
      list.append(frag);
    };
    const details = el("details", { class: "related-candidates" },
      el("summary", {}, `候选 ${uniq.length}`),
      list);
    details.addEventListener("toggle", () => { if (details.open) renderList(); });
    return details;
  }
  // 通用状态筛选条:items 形如 [[value,label,count],...](含 "all"),current 为当前选中值。
  function statusChips(current, items, onPick) {
    const bar = el("div", { class: "filter-bar row", style: "gap:6px;margin:0 0 8px;flex-wrap:wrap" });
    for (const [value, label, n] of items) {
      const btn = el("button", { type: "button", class: "seg-btn" + (current === value ? " active" : "") }, `${label} ${n}`);
      btn.addEventListener("click", () => { if (current !== value) onPick(value); });
      bar.append(btn);
    }
    return bar;
  }
  // 仅展示有数据的状态(动态);value→label 由 labelMap 提供。
  function dynamicStatusChips(current, list, statusOf, order, labelMap, onPick) {
    const counts = {};
    for (const x of list) { const s = statusOf(x); counts[s] = (counts[s] || 0) + 1; }
    const items = [["all", "全部", list.length]];
    for (const k of order) if (counts[k]) items.push([k, labelMap[k] || k, counts[k]]);
    return statusChips(current, items, onPick);
  }
  const CAND_FILTERS = [["all", "全部"], ["pending", "验证中"], ["needs_manual_review", "待人工复核"],
    ["promoted_to_risk", "转风险"], ["suppressed_unproven", "证据不足压制"], ["confirmed", "已确认"],
    ["rejected", "已否决"], ["verify_failed", "验证失败"]];
  function candStatusFilterBar(counts) {
    const bar = el("div", { class: "filter-bar row", style: "gap:6px;margin-top:8px;flex-wrap:wrap" });
    for (const [value, label] of CAND_FILTERS) {
      const btn = el("button", { type: "button", class: "seg-btn" + (candStatusFilter === value ? " active" : "") },
        `${label} ${counts[value] || 0}`);
      btn.addEventListener("click", () => {
        if (candStatusFilter === value) return;
        candStatusFilter = value;
        pageState.candidates = 1;   // 切筛选回到第一页
        renderTab();
      });
      bar.append(btn);
    }
    return bar;
  }
  function renderCandidates() {
    if (!candidatesLoaded) {
      tabBody.append(el("div", { class: "panel empty" }, "候选数据加载中…"));
      fetchCandidates();
      return;
    }
    const all = [...S.candidateMap.values()];
    const counts = { all: all.length, pending: 0, confirmed: 0, rejected: 0, verify_failed: 0,
      suppressed_unproven: 0, promoted_to_risk: 0, needs_manual_review: 0 };
    for (const c of all) if (counts[c.status] !== undefined) counts[c.status]++;
    // 若跳转目标被当前筛选隐藏,自动切回「全部」以保证能定位到。
    const focusKey = pendingFocus?.type === "candidate" ? pendingFocus.key : null;
    if (focusKey && candStatusFilter !== "all") {
      const target = all.find(c => (c.key || candKeyOf(c)) === focusKey);
      if (target && target.status !== candStatusFilter) candStatusFilter = "all";
    }
    tabBody.append(el("div", { class: "panel" },
      el("div", { class: "row", style: "justify-content:space-between" },
        el("strong", {}, "漏洞候选点"),
        el("span", { class: "muted" }, `共 ${counts.all} · 验证中 ${counts.pending} · 待复核 ${counts.needs_manual_review} · 转风险 ${counts.promoted_to_risk} · 已确认 ${counts.confirmed} · 已否决 ${counts.rejected}`)),
      el("p", { class: "muted", style: "margin:6px 0 0;font-size:12px" },
        "候选点 = 审计/复查 agent 报出、进入 witness/blocker 对抗验证流水线中的疑点;验证后会升级为漏洞、非问题、风险种子或人工复核项。"),
      candStatusFilterBar(counts)));
    if (!all.length) { tabBody.append(el("div", { class: "panel empty" }, "暂无候选点(审计开始后会实时出现)。")); return; }
    const list = candStatusFilter === "all" ? all : all.filter(c => c.status === candStatusFilter);
    if (!list.length) { tabBody.append(el("div", { class: "panel empty" }, "当前筛选下暂无候选点。")); return; }
    const rank = { pending: 0, needs_manual_review: 1, promoted_to_risk: 2, suppressed_unproven: 3, verify_failed: 4, confirmed: 5, rejected: 6 };
    list.sort((a, b) =>
      (rank[a.status] ?? 9) - (rank[b.status] ?? 9) ||
      (SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity)) ||
      ((a.seq || 0) - (b.seq || 0)));
    const focusIdx = focusKey ? list.findIndex(c => (c.key || candKeyOf(c)) === focusKey) : -1;
    const info = paginate("candidates", list, focusIdx);
    const tbl = el("table", { class: "cand-table" }, el("thead", {}, el("tr", {},
      el("th", {}, "状态"), el("th", {}, "严重度"), el("th", {}, "类别"), el("th", {}, "标题"),
      el("th", {}, "位置"), el("th", {}, "lens"), el("th", {}, "确认编号"))));
    const tb = el("tbody");
    for (const c of info.items) {
      const hasDetails = Array.isArray(c.votes) && c.votes.length || c.decision_reason || c.rejection_reason || c.reason || c.residual_uncertainty || c.risk_note;
      const titleCell = el("td", {});
      if (hasDetails) {
        const details = el("details", { class: "candidate-detail" }, el("summary", {}, c.title || c.key || ""));
        details.append(
          detailLine("终局决策", c.operational_decision || c.status),
          detailLine("证据结论", c.epistemic_verdict),
          detailLine("决策理由", c.decision_reason || c.rejection_reason || c.reason, true),
          detailLine("剩余不确定性", c.residual_uncertainty, true),
          detailLine("建议动作", c.recommended_next_action, true),
          detailLine("风险说明", c.risk_note, true));
        if (Array.isArray(c.votes) && c.votes.length) details.append(el("div", { class: "vote-list" }, ...c.votes.map(renderVoteCard)));
        titleCell.append(details);
      } else {
        titleCell.append(c.title || "");
      }
      const confirmedRef = c.status === "confirmed" && c.id
        ? linkButton(String(c.id), () => jumpToCandidate(c), "查看漏洞")
        : c.status === "rejected"
          ? linkButton("非问题", () => jumpToCandidate(c), "查看非问题")
        : el("span", { class: "muted" }, "—");
      tb.append(el("tr", { class: "cand-row cand-" + cssKey(c.status), "data-cand-key": c.key || candKeyOf(c) },
        el("td", {}, candPill(c.status)),
        el("td", {}, sevPill(c.severity || "none")),
        el("td", {}, c.bug_class || ""),
        titleCell,
        el("td", { class: "loc" }, `${c.file || ""}:${c.line || 0}${c.function ? " · " + c.function : ""}`),
        el("td", {}, c.lens || ""),
        el("td", {}, confirmedRef)));
    }
    tbl.append(tb);
    const panel = el("div", { class: "panel" }, tbl);
    const pager = pagerBar("candidates", info);
    if (pager) panel.append(pager);
    tabBody.append(panel);
  }

  function nonIssueVoteReason(v) {
    return (v && (v.non_issue_reason || v.final_reason || v.rejection_reason || v.reasoning || v.reachability || v.controllability)) || "";
  }
  function detailList(label, values) {
    const arr = Array.isArray(values) ? values.filter(Boolean) : (values ? [values] : []);
    if (!arr.length) return null;
    return detailLine(label, arr.map(x => "- " + x).join("\n"), true);
  }
  function detailLine(label, value, asMd = false) {
    if (value === undefined || value === null || value === "") return null;
    return el("div", { class: "detail-line" },
      el("div", { class: "detail-label" }, label),
      asMd ? el("div", { class: "detail-value md", html: mdToHtml(value) }) : el("div", { class: "detail-value" }, String(value)));
  }
  function renderVoteCard(v, idx) {
    const decision = v.decision || (v.is_real ? "confirm" : "reject");
    const invalid = v.validation_ok === false;
    const isReal = decision === "confirm";
    const phaseLabel = {
      witness: "正方 witness", blocker: "反方 blocker", witness_judge: "质询 witness",
      blocker_judge: "质询 blocker", final_adjudicator: "终局裁判"
    }[v.phase] || "";
    const op = v.operational_decision || "";
    const label = invalid ? "无效证据"
      : (op ? (CAND_STATUS_TXT[op] || op)
        : (decision === "confirm" ? "支持问题" : (decision === "reject" ? "支持非问题" : "证据不足")));
    const meta = [v.phase, v.model, v.verify_lens ? "视角 " + v.verify_lens : ""].filter(Boolean).join(" · ");
    const reason = nonIssueVoteReason(v);
    return el("div", { class: "vote-card " + (invalid ? "vote-invalid" : (isReal ? "vote-real" : "vote-false")) },
      el("div", { class: "vote-head" },
        el("strong", {}, `验证记录 #${idx + 1}${phaseLabel ? " · " + phaseLabel : ""}`),
        el("span", { class: "pill " + (invalid ? "cand-verify-failed" : (isReal ? "cand-confirmed" : (decision === "reject" ? "cand-rejected" : "cand-pending"))) }, label),
        meta ? el("span", { class: "muted model-attr" }, meta) : null),
      detailLine("证据有效性", v.validation_ok === false ? (v.validation_reason || "未通过证据门槛") : "", true),
      detailLine("工程决策", v.operational_decision),
      detailLine("证据结论", v.epistemic_verdict),
      detailLine("Witness", v.witness, true),
      detailList("攻击前置条件", v.attack_preconditions),
      detailList("输入域约束", v.input_domain_constraints),
      detailList("状态约束", v.state_constraints),
      detailList("代码约束", v.code_constraints),
      detailList("路径节点", v.path_nodes),
      detailLine("触发条件", v.trigger_condition, true),
      detailLine("坏结果", v.bad_result, true),
      detailLine("Blocker", v.blocker_description || v.impossibility_proof, true),
      detailLine("Blocker 作用域", v.blocker_scope),
      detailList("阻断点", v.blocking_checks),
      detailLine("Witness 裁决", v.witness_verdict),
      detailLine("Blocker 裁决", v.blocker_verdict),
      detailList("已复核事实", v.reviewed_checks),
      detailList("失败/削弱点", v.failed_checks),
      detailList("终局补查事实", v.deciding_facts_checked),
      detailList("代码证据", v.evidence_refs),
      detailList("调用链", v.source_chain),
      detailLine("Sink", v.sink_ref, true),
      detailList("证伪点", v.clearing_checks),
      detailLine("可达性", v.reachability, true),
      detailLine("可控性", v.controllability, true),
      detailLine(isReal ? "保留问题依据" : "非问题原因", reason || "该验证记录未记录详细原因", true),
      detailLine("缺失证据", v.missing_evidence, true),
      detailLine("剩余不确定性", v.residual_uncertainty, true),
      detailLine("为何不确认", v.why_not_confirmed, true),
      detailLine("为何不否决", v.why_not_rejected, true),
      detailLine("建议动作", v.recommended_next_action, true),
      detailLine("风险说明", v.risk_note, true),
      detailLine("可利用性", v.exploitability, true));
  }
  function renderNonIssueBody(c, votes, falseCount, total, verifyModels) {
    const body = el("div", { class: "body md" },
      el("h3", {}, "疑似问题候选原因"),
      detailLine("描述", c.description || "旧事件未记录候选描述", true),
      detailLine("声称的 source→sink", c.source_to_sink, true),
      detailLine("变体来源", c.variant_of, true),
      detailLine("正面对照", c.good_validation_ref, true),
      detailLine("审计模型", c.audit_model),
      detailLine("置信度", c.confidence),
      el("h3", {}, "最终验证非问题原因"),
      detailLine("终局结论", c.rejection_reason || c.decision_reason || (total ? `验证记录判定为非问题(${falseCount}/${total})` : "旧事件未记录验证详情"), true),
      verifyModels.length ? detailLine("验证模型", verifyModels.join("、")) : null);
    if (votes.length) {
      body.append(el("div", { class: "vote-list" }, ...votes.map(renderVoteCard)));
    }
    return body;
  }
  function renderNonIssues() {
    if (!candidatesLoaded) {
      tabBody.append(el("div", { class: "panel empty" }, "非问题数据加载中…"));
      fetchCandidates();
      return;
    }
    const list = [...S.nonIssueMap.values()];
    tabBody.append(el("div", { class: "panel" },
      el("div", { class: "row", style: "justify-content:space-between" },
        el("strong", {}, "对抗验证后的非问题"),
        el("span", { class: "muted" }, `共 ${list.length}`)),
      el("p", { class: "muted", style: "margin:6px 0 0;font-size:12px" },
        "这里收集 witness/blocker 对抗验证后被终局裁判否决的候选点,保留原始疑似问题依据和最终非问题验证依据。")));
    if (!list.length) { tabBody.append(el("div", { class: "panel empty" }, "暂无已验证为非问题的候选。")); return; }
    list.sort((a, b) =>
      (SEVS.indexOf(a.severity || "info") - SEVS.indexOf(b.severity || "info")) ||
      ((a.seq || 0) - (b.seq || 0)));
    const focusKey = pendingFocus?.type === "candidate" ? pendingFocus.key : null;
    const focusIdx = focusKey ? list.findIndex(c => c.key === focusKey) : -1;
    const info = paginate("nonissues", list, focusIdx);
    const topPager = pagerBar("nonissues", info);
    if (topPager) tabBody.append(topPager);
    const frag = document.createDocumentFragment();
    for (const c of info.items) {
      const votes = Array.isArray(c.votes) ? c.votes : [];
      const falseCount = c.vote_false ?? votes.filter(v => !v.is_real).length;
      const total = c.vote_total ?? votes.length;
      const verifyModels = Array.isArray(c.verify_models) ? c.verify_models : [];
      const head = el("div", { class: "head" },
        candPill("rejected"),
        sevPill(c.severity || "none"),
        el("span", { class: "title" }, c.title || c.key),
        el("span", { class: "muted" }, c.bug_class || ""),
        el("span", { class: "loc" }, `${c.file || ""}:${c.line || 0}`),
        total ? el("span", { class: "muted model-attr" }, `非问题票 ${falseCount}/${total}`) : null);
      const bodyHost = el("div", { class: "body md" });
      const card = el("div", { class: "finding nonissue" + (nonIssueOpenKeys.has(c.key) ? " open" : ""), "data-cand-key": c.key }, head, bodyHost);
      const loadBody = () => {
        if (bodyHost.dataset.loaded) return;
        bodyHost.dataset.loaded = "1";
        bodyHost.replaceWith(renderNonIssueBody(c, votes, falseCount, total, verifyModels));
      };
      if (nonIssueOpenKeys.has(c.key)) loadBody();
      head.addEventListener("click", () => {
        const open = !card.classList.contains("open");
        card.classList.toggle("open", open);
        if (open) {
          nonIssueOpenKeys.add(c.key);
          loadBody();
        } else {
          nonIssueOpenKeys.delete(c.key);
        }
      });
      frag.append(card);
    }
    tabBody.append(frag);
    const bottomPager = pagerBar("nonissues", info);
    if (bottomPager) tabBody.append(bottomPager);
  }

  const HEALTH_TXT = { ok: "✅ 正常", down: "⛔ 不可达", degraded: "⚠️ 异常", checking: "⏳ 检查中", unavailable: "时间窗外", unknown: "· 未检查" };
  function healthPill(s) { return el("span", { class: "pill health-" + (s || "unknown") }, HEALTH_TXT[s] || s || "未检查"); }
  function isCallErrorText(s) { return /CLI 未产出|后端输出无可解析 JSON|结构化 JSON|parsefail|stdout 已存/.test(String(s || "")); }
  function runningModelCounts() {
    const counts = new Map();
    for (const a of S.agentMap.values()) {
      if (a.status !== "running" || !a.model) continue;
      counts.set(a.model, (counts.get(a.model) || 0) + 1);
    }
    return counts;
  }
  function renderConfigPanel() {
    const cfg = runConfig();
    const running = isRunClockActive();
    let roles = ((S.meta && S.meta.roles) || ["recon", "history", "recheck", "decompose", "audit", "verify", "report", "poc"])
      .filter(r => r !== "synthesis" && r !== "util");
    if (isHistoryOnly()) {
      const allowed = new Set(["recheck", "verify", "report", "poc"]);
      if (!cfg.history_import_from) allowed.add("history");
      roles = roles.filter(r => allowed.has(r));
    }
    const f = (label, node) => el("label", { class: "field" }, el("span", {}, label), node);
    const inputs = {};
    const modelGrid = el("div", { class: "grid" }, ...roles.map(role => {
      inputs[role] = el("input", { type: "text", value: modelText((cfg.models || {})[role]) });
      return f("模型 · " + (AGENT_ROLE_TXT[role] || role), inputs[role]);
    }));
    const concInput = el("input", { type: "number", min: "1", value: cfg.concurrency ?? 4 });
    const mcInput = el("input", { type: "text", value: kvText(cfg.model_concurrency) });
    const mtwInput = el("textarea", { rows: "4" }, modelWindowsText(cfg.model_time_windows));
    const btn = el("button", { class: "btn" }, "应用配置");
    btn.addEventListener("click", async () => {
      const models = {};
      for (const role of roles) { const v = splitModels(inputs[role].value); if (v.length) models[role] = v; }
      const payload = {
        models,
        concurrency: +concInput.value,
        model_concurrency: parseKvInts(mcInput.value),
        model_time_windows: parseModelWindows(mtwInput.value),
      };
      btn.disabled = true;
      try {
        const r = await api("POST", `/api/runs/${encodeURIComponent(runId)}/config`, payload);
        flash(r.model_config_error ? ("已应用,但模型配置不完整:" + r.model_config_error) : "✅ 配置已更新");
      } catch (e) { flash("应用失败: " + e.message); } finally { btn.disabled = false; }
    });
    const panel = el("div", { class: "panel" },
      el("div", { class: "row", style: "justify-content:space-between;margin-bottom:8px" },
        el("strong", {}, "⚙ 模型与并发(运行中可调)"),
        el("span", { class: "muted", style: "font-size:12px" },
          running ? "改动即时生效:增/减模型、调整并发" : "run 未在运行 · 改动将在续跑时生效")),
      el("div", { class: "muted", style: "margin-bottom:6px;font-size:12px" },
        "每个角色填写一个或多个模型(逗号分隔);留空=该角色不派任务。每模型并发用 model=limit(未配置默认为 1);可用时间段每行 model=00:00~06:00,多段用 |。"),
      modelGrid,
      el("div", { class: "grid", style: "margin-top:8px" }, f("全局并发", concInput), f("每模型并发 model=limit", mcInput)),
      f("模型可用时间段 model=00:00~06:00", mtwInput),
      el("div", { style: "margin-top:10px" }, btn));
    tabBody.append(panel);
  }

  function renderModels() {
    renderConfigPanel();
    const list = [...S.health.values()];
    const runningByModel = runningModelCounts();
    const bar = el("div", { class: "row", style: "justify-content:space-between;margin-bottom:6px" },
      el("strong", {}, "各模型健康度"),
      el("button", { class: "btn secondary", onclick: recheckHealth }, "🩺 重新检查"));
    tabBody.append(el("div", { class: "panel" }, bar,
      el("p", { class: "muted", style: "margin:0" },
        "运行开始前会对每个配置的模型发一个短探针;调用某模型前若健康状态陈旧/异常会自动补检。首 token 与输出速度实时更新。")));
    if (!list.length) { tabBody.append(el("div", { class: "panel empty" }, "暂无模型健康数据(开始运行后会自动检测)。")); return; }
    const order = { checking: 0, down: 1, degraded: 2, unavailable: 3, unknown: 4, ok: 5 };
    list.sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9) || String(a.model).localeCompare(String(b.model)));
    const tbl = el("table", {}, el("thead", {}, el("tr", {},
      el("th", {}, "状态"), el("th", {}, "模型"), el("th", {}, "运行中"), el("th", {}, "首 token"), el("th", {}, "平均输出速度"), el("th", {}, "探针(正常/总)"),
      el("th", {}, "成功调用"), el("th", {}, "失败"), el("th", {}, "最近探针答复"), el("th", {}, "最近调用异常"), el("th", {}, "最近检查"))));
    const tb = el("tbody");
    for (const h of list) {
      const legacyCallErr = (!h.last_call_error && isCallErrorText(h.error)) ? h.error : "";
      const probeErr = h.error && !legacyCallErr ? h.error : "";
      const ans = h.answer ? h.answer : (probeErr ? el("span", { class: "muted", title: probeErr }, "⚠ " + probeErr) : "—");
      const callErrText = h.last_call_error || legacyCallErr;
      const callErr = callErrText ? el("span", { class: "muted", title: callErrText }, "⚠ " + callErrText) : "—";
      const firstTokenMs = h.last_first_token_latency_ms || (!("last_first_token_latency_ms" in h) ? h.last_latency_ms : 0);
      const speedTitle = h.last_output_tokens ? `输出 ${fmtNum(h.last_output_tokens)} token` : "";
      tb.append(el("tr", {},
        el("td", {}, healthPill(h.status)),
        el("td", { class: "loc" }, h.model || "—"),
        el("td", {}, String(runningByModel.get(h.model) || 0)),
        el("td", {}, fmtMs(firstTokenMs)),
        el("td", { title: speedTitle }, fmtTps(h.last_output_tokens_per_s)),
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
  const AGENT_ROLE_TXT = {
    recon: "侦察",
    history: "历史",
    decompose: "拆解",
    audit: "审计",
    verify: "验证",
    report: "报告",
    poc: "PoC",
    synthesis: "汇总",
    recheck: "复查",
    util: "工具",
  };
  const AGENT_ROLE_ORDER = ["recheck", "recon", "history", "decompose", "audit", "verify", "report", "poc", "synthesis", "util"];
  // 始终常驻显示的 8 个角色分组(与 pipeline 实际拉起的 role 一一对应),无论当前是否有在跑的 agent。
  const AGENT_REAL_ROLES = ["recon", "decompose", "history", "audit", "verify", "recheck", "report", "poc"];
  function isAgentActive(a) { return ["queued", "running", "retrying", "failed_attempt"].includes(a.status); }
  function agentPill(s) { return el("span", { class: "pill agent-" + cssKey(s) }, AGENT_TXT[s] || s || "unknown"); }
  function agentOrderValue(a) {
    const v = Number(a.created_ts || a.ts || a.id || 0);
    return Number.isFinite(v) ? v : 0;
  }
  function agentSort(a, b) {
    const at = agentOrderValue(a);
    const bt = agentOrderValue(b);
    if (at !== bt) return at - bt;
    return String(a.id || "").localeCompare(String(b.id || ""), undefined, { numeric: true });
  }
  function loadLocalSet(key) {
    try {
      const v = JSON.parse(localStorage.getItem(key) || "[]");
      return new Set(Array.isArray(v) ? v.map(String) : []);
    } catch (_) {
      return new Set();
    }
  }
  function saveLocalSet(key, set) {
    try { localStorage.setItem(key, JSON.stringify([...set])); } catch (_) {}
  }
  function toggleLocalSet(set, key, storeKey) {
    key = String(key);
    if (set.has(key)) set.delete(key);
    else set.add(key);
    saveLocalSet(storeKey, set);
    renderTab();
  }
  function agentCategory(a) { return String(a.role || "agent"); }
  function isVisibleAgentCategory(key) { return key && key !== "agent"; }
  function agentCategoryLabel(key) { return AGENT_ROLE_TXT[key] || key || "Agent"; }
  function agentGroupOrder(key) {
    const i = AGENT_ROLE_ORDER.indexOf(key);
    return i >= 0 ? i : AGENT_ROLE_ORDER.length;
  }
  function agentRawOutput(a) {
    return (a.chunks || []).length ? a.chunks.map(c => c.chunk).join("") : (a.output || "");
  }
  function agentStreamOutput(a, stream) {
    return (a.chunks || []).filter(c => c.stream === stream).map(c => c.chunk).join("");
  }
  // 缓存 stdout 拼接,按 chunk 数量失效,避免每次渲染都 filter+join 全量分片。
  function agentStdout(a) {
    const n = (a.chunks || []).length;
    if (a._stdoutN === n && a._stdout !== undefined) return a._stdout;
    a._stdoutN = n;
    a._stdout = agentStreamOutput(a, "stdout") || (n ? "" : (a.output || ""));
    return a._stdout;
  }
  function modeButton(mode, label) {
    const b = el("button", { type: "button", class: "seg-btn" + (agentOutputMode === mode ? " active" : "") }, label);
    b.addEventListener("click", () => {
      agentOutputMode = mode;
      localStorage.setItem("pvh.agentOutputMode", mode);
      renderTab();
    });
    return b;
  }
  function agentModeSwitch() {
    return el("div", { class: "segmented", role: "group", "aria-label": "Agent 输出显示模式" },
      modeButton("pretty", "可读"),
      modeButton("raw", "原始"));
  }
  function maybeJsonObj(v) {
    if (v && typeof v === "object" && !Array.isArray(v)) return v;
    if (typeof v === "string" && v.trim().startsWith("{")) {
      try {
        const obj = JSON.parse(v);
        return obj && typeof obj === "object" && !Array.isArray(obj) ? obj : null;
      } catch (_) {}
    }
    return null;
  }
  function eventPart(ev) {
    const direct = maybeJsonObj(ev.part);
    if (direct) return direct;
    for (const key of ["data", "properties", "payload"]) {
      const inner = maybeJsonObj(ev[key]);
      if (!inner) continue;
      const p = maybeJsonObj(inner.part);
      if (p) return p;
      const t = String(inner.type || "");
      if ("text" in inner || ["step-finish", "step-start", "tool", "reasoning"].includes(t)) return inner;
    }
    const t = String(ev.type || "");
    if ("text" in ev || ["step-finish", "step-start", "tool", "reasoning"].includes(t)) return ev;
    return {};
  }
  function eventMessage(ev) {
    const direct = maybeJsonObj(ev.message);
    if (direct) return direct;
    for (const key of ["data", "properties", "payload"]) {
      const inner = maybeJsonObj(ev[key]);
      if (!inner) continue;
      const msg = maybeJsonObj(inner.message);
      if (msg) return msg;
      if ("role" in inner && "id" in inner) return inner;
    }
    return {};
  }
  function textDelta(ev, part) {
    for (const obj of [part || {}, ev || {}]) {
      for (const key of ["delta", "textDelta", "text_delta"]) {
        const v = obj[key];
        if (typeof v === "string") return v;
        if (v && typeof v === "object") {
          const txt = v.text || v.content;
          if (typeof txt === "string") return txt;
        }
      }
    }
    return "";
  }
  function parseOpencodeEvents(stdout) {
    if (!stdout || !stdout.includes("{")) return null;
    const lines = stdout.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    if (!lines.length) return null;
    const events = [];
    for (const ln of lines) {
      if (!ln.startsWith("{")) continue;
      try {
        const ev = JSON.parse(ln);
        if (ev && typeof ev === "object" && !Array.isArray(ev) &&
            (ev.type || ev.part || ev.sessionID || ev.session_id || ev.data || ev.payload || ev.properties)) {
          events.push(ev);
        }
      } catch (_) {}
    }
    return events.length && events.length * 2 >= Math.max(1, lines.length - 1) ? events : null;
  }
  function opencodeEventTitle(ev, part) {
    const et = String(ev.type || "");
    const pt = String(part.type || "");
    const norm = (pt || et).replace(/_/g, "-");
    if (norm.includes("step-start")) return "step start";
    if (norm.includes("step-finish")) {
      const reason = part.reason || ev.reason;
      const tokens = part.tokens || ev.tokens;
      const usage = tokens ? ` · ${shortJson(tokens, 120).replace(/\s+/g, " ")}` : "";
      return "step finish" + (reason ? ` · ${reason}` : "") + usage;
    }
    if (et.includes("session")) return ev.status ? `session · ${ev.status}` : et;
    return et || pt || "event";
  }
  function toolSummary(ev, part) {
    const name = part.tool || part.name || part.command || ev.tool || ev.name || ev.command ||
      part.function?.name || part.call?.name || part.input?.tool || "tool";
    const state = part.state?.status || part.state || part.status || ev.status || "";
    const input = part.input || part.args || part.arguments || ev.input || ev.args || ev.arguments || "";
    const output = part.output || part.result || ev.output || ev.result || "";
    const bits = [name, state].filter(Boolean).join(" · ");
    const detail = [input ? shortJson(input) : "", output ? shortJson(output) : ""].filter(Boolean).join("\n");
    return { title: bits, detail };
  }
  function appendOpencodeItem(items, itemByPart, pid, item) {
    if (pid && itemByPart.has(pid)) return itemByPart.get(pid);
    items.push(item);
    if (pid) itemByPart.set(pid, item);
    return item;
  }
  function buildOpencodeItems(events) {
    const items = [];
    const itemByPart = new Map();
    const messageRoles = new Map();
    let sessionId = "";
    for (const ev of events) {
      const etype = String(ev.type || "");
      const part = eventPart(ev);
      const msg = eventMessage(ev);
      const ptype = String(part.type || "");
      if (!sessionId) sessionId = String(ev.sessionID || ev.session_id || part.sessionID || part.session_id || msg.sessionID || msg.session_id || "");
      const mid = String(part.messageID || part.message_id || part.messageId || msg.id || msg.messageID || "");
      const role = String(part.role || msg.role || "");
      if (mid && role) messageRoles.set(mid, role);
      const fallbackPid = mid && (ptype || etype) ? `${mid}:${ptype || etype}` : "";
      const pid = String(part.id || fallbackPid);
      const norm = (ptype || etype).replace(/_/g, "-");
      const isText = ptype === "text" || etype === "text" || etype === "message.part.updated" || etype === "message.part.delta";
      const isReasoning = ptype === "reasoning" || etype === "reasoning";
      const isTool = ptype === "tool" || ptype === "tool-use" || etype === "tool_use" || etype === "tool" || part.tool || part.call;
      const isStep = norm.includes("step-start") || norm.includes("step-finish");
      if (isText || isReasoning) {
        const item = appendOpencodeItem(items, itemByPart, pid || `${items.length}`, {
          kind: isReasoning ? "reasoning" : "text",
          role: role || messageRoles.get(mid) || "assistant",
          text: "",
        });
        if (typeof part.text === "string") item.text = part.text;
        else if (typeof part.content === "string") item.text = part.content;
        const delta = textDelta(ev, part);
        if (delta) item.text += delta;
        continue;
      }
      if (isTool) {
        const s = toolSummary(ev, part);
        const item = appendOpencodeItem(items, itemByPart, pid || `${items.length}`, {
          kind: "tool",
          title: s.title,
          detail: "",
        });
        item.title = s.title || item.title;
        if (s.detail) item.detail = s.detail;
        continue;
      }
      if (etype === "error" || ev.error || part.error) {
        items.push({ kind: "error", title: "error", text: shortJson(ev.error || part.error || ev.message || ev) });
        continue;
      }
      if (isStep) {
        items.push({ kind: "step", title: opencodeEventTitle(ev, part), text: "" });
      }
    }
    return { items: items.filter(x => x.kind !== "step" || /finish/.test(x.title)), sessionId };
  }
  function renderAgentReadable(a) {
    const stdout = agentStdout(a);
    // 解析结果按 stdout 长度缓存:流式追加时 length 变化才重解析,切回页签复用上次结果。
    let cache = a._oc;
    if (!cache || cache.len !== stdout.length) {
      const events = parseOpencodeEvents(stdout);
      cache = a._oc = { len: stdout.length, events: !!events, parsed: events ? buildOpencodeItems(events) : null };
    }
    if (!cache.events) {
      return el("pre", { class: "agent-output agent-raw" }, stdout || "(暂未收到 stdout)");
    }
    const parsed = cache.parsed;
    const out = el("div", { class: "agent-output agent-pretty" });
    if (parsed.sessionId) out.append(el("div", { class: "agent-session" }, "session ", el("code", {}, parsed.sessionId)));
    let hasContent = false;
    for (const item of parsed.items) {
      if (item.kind === "text") {
        if (!String(item.text || "").trim()) continue;
        hasContent = true;
        out.append(el("div", { class: "agent-event agent-event-text" },
          el("div", { class: "agent-event-label" }, item.role || "assistant"),
          el("div", { class: "agent-event-body agent-text md", html: mdToHtml(item.text) })));
      } else if (item.kind === "reasoning") {
        if (!String(item.text || "").trim()) continue;
        hasContent = true;
        out.append(el("div", { class: "agent-event agent-event-reasoning" },
          el("div", { class: "agent-event-label" }, "reasoning"),
          el("pre", { class: "agent-event-body" }, item.text)));
      } else if (item.kind === "tool") {
        hasContent = true;
        out.append(el("div", { class: "agent-event agent-event-tool" },
          el("div", { class: "agent-event-label" }, "tool"),
          el("div", { class: "agent-event-body" },
            el("div", { class: "agent-tool-title" }, item.title || "tool"),
            item.detail ? el("pre", {}, item.detail) : null)));
      } else if (item.kind === "error") {
        hasContent = true;
        out.append(el("div", { class: "agent-event agent-event-error" },
          el("div", { class: "agent-event-label" }, item.title || "error"),
          el("pre", { class: "agent-event-body" }, item.text || "")));
      } else if (item.kind === "step") {
        out.append(el("div", { class: "agent-event agent-event-step" },
          el("div", { class: "agent-event-label" }, "step"),
          el("div", { class: "agent-event-body" }, item.title || "")));
      }
    }
    if (!hasContent) out.append(el("div", { class: "agent-empty" }, "(已识别 opencode JSON 流，暂无 assistant 文本或工具输出)"));
    return out;
  }
  function renderAgentOutput(a) {
    if (agentOutputMode === "raw") return el("pre", { class: "agent-output agent-raw" }, agentRawOutput(a) || "(暂未收到 stdout/stderr)");
    return renderAgentReadable(a);
  }
  function renderAgentCard(a) {
    const id = String(a.id || "");
    const title = `${a.role || "agent"} · ${a.label || ""}`.replace(/\s+$/, "");
    const meta = [
      `#${a.id}`,
      a.model ? `model ${a.model}` : "",
      a.attempt ? `attempt ${a.attempt}` : "",
      a.duration_ms ? `耗时 ${fmtMs(a.duration_ms)}` : "",
      a.retry_in_ms ? `重试等待 ${fmtMs(a.retry_in_ms)}` : "",
      a.updated_ts || a.ts ? `更新 ${fmtClock(a.updated_ts || a.ts)}` : "",
    ].filter(Boolean).join(" · ");
    const outputExpanded = expandedAgentOutputs.has(id);
    const toggle = el("button", {
      type: "button",
      class: "agent-toggle",
      "aria-expanded": outputExpanded ? "true" : "false",
    }, outputExpanded ? "隐藏输出" : "显示输出");
    toggle.addEventListener("click", () => toggleLocalSet(expandedAgentOutputs, id, agentOutputStoreKey));
    const out = outputExpanded ? renderAgentOutput(a) : null;
    const card = el("div", { class: "agent-card " + (isAgentActive(a) ? "active " : "") + (outputExpanded ? "" : "output-collapsed") },
      el("div", { class: "agent-head" },
        agentPill(a.status),
        el("span", { class: "agent-title" }, title),
        el("span", { class: "muted agent-head-meta" }, meta),
        toggle),
      el("div", { class: "agent-meta" },
        el("span", {}, a.cwd || ""),
        a.error ? el("span", { class: "agent-error" }, a.error) : null),
      out);
    if (isAgentActive(a) && out) setTimeout(() => { out.scrollTop = out.scrollHeight; }, 0);
    return card;
  }
  function renderAgentGroup(group) {
    const running = group.agents.filter(isAgentActive);
    const active = running.length;
    const done = group.agents.length - active;          // 已结束(完成 + 失败)
    const failed = group.agents.filter(a => a.status === "failed").length;
    const collapsed = collapsedAgentGroups.has(group.key);
    const summary = [
      `运行中 ${active}`,
      `已结束 ${done}`,
      failed ? `异常 ${failed}` : "",
    ].filter(Boolean).join(" · ");
    const head = el("button", {
      type: "button",
      class: "agent-group-head",
      "aria-expanded": collapsed ? "false" : "true",
    },
      el("span", { class: "agent-group-caret" }, collapsed ? ">" : "v"),
      el("span", { class: "agent-group-title" }, agentCategoryLabel(group.key)),
      el("span", { class: "agent-group-key" }, group.key),
      el("span", { class: "agent-group-summary" }, summary));
    head.addEventListener("click", () => toggleLocalSet(collapsedAgentGroups, group.key, agentGroupStoreKey));
    const cards = active
      ? running.map(renderAgentCard)
      : [el("div", { class: "muted agent-group-empty" }, "暂无运行中 agent")];
    return el("section", { class: "agent-group " + (collapsed ? "collapsed" : "open") + (active ? " has-active" : " idle") },
      head,
      collapsed ? null : el("div", { class: "agent-group-body" }, ...cards));
  }
  function renderAgents() {
    // 8 个角色分组常驻显示(无论当前是否有在跑的 agent),组头显示运行中/已结束数量;
    // 组体只列正在运行的 agent 卡片,跑完的不再展示。出现非兜底未知角色时追加其分组,确保不遗漏。
    const all = [...S.agentMap.values()].sort(agentSort).filter(a => isVisibleAgentCategory(agentCategory(a)));
    const running = all.filter(isAgentActive);
    const done = all.length - running.length;
    tabBody.append(el("div", { class: "panel agent-summary" },
      el("div", { class: "row", style: "justify-content:space-between" },
        el("strong", {}, "实时 Agent"),
        el("div", { class: "row" },
          el("span", { class: "muted" }, `运行中 ${running.length} · 已结束 ${done}`),
          agentModeSwitch()))));
    const byRole = new Map();
    for (const a of all) {
      const k = agentCategory(a);
      if (!byRole.has(k)) byRole.set(k, []);
      byRole.get(k).push(a);
    }
    const roles = isHistoryOnly() ? ["history", "recheck", "verify", "report", "poc"] : [...AGENT_REAL_ROLES];
    for (const k of byRole.keys()) if (!roles.includes(k)) roles.push(k);
    for (const key of roles) {
      tabBody.append(renderAgentGroup({ key, agents: (byRole.get(key) || []).sort(agentSort) }));
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

  function renderHistoryProgress() {
    const c = S.coverage;
    const hist = (S.recon || {}).history || [];
    if (!c && !hist.length) { tabBody.append(el("div", { class: "panel empty" }, "暂无历史排查数据。")); return; }
    if (!candidatesLoaded) fetchCandidates();
    const hs = historyModeStats();
    const pct = hs.total ? Math.round(100 * hs.completed / hs.total) : 0;
    tabBody.append(el("div", { class: "panel history-progress-panel" },
      el("div", { class: "row", style: "justify-content:space-between" },
        el("strong", {}, `历史模式排查:${hs.completed}/${hs.total} 已完成`),
        el("span", { class: "muted" }, pct + "%")),
      el("div", { class: "bar" }, el("span", { style: `width:${pct}%;background:var(--ok)` })),
      el("div", { class: "history-progress-grid" },
        el("div", {}, el("div", { class: "n" }, String(hs.pending)), el("div", { class: "l" }, "待排查")),
        el("div", {}, el("div", { class: "n" }, String(hs.running)), el("div", { class: "l" }, "排查中")),
        el("div", {}, el("div", { class: "n" }, String(hs.clean)), el("div", { class: "l" }, "未命中")),
        el("div", {}, el("div", { class: "n" }, String(hs.hits)), el("div", { class: "l" }, "有候选")),
        el("div", {}, el("div", { class: "n" }, String(hs.failed)), el("div", { class: "l" }, "失败")))));

    const variants = variantStatusByPattern();
    const rows = hist.length ? hist : historyVariantLedger().map(v => ({
      pattern: v.pattern || v.name,
      source: v.source || "",
      lens_hint: (v.lenses || [])[0] || "",
      files: [],
    }));
    if (!rows.length) return;
    const tbl = el("table", { class: "data-table history-progress-table" }, el("thead", {}, el("tr", {},
      el("th", {}, "状态"), el("th", {}, "lens"), el("th", {}, "问题模式"), el("th", {}, "候选"),
      el("th", {}, "pass"), el("th", {}, "出处"), el("th", {}, "相关文件"))));
    const tb = el("tbody");
    for (const h of rows) {
      const key = String(h.pattern || "").trim().toLowerCase();
      const v = variants.get(key);
      const status = v?.status || "pending";
      const related = candidatesForHistory(h);
      const empty = !candidatesLoaded ? "候选关联加载中…" : (v?.candidates ? `候选 ${v.candidates}(旧数据未保存关联)` : "—");
      tb.append(el("tr", {},
        el("td", {}, statusBadge(status)),
        el("td", {}, el("span", { class: "tag" }, h.lens_hint || (v?.lenses || [])[0] || "—")),
        el("td", {}, h.pattern || v?.name || ""),
        el("td", {}, renderRelatedCandidates(related, empty)),
        el("td", {}, String(v?.passes || 0)),
        el("td", {}, h.source || v?.source || "—"),
        el("td", { class: "loc" }, (h.files || []).join(", ") || "—")));
    }
    tbl.append(tb);
    tabBody.append(el("div", { class: "panel" }, el("div", { class: "table-wrap" }, tbl)));
  }

  function renderCoverage() {
    if (isHistoryOnly()) { renderHistoryProgress(); return; }
    const c = S.coverage;
    if (!c) { tabBody.append(el("div", { class: "panel empty" }, "暂无覆盖数据(运行开始后会出现攻击面审计进度与拆解的子任务)。")); return; }
    if (!candidatesLoaded) fetchCandidates();
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
      const regionFrag = document.createDocumentFragment();
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
        regionFrag.append(card);
      }
      // 区域记录里没有的 region(兜底:子任务的 region 名不在 region 台账里)
      for (const [rname, subs] of tasksByRegion) {
        if (regionNames.has(rname)) continue;
        regionFrag.append(el("div", { class: "region" },
          el("div", { class: "region-head" }, el("span", { class: "rname" }, rname),
            el("span", { class: "rmeta" }, `${subs.length} 个子任务`)),
          el("div", { class: "subtasks" }, ...subs.map(subtaskRow))));
      }
      tabBody.append(regionFrag);
    }

    // 历史模式排查(variant 工作项)
    if (variants.length) {
      tabBody.append(el("h3", { class: "section-title" }, "历史模式同类变体排查"));
      const vt = el("table", {}, el("thead", {}, el("tr", {},
        el("th", {}, "状态"), el("th", {}, "问题模式"), el("th", {}, "出处"), el("th", {}, "轮"), el("th", {}, "候选"))));
      const vtb = el("tbody");
      for (const v of variants) {
        const related = candidatesForHistory({ pattern: v.pattern || v.name, source: v.source });
        const empty = !candidatesLoaded ? "候选关联加载中…" : (v.candidates ? `候选 ${v.candidates}(旧数据未保存关联)` : "—");
        vtb.append(el("tr", {}, el("td", {}, statusBadge(v.status)), el("td", {}, v.name || ""),
          el("td", {}, v.source || "—"), el("td", {}, String(v.passes || 0)), el("td", {}, renderRelatedCandidates(related, empty))));
      }
      vt.append(vtb);
      tabBody.append(el("div", { class: "panel" }, vt));
    }

    // 审计中动态新增的攻击面 —— 每个都会作为新审计单元重新入队、扇出 finder 再审计,
    // 这里把发现信息(surface_log)与台账记录(kind=surface:状态/pass/候选/风险/lens)join 起来,
    // 体现“动态扩面 → 进一步处理”的闭环,而非只登记一行。
    if ((c.surfaces || []).length) {
      const surfaceRecs = new Map();
      for (const r of ledger) if (r.kind === "surface") surfaceRecs.set(r.name, r);
      const audited = c.surfaces.filter(s => {
        const r = surfaceRecs.get(s.name);
        return r && r.status && r.status !== "pending";
      }).length;
      tabBody.append(el("h3", { class: "section-title" },
        `审计中动态新增的攻击面 · ${c.surfaces.length} 个(已再审 ${audited})`));
      const st = el("table", {}, el("thead", {}, el("tr", {},
        el("th", {}, "状态"), el("th", {}, "动态新增攻击面"), el("th", {}, "来自"),
        el("th", {}, "发现轮"), el("th", {}, "pass"), el("th", {}, "候选"),
        el("th", {}, "风险"), el("th", {}, "lens"), el("th", {}, "为何可疑"))));
      const stb = el("tbody");
      for (const s of c.surfaces) {
        const r = surfaceRecs.get(s.name) || {};
        stb.append(el("tr", {},
          el("td", {}, statusBadge(r.status || "pending")),
          el("td", {}, s.name || ""),
          el("td", {}, s.from || ""),
          el("td", {}, "r" + (s.round || "?")),
          el("td", {}, String(r.passes || 0)),
          el("td", {}, String(r.candidates || 0)),
          el("td", {}, String(r.risks || 0)),
          el("td", {}, (r.lenses || []).join(", ") || (s.lens_hint || "")),
          el("td", {}, s.why || "")));
      }
      st.append(stb);
      tabBody.append(el("div", { class: "panel" }, el("div", { class: "table-wrap" }, st)));
    }
  }
  const STATUS_TXT = { "decomposed": "🧩 已拆解", "completed-clean": "✅ 未发现", "completed-findings": "⚠️ 有候选", "in-progress": "🔄 进行中", "incomplete": "⛔ 未审完", "abandoned": "⛔ 复查失败", "pending": "⏳ 待审" };
  function statusBadge(s) { return el("span", {}, STATUS_TXT[s] || s || "?"); }

  const RECHECK_TXT = { none: "—", queued: "排队中", running: "排查中", done: "已排查", failed: "排查失败" };
  const RISK_STATUS_ORDER = ["none", "queued", "running", "done", "failed"];
  const RISK_STATUS_LABEL = { none: "未排查", queued: "排队中", running: "排查中", done: "已排查", failed: "排查失败" };
  const HISTORY_STATUS_ORDER = ["pending", "in-progress", "completed-clean", "completed-findings", "incomplete", "abandoned", "decomposed"];

  function severitySelect(r) {
    const sel = el("select", { class: "sevsel" });
    for (const s of ["high", "medium", "low", "info"]) {
      const o = el("option", { value: s }, s);
      if (s === (r.severity_hint || "info")) o.selected = true;
      sel.append(o);
    }
    sel.onchange = async () => {
      const sev = sel.value;
      try {
        await api("POST", `/api/runs/${encodeURIComponent(runId)}/risks/${encodeURIComponent(r.id)}/severity`, { severity_hint: sev });
        r.severity_hint = sev;
        flash(`✔ ${r.id} 风险级别已改为 ${sev}`);
        fetchRisks();
      } catch (e) { flash("⚠ 调级失败:" + e.message); }
    };
    return sel;
  }

  const riskRecheckOf = (r) => r.recheck_status || "none";
  function renderRisks() {
    if (!candidatesLoaded) fetchCandidates();
    const all = [...S.risks.values()].sort((a, b) => SEVS.indexOf(a.severity_hint) - SEVS.indexOf(b.severity_hint));
    if (!all.length) { tabBody.append(el("div", { class: "panel empty" }, "暂无风险登记。")); return; }
    tabBody.append(dynamicStatusChips(riskStatusFilter, all, riskRecheckOf, RISK_STATUS_ORDER, RISK_STATUS_LABEL,
      v => { riskStatusFilter = v; pageState.risks = 1; renderTab(); }));
    const list = riskStatusFilter === "all" ? all : all.filter(r => riskRecheckOf(r) === riskStatusFilter);
    if (!list.length) { tabBody.append(el("div", { class: "panel empty" }, "当前筛选下暂无风险。")); return; }
    const info = paginate("risks", list);
    const tbl = el("table", { class: "data-table risk-table" }, el("thead", {}, el("tr", {}, el("th", {}, "风险"), el("th", {}, "主题"), el("th", {}, "位置"), el("th", {}, "说明"), el("th", {}, "lens"), el("th", {}, "排查"), el("th", {}, "候选"))));
    const tb = el("tbody");
    for (const r of info.items) {
      const sevCell = r.id ? severitySelect(r) : sevPill(r.severity_hint);
      const related = candidatesForRisk(r);
      const ledger = r.id ? ledgerByKey("risk:" + r.id) : null;
      const empty = !candidatesLoaded ? "候选关联加载中…" : (ledger?.candidates ? `候选 ${ledger.candidates}(旧数据未保存关联)` : "—");
      tb.append(el("tr", {}, el("td", {}, sevCell), el("td", {}, r.area || ""), el("td", { class: "loc" }, r.file || "—"), el("td", {}, r.note || ""), el("td", {}, r.lens || ""), el("td", {}, RECHECK_TXT[r.recheck_status] || r.recheck_status || "—"), el("td", {}, renderRelatedCandidates(related, empty))));
    }
    tbl.append(tb);
    const panel = el("div", { class: "panel" }, el("div", { class: "table-wrap" }, tbl));
    const pager = pagerBar("risks", info);
    if (pager) panel.append(pager);
    tabBody.append(panel);
  }

  const PRI_PILL = { high: "high", medium: "medium", low: "low" };
  function renderRecon() {
    const r = S.recon;
    if (!r) { tabBody.append(el("div", { class: "panel empty" }, "侦察数据加载中…")); return; }
    const sec = (t, b) => el("div", { class: "panel" }, el("h3", {}, t), el("div", { class: "md", html: mdToHtml(b || "(无)") }));
    const toMd = (v) => Array.isArray(v) ? v.map(x => "- " + x).join("\n") : v;   // threat_summary/repo_knowledge 现为列表
    tabBody.append(sec("项目用途", r.purpose), sec("威胁分析", toMd(r.threat_summary)), sec("仓库知识", toMd(r.repo_knowledge)));
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

  }

  function variantStatusByPattern() {
    const out = new Map();
    for (const v of ((S.coverage || {}).ledger || [])) {
      if (v.kind !== "variant") continue;
      for (const key of [v.name, v.pattern, String(v.key || "").replace(/^variant:/, "")]) {
        const k = String(key || "").trim().toLowerCase();
        if (k) out.set(k, v);
      }
    }
    return out;
  }
  function historyCheckText(status) {
    if (status === "completed-clean" || status === "completed-findings") return "是";
    if (status === "in-progress") return "否(排查中)";
    if (status === "incomplete") return "否(未审完)";
    if (status === "abandoned") return "否(复查失败)";
    if (status === "pending") return "否(待排查)";
    return "否";
  }
  function renderHistory() {
    if (!candidatesLoaded) fetchCandidates();
    const hist = (S.recon || {}).history || [];
    if (!hist.length) {
      tabBody.append(el("div", { class: "panel empty" }, "暂无历史问题模式。"));
      return;
    }
    const variants = variantStatusByPattern();
    const histStatusOf = (h) => (variants.get(String(h.pattern || "").trim().toLowerCase())?.status) || "pending";
    tabBody.append(dynamicStatusChips(histStatusFilter, hist, histStatusOf, HISTORY_STATUS_ORDER, STATUS_TXT,
      v => { histStatusFilter = v; pageState.history = 1; renderTab(); }));
    const filtered = histStatusFilter === "all" ? hist : hist.filter(h => histStatusOf(h) === histStatusFilter);
    if (!filtered.length) { tabBody.append(el("div", { class: "panel empty" }, "当前筛选下暂无历史问题模式。")); return; }
    const info = paginate("history", filtered);
    const tbl = el("table", { class: "data-table history-table" }, el("thead", {}, el("tr", {},
      el("th", {}, "lens"), el("th", {}, "问题模式"), el("th", {}, "是否排查完"),
      el("th", {}, "排查状态"), el("th", {}, "候选"), el("th", {}, "出处"), el("th", {}, "相关文件"))));
    const tb = el("tbody");
    for (const h of info.items) {
      const key = String(h.pattern || "").trim().toLowerCase();
      const v = variants.get(key);
      const status = v?.status || "";
      const related = candidatesForHistory(h);
      const empty = !candidatesLoaded ? "候选关联加载中…" : (v?.candidates ? `候选 ${v.candidates}(旧数据未保存关联)` : "—");
      tb.append(el("tr", {},
        el("td", {}, el("span", { class: "tag" }, h.lens_hint || "—")),
        el("td", {}, h.pattern || ""),
        el("td", {}, historyCheckText(status)),
        el("td", {}, statusBadge(status || "pending")),
        el("td", {}, renderRelatedCandidates(related, empty)),
        el("td", {}, h.source || "—"),
        el("td", { class: "loc" }, (h.files || []).join(", ") || "—")));
    }
    tbl.append(tb);
    const panel = el("div", { class: "panel" }, el("div", { class: "table-wrap" }, tbl));
    const pager = pagerBar("history", info);
    if (pager) panel.append(pager);
    tabBody.append(panel);
  }

  function renderUsage() {
    if (!usageLoaded) {
      tabBody.append(el("div", { class: "panel empty" }, "用量数据加载中…"));
      fetchUsage();
      return;
    }
    const rows = [...S.usageRows].map(cleanUsage).slice(-80).reverse();
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
    const a = S.agentMap.get(id) || { id, status: "queued", output: "", chunks: [], stdout_chars: 0, stderr_chars: 0, created_ts: d.ts || now };
    if (!Array.isArray(a.chunks)) a.chunks = [];
    if (d.status === "output") {
      const chunk = String(d.chunk == null ? "" : d.chunk);
      a.output += chunk;
      a.chunks.push({ stream: d.stream === "stderr" ? "stderr" : "stdout", chunk });
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
    S.agents = Math.max(S.agents || 0, S.agentMap.size);
  }
  function applyEvent(ev) {
    const d = ev.data || {};
    switch (ev.type) {
      case "run_status": setRunStatus(d.status); renderHeader(); break;
      case "metrics": applyMetrics(d); renderHeader(); break;
      case "usage": { const u = cleanUsage(d); const uid = u.id == null ? "" : String(u.id); if (uid && S.usageIds.has(uid)) break; if (uid) S.usageIds.add(uid); S.usageRows.push(u); S.usageTotal = Math.max((S.usageTotal || 0) + 1, S.usageRows.length); addUsage(S.usage, u); renderHeader(); renderTabs(); if (activeTab === "usage") renderTab(); break; }
      case "agent_update": applyAgentUpdate(d); scheduleAgentRefresh(); break;
      case "candidate_found": { const existed = S.candidateMap.has(candKeyOf(d)); upsertCandidate(d); if (!existed) { S.candidates++; S.candidateTotal = Math.max(S.candidateTotal || 0, S.candidates); } renderHeader(); renderTabs(); if (activeTab === "candidates") renderTab(); break; }
      case "finding_confirmed": {
        if (!d.output_ts && ev.ts) d.output_ts = ev.ts / 1000;
        if (d.id && !S.findings.has(d.id)) { S.findings.set(d.id, d); flash("✔ 疑似漏洞 " + d.id + " [" + d.corrected_severity + "]"); }
        else if (d.id) S.findings.set(d.id, d);
        const cc = upsertCandidate(d);
        cc.status = "confirmed"; cc.id = d.id; cc.severity = d.corrected_severity || cc.severity;
        S.nonIssueMap.delete(cc.key);
        S.candidateTotal = Math.max(S.candidateTotal || 0, S.candidateMap.size, S.candidates || 0);
        renderHeader(); renderTabs(); if (activeTab === "findings" || activeTab === "candidates" || activeTab === "nonissues") renderTab(); break;
      }
      case "finding_rejected": {
        const existed = S.nonIssueMap.has(candKeyOf(d));
        upsertNonIssue(d);
        if (!existed) S.nonIssueTotal = Math.max(S.nonIssueTotal || 0, S.nonIssueMap.size);
        renderTabs(); if (activeTab === "candidates") renderTab(); else if (activeTab === "nonissues") scheduleRenderTab(); break;
      }
      case "candidate_failed": {
        const cf = upsertCandidate(d);
        cf.status = "verify_failed"; cf.reason = d.reason || ""; cf.attempts = d.attempts || cf.attempts;
        renderHeader(); renderTabs(); if (activeTab === "candidates") renderTab(); break;
      }
      case "candidate_decided": {
        const cd = upsertCandidate(d);
        Object.assign(cd, d, { key: cd.key, status: d.status || d.operational_decision || cd.status });
        if (cd.status === "rejected") S.nonIssueMap.set(cd.key, cd);
        else S.nonIssueMap.delete(cd.key);
        renderHeader(); renderTabs(); if (activeTab === "candidates" || activeTab === "nonissues") renderTab(); break;
      }
      case "risk_added": { const k = (d.area || "") + "::" + (d.file || ""); S.risks.set(k, d); S.riskTotal = Math.max(S.riskTotal || 0, S.risks.size); renderHeader(); renderTabs(); if (activeTab === "risks") renderTab(); break; }
      case "recheck_enqueued": case "recheck_done": case "risk_severity_changed":
        fetchRisks(); fetchCoverage(); break;
      case "surface_added": case "coverage_update":
        if (ev.type === "coverage_update") S.coverage = Object.assign({}, S.coverage, d);
        if (activeTab === "coverage" || activeTab === "history") renderTab(); break;
      case "round_start": S.round = d.round; renderHeader(); break;
      case "round_done": S.round = d.round; S.dry = d.dry_streak; renderHeader(); break;
      case "recon_done": if (d.purpose != null || d.threat_summary != null) { S.recon = Object.assign({}, S.recon, d); } fetchRecon(); break;
      case "history_added": flash(`🕮 历史问题模式 +1(共 ${d.total || "?"} 条):${(d.pattern || "").slice(0, 50)}`); fetchRecon(); fetchCoverage(); break;
      case "run_done": applyMetrics(d); setRunStatus(d.status || "done"); renderHeader(); break;
      case "config_updated":
        if (S.manifest) {
          S.manifest.config = Object.assign({}, S.manifest.config, {
            models: d.models, model_concurrency: d.model_concurrency,
            model_time_windows: d.model_time_windows, concurrency: d.concurrency,
          });
        }
        flash("⚙ 配置已更新:全局并发 " + (d.concurrency ?? "?") + (d.model_config_error ? "(模型配置不完整)" : ""));
        renderHeader(); if (activeTab === "health") renderTab(); break;
      case "model_health": if (d.model) { S.health.set(d.model, d); renderTabs(); if (activeTab === "health") renderTab(); } break;
      case "health_check_start": if (Array.isArray(d.models)) for (const m of d.models) if (!S.health.has(m)) S.health.set(m, { model: m, status: "checking" }); renderTabs(); if (activeTab === "health") renderTab(); break;
      case "health_check_done": flash(`🩺 健康检查:${d.ok}/${d.total} 正常` + ((d.unhealthy || []).length ? `,异常 ${d.unhealthy.join(", ")}` : "")); if (activeTab === "health") renderTab(); break;
      case "log": S.log.push(d.message); if (S.log.length > 600) S.log.shift(); if (activeTab === "activity") renderTab(); break;
    }
  }
  async function fetchRecon() { try { S.recon = await api("GET", `/api/runs/${encodeURIComponent(runId)}/recon`); renderTabs(); if (activeTab === "recon" || activeTab === "history") renderTab(); } catch (e) {} }
  async function fetchCoverage() { try { const c = await api("GET", `/api/runs/${encodeURIComponent(runId)}/coverage`); if (c) { S.coverage = Object.assign({}, S.coverage, c); if (activeTab === "coverage" || activeTab === "history") renderTab(); } } catch (e) {} }
  async function fetchRisks() { try { const list = await api("GET", `/api/runs/${encodeURIComponent(runId)}/risks`); for (const r of (list || [])) { const k = (r.area || "") + "::" + (r.file || ""); S.risks.set(k, r); } S.riskTotal = Math.max(S.riskTotal || 0, S.risks.size); renderHeader(); renderTabs(); if (activeTab === "risks") renderTab(); } catch (e) {} }
  async function fetchHealth() { try { const h = await api("GET", `/api/runs/${encodeURIComponent(runId)}/health`); for (const r of (h.models || [])) if (r.model) S.health.set(r.model, r); renderTabs(); if (activeTab === "health") renderTab(); } catch (e) {} }
  async function fetchMeta() { try { S.meta = await api("GET", "/api/meta"); if (activeTab === "health") renderTab(); } catch (e) {} }

  function applyCandidateRows(candidates, nonissues) {
    invalidateCandIndex();
    for (const c of (candidates || [])) {
      const k = candKeyOf(c);
      const rec = S.candidateMap.get(k) || { key: k, seq: S.candidateMap.size };
      Object.assign(rec, c, { key: k });
      S.candidateMap.set(k, rec);
    }
    for (const c of (nonissues || [])) {
      const k = candKeyOf(c);
      const rec = S.candidateMap.get(k) || Object.assign({ key: k, seq: S.candidateMap.size }, c, { key: k });
      rec.status = "rejected";
      mergeCandidateFields(rec, c);
      if (Array.isArray(c.votes)) rec.votes = c.votes;
      if (Array.isArray(c.verify_models)) rec.verify_models = c.verify_models;
      for (const k2 of ["rejection_reason", "vote_total", "vote_false", "vote_real"]) if (c[k2] != null) rec[k2] = c[k2];
      S.candidateMap.set(k, rec);
    }
    S.nonIssueMap.clear();
    for (const [k, rec] of S.candidateMap) if (rec.status === "rejected") S.nonIssueMap.set(k, rec);
    S.candidateTotal = Math.max(S.candidateTotal || 0, S.candidateMap.size);
    S.nonIssueTotal = Math.max(S.nonIssueTotal || 0, S.nonIssueMap.size);
    candidatesLoaded = true;
  }

  async function fetchCandidates(force = false) {
    if (candidatesLoaded && !force) return;
    if (candidatesLoading) return candidatesLoading;
    candidatesLoading = (async () => {
      const r = await api("GET", `/api/runs/${encodeURIComponent(runId)}/candidates`);
      applyCandidateRows(r.candidates || [], r.nonissues || []);
      renderHeader();
      renderTabs();
      if (["findings", "candidates", "nonissues", "coverage", "history", "risks"].includes(activeTab)) renderTab();
    })().catch(e => {
      flash("加载候选失败: " + e.message);
    }).finally(() => { candidatesLoading = null; });
    return candidatesLoading;
  }

  function applyUsageRows(rows) {
    S.usageRows = (rows || []).map(cleanUsage);
    S.usageIds = new Set(S.usageRows.map(u => u.id == null ? "" : String(u.id)).filter(Boolean));
    usageLoaded = true;
  }

  async function fetchUsage(force = false) {
    if (usageLoaded && !force) return;
    if (usageLoading) return usageLoading;
    usageLoading = (async () => {
      applyUsageRows(await api("GET", `/api/runs/${encodeURIComponent(runId)}/usage?limit=80`));
      renderTabs();
      if (activeTab === "usage") renderTab();
    })().catch(e => {
      flash("加载用量失败: " + e.message);
    }).finally(() => { usageLoading = null; });
    return usageLoading;
  }

  function applySnapshot(snap) {
    if (!snap) return 0;
    S.manifest = snap.manifest || S.manifest || {};
    const snapCounts = snap.counts || {};
    S.candidateTotal = tokenCount(snapCounts.candidates);
    S.nonIssueTotal = tokenCount(snapCounts.nonissues);
    S.usageTotal = tokenCount(snapCounts.usage);
    S.riskTotal = tokenCount(snapCounts.risks);
    S.findings.clear();
    for (const f of (snap.findings || [])) if (f.id) S.findings.set(f.id, f);
    applyCandidateRows(Array.isArray(snap.candidates) ? snap.candidates : [], Array.isArray(snap.nonissues) ? snap.nonissues : []);
    candidatesLoaded = !snap.lite && Array.isArray(snap.candidates);
    S.risks.clear();
    for (const r of (snap.risks || [])) S.risks.set((r.area || "") + "::" + (r.file || ""), r);
    S.riskTotal = Math.max(S.riskTotal || 0, S.risks.size);
    S.health.clear();
    for (const h of ((snap.health || {}).models || [])) if (h.model) S.health.set(h.model, h);
    S.coverage = snap.coverage || null;
    S.recon = snap.recon || null;
    applyUsageRows(snap.usage || []);
    usageLoaded = !snap.lite && Array.isArray(snap.usage);
    Object.assign(S.usage, emptyUsage());
    for (const u of S.usageRows) addUsage(S.usage, u);
    applyMetrics((S.manifest && S.manifest.summary) || {});
    if (S.candidates == null || S.candidates === 0) S.candidates = S.candidateMap.size;
    S.candidateTotal = Math.max(S.candidateTotal || 0, S.candidates || 0, S.candidateMap.size);
    S.nonIssueTotal = Math.max(S.nonIssueTotal || 0, S.nonIssueMap.size);
    S.usageTotal = Math.max(S.usageTotal || 0, S.usageRows.length);
    S.round = snap.round ?? S.round;
    setRunStatus(S.manifest.running ? "running" : S.manifest.status);
    if (!initialModeTabApplied && isHistoryOnly()) {
      activeTab = "coverage";
      initialModeTabApplied = true;
    }
    return Number(snap.last_seq || 0);
  }

  async function boot() {
    let lastSeq = 0;
    try {
      lastSeq = applySnapshot(await api("GET", `/api/runs/${encodeURIComponent(runId)}/snapshot?lite=1`));
    } catch (e) {}
    renderHeader(); renderTabs(); renderTab();
    fetchMeta();
    if (window._pvhElapsedTimer) clearInterval(window._pvhElapsedTimer);
    window._pvhElapsedTimer = setInterval(() => {
      if (isRunClockActive()) renderHeader();
    }, 1000);
    if (window._es) try { window._es.close(); } catch (_) {}
    if (!(S.manifest && S.manifest.running)) return;
    // 首屏由 snapshot 提供完整关键数据;SSE 只接 snapshot 之后的新事件。
    const es = new EventSource(`/api/runs/${encodeURIComponent(runId)}/events?last_id=${encodeURIComponent(lastSeq)}`);
    window._es = es;
    const TYPES = ["run_status", "metrics", "usage", "agent_update", "candidate_found", "finding_confirmed", "finding_rejected", "candidate_failed", "candidate_decided", "risk_added", "recheck_enqueued", "recheck_done", "risk_severity_changed", "surface_added", "coverage_update", "round_start", "round_done", "recon_done", "history_added", "run_done", "log", "decompose_done", "poc_done", "error", "model_health", "health_check_start", "health_check_done", "config_updated"];
    for (const t of TYPES) es.addEventListener(t, (e) => { try { applyEvent(JSON.parse(e.data)); } catch (_) {} });
    es.onerror = () => { /* EventSource 自动重连 */ };
  }
  boot();
}
