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
function sevPill(s) { return el("span", { class: "pill sev-" + (s || "none") }, s || "none"); }
function stPill(s) { return el("span", { class: "pill st-" + (s || "queued") }, s || "queued"); }
function fmtNum(n) { return Number(n || 0).toLocaleString(); }
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
  const S = { findings: new Map(), risks: new Map(), coverage: null, recon: null, log: [], usageRows: [], usage: emptyUsage(), manifest: null, candidates: 0, status: "queued", round: 0, dry: 0, agents: 0, elapsed: 0 };
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

  const TABS = [["findings", "漏洞"], ["coverage", "覆盖"], ["risks", "风险"], ["usage", "用量"], ["recon", "侦察"], ["activity", "活动"], ["exports", "导出"]];
  function renderTabs() {
    tabsBar.innerHTML = "";
    const counts = { findings: S.findings.size, risks: S.risks.size, usage: S.usageRows.length };
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

  function renderCoverage() {
    const c = S.coverage;
    if (!c) { tabBody.append(el("div", { class: "panel empty" }, "暂无覆盖数据。")); return; }
    const p = c.progress || { done: 0, clean: 0, total: 0 };
    const pct = p.total ? Math.round(100 * p.done / p.total) : 0;
    const prog = el("div", { class: "panel" },
      el("div", { class: "row", style: "justify-content:space-between" },
        el("strong", {}, `审计覆盖:${p.done}/${p.total} 工作项已完成(其中未发现漏洞 ${p.clean})`),
        el("span", { class: "muted" }, pct + "%")),
      el("div", { class: "bar" }, el("span", { style: `width:${pct}%;background:var(--ok)` })));
    tabBody.append(prog);
    const tbl = el("table", {}, el("thead", {}, el("tr", {},
      el("th", {}, "状态"), el("th", {}, "工作项"), el("th", {}, "类型"), el("th", {}, "轮"), el("th", {}, "lens"), el("th", {}, "候选"), el("th", {}, "新面"), el("th", {}, "风险"))));
    const tb = el("tbody");
    const order = { "completed-findings": 0, "in-progress": 1, "completed-clean": 2, "decomposed": 3, "incomplete": 1.5, "pending": 4 };
    for (const r of [...(c.ledger || [])].sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9))) {
      tb.append(el("tr", {}, el("td", {}, statusBadge(r.status)), el("td", {}, r.name || ""), el("td", {}, r.kind || ""),
        el("td", {}, String(r.passes || 0)), el("td", {}, (r.lenses || []).join("/")), el("td", {}, String(r.candidates || 0)),
        el("td", {}, String(r.surfaces || 0)), el("td", {}, String(r.risks || 0))));
    }
    tbl.append(tb);
    tabBody.append(el("div", { class: "panel" }, el("h3", {}, "审计覆盖台账"), tbl));
    if ((c.surfaces || []).length) {
      const st = el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "轮"), el("th", {}, "动态新增攻击面"), el("th", {}, "来自"), el("th", {}, "为何可疑"))));
      const stb = el("tbody");
      for (const s of c.surfaces) stb.append(el("tr", {}, el("td", {}, "r" + (s.round || "?")), el("td", {}, s.name || ""), el("td", {}, s.from || ""), el("td", {}, s.why || "")));
      st.append(stb);
      tabBody.append(el("div", { class: "panel" }, el("h3", {}, "审计中动态新增的攻击面"), st));
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

  function renderRecon() {
    const r = S.recon;
    if (!r) { tabBody.append(el("div", { class: "panel empty" }, "侦察数据加载中…")); return; }
    const sec = (t, b) => el("div", { class: "panel" }, el("h3", {}, t), el("div", { class: "md", html: mdToHtml(b || "(无)") }));
    tabBody.append(sec("项目用途", r.purpose), sec("威胁分析", r.threat_summary), sec("仓库知识", r.repo_knowledge));
    if ((r.regions || []).length) {
      const tbl = el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "优先级"), el("th", {}, "区域"), el("th", {}, "类别"), el("th", {}, "不可信输入"), el("th", {}, "文件"))));
      const tb = el("tbody");
      for (const rg of r.regions) tb.append(el("tr", {}, el("td", {}, sevPill(({ high: "high", medium: "medium", low: "low" })[rg.priority] || "info")), el("td", {}, rg.name || ""), el("td", {}, rg.category || ""), el("td", {}, rg.untrusted_input || ""), el("td", { class: "loc" }, (rg.files || []).join(", "))));
      tbl.append(tb);
      tabBody.append(el("div", { class: "panel" }, el("h3", {}, "攻击面地图"), tbl));
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
  function applyEvent(ev) {
    const d = ev.data || {};
    switch (ev.type) {
      case "run_status": S.status = d.status; renderHeader(); break;
      case "metrics": S.agents = d.agents_spawned ?? S.agents; S.elapsed = d.elapsed_s ?? S.elapsed; S.candidates = d.candidates ?? S.candidates; if (d.token_usage) setUsage(S.usage, d.token_usage); renderHeader(); break;
      case "usage": S.usageRows.push(d); addUsage(S.usage, d); renderHeader(); renderTabs(); if (activeTab === "usage") renderTab(); break;
      case "candidate_found": S.candidates++; renderHeader(); break;
      case "finding_confirmed":
        if (d.id && !S.findings.has(d.id)) { S.findings.set(d.id, d); flash("✔ 确认漏洞 " + d.id + " [" + d.corrected_severity + "]"); }
        else if (d.id) S.findings.set(d.id, d);
        renderHeader(); renderTabs(); if (activeTab === "findings") renderTab(); break;
      case "risk_added": { const k = (d.area || "") + "::" + (d.file || ""); S.risks.set(k, d); renderHeader(); renderTabs(); if (activeTab === "risks") renderTab(); break; }
      case "surface_added": case "coverage_update":
        if (ev.type === "coverage_update") S.coverage = d;
        if (activeTab === "coverage") renderTab(); break;
      case "round_start": S.round = d.round; renderHeader(); break;
      case "round_done": S.round = d.round; S.dry = d.dry_streak; renderHeader(); break;
      case "recon_done": if (d.purpose != null || d.threat_summary != null) { S.recon = Object.assign({}, S.recon, d); } fetchRecon(); break;
      case "run_done": S.status = "done"; renderHeader(); break;
      case "log": S.log.push(d.message); if (S.log.length > 600) S.log.shift(); if (activeTab === "activity") renderTab(); break;
    }
  }
  async function fetchRecon() { try { S.recon = await api("GET", `/api/runs/${encodeURIComponent(runId)}/recon`); if (activeTab === "recon") renderTab(); } catch (e) {} }

  async function boot() {
    try { S.manifest = await api("GET", `/api/runs/${encodeURIComponent(runId)}`); S.status = S.manifest.running ? "running" : S.manifest.status; } catch (e) {}
    renderHeader(); renderTabs(); renderTab();
    fetchRecon();
    // SSE:从 seq 0 重放历史事件(重建 findings/coverage/risks/log)再接实时;EventSource 断线自动带 Last-Event-ID 续传
    const es = new EventSource(`/api/runs/${encodeURIComponent(runId)}/events`);
    window._es = es;
    const TYPES = ["run_status", "metrics", "usage", "candidate_found", "finding_confirmed", "risk_added", "surface_added", "coverage_update", "round_start", "round_done", "recon_done", "run_done", "log", "decompose_done", "poc_done", "error"];
    for (const t of TYPES) es.addEventListener(t, (e) => { try { applyEvent(JSON.parse(e.data)); } catch (_) {} });
    es.onerror = () => { /* EventSource 自动重连 */ };
  }
  boot();
}
