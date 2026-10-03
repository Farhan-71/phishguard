// PhishGuard console. No build step, no external requests except same-origin
// /api/v1/admin/* (the page's own CSP forbids anything else). The admin key
// lives only in sessionStorage for this tab; it is never written to disk here.
"use strict";

const API = "/api/v1/admin";
const state = { key: sessionStorage.getItem("pg_admin_key") || "", days: 30, scansOffset: 0, scansLevel: "" };

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtTime = (iso) => { try { return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); } catch { return iso; } };
const fmtPct = (x) => `${Math.round(x * 100)}%`;

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    ...opts,
    headers: { "X-API-Key": state.key, "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  setConn(res.status !== 0);
  if (res.status === 401 || res.status === 403) { signOut("Key rejected by the server."); throw new Error("auth"); }
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch { /* ignore */ }
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

function setConn(ok) {
  const dot = $("#conn-dot");
  if (dot) dot.className = "dot " + (ok ? "ok" : "bad");
}

// ------------------------------------------------------------------- auth
function signOut(msg) {
  sessionStorage.removeItem("pg_admin_key");
  state.key = "";
  $("#app").hidden = true;
  $("#gate").hidden = false;
  const err = $("#gate-error");
  if (msg) { err.textContent = msg; err.hidden = false; } else { err.hidden = true; }
}

async function tryEnter(key) {
  state.key = key;
  try {
    await api("/events?limit=1");
    sessionStorage.setItem("pg_admin_key", key);
    $("#gate").hidden = true;
    $("#app").hidden = false;
    setConn(true);
    loadOverview();
  } catch (e) {
    signOut(e.message === "auth" ? "Invalid administrator key." : "Could not reach the API. Is the backend running?");
  }
}

$("#gate-form").addEventListener("submit", (e) => {
  e.preventDefault();
  tryEnter($("#gate-key").value.trim());
});
$("#signout").addEventListener("click", () => signOut());

// ------------------------------------------------------------------- tabs
$("#tabs").addEventListener("click", (e) => {
  const btn = e.target.closest(".tab");
  if (!btn) return;
  $$(".tab").forEach((t) => t.classList.toggle("active", t === btn));
  const view = btn.dataset.view;
  $$(".view").forEach((v) => (v.hidden = v.id !== `view-${view}`));
  if (view === "overview") loadOverview();
  if (view === "scans") loadScans(true);
  if (view === "intel") loadIntel();
  if (view === "reports") loadReports();
  if (view === "model") loadModel();
});

$("#range").addEventListener("change", (e) => { state.days = Number(e.target.value); loadOverview(); });

// -------------------------------------------------------------- SVG chart
function svgEl(tag, attrs) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

function stackedBarChart(container, rows, keys, colors) {
  container.innerHTML = "";
  if (!rows.length) { container.innerHTML = '<div class="chart-empty">No scans in this window.</div>'; return; }
  const W = 640, H = 160, pad = 24;
  const max = Math.max(1, ...rows.map((r) => keys.reduce((s, k) => s + (r[k] || 0), 0)));
  const bw = (W - pad * 2) / rows.length;
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none" });
  [0.25, 0.5, 0.75, 1].forEach((f) => {
    const y = H - pad - f * (H - pad * 2);
    svg.appendChild(svgEl("line", { x1: pad, x2: W - 4, y1: y, y2: y, stroke: "#1a252c", "stroke-width": 1 }));
  });
  rows.forEach((r, i) => {
    let y0 = H - pad;
    const x = pad + i * bw + bw * 0.15;
    const w = bw * 0.7;
    keys.forEach((k, ki) => {
      const v = r[k] || 0;
      const h = (v / max) * (H - pad * 2);
      if (h > 0) svg.appendChild(svgEl("rect", { x, y: y0 - h, width: w, height: h, fill: colors[ki], rx: 1 }));
      y0 -= h;
    });
  });
  const step = Math.max(1, Math.ceil(rows.length / 7));
  rows.forEach((r, i) => {
    if (i % step !== 0 && i !== rows.length - 1) return;
    const x = pad + i * bw + bw / 2;
    const t = svgEl("text", { x, y: H - 6, "font-size": 9, fill: "#5b6e78", "text-anchor": "middle" });
    t.textContent = (r.date || "").slice(5);
    svg.appendChild(t);
  });
  container.appendChild(svg);
}

function histogram(container, values, buckets = 10, color = "#4fd4c8") {
  container.innerHTML = "";
  if (!values.length) { container.innerHTML = '<div class="chart-empty">No data yet.</div>'; return; }
  const counts = new Array(buckets).fill(0);
  values.forEach((v) => counts[Math.min(buckets - 1, Math.floor((v / 100) * buckets))]++);
  const W = 640, H = 160, pad = 24;
  const max = Math.max(1, ...counts);
  const bw = (W - pad * 2) / buckets;
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none" });
  counts.forEach((c, i) => {
    const h = (c / max) * (H - pad * 2);
    const x = pad + i * bw + bw * 0.1;
    const fill = i >= 6 ? "#e0574a" : i >= 3 ? "#e0a840" : color;
    svg.appendChild(svgEl("rect", { x, y: H - pad - h, width: bw * 0.8, height: h, fill, rx: 1 }));
  });
  [0, 30, 60, 100].forEach((v) => {
    const x = pad + (v / 100) * (W - pad * 2);
    const t = svgEl("text", { x, y: H - 6, "font-size": 9, fill: "#5b6e78", "text-anchor": "middle" });
    t.textContent = v;
    svg.appendChild(t);
  });
  container.appendChild(svg);
}

// -------------------------------------------------------------- overview
async function loadOverview() {
  let stats;
  try { stats = await api(`/stats?days=${state.days}`); } catch { return; }

  const t = stats.totals;
  $("#kpi-cards").innerHTML = `
    <div class="kpi"><div class="kpi-label">Total scans</div><div class="kpi-value">${t.scans.toLocaleString()}</div></div>
    <div class="kpi low"><div class="kpi-label">Low risk</div><div class="kpi-value">${t.low.toLocaleString()}</div></div>
    <div class="kpi medium"><div class="kpi-label">Suspicious</div><div class="kpi-value">${t.medium.toLocaleString()}</div></div>
    <div class="kpi high"><div class="kpi-label">High risk</div><div class="kpi-value">${t.high.toLocaleString()}</div></div>
    <div class="kpi"><div class="kpi-label">p95 latency</div><div class="kpi-value">${stats.latency_ms.p95}<span style="font-size:13px;color:var(--ink-faint)">ms</span></div></div>
  `;

  $("#timeline-sub").textContent = `${stats.window_days}-day window`;
  stackedBarChart($("#timeline-chart"), stats.timeline, ["low", "medium", "high"], ["#2c6a64", "#e0a840", "#e0574a"]);
  $("#timeline-legend").innerHTML =
    '<span><i style="background:#2c6a64"></i>Low</span><span><i style="background:#e0a840"></i>Suspicious</span><span><i style="background:#e0574a"></i>High</span>';

  histogram($("#dist-chart"), stats.scan_distribution);

  const maxCount = Math.max(1, ...stats.top_indicators.map((i) => i.count));
  $("#indicator-bars").innerHTML = stats.top_indicators.length
    ? stats.top_indicators.map((i) => `
        <div class="bar-row-wrap">
          <div class="bar-label"><span>${esc(i.title)}</span><b>${i.count}</b></div>
          <div class="bar-track"><div class="bar-fill" style="width:${(i.count / maxCount) * 100}%"></div></div>
        </div>`).join("")
    : '<div class="chart-empty">No indicators triggered yet.</div>';

  const evRows = Object.entries(stats.security_events_24h || {});
  $("#events-table tbody").innerHTML = evRows.length
    ? evRows.map(([k, v]) => `<tr><td>${esc(k.replace(/_/g, " "))}</td><td>${v}</td></tr>`).join("")
    : '<tr><td colspan="2" class="table-empty">No security events in the last 24h.</td></tr>';

  $("#threats-table tbody").innerHTML = stats.recent_threats.length
    ? stats.recent_threats.map((s) => `
        <tr>
          <td class="mono">${fmtTime(s.created_at)}</td>
          <td class="url-cell" title="${esc(s.url)}">${esc(s.url)}</td>
          <td class="mono">${s.risk_score}</td>
          <td>${intelBadge(s.intel_match)}</td>
        </tr>`).join("")
    : '<tr><td colspan="4" class="table-empty">No high-risk scans in this window.</td></tr>';
}

function intelBadge(m) {
  if (m === "exact") return '<span class="badge exact">exact match</span>';
  if (m === "host") return '<span class="badge host">host match</span>';
  if (m === "allow") return '<span class="badge allow">allow-listed</span>';
  return '<span class="badge neutral">none</span>';
}
function levelBadge(l) { return `<span class="badge ${l}">${l}</span>`; }

// ------------------------------------------------------------------ scans
async function loadScans(reset) {
  if (reset) { state.scansOffset = 0; $("#scans-table tbody").innerHTML = ""; }
  const level = $("#scan-level").value;
  const params = new URLSearchParams({ limit: "50", offset: String(state.scansOffset) });
  if (level) params.set("level", level);
  let rows;
  try { rows = await api(`/scans?${params}`); } catch { return; }
  const body = $("#scans-table tbody");
  if (reset && !rows.length) body.innerHTML = '<tr><td colspan="8" class="table-empty">No scans recorded yet.</td></tr>';
  else if (reset) body.innerHTML = "";
  body.insertAdjacentHTML("beforeend", rows.map((s) => `
    <tr>
      <td class="mono">${fmtTime(s.created_at)}</td>
      <td class="url-cell" title="${esc(s.url)}">${esc(s.url)}</td>
      <td class="mono">${esc(s.host)}</td>
      <td class="mono">${s.risk_score}</td>
      <td>${levelBadge(s.risk_level)}</td>
      <td>${intelBadge(s.intel_match)}</td>
      <td class="mono">${esc(s.model_version || "—")}</td>
      <td class="mono">${s.latency_ms}ms</td>
    </tr>`).join(""));
  state.scansOffset += rows.length;
  $("#scans-more").hidden = rows.length < 50;
}
$("#scan-level").addEventListener("change", () => loadScans(true));
$("#scan-refresh").addEventListener("click", () => loadScans(true));
$("#scans-more").addEventListener("click", () => loadScans(false));

// ------------------------------------------------------------------ intel
async function loadIntel() {
  const verdict = $("#intel-verdict").value;
  const params = new URLSearchParams({ limit: "100" });
  if (verdict) params.set("verdict", verdict);
  let rows;
  try { rows = await api(`/indicators?${params}`); } catch { return; }
  const body = $("#intel-table tbody");
  body.innerHTML = rows.length ? rows.map((r) => `
    <tr data-id="${r.id}">
      <td class="mono">${r.kind}</td>
      <td class="url-cell" title="${esc(r.value)}">${esc(r.value)}</td>
      <td>${r.verdict === "malicious" ? '<span class="badge high">malicious</span>' : '<span class="badge low">allow</span>'}</td>
      <td class="mono">${esc(r.source)}</td>
      <td class="mono">${fmtTime(r.added_at)}</td>
      <td class="mono">${r.expires_at ? fmtTime(r.expires_at) : "never"}</td>
      <td><button class="icon-btn" data-del="${r.id}">Remove</button></td>
    </tr>`).join("") : '<tr><td colspan="7" class="table-empty">No indicators yet — add one or import a feed.</td></tr>';
}
$("#intel-verdict").addEventListener("change", loadIntel);
$("#intel-refresh").addEventListener("click", loadIntel);
$("#intel-table").addEventListener("click", async (e) => {
  const id = e.target.dataset.del;
  if (!id) return;
  if (!confirm("Remove this indicator?")) return;
  try { await api(`/indicators/${id}`, { method: "DELETE" }); loadIntel(); } catch (err) { alert(err.message); }
});

function formMsg(el, ok, text) {
  el.hidden = false;
  el.className = "form-msg " + (ok ? "ok" : "err");
  el.textContent = text;
}

$("#indicator-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const kindRaw = f.get("kind");
  const body = {
    kind: kindRaw === "domain-allow" ? "domain" : kindRaw,
    value: f.get("value").trim(),
    verdict: kindRaw === "domain-allow" ? "allow" : "malicious",
    source: f.get("source").trim() || "manual",
    ttl_days: f.get("ttl_days") ? Number(f.get("ttl_days")) : null,
  };
  const msg = $("#indicator-msg");
  try {
    await api("/indicators", { method: "POST", body: JSON.stringify(body) });
    formMsg(msg, true, "Indicator added.");
    e.target.reset();
    loadIntel();
  } catch (err) { formMsg(msg, false, err.message); }
});

$("#feed-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const urls = f.get("urls").split("\n").map((s) => s.trim()).filter(Boolean);
  const msg = $("#feed-msg");
  if (!urls.length) { formMsg(msg, false, "Add at least one URL."); return; }
  try {
    const res = await api("/indicators/import", {
      method: "POST",
      body: JSON.stringify({ source: f.get("source").trim(), urls, ttl_days: Number(f.get("ttl_days")) || 30 }),
    });
    formMsg(msg, true, `Imported: ${res.added} new, ${res.refreshed} refreshed, ${res.received - res.valid} invalid.`);
    e.target.reset();
    loadIntel();
  } catch (err) { formMsg(msg, false, err.message); }
});

// ---------------------------------------------------------------- reports
async function loadReports() {
  const status = $("#report-status").value;
  const params = new URLSearchParams({ limit: "100" });
  if (status) params.set("status", status);
  let rows;
  try { rows = await api(`/reports?${params}`); } catch { return; }
  $("#reports-table tbody").innerHTML = rows.length ? rows.map((r) => `
    <tr data-id="${r.id}">
      <td class="mono">${fmtTime(r.created_at)}</td>
      <td class="url-cell" title="${esc(r.url)}">${esc(r.url)}</td>
      <td class="mono">${r.report_type.replace("_", " ")}</td>
      <td>${esc(r.comment || "—")}</td>
      <td><span class="badge ${r.status === "open" ? "medium" : r.status === "resolved" ? "low" : "neutral"}">${r.status}</span></td>
      <td>
        ${r.status !== "resolved" ? `<button class="link-btn" data-act="resolved" data-id="${r.id}">Resolve</button>` : ""}
        ${r.status !== "rejected" ? `<button class="link-btn" data-act="rejected" data-id="${r.id}" style="margin-left:8px;color:var(--ink-dim)">Reject</button>` : ""}
      </td>
    </tr>`).join("") : '<tr><td colspan="6" class="table-empty">No reports match this filter.</td></tr>';
}
$("#report-status").addEventListener("change", loadReports);
$("#report-refresh").addEventListener("click", loadReports);
$("#reports-table").addEventListener("click", async (e) => {
  const act = e.target.dataset.act, id = e.target.dataset.id;
  if (!act) return;
  try { await api(`/reports/${id}`, { method: "PATCH", body: JSON.stringify({ status: act }) }); loadReports(); }
  catch (err) { alert(err.message); }
});

// ------------------------------------------------------------------ model
async function loadModel() {
  const el = $("#model-content");
  let m;
  try { m = await api("/model"); }
  catch { el.innerHTML = '<div class="panel"><p class="chart-empty">No model metrics available. Train a model with <code>python -m ml.training.train</code>.</p></div>'; return; }

  const warn = m.warning ? `<div class="model-note">⚠ ${esc(m.warning)}</div>` : "";
  const fm = m.test_metrics_final;
  const cm = fm.confusion_matrix;
  el.innerHTML = `
    ${warn}
    <div class="model-grid">
      <div class="kpi"><div class="kpi-label">Algorithm</div><div class="kpi-value" style="font-size:16px">${esc(m.selected_algorithm)}</div></div>
      <div class="kpi"><div class="kpi-label">Version</div><div class="kpi-value" style="font-size:16px">${esc(m.model_version)}</div></div>
      <div class="kpi"><div class="kpi-label">Precision</div><div class="kpi-value">${fmtPct(fm.precision)}</div></div>
      <div class="kpi"><div class="kpi-label">Recall</div><div class="kpi-value">${fmtPct(fm.recall)}</div></div>
      <div class="kpi"><div class="kpi-label">F1</div><div class="kpi-value">${fmtPct(fm.f1)}</div></div>
      <div class="kpi"><div class="kpi-label">PR-AUC</div><div class="kpi-value">${fmtPct(fm.average_precision)}</div></div>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>Test-split confusion matrix</h2><span class="panel-sub">threshold 0.5</span></div>
      <table class="model-table">
        <thead><tr><th></th><th class="n">Predicted benign</th><th class="n">Predicted phishing</th></tr></thead>
        <tbody>
          <tr><th>Actual benign</th><td class="n">${cm.tn}</td><td class="n">${cm.fp}</td></tr>
          <tr><th>Actual phishing</th><td class="n">${cm.fn}</td><td class="n">${cm.tp}</td></tr>
        </tbody>
      </table>
      <p class="panel-sub">Dataset: ${m.dataset.source} — ${m.dataset.rows.toLocaleString()} rows
        (${m.dataset.phishing.toLocaleString()} phishing / ${m.dataset.benign.toLocaleString()} benign),
        split by registered domain (${m.dataset.split_strategy}).</p>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>Top features (${esc(m.selected_algorithm)})</h2></div>
      <div id="feature-bars"></div>
    </div>
  `;
  const importance = m.feature_importance[m.selected_algorithm] || {};
  const top = Object.entries(importance).sort((a, b) => b[1] - a[1]).slice(0, 12);
  const maxV = Math.max(1e-9, ...top.map(([, v]) => v));
  $("#feature-bars").innerHTML = top.map(([name, v]) => `
    <div class="bar-row-wrap">
      <div class="bar-label"><span>${esc(name)}</span><b>${(v * 100).toFixed(1)}%</b></div>
      <div class="bar-track"><div class="bar-fill" style="width:${(v / maxV) * 100}%"></div></div>
    </div>`).join("");
}

// ------------------------------------------------------------------- init
if (state.key) tryEnter(state.key);
