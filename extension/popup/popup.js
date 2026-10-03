import { splitDisplayHost } from "../shared/url.js";

const app = document.getElementById("app");
const GLYPH = { pass: ["✓", "passed"], warn: ["▲", "warning"], fail: ["✕", "failed"], unknown: ["–", "unknown"], info: ["•", "info"] };
const SRC = { threat_intel: "Threat intelligence", model: "Classifier", domain: "Domain & certificate",
              url: "Address", redirect: "Redirects" };
const LEVEL = { low: "Low risk", medium: "Suspicious", high: "High risk" };

// Build DOM with textContent only: nothing from the API or the page is ever parsed as HTML.
function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") el.className = v; else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) el.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k != null) el.append(k.nodeType ? k : document.createTextNode(k));
  return el;
}
const send = (msg) => chrome.runtime.sendMessage(msg);
let tabId = null;

async function load(force = false) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  tabId = tab?.id;
  if (tabId == null) return render(null);
  render(force ? await send({ type: "rescan", tabId }) : await send({ type: "getResult", tabId }));
}

function render(data) {
  app.replaceChildren();
  if (!data) {
    return app.append(h("p", { class: "na" }, "This page is not assessed. PhishGuard skips browser pages, local and private addresses, and pages opened before it was installed."),
      h("button", { class: "btn", onclick: () => load(true) }, "Check again"));
  }
  if (data.error) return app.append(errorView(data.error));
  const r = data.result;
  if (r.not_applicable) return app.append(h("p", { class: "na" }, r.summary));

  const { rest, registered } = splitDisplayHost(r.host, r.registered_domain);
  const wrap = h("div", { class: `lvl-${r.risk_level}` });
  wrap.append(
    h("div", { class: "top" }, h("span", { class: "brand" }, "PhishGuard"),
      h("button", { class: "btn link", onclick: () => load(true) }, "Check again")),
    h("div", { class: "addr", title: r.url }, rest ? h("span", { class: "rest" }, rest) : null, registered),
    h("div", { class: "verdict" },
      h("span", { class: "score", "aria-label": `Risk score ${r.risk_score} out of 100` }, String(r.risk_score), h("small", {}, "/100")),
      h("span", { class: "label" }, LEVEL[r.risk_level])),
    ruler(r.risk_score),
    h("p", { class: "summary" }, r.summary),
    h("ul", { class: "checks" }, r.checks.map((c) => {
      const [g, word] = GLYPH[c.status] || GLYPH.info;
      return h("li", {}, h("span", { class: `g ${c.status}`, "aria-label": word }, g),
        h("span", {}, c.name, h("span", { class: "d" }, c.detail)));
    })),
  );
  const shown = r.indicators.filter((i) => i.weight > 0 || i.source === "threat_intel");
  if (shown.length) {
    wrap.append(h("h2", {}, "Why this score"), h("ul", { class: "ind" }, shown.map((i) =>
      h("li", { class: `s-${i.severity}` }, h("span", { class: "t" }, i.title, " "),
        h("span", { class: "src" }, `(${SRC[i.source] || i.source})`), h("span", { class: "dd" }, i.detail)))));
  }

  const details = h("div", { class: "details", hidden: true }, detailView(r));
  const actions = h("div", { class: "actions" });
  if (r.risk_level === "high") actions.append(h("button", { class: "btn primary", onclick: () => send({ type: "leave", tabId }) }, "Leave website"));
  actions.append(h("button", { class: "btn", "aria-expanded": "false", onclick: (e) => {
    details.hidden = !details.hidden; e.target.setAttribute("aria-expanded", String(!details.hidden)); } }, "View analysis"));
  wrap.append(actions, details);

  const toast = h("div", { class: "toast", role: "status" });
  const rep = (type) => async () => {
    const res = await send({ type: "report", scanId: r.scan_id, reportType: type });
    toast.textContent = res?.ok ? "Thanks, your report was sent." : `Could not send report: ${res?.message || "unknown error"}`;
  };
  wrap.append(h("div", { class: "foot" },
    r.risk_level === "low"
      ? h("button", { class: "btn link", onclick: rep("false_negative") }, "Report missed phishing")
      : h("button", { class: "btn link", onclick: rep("false_positive") }, "Report false alarm")), toast);
  app.append(wrap);
}

function ruler(score) {
  return h("div", { class: "ruler", role: "img", "aria-label": `Risk ruler: ${score} of 100. Suspicious from 30, high from 60.` },
    h("div", { class: "fill", style: `width:${score}%` }), h("div", { class: "mark", style: `left:${score}%` }),
    h("span", { class: "tick", style: "left:30%" }, "30"), h("span", { class: "tick", style: "left:60%" }, "60"));
}

function detailView(r) {
  const sc = r.scoring || {}, m = r.evidence?.model, d = r.evidence?.domain || {};
  const rows = [["Score breakdown", `classifier ${sc.ml ?? 0} + rules ${sc.heuristics ?? 0} + threat intel ${sc.threat_intel ?? 0}` + (sc.override ? ` (${sc.override.replaceAll("_", " ")})` : "")]];
  if (m) rows.push(["Classifier", `${m.algorithm.replaceAll("_", " ")}, estimated phishing likelihood ${(m.probability_adjusted * 100).toFixed(0)}%`]);
  else rows.push(["Classifier", "unavailable, rules only"]);
  rows.push(["Threat intel", r.evidence?.threat_intel?.exact_match ? "listed" : r.evidence?.threat_intel?.host_match ? "site partly listed" : "no match"]);
  if (d.rdap?.age_days != null) rows.push(["Domain age", `${d.rdap.age_days} days` + (d.rdap.registrar ? ` (${d.rdap.registrar})` : "")]);
  if (d.tls?.status === "ok") rows.push(["Certificate", `${d.tls.issuer || "unknown issuer"}, ${d.tls.days_to_expiry} days left`]);
  if (d.dns?.ns?.length) rows.push(["Nameservers", d.dns.ns.slice(0, 3).join(", ")]);
  const dl = h("dl", {}, rows.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  const out = [dl];
  if (m?.top_features?.length) {
    out.push(h("div", {}, h("strong", {}, "What moved the classifier"),
      h("ul", { class: "ind" }, m.top_features.map((f) => h("li", { class: "s-low" }, h("span", { class: "t" }, f.title),
        h("span", { class: "dd" }, `${f.detail} (+${Math.round(f.contribution * 100)} points of likelihood)`))))));
  }
  out.push(h("p", { class: "src" }, `Scan ${r.scan_id?.slice(0, 8)} · ${r.latency_ms} ms · scoring v${sc.scoring_version}`));
  return out;
}

function errorView(e) {
  const msg = { no_key: "Add your API key in the extension options to start checking pages.",
    auth: "The service rejected the API key. Check it in the options.",
    rate: "Too many checks in a short time. Try again in a minute.",
    network: "Pages are not being checked because the detection service can't be reached. Start it or fix the address in the options." }[e.code] || e.message;
  return h("div", { class: "err", role: "alert" }, h("strong", {}, "Not checked"), h("p", {}, msg),
    h("div", { class: "actions" },
      h("button", { class: "btn", onclick: () => chrome.runtime.openOptionsPage() }, "Open options"),
      h("button", { class: "btn", onclick: () => load(true) }, "Try again")));
}

load();
