import { splitDisplayHost } from "../shared/url.js";

const $ = (id) => document.getElementById(id);
const send = (msg) => chrome.runtime.sendMessage(msg);

function h(tag, text, cls) { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; }

(async () => {
  const tab = await chrome.tabs.getCurrent();
  const w = await send({ type: "getWarning", tabId: tab.id });
  if (!w) { $("lead").textContent = "This warning has expired. Close this tab or reload the site you were visiting."; return; }
  const r = w.result;
  const { rest, registered } = splitDisplayHost(r.host, r.registered_domain);
  const addr = $("addr"); addr.classList.add("addr");
  if (rest) addr.append(Object.assign(h("span", rest, "rest")));
  addr.append(registered);

  const list = h("ul");
  for (const i of r.indicators.filter((x) => x.weight > 0).slice(0, 4)) list.append(h("li", i.title));
  $("why").append(h("strong", `Risk score ${r.risk_score} of 100. Main reasons:`), list);

  $("leave").addEventListener("click", () => send({ type: "leave", tabId: tab.id }));
  $("proceed").addEventListener("click", () => send({ type: "proceed", tabId: tab.id }));
  $("analysis").addEventListener("click", (e) => {
    const d = $("details");
    if (!d.hidden) { d.hidden = true; e.target.setAttribute("aria-expanded", "false"); return; }
    d.replaceChildren();
    const dl = h("dl");
    const sc = r.scoring, m = r.evidence.model, ti = r.evidence.threat_intel;
    const rows = [["Full address", r.url], ["Score", `classifier ${sc.ml} + rules ${sc.heuristics} + threat intel ${sc.threat_intel}`],
      ["Threat intel", ti.exact_match ? `listed (${ti.sources.join(", ")})` : ti.host_match ? "other pages on this site are listed" : "no match"]];
    if (m) rows.push(["Classifier", `${m.algorithm.replaceAll("_", " ")}: ${(m.probability_adjusted * 100).toFixed(0)}% likelihood`]);
    for (const f of m?.top_features || []) rows.push([f.title, f.detail]);
    for (const [k, v] of rows) { dl.append(h("dt", k), h("dd", v)); }
    d.append(dl); d.hidden = false; e.target.setAttribute("aria-expanded", "true");
  });
})();
