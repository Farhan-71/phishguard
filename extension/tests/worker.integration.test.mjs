// Runs the REAL service worker against a REAL running backend, with a faked chrome.* API.
// Skipped unless PG_SCAN_KEY (and a reachable PG_API) are provided.
import test from "node:test";
import assert from "node:assert/strict";
import { installFakeChrome, serverUp, API, ADMIN_KEY, SCAN_KEY } from "./helpers/fake-chrome.mjs";

const up = await serverUp();
const opts = { skip: up ? false : "backend not running (set PG_API, PG_SCAN_KEY)" };
const env = installFakeChrome();
if (up) await import("../background/service_worker.js");

const PHISH = "http://paypal.com.secure-login.evil-site.top/signin/verify.php?session=SECRET123&email=victim@example.com#access_token=TOK";
const res = (tab) => env.session[`res:${tab}`];

test("benign page: green badge, no interception", opts, async () => {
  await env.nav(1, "https://www.wikipedia.org/");
  const r = await env.waitFor(() => res(1)?.result);
  assert.equal(r.risk_level, "low");
  assert.equal(env.calls.badge.at(-1).text, "✓");
  assert.equal(env.calls.tabsUpdate.filter(([id]) => id === 1).length, 0);
});

test("phishing page: interstitial shown, original URL kept for 'proceed'", opts, async () => {
  await env.nav(2, PHISH);
  await env.waitFor(() => env.session["warn:2"]);
  const [, upd] = env.calls.tabsUpdate.find(([id]) => id === 2);
  assert.equal(upd.url, "chrome-extension://testextensionid/warning/warning.html");
  assert.equal(res(2).result.risk_level, "high");
  assert.equal(env.calls.badge.at(-1).text, "!!");
  assert.equal(env.session["warn:2"].originalUrl, PHISH);
});

test("privacy: secrets never leave the browser or reach the database", opts, async () => {
  const sent = env.calls.fetch.filter((u) => u.includes("/scan"));
  assert.ok(sent.length >= 2);
  const r = res(2).result;
  for (const secret of ["SECRET123", "victim", "TOK"]) assert.ok(!r.url.includes(secret));
  if (ADMIN_KEY) {
    const rows = await (await fetch(`${API}/api/v1/admin/scans?limit=50`, { headers: { "X-API-Key": ADMIN_KEY } })).json();
    const stored = rows.map((x) => x.url).join("\n");
    assert.ok(stored.includes("evil-site.top") && !stored.includes("SECRET123") && !stored.includes("victim"));
  }
});

test("local/private/browser pages are never sent to the service", opts, async () => {
  const before = env.calls.fetch.length;
  for (const [tab, url] of [[3, "http://localhost:3000/login"], [4, "http://192.168.0.1/"], [5, "chrome://settings"], [6, "http://intranet/x"]]) {
    await env.nav(tab, url);
  }
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(env.calls.fetch.length, before);
});

test("redirected navigation forwards the first hop", opts, async () => {
  await env.nav(7, "https://landing.example.net/page", ["server_redirect"], "https://bit.ly/abc");
  const r = await env.waitFor(() => res(7)?.result);
  assert.deepEqual(r.evidence.redirect_chain, ["bit.ly"]);
});

test("'proceed' permanently allow-lists the host and does not re-block", opts, async () => {
  const ok = await env.send({ type: "proceed", tabId: 2 });
  assert.equal(ok.ok, true);
  assert.deepEqual(env.local.allow, ["paphish".replace("paphish", "paypal.com.secure-login.evil-site.top")]);
  const last = env.calls.tabsUpdate.at(-1);
  assert.equal(last[1].url, PHISH);
  const n = env.calls.tabsUpdate.length;
  await env.nav(2, PHISH);
  await env.waitFor(() => res(2)?.result);
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(env.calls.tabsUpdate.length, n, "must not show the warning again after the user proceeded");
});

test("messages from other senders are ignored", opts, async () => {
  assert.equal(await env.send({ type: "getResult", tabId: 1 }, "some-other-extension"), undefined);
});

test("fails open when the service is down or the key is wrong", opts, async () => {
  env.local.apiBase = "http://127.0.0.1:9";
  await env.nav(8, "https://down.example.org/");
  let r = await env.waitFor(() => res(8));
  assert.equal(r.error.code, "network");
  assert.equal(env.calls.tabsUpdate.filter(([id]) => id === 8).length, 0);
  assert.equal(env.calls.badge.at(-1).text, "?");

  env.local.apiBase = API; env.local.apiKey = "definitely-not-the-key-000";
  await env.nav(9, "https://wrongkey.example.org/");
  r = await env.waitFor(() => res(9));
  assert.equal(r.error.code, "auth");
  env.local.apiKey = SCAN_KEY;
});

test("report round-trip reaches the backend", opts, async () => {
  const r = res(1).result;
  const out = await env.send({ type: "report", scanId: r.scan_id, reportType: "false_negative", comment: "integration test" });
  if (!out.ok) console.error("Report test failed:", out.message);
  assert.equal(out.ok, true);
  assert.ok(out.id > 0);
});
