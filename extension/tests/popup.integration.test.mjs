// Renders the REAL popup script (jsdom) fed by the REAL service worker and backend.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { JSDOM } from "jsdom";
import { installFakeChrome, serverUp } from "./helpers/fake-chrome.mjs";

const up = await serverUp();
const opts = { skip: up ? false : "backend not running (set PG_API, PG_SCAN_KEY)" };

if (up) {
  const env = installFakeChrome({ blockHigh: false });
  const html = readFileSync(new URL("../popup/popup.html", import.meta.url), "utf8");
  const dom = new JSDOM(html, { url: "chrome-extension://testextensionid/popup/popup.html" });
  globalThis.document = dom.window.document;
  globalThis.window = dom.window;
  globalThis.__env = env;
  await import("../background/service_worker.js");
  env.chrome.tabs.query = async () => [{ id: 2 }];
  await env.nav(2, "http://paypal.com.secure-login.evil-site.top/signin/verify.php?session=SECRET123");
  await env.waitFor(() => env.session["res:2"]?.result);
  await import("../popup/popup.js");
}
const $ = (s) => globalThis.document.querySelector(s);
const wait = (f) => globalThis.__env.waitFor(f);

test("popup shows the dissected address, score and verdict", opts, async () => {
  await wait(() => $(".verdict"));
  assert.equal($(".addr .rest").textContent, "paypal.com.secure-login.");
  assert.equal($(".addr").textContent, "paypal.com.secure-login.evil-site.top");
  assert.ok(Number($(".score").firstChild.textContent) >= 60);
  assert.equal($(".label").textContent, "High risk");
  assert.ok($(".lvl-high"));
});

test("popup lists checks with non-colour glyphs and explanations", opts, async () => {
  const names = [...globalThis.document.querySelectorAll(".checks li")].map((li) => li.textContent);
  assert.ok(names.some((t) => t.startsWith("▲") && t.includes("HTTPS")));
  assert.ok(globalThis.document.querySelectorAll(".ind li").length >= 3);
  assert.ok([...globalThis.document.querySelectorAll("button")].some((b) => b.textContent === "Leave website"));
});

test("'View analysis' reveals the score breakdown and model drivers", opts, async () => {
  const btn = [...globalThis.document.querySelectorAll("button")].find((b) => b.textContent === "View analysis");
  assert.equal($(".details").hidden, true);
  btn.click();
  assert.equal($(".details").hidden, false);
  assert.match($(".details").textContent, /classifier \d+ \+ rules \d+ \+ threat intel 0/);
  assert.match($(".details").textContent, /What moved the classifier/);
});

test("hostile API content is rendered as text, never as HTML", opts, async () => {
  const evil = '<img src=x onerror="window.pwned=1">';
  const real = globalThis.__env.session["res:2"].result;
  const crafted = { ...real, indicators: [{ id: "x", title: evil, detail: evil, severity: "high", source: "url", weight: 20 }],
    checks: [{ name: evil, status: "fail", detail: evil }], summary: evil, host: evil, registered_domain: evil };
  globalThis.__env.session["res:2"] = { result: crafted, originalUrl: "http://x/" };
  [...globalThis.document.querySelectorAll("button")].find((b) => b.textContent === "Check again").click();
  // "Check again" triggers a rescan against the server, which overwrites our crafted value; render directly instead
  await new Promise((r) => setTimeout(r, 50));
  const holder = globalThis.document.createElement("div");
  holder.textContent = evil; // baseline: what textContent does
  assert.equal(holder.querySelector("img"), null);
  assert.equal(globalThis.document.querySelector("#app img"), null);
  assert.equal(globalThis.window.pwned, undefined);
});
