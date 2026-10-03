import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { sanitizeUrl, isLocalHost, isScannable, redirectHosts, splitDisplayHost, guessRegistered } from "../shared/url.js";

const vec = JSON.parse(readFileSync(new URL("../../tests/vectors/sanitize.json", import.meta.url)));

for (const c of vec.valid) {
  test(`sanitize: ${c.input.slice(0, 50)}`, () => assert.equal(sanitizeUrl(c.input), c.expected));
}
for (const bad of vec.invalid) {
  test(`reject: ${JSON.stringify(bad)}`, () => assert.throws(() => sanitizeUrl(bad)));
}

test("secrets never survive sanitisation", () => {
  const s = sanitizeUrl("https://bob:hunter2@shop.example.com/cb?session=abc123&email=a@b.c#access_token=xyz");
  for (const secret of ["hunter2", "abc123", "a@b.c", "xyz"]) assert.ok(!s.includes(secret), secret);
});

test("local and private hosts are not scannable", () => {
  for (const h of ["localhost", "127.0.0.1", "192.168.0.1", "10.1.2.3", "172.20.0.1", "169.254.169.254", "intranet", "printer.local", "::1", "[::1]"]) {
    assert.ok(isLocalHost(h), h);
  }
  for (const h of ["example.com", "8.8.8.8", "172.32.0.1", "evil.github.io"]) assert.ok(!isLocalHost(h), h);
  assert.ok(!isScannable("chrome://settings"));
  assert.ok(!isScannable("http://localhost:3000/"));
  assert.ok(isScannable("https://example.com/"));
});

test("redirect hosts only for redirected navigations that change site", () => {
  assert.deepEqual(redirectHosts("https://bit.ly/x", "https://evil.top/", ["server_redirect"]), ["bit.ly"]);
  assert.deepEqual(redirectHosts("https://a.com/", "https://a.com/x", ["server_redirect"]), []);
  assert.deepEqual(redirectHosts("https://bit.ly/x", "https://evil.top/", []), []);
  assert.deepEqual(redirectHosts("http://localhost/x", "https://evil.top/", ["server_redirect"]), []);
});

test("address is split so the registered domain can be emphasised", () => {
  assert.deepEqual(splitDisplayHost("paypal.com.secure-login.evil-site.top", "evil-site.top"),
    { rest: "paypal.com.secure-login.", registered: "evil-site.top" });
  assert.deepEqual(splitDisplayHost("example.com", "example.com"), { rest: "", registered: "example.com" });
  assert.equal(guessRegistered("a.b.example.co.uk"), "example.co.uk");
  assert.equal(guessRegistered("www.example.com"), "example.com");
});
