// URL helpers shared by the service worker, popup and tests.
// sanitizeUrl mirrors backend/services/url_utils.py::sanitize_url (checked against the
// shared vectors in tests/vectors/sanitize.json). The server re-sanitises everything, so
// this is data minimisation on the client, not the security boundary.

export const MAX_URL_LENGTH = 2048;
export const MAX_QUERY_PARAMS = 50;

export function sanitizeUrl(raw) {
  if (typeof raw !== "string") throw new Error("URL must be a string");
  const s = raw.trim();
  if (!s) throw new Error("URL is empty");
  if (s.length > MAX_URL_LENGTH) throw new Error("URL too long");
  let u;
  try { u = new URL(s); } catch { throw new Error("Malformed URL"); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Unsupported scheme");
  if (!u.hostname) throw new Error("URL has no host");
  u.hash = "";
  u.password = "";
  const kept = [];
  for (const seg of u.search.slice(1).split("&")) {
    if (!seg) continue;
    const i = seg.indexOf("=");
    kept.push(i === -1 ? seg : seg.slice(0, i) + "=");
    if (kept.length >= MAX_QUERY_PARAMS) break;
  }
  u.search = kept.join("&");
  return u.toString();
}

export function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase().replace(/\.$/, ""); } catch { return ""; }
}

const PRIVATE_V4 = [/^10\./, /^127\./, /^169\.254\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^0\./, /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./];
const LOCAL_SUFFIXES = [".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".intranet", ".test"];

// Local/private hosts are never scanned or sent anywhere.
export function isLocalHost(host) {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (!h) return true;
  if (h === "localhost" || LOCAL_SUFFIXES.some((s) => h.endsWith(s))) return true;
  if (/^[\d.]+$/.test(h)) return PRIVATE_V4.some((r) => r.test(h));
  if (h.includes(":")) return h === "::1" || h === "::" || /^f[cd]/.test(h) || /^fe[89ab]/.test(h);
  return !h.includes(".");
}

export function isScannable(url) {
  try {
    const u = new URL(url);
    return (u.protocol === "http:" || u.protocol === "https:") && !isLocalHost(u.hostname);
  } catch { return false; }
}

// Rough registrable-domain guess for redirect comparison only (server is authoritative).
export function guessRegistered(host) {
  const p = host.split(".");
  const twoLevel = new Set(["co", "com", "org", "net", "gov", "ac", "edu"]);
  return p.length >= 3 && twoLevel.has(p[p.length - 2]) && p[p.length - 1].length === 2
    ? p.slice(-3).join(".") : p.slice(-2).join(".");
}

// webNavigation only exposes the first and last hop of a redirected navigation.
export function redirectHosts(initialUrl, finalUrl, qualifiers = []) {
  if (!initialUrl || !qualifiers.some((q) => q === "server_redirect" || q === "client_redirect")) return [];
  const a = hostOf(initialUrl), b = hostOf(finalUrl);
  if (!a || a === b || isLocalHost(a)) return [];
  return [a];
}

// Splits "a.b.evil-site.top" into { rest: "a.b.", registered: "evil-site.top" } so the UI can
// emphasise the part of the address that actually identifies the site.
export function splitDisplayHost(host, registered) {
  if (registered && host.endsWith(registered) && host !== registered) {
    return { rest: host.slice(0, host.length - registered.length), registered };
  }
  return { rest: "", registered: host };
}
