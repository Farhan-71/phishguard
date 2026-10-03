// Minimal but faithful in-memory stand-in for the chrome.* APIs the extension uses.
export const API = process.env.PG_API || "http://127.0.0.1:8000";
export const SCAN_KEY = process.env.PG_SCAN_KEY || "";
export const ADMIN_KEY = process.env.PG_ADMIN_KEY || "";

export async function serverUp() {
  try { return (await fetch(API + "/api/v1/health")).ok && !!SCAN_KEY; } catch { return false; }
}

export function installFakeChrome(overrides = {}) {
  const local = { apiBase: API, apiKey: SCAN_KEY, blockHigh: true, banner: false, ...overrides };
  const session = {};
  const calls = { tabsUpdate: [], badge: [], fetch: [] };
  const on = { before: [], committed: [], message: [] };

  const realFetch = globalThis.fetch;
  globalThis.fetch = (...a) => { calls.fetch.push(String(a[0])); return realFetch(...a); };

  const pick = (store, k) => (k == null ? { ...store } : typeof k === "string" ? (k in store ? { [k]: store[k] } : {})
    : Array.isArray(k) ? Object.fromEntries(k.filter((x) => x in store).map((x) => [x, store[x]])) : { ...k, ...Object.fromEntries(Object.keys(k).filter((x) => x in store).map((x) => [x, store[x]])) });

  const chrome = {
    runtime: {
      id: "testextensionid", getURL: (p = "") => `chrome-extension://testextensionid/${p}`,
      onMessage: { addListener: (f) => on.message.push(f) }, onInstalled: { addListener() {} },
      openOptionsPage() {}, sendMessage: (m) => send(m),
    },
    storage: {
      local: { get: async (d) => ({ ...d, ...local }), set: async (o) => Object.assign(local, o) },
      session: { get: async (k) => pick(session, k), set: async (o) => Object.assign(session, o),
                 remove: async (k) => { for (const x of [].concat(k)) delete session[x]; } },
      onChanged: { addListener() {} },
    },
    webNavigation: { onBeforeNavigate: { addListener: (f) => on.before.push(f) }, onCommitted: { addListener: (f) => on.committed.push(f) } },
    tabs: { update: (id, p) => { calls.tabsUpdate.push([id, p]); }, onRemoved: { addListener() {} }, sendMessage: async () => {},
            query: async () => [{ id: 1 }], getCurrent: async () => ({ id: 1 }) },
    action: { setBadgeText: (o) => calls.badge.push(o), setBadgeBackgroundColor() {} },
    scripting: { getRegisteredContentScripts: async () => [], registerContentScripts: async () => {}, unregisterContentScripts: async () => {} },
    permissions: { contains: async () => false },
  };
  globalThis.chrome = chrome;

  // deliver a message the way Chrome does: from an extension page with our id
  function send(msg, senderId = chrome.runtime.id) {
    return new Promise((resolve) => {
      let answered = false;
      for (const f of on.message) {
        const keep = f(msg, { id: senderId }, (r) => { answered = true; resolve(r); });
        if (keep === false) { /* listener declined */ }
      }
      setTimeout(() => { if (!answered) resolve(undefined); }, 200);
    });
  }

  const nav = async (tabId, url, qualifiers = [], initialUrl = url) => {
    for (const f of on.before) f({ tabId, frameId: 0, url: initialUrl });
    for (const f of on.committed) f({ tabId, frameId: 0, url, transitionQualifiers: qualifiers });
  };
  const waitFor = async (fn, ms = 4000) => {
    const t0 = Date.now();
    while (Date.now() - t0 < ms) { const v = await fn(); if (v) return v; await new Promise((r) => setTimeout(r, 25)); }
    throw new Error("timed out waiting for condition");
  };
  return { chrome, local, session, calls, send, nav, waitFor };
}
