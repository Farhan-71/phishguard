// PhishGuard service worker (Manifest V3). Stateless between wake-ups: all per-tab state
// lives in chrome.storage.session, which is cleared when the browser closes.
import { getConfig, scanUrl, sendReport, ApiError } from "../shared/api.js";
import { sanitizeUrl, hostOf, isScannable, redirectHosts } from "../shared/url.js";

const CACHE_TTL_MS = 10 * 60 * 1000;
const BADGE = {
  low: { text: "✓", color: "#2F7D5B" },
  medium: { text: "!", color: "#B7791F" },
  high: { text: "!!", color: "#B3372B" },
  error: { text: "?", color: "#6B7B7F" },
  none: { text: "", color: "#6B7B7F" },
};

const S = chrome.storage.session;
const get = async (k) => (await S.get(k))[k];
const set = (k, v) => S.set({ [k]: v });

function setBadge(tabId, kind) {
  const b = BADGE[kind] || BADGE.none;
  chrome.action.setBadgeText({ tabId, text: b.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
}

async function isApiHost(url) {
  const cfg = await getConfig();
  return hostOf(url) === hostOf(cfg.apiBase) && new URL(url).port === new URL(cfg.apiBase).port;
}

// ---------------------------------------------------------------- scanning
async function assess(tabId, url, qualifiers = []) {
  if (!isScannable(url) || (await isApiHost(url))) {
    await S.remove([`res:${tabId}`]);
    setBadge(tabId, "none");
    return null;
  }
  const cfg = await getConfig();
  const clean = sanitizeUrl(url);
  const initial = (await get(`nav:${tabId}`)) || {};
  const hops = redirectHosts(initial.url, url, qualifiers);

  const cacheKey = `cache:${clean}|${hops.join(",")}`;
  const cached = await get(cacheKey);
  let result;
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) {
    result = cached.result;
  } else {
    setBadge(tabId, "none");
    try {
      result = await scanUrl(cfg, clean, hops);
      await set(cacheKey, { at: Date.now(), result });
    } catch (e) {
      const err = e instanceof ApiError ? e : new ApiError("network", "Scan failed");

      // Telemetry hook: Record fail-open event
      console.warn(`[Telemetry] Fail-open triggered for tab ${tabId} due to: ${err.code}`);
      // TODO (Task 3.2): Push metric to Sentry/LogRocket.

      await set(`res:${tabId}`, { error: { code: err.code, message: err.message }, url: clean, at: Date.now() });
      setBadge(tabId, "error");
      return null; // fail open: never block browsing because the service is down
    }
  }
  await set(`res:${tabId}`, { result, originalUrl: url, at: Date.now() });
  setBadge(tabId, result.not_applicable ? "none" : result.risk_level);

  const localCfg = await chrome.storage.local.get("allow");
  const allowed = localCfg.allow || [];
  if (result.risk_level === "high" && cfg.blockHigh && !allowed.includes(result.host)) {
    await set(`warn:${tabId}`, { result, originalUrl: url });
    chrome.tabs.update(tabId, { url: chrome.runtime.getURL("warning/warning.html") });
  } else if (result.risk_level !== "low" && cfg.banner) {
    chrome.tabs.sendMessage(tabId, { type: "phishguard:banner", level: result.risk_level,
      score: result.risk_score, summary: result.summary }).catch(() => {});
  }
  return result;
}

chrome.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId === 0) set(`nav:${d.tabId}`, { url: d.url, at: Date.now() });
});

chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId !== 0) return;
  if (d.url.startsWith(chrome.runtime.getURL(""))) return; // our own warning page
  assess(d.tabId, d.url, d.transitionQualifiers).catch(() => setBadge(d.tabId, "error"));
});

chrome.tabs.onRemoved.addListener((tabId) => S.remove([`res:${tabId}`, `nav:${tabId}`, `warn:${tabId}`]));

// ---------------------------------------------------------------- messages
// Only our own extension pages may message the worker.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false;
  (async () => {
    switch (msg.type) {
      case "getResult": sendResponse((await get(`res:${msg.tabId}`)) || null); break;
      case "getWarning": sendResponse((await get(`warn:${msg.tabId}`)) || null); break;
      case "rescan": {
        const cur = await get(`res:${msg.tabId}`);
        const url = cur?.originalUrl;
        if (url) {
          const keys = Object.keys(await S.get(null)).filter((k) => k.startsWith("cache:"));
          await S.remove(keys);
          await assess(msg.tabId, url);
        }
        sendResponse((await get(`res:${msg.tabId}`)) || null);
        break;
      }
      case "proceed": { // user chose to continue to a high-risk page (stored persistently)
        const w = await get(`warn:${msg.tabId}`);
        if (w) {
          const cfg = await chrome.storage.local.get("allow");
          const allow = cfg.allow || [];
          await chrome.storage.local.set({ allow: [...new Set([...allow, w.result.host])] });
          chrome.tabs.update(msg.tabId, { url: w.originalUrl });
        }
        sendResponse({ ok: true });
        break;
      }
      case "leave":
        chrome.tabs.update(msg.tabId, { url: "chrome://newtab/" });
        sendResponse({ ok: true });
        break;
      case "report": {
        try {
          sendResponse({ ok: true, ...(await sendReport(await getConfig(), msg.scanId, msg.reportType, msg.comment || "")) });
        } catch (e) { sendResponse({ ok: false, message: e.message }); }
        break;
      }
      default: sendResponse(null);
    }
  })();
  return true; // async response
});

// -------------------------------------------------- opt-in banner registration
async function syncBannerScript() {
  const cfg = await getConfig();
  const ID = "phishguard-banner";
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [ID] });
  const hasPerm = await chrome.permissions.contains({ origins: ["<all_urls>"] });
  if (cfg.banner && hasPerm && existing.length === 0) {
    await chrome.scripting.registerContentScripts([{ id: ID, js: ["content/banner.js"], matches: ["http://*/*", "https://*/*"],
      runAt: "document_idle", persistAcrossSessions: true }]);
  } else if ((!cfg.banner || !hasPerm) && existing.length) {
    await chrome.scripting.unregisterContentScripts({ ids: [ID] });
  }
}
chrome.storage.onChanged.addListener((_c, area) => { if (area === "local") syncBannerScript().catch(() => {}); });
chrome.runtime.onInstalled.addListener((d) => {
  if (d.reason === "install") chrome.runtime.openOptionsPage();
  syncBannerScript().catch(() => {});
});
