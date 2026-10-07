// Detection API client. The API key in this extension is a low-privilege *scan* key:
// anything stored in an extension can be read by its user, so it must never be an admin key.

export const DEFAULTS = {
  // Update this to your deployed Render URL once live (e.g., https://phishguard-api.onrender.com)
  // For local development, change back to "http://127.0.0.1:8000"
  apiBase: "https://your-phishguard-api.onrender.com",
  apiKey: "",
  blockHigh: true,   // show an interstitial for high-risk pages
  banner: false,     // opt-in in-page warning bar (needs an extra permission)
};
export const CLIENT_VERSION = "1.0.0";
const TIMEOUT_MS = 7000;

export async function getConfig() {
  const stored = await chrome.storage.local.get(DEFAULTS);
  return { ...DEFAULTS, ...stored, apiBase: String(stored.apiBase || DEFAULTS.apiBase).replace(/\/+$/, "") };
}

export class ApiError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

async function call(cfg, path, { method = "GET", body } = {}) {
  if (!cfg.apiKey && path !== "/api/v1/health") throw new ApiError("no_key", "No API key configured");
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(cfg.apiBase + path, {
      method,
      headers: { "Content-Type": "application/json", "X-API-Key": cfg.apiKey },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
      credentials: "omit",
      cache: "no-store",
    });
    if (res.status === 401) throw new ApiError("auth", "The API key was rejected");
    if (res.status === 429) throw new ApiError("rate", "Rate limit reached; try again shortly");
    if (res.status === 422) throw new ApiError("invalid", "This address could not be assessed");
    if (!res.ok) throw new ApiError("http", `Server error (${res.status})`);
    return await res.json();
  } catch (e) {
    if (e instanceof ApiError) throw e;

    // Telemetry hook: Log unexpected network/timeout failures
    const errType = e.name === "AbortError" ? "timeout" : "network_failure";
    console.warn(`[Telemetry] API Error (${errType}) targeting ${path}:`, e.message);
    // TODO (Task 3.2): Push this error to Sentry if configured.

    throw new ApiError("network", e.name === "AbortError" ? "The detection service timed out" : "Could not reach the detection service");
  } finally {
    clearTimeout(timer);
  }
}

export const scanUrl = (cfg, url, redirect_hosts = []) =>
  call(cfg, "/api/v1/scan", { method: "POST", body: { url, redirect_hosts, client_version: CLIENT_VERSION } });
export const sendReport = (cfg, scan_id, report_type, comment = "") =>
  call(cfg, "/api/v1/report", { method: "POST", body: { scan_id, report_type, comment } });
export const health = (cfg) => call(cfg, "/api/v1/health");
