import { DEFAULTS, getConfig, health, scanUrl, ApiError } from "../shared/api.js";

const $ = (id) => document.getElementById(id);
const status = (msg, cls = "") => { $("status").textContent = msg; $("status").className = cls; };

async function load() {
  const c = await getConfig();
  $("apiBase").value = c.apiBase; $("apiKey").value = c.apiKey;
  $("blockHigh").checked = c.blockHigh; $("banner").checked = c.banner;
}

function readForm() {
  let base = $("apiBase").value.trim().replace(/\/+$/, "") || DEFAULTS.apiBase;
  const u = new URL(base); // throws on nonsense
  if (u.protocol !== "https:" && !["127.0.0.1", "localhost", "[::1]"].includes(u.hostname)) {
    throw new Error("Use https:// for a service that is not on this computer.");
  }
  return { apiBase: u.origin, apiKey: $("apiKey").value.trim(), blockHigh: $("blockHigh").checked, banner: $("banner").checked };
}

async function ensurePermission(origin, banner) {
  const wanted = new Set([origin + "/*"]);
  if (banner) wanted.add("<all_urls>");
  const origins = [...wanted];
  if (await chrome.permissions.contains({ origins })) return true;
  return chrome.permissions.request({ origins }); // must run inside the click handler
}

$("save").addEventListener("click", async () => {
  try {
    const cfg = readForm();
    if (!(await ensurePermission(cfg.apiBase, cfg.banner))) {
      if (cfg.banner) { cfg.banner = false; $("banner").checked = false; }
      else return status("Permission to contact that address was not granted.", "bad");
    }
    await chrome.storage.local.set(cfg);
    status("Saved.", "ok");
  } catch (e) { status(e.message, "bad"); }
});

$("test").addEventListener("click", async () => {
  try {
    const cfg = readForm();
    const hres = await health(cfg);
    status(`Connected. Model: ${hres.model_loaded ? hres.model_version : "not loaded (rules only)"}. Checking the key…`);
    await scanUrl(cfg, "https://example.com/");
    status("Connected and the key works.", "ok");
  } catch (e) {
    status(e instanceof ApiError ? e.message : e.message, "bad");
  }
});

async function loadTrustedSites() {
  const localCfg = await chrome.storage.local.get("allow");
  const allowed = localCfg.allow || [];
  const list = $("trustedList");
  const empty = $("noTrustedSites");

  list.innerHTML = "";
  if (allowed.length === 0) {
    empty.style.display = "block";
  } else {
    empty.style.display = "none";
    allowed.forEach(host => {
      const li = document.createElement("li");
      li.className = "trusted-item";
      const hostSpan = document.createElement("span");
      hostSpan.textContent = host;
      const removeBtn = document.createElement("button");
      removeBtn.className = "btn danger sm";
      removeBtn.textContent = "Remove";
      removeBtn.onclick = async () => {
        const newAllow = allowed.filter(h => h !== host);
        await chrome.storage.local.set({ allow: newAllow });
        loadTrustedSites(); // re-render
      };
      li.appendChild(hostSpan);
      li.appendChild(removeBtn);
      list.appendChild(li);
    });
  }
}

load();
loadTrustedSites();

