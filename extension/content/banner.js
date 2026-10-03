// Opt-in in-page warning bar. Registered dynamically only if the user enabled it AND granted the
// extra host permission. It never reads page content beyond "is there a password field?".
(() => {
  if (window.__phishguardBanner) return;
  window.__phishguardBanner = true;

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type !== "phishguard:banner") return;
    document.getElementById("phishguard-banner-host")?.remove();
    const hasPassword = !!document.querySelector('input[type="password"]');
    const host = document.createElement("div");
    host.id = "phishguard-banner-host";
    const root = host.attachShadow({ mode: "closed" }); // page CSS/JS cannot restyle or read it
    const high = msg.level === "high";
    const style = document.createElement("style");
    style.textContent = `
      .bar { all: initial; position: fixed; z-index: 2147483647; top: 0; left: 0; right: 0; display: flex; gap: 12px;
        align-items: baseline; padding: 10px 16px; font: 14px/1.4 system-ui, sans-serif; color: #14262B;
        background: ${high ? "#FBEDEA" : "#FBF3E0"}; border-bottom: 3px solid ${high ? "#B3372B" : "#B7791F"}; }
      .score { font: 700 20px Georgia, serif; color: ${high ? "#B3372B" : "#8A5A00"}; }
      .msg { flex: 1; } button { all: initial; cursor: pointer; font: 13px system-ui, sans-serif; padding: 4px 10px;
        border: 1px solid #14262B; border-radius: 4px; } button:focus-visible { outline: 2px solid #0E4F5C; outline-offset: 2px; }`;
    const bar = document.createElement("div");
    bar.className = "bar";
    bar.setAttribute("role", "alert");
    const score = document.createElement("span"); score.className = "score"; score.textContent = String(msg.score);
    const text = document.createElement("span"); text.className = "msg";
    text.textContent = (hasPassword && high ? "This page asks for a password and looks like phishing. " : "") + msg.summary;
    const close = document.createElement("button"); close.textContent = "Dismiss";
    close.addEventListener("click", () => host.remove());
    bar.append(score, text, close);
    root.append(style, bar);
    document.documentElement.append(host);
  });
})();
