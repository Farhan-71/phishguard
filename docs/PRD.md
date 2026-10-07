# Product Requirements Document (PRD): PhishGuard

## 1. Product Overview
**Mission:** Provide real-time, privacy-first, explainable phishing detection directly in the browser to protect users from credential harvesting and malicious sites.
**Background:** Traditional phishing lists (like Google Safe Browsing) are reactive and often miss zero-day phishing campaigns. PhishGuard uses a combination of ML (Random Forest), heuristic rules, and threat-intel to provide proactive, explainable risk scoring.

## 2. User Personas & Stories
* **Target Audience:** Everyday web users, corporate employees, and security researchers.
* **Persona:** "Security-Conscious User"
  * *As a user, I want my browser to warn me before I enter passwords on a deceptive site, so that my accounts remain secure.*
  * *As a user, I want my browsing history to remain private, so that the extension doesn't leak my internal network data or secrets.*
* **Persona:** "Security Administrator"
  * *As an admin, I want to review flagged URLs in a dashboard and manage custom threat-intel lists, so I can protect my organization.*

## 3. Core vs. MVP Scope
### Phase 1 (MVP) - *Current*
- Manifest V3 Chrome Extension.
- Local URL sanitization (stripping query values, fragments, credentials).
- FastAPI backend with Random Forest ML, heuristics, and domain analysis.
- Basic Admin Dashboard for scan logs and threat intel.
- Fail-open design (if backend is down, browsing is not interrupted).

### Phase 2 (Future)
- Sentry/LogRocket integration for production telemetry.
- Global Allowlist syncing across user devices.
- Automatic retraining pipeline for the ML model using reported false positives/negatives.
- Firefox Add-on (Mozilla) support.

## 4. Technical Constraints
- **Security:** Zero secrets or PII leave the browser. Extension uses strict Vanilla JS DOM manipulation (no `innerHTML` to prevent XSS).
- **Architecture:** Must comply strictly with Chrome Manifest V3 (no persistent background pages, no remote code execution).
- **Performance:** Backend API response time (SLA) must be < 500ms on average to prevent perceived browsing latency.

## 5. Success Metrics
- **False Positive Rate:** Maintain < 2% FPR on legitimate URLs.
- **Latency:** 95th percentile API response time < 1 second.
- **Uptime:** 99.9% availability for the FastAPI scoring endpoint.
