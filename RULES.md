# PhishGuard Project Rules & AI Governance

These rules constrain AI behavior and development standards across the PhishGuard repository.

## 1. Coding Standards
### Extension (Frontend)
- **Vanilla JS Only:** The extension uses modern Vanilla ES modules. No React, Vue, or heavy frameworks are allowed in the extension footprint to maximize performance and minimize bundle size.
- **Strict DOM Safety:** Never use `innerHTML`, `insertAdjacentHTML`, or `eval()`. Use `document.createElement`, `textContent`, and safe DOM building patterns (like the `h()` helper in `popup.js`) to prevent XSS.
- **Manifest V3 Compliance:** 
  - All background scripts must be stateless Service Workers.
  - State must be stored in `chrome.storage.session` (ephemeral) or `chrome.storage.local` (persistent).
  - No remote code execution (RCE) or dynamically loaded scripts.

### Backend (Python/FastAPI)
- **Type Hinting:** All Python functions must include strict type hints.
- **Async First:** Use asynchronous functions (`async def`) for all I/O bound operations (database calls, external API requests).
- **Security:** Secrets must never be hardcoded. Use `python-dotenv` and the `config.py` schema for environment variables.

## 2. File Organization
- `/extension/`: Contains all client-side browser code.
  - `/background/`: Service workers.
  - `/popup/` & `/options/`: UI views.
  - `/shared/`: Common utilities (e.g., URL parsing, API clients).
- `/backend/`: FastAPI application.
- `/ml/`: Machine learning pipeline scripts (training, dataset generation). Do NOT run ML scripts in production APIs.
- `/docs/`: Architectural documentation, XAI (Explainable AI) reports, and PRDs.

## 3. Forbidden Actions
- Do not modify working configurations (`manifest.json`, `pytest.ini`, `requirements.txt`) without explicit permission.
- Do not delete or skip unit/integration tests when adding new features.
- Do not introduce third-party libraries for trivial tasks (e.g., date formatting, simple HTTP requests in the extension) unless absolutely necessary.
- Never log raw URLs containing query strings on the backend (enforce client-side and server-side sanitization).
