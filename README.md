# PhishGuard

Real-time phishing detection: a Manifest V3 browser extension, a FastAPI
detection service (ML + rule-based risk engine + threat intel + domain/DNS/TLS
checks), and an admin dashboard, all wired end to end and tested.

```
extension/  Chrome MV3 extension — badges, warning interstitial, popup, options
backend/    FastAPI service — scanning API, risk engine, threat intel, admin API
dashboard/  Static admin console (served by the backend, no build step)
ml/         Dataset generation, training, evaluation
docs/       Scoring methodology, threat model, ML report
tests/      152 backend/ML pytest cases
```

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# generates a synthetic bootstrap dataset + trains the model (see caveat below)
python -m ml.training.train

cp .env.example .env
python scripts/gen_keys.py           # paste the two lines into .env
# edit .env: set PHISHGUARD_SCAN_KEYS / PHISHGUARD_ADMIN_KEYS from the output above

set -a && source .env && set +a
uvicorn --factory backend.api.main:app_factory --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/dashboard/` and sign in with the admin key.

Load the extension: `chrome://extensions` → Developer mode → *Load unpacked* →
select `extension/`. Open its **Options** page and paste the scan key.

Run the tests:

```bash
pytest -q                            # backend + ML (152 tests)
cd extension && npm install && npm test   # extension unit tests (node --test)
```

## What it does

* The extension watches page navigations, sanitises the URL client-side
  (strips query-string *values*, fragments, credentials — see
  `extension/shared/url.js`), and POSTs it to `/api/v1/scan`.
* The backend re-sanitises independently (`backend/services/url_utils.py` is
  the single choke point every URL passes through) and runs four layers in
  parallel where possible:
  1. **37 lexical URL features** (`backend/services/features.py`) — brand
     look-alike detection (edit distance + homoglyphs), shared-hosting and
     large-platform awareness, keyword/entropy/structure features — feeding
  2. a **calibrated ML classifier** (random forest, chosen over logistic
     regression and a decision tree on held-out F1/PR-AUC; see
     `docs/ml-report.md`),
  3. **domain/DNS/RDAP/TLS analysis** with an SSRF guard (globally-routable
     addresses only, port 443 handshake only, no HTTP request ever sent to the
     target — see `docs/threat-model.md` §2), and
  4. **threat-intel lookup** (locally-imported feeds + admin-managed
     indicators, exact/host/domain match levels with shared-hosting awareness).
* A documented, testable **risk engine** (`docs/scoring.md`) combines all four
  into a 0–100 score with a named reason for every point, and a per-feature
  counterfactual explanation of the model's contribution.
* Results are cached client-side for 10 minutes, and the extension **fails
  open**: if the API is unreachable, browsing is never blocked, only the badge
  goes to "unknown."
* Everything is written to a database (`backend/database/models.py`) and
  surfaced on the dashboard: scan history, timelines, top indicators, security
  events, threat-intel management, a report queue, and live model metrics.

## Honest caveats

* **The shipped model is trained on synthetic data.** A labelled, redistributable
  phishing/benign corpus wasn't available offline when this was built, so
  `ml/dataset/synthetic.py` generates a reproducible bootstrap dataset with
  deliberate class overlap (brand login pages on real brand domains, phishing
  with no lexical tells, shared hosting on both sides, ...). Metrics in
  `docs/ml-report.md` measure how well the pipeline learned the generator's
  patterns, not real-world phishing detection. `ml/evaluation/external_check.py`
  scores the model against real URLs (a phishing-feed snapshot + a hand-curated
  legitimate list, both held out from training) as an honest sanity check —
  results are in `docs/external-check.json`. **Retrain on a real labelled
  corpus** (PhishTank's verified feed, OpenPhish, Tranco + real crawled paths
  for benign — check each source's licence) before relying on this for anything
  beyond a demo: `python -m ml.dataset.build_dataset --mode files --phish-file
  ... --benign-file ...` then `python -m ml.training.train`.
* **Content is never inspected** — only the URL and DNS/RDAP/TLS/threat-intel
  metadata. A phishing page with no lexical red flags on an aged domain won't be
  caught until threat intel catches up.
* **Rate limiting is per-process** (see `docs/threat-model.md` §6) — fine for a
  single-process deployment, not yet ready for a multi-worker one without a
  shared limiter in front.

## Documentation

* [`docs/scoring.md`](docs/scoring.md) — the risk formula, why the weights are
  what they are, and how the prior-shift correction's default was chosen.
* [`docs/threat-model.md`](docs/threat-model.md) — SSRF guard, model integrity,
  privacy (what's sent/logged/stored), auth, rate limiting, explicit non-goals.
* [`docs/ml-report.md`](docs/ml-report.md) — model comparison, calibrated test
  metrics, feature importances, error analysis (auto-generated by
  `ml/evaluation/evaluate.py`).

## API surface

All routes are under `/api/v1`. `POST /scan` and `POST /report` need an
`X-API-Key` with the `scan` role; everything under `/admin/*` needs the `admin`
role. Interactive docs at `/api/docs` when `PHISHGUARD_ENV=dev`.

| Method & path | Purpose |
|---|---|
| `POST /scan` | Score a URL |
| `POST /report` | Submit a false positive/negative |
| `GET /health` | Liveness + model/DB status |
| `GET /admin/stats` | Dashboard aggregates |
| `GET /admin/scans` | Scan log |
| `GET/POST/DELETE /admin/indicators` | Manage threat-intel entries |
| `POST /admin/indicators/import` | Bulk-import a feed |
| `GET/PATCH /admin/reports` | Report queue |
| `GET /admin/events` | Security audit log |
| `GET /admin/model` | Live model metrics |
