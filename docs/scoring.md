# Scoring methodology

This document explains the 0–100 risk score end to end: what feeds it, why the
weights are what they are, and where the numbers came from. The implementation
is `backend/services/risk_engine.py`; this file is the "why", that file is the
"what".

## 1. Components

```
score = clamp(ml_component + heuristic_component + intel_component, 0, 100)

ml_component        = round(ML_MAX * p_adjusted)          # 0..60
heuristic_component = min(HEURISTIC_MAX, Σ rule weights)  # 0..30 (0..60 if no model)
intel_component      = 30 if host-level threat-intel match, else 0
```

Two overrides run after the sum:

* an **exact** threat-intel match on this URL floors the score at 95, regardless
  of what the model or rules say — a confirmed report is stronger evidence than
  a prediction;
* an **admin allow-list** entry caps the score at 15 (never possible for shared
  hosting or large multi-tenant platforms, since allow-listing `github.io` would
  allow-list every phishing page hosted there too).

The split (60 / 30 / 30, capped) keeps the model as the largest single voice
without letting it be the *only* voice: a novel phishing kit the model has never
seen can still be caught by the deterministic rules (raw IP host, `@` in the URL,
look-alike domain, ...) or by threat intel, and a model false positive on an
unusual-but-legitimate URL is bounded by the fact that heuristics and intel don't
also fire.

## 2. The model's probability isn't used raw

The classifier is trained on a **balanced** dataset (roughly 50% phishing), because
that is what makes the three candidate models comparable and lets F1 mean something
during model selection. Real browsing is nowhere near 50% phishing — most URLs
people visit are benign. Feeding the raw probability into the score would
systematically overstate risk once deployed.

`adjust_for_prevalence()` applies the standard prior-shift correction (Saerens et
al., 2002): rescale the predicted odds by the ratio of the assumed deployment
prevalence to the training prevalence,

```
odds_adjusted = odds_raw * (deploy_prior / (1 - deploy_prior)) / (train_prior / (1 - train_prior))
```

`PHISHGUARD_ASSUMED_PREVALENCE` (default `0.3`) is the deployment prior. It is
intentionally *not* a realistic guess at population-wide phishing prevalence
(that would be under 1%) — it is a deliberately conservative operating point,
chosen with the sweep below, that keeps genuine phishing scoring high without
flooding ordinary browsing with medium/high verdicts.

### How the default was chosen

Using the model trained on the synthetic dataset (see the caveat in
`ml-report.md`), scored against the two sets of *real* URLs that were never used
for training — `ml/dataset/external/legit_urls.txt` (benign) and a slice of a
public phishing feed (`/tmp/phish_dev.txt` in the session that produced this repo)
— the score-level share above the medium (30) and high (60) thresholds moved like
this as the assumed prevalence changed:

| assumed prevalence | benign ≥ medium | benign ≥ high | phishing ≥ medium | phishing ≥ high |
|---|---|---|---|---|
| none (raw p) | 5.6% | 0.0% | 68.0% | 36.7% |
| 0.30 | 0.0% | 0.0% | 60.0% | 31.3% |
| 0.20 | 0.0% | 0.0% | 54.7% | 29.3% |
| 0.10 | 0.0% | 0.0% | 44.7% | 20.7% |
| 0.05 | 0.0% | 0.0% | 36.0% | 9.3% |
| 0.02 | 0.0% | 0.0% | 28.0% | 0.0% |

`0.3` was picked as the point that keeps benign false-alarm risk at essentially
zero on this (small) benign sample while still surfacing a majority of real
phishing at medium-or-above. **This was tuned against ~90 benign URLs and ~150
phishing URLs — treat it as a documented starting point, not a validated
threshold, and re-run `ml/evaluation/external_check.py` after retraining on real
data before trusting it further.**

## 3. Deterministic rules (`url_indicators`, `domain_indicators`, `redirect_indicators`)

These run independently of the model and never depend on it, which is what lets
the risk engine degrade gracefully to "rules only" (`HEURISTIC_MAX` rises to 60)
if the model artifact is missing or fails its integrity check. Weights were set
by hand based on how strong a signal each rule is in isolation, not fit to data:

* **High-confidence rules (12–20 points):** obfuscated/raw IP host, `@` in the
  URL, punycode host, brand look-alike (edit-distance/homoglyph), brand name in
  a subdomain of an unrelated domain. These are things a legitimate site
  essentially never does.
* **Medium rules (5–10 points):** sensitive keywords in the host, many
  subdomains, risky TLD, URL shortener, non-standard port, executable/archive
  download, heavy percent-encoding.
* **Low rules (3–5 points):** double slash in path, no HTTPS. HTTPS is
  deliberately worth very little in either direction — it is necessary but says
  nothing about identity, and a large share of real phishing sites now have a
  valid certificate.

Domain rules add points for a domain registered in the last 7/30/90 days
(decreasing weight with age) and for a TLS certificate that fails verification.
A brand-new certificate is only a very weak signal on its own (free CAs issue
certificates in minutes for anyone) and is intentionally capped at 4 points.

Redirect rules see only the hostnames the browser extension passed along
(`webNavigation` exposes the first and last hop of a redirected navigation, not
the full chain) and add a small amount for hopping through several unrelated
domains or through a shortener/IP.

## 4. Threat intelligence

Three match levels, from `backend/services/threat_intel.py`:

* **exact** — this exact URL (host + path, query values ignored) was reported.
  Floors the score at 95.
* **host** — a *different* page on the same host was reported. Adds 30 points,
  but is disabled for shared hosting (`github.io`, `netlify.app`, ...) and very
  large multi-tenant platforms (`docs.google.com`, ...), where one bad page on
  someone else's subdomain or a huge platform says nothing about the platform
  itself.
* **domain** (admin-managed) — an administrator has flagged the whole registered
  domain. Also disabled for shared hosting/large platforms for the same reason.

## 5. Explanations

Two separate explanation mechanisms feed the API response:

* **Rule indicators** are self-explaining by construction — each one is a named
  rule with a fixed title/detail template.
* **Model contribution** is explained with per-feature counterfactual occlusion
  (`MLModel.explain`): each non-baseline feature is set back to its typical
  benign value one at a time, and the drop in predicted probability is that
  feature's attributed contribution. This is model-agnostic (works the same for
  the random forest, logistic regression or decision tree) and cheap, but
  under-counts interactions between correlated features — e.g. "brand in
  subdomain" and "many subdomains" often co-occur, and occluding either one alone
  understates their combined effect. Good enough to point a person at *why* a
  score is high; not a substitute for a full attribution method (SHAP, etc.) if
  that precision is ever needed.

## 6. Known limitations

* The default prevalence and every rule weight above were tuned against a small,
  hand-assembled real-URL sample (~90 benign, ~150 phishing) plus a synthetic
  training set. They are a reasonable starting point for a portfolio-scale
  deployment, not a validated production threshold.
* The risk engine has no notion of page *content* — it only ever sees the URL,
  DNS/RDAP/TLS metadata and threat intel, never the rendered page. A phishing
  page hosted at a URL with no lexical tells and on an aged, previously-benign
  domain will score low until threat intel catches up.
* `RateLimiter` state is per-process (see `docs/threat-model.md`), which matters
  for the rate-limit *numbers* here too: with N worker processes the effective
  request budget is N× the configured limit.
