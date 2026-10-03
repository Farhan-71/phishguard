# Threat model

What PhishGuard defends against, what it deliberately does not attempt, and the
specific mitigations in the code for each risk taken on by *running this
service*, as opposed to risks to the people it's protecting (that's
`scoring.md`).

## 1. Assets and trust boundaries

* **The scanning API** (`backend/`) is the trust boundary. It accepts URLs from
  untrusted callers (the browser extension, in practice, but the API has no way
  to know that) and makes outbound network calls (DNS, RDAP, TLS) to
  attacker-chosen hostnames on the caller's behalf. That's the dangerous part.
* **The database** holds sanitised URLs, scan results, threat-intel entries and
  hashed-actor security events. No raw client IP addresses, no query-string
  values, no passwords are ever written to it (see §4).
* **The model artifact** (`ml/models/model.joblib`) is a pickle — code that runs
  on load. Treated as a deploy-time asset that must come from a trusted build,
  not user input.
* **API keys** authenticate callers into two roles (`scan`, `admin`). There is no
  per-user identity; a compromised key can do what its role allows, no more.

## 2. Server-side request forgery (SSRF)

The single riskiest thing this service does is resolve and connect to hosts
supplied by the caller (`backend/services/domain_analysis.py`). Mitigations:

* **We resolve the host ourselves and connect to the address we resolved** — not
  a second lookup at connect time — so a DNS answer that changes between
  resolution and connection (classic TOCTOU/rebinding) can't redirect the
  connection.
* **Only globally-routable, non-multicast addresses are ever connected to**
  (`url_utils.is_public_ip`). A domain that resolves to `127.0.0.1`,
  `10.0.0.0/8`, `169.254.0.0/16`, etc. is recorded as a `private_ip` finding and
  the TLS step is skipped entirely — the server never opens a socket to it.
* **Only port 443, only a TLS handshake.** No HTTP request is ever sent to the
  target and no response body is downloaded, parsed or executed. The only thing
  extracted from the connection is the certificate metadata.
* **RDAP goes to one fixed, first-party bootstrap host** (`rdap.org`), never to
  the scanned domain. The registered domain is passed as a path segment, not
  used to construct a request to an attacker-controlled server.
* **Local/private/intranet URLs are rejected before any of this runs.**
  `Scanner.scan()` calls `is_local_host()` first and returns a fixed "not
  assessed" response for anything on `localhost`, RFC1918 space, link-local, or
  common internal TLDs (`.local`, `.internal`, `.lan`, ...) — these are never
  looked up, connected to, or stored.
* **Every network call has a short timeout and the whole domain-analysis step
  has an overall deadline** (`PHISHGUARD_SCAN_DEADLINE`), so a target that
  accepts a TCP connection and never responds can't tie up a worker
  indefinitely.

## 3. Model integrity

`ml/models/model.joblib` is loaded with `joblib.load`, which is unpickling —
arbitrary code execution if the file is attacker-controlled. `MLModel.load()`
therefore:

* requires a co-located `model.joblib.sha256` digest file (written by the
  training script) and refuses to load if it's missing;
* compares the digest with `hmac.compare_digest` (constant-time) before calling
  `joblib.load`;
* verifies the loaded artifact's feature list matches the feature engine
  exactly, so a stale model can't silently misinterpret feature order.

This protects against a *tampered* model file reaching a trusted deployment; it
does **not** protect against a malicious model deliberately trained and shipped
by someone with legitimate write access to the models directory. Keep that
directory in the same trust tier as your application code (code review before
merge, no direct production writes).

## 4. Privacy: what is sent, logged and stored

* **Query string values are stripped before the URL leaves the browser** (and
  stripped again, redundantly, on the server) — `?token=abc&session=xyz` becomes
  `?token=&session=`. Parameter *names* are kept because they're sometimes useful
  signal (`?verify=`, `?redirect=`); values are where session tokens, emails and
  one-time codes live, and they are never transmitted, logged or stored intact.
* **Fragments (`#...`) and passwords in the URL's userinfo are dropped** before
  anything else happens.
* **Client IP addresses are never stored.** `actor_hash()` hashes
  `salt + ip` with SHA-256 and truncates to 12 hex characters purely to let
  repeated-abuse patterns be correlated in `security_events`; the salt is
  server-side and per-deployment, so the hash can't be reversed or matched
  against IPs seen elsewhere.
* **Local/private addresses are never sent anywhere** — see §2.
* **Threat-intel imports store only the sanitised URL's host+path** (`match_key`),
  same redaction as above.

## 5. AuthN/authZ

* Two static-key roles, `scan` and `admin`, compared with `hmac.compare_digest`
  against *every* configured key (no early exit) to avoid a timing side-channel
  that could distinguish "wrong key" from "key close to correct."
* A `scan` key can never reach an `/admin/*` route (`require_admin` checks the
  role explicitly, not just "is a key present").
* In `PHISHGUARD_ENV=dev` with no keys configured, ephemeral keys are generated
  and logged once, for local trial-and-error only. Any other `PHISHGUARD_ENV`
  value refuses to start without explicit keys (`config.load_settings`).
* Keys must be 16+ characters; `scripts/gen_keys.py` generates 32-byte
  URL-safe tokens.

## 6. Rate limiting and abuse handling

`RateLimiter` (`backend/api/security.py`) is a sliding-window limiter applied at
three layers, in order: a per-address limit *before* authentication (so
unauthenticated floods are cheap to reject), a per-key limit after
authentication (separate budgets for `scan` vs `admin`), and a small separate
budget on auth *failures* and reports, so a wrong key can't be brute-forced at
the main request rate.

**Known limitation:** the limiter's state is in-process memory. With N worker
processes behind a load balancer, the effective rate limit is N× the configured
number, and limits reset on restart. This is fine for the single-process
deployment this project targets; a multi-worker deployment should put a shared
limiter (Redis, or the reverse proxy's own rate limiting) in front instead.

## 7. Input validation

* All Pydantic schemas (`backend/models/schemas.py`) use `extra="forbid"` and
  explicit length bounds on every string field — unrecognised fields and
  oversized payloads are rejected before touching business logic.
* A body-size middleware rejects requests over 64 KB by `Content-Length` before
  the body is even read.
* `sanitize_url()` is the single choke point for every URL entering the system
  (API requests, training data, feed imports): rejects non-http(s) schemes,
  control characters, oversized input, malformed IDNs, and normalises everything
  else (case, punycode, IPv6 compression) so that the same URL always produces
  the same stored/matched string.
* Database access is exclusively through the SQLAlchemy ORM with bound
  parameters — there is no string-built SQL anywhere in the codebase.

## 8. Dashboard

The dashboard is a static, same-origin page with no build step and no external
network access: its Content-Security-Policy (`backend/api/main.py`,
`DASHBOARD_CSP`) allows scripts and styles only from `'self'`, forbids framing,
and disables `form-action`. The admin key it uses lives in `sessionStorage` for
that browser tab only (cleared on sign-out) and is never written to any
persistent store the dashboard controls.

## 9. Explicitly out of scope

* **Content analysis.** The service never fetches, renders or inspects the page
  a URL points to — only the URL string and DNS/RDAP/TLS/threat-intel metadata.
  A phishing page with no lexical red flags on an aged, previously-clean domain
  will not be caught until threat intel or a report catches up with it.
* **Malware/attachment scanning.** Out of scope entirely.
* **Multi-tenant isolation.** There is no per-organisation data separation; the
  two roles (`scan`, `admin`) are global.
* **Distributed rate limiting / horizontal scaling hardening** — see §6.
