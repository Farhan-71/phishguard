"""Risk engine: combines model output and security indicators into a score.

The formula is intentionally simple, documented in ``docs/scoring.md`` and covered
by unit tests, so every point of a score can be traced to a named cause.

    ml_component        = round(ML_MAX * p_adj)                      0..60
    heuristic_component = min(HEURISTIC_MAX, sum(rule weights))      0..30
    intel_component     = HOST_INTEL_POINTS if the host is listed     0 or 30
    score               = clamp(ml + heuristic + intel, 0, 100)

    exact URL listed as malicious by threat intel   -> score = max(score, 95)
    registered domain on the admin allow-list        -> score = min(score, 15)
                                                        (exact-URL listing still wins)
    no model available (degraded mode)               -> HEURISTIC_MAX rises to 60

``p_adj`` is the classifier probability after *prior-shift correction*: the model
is trained on a balanced dataset, but real browsing is overwhelmingly benign, so
raw probabilities overstate risk. See :func:`adjust_for_prevalence`.

HTTPS is never treated as evidence of legitimacy: it adds no points when present
and a small number when absent.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

SCORING_VERSION = "1.0"
ML_MAX = 60
HEURISTIC_MAX = 30
HEURISTIC_MAX_NO_MODEL = 60
HOST_INTEL_POINTS = 30
EXACT_INTEL_FLOOR = 95
ALLOWLIST_CAP = 15
MEDIUM_THRESHOLD = 30
HIGH_THRESHOLD = 60
TRAIN_PREVALENCE = 0.5


def adjust_for_prevalence(p: float, deploy_prevalence: float,
                          train_prevalence: float = TRAIN_PREVALENCE) -> float:
    """Prior-shift correction (Saerens et al. 2002): rescale the odds by the ratio of
    deployment to training class priors."""
    p = min(max(p, 1e-6), 1 - 1e-6)
    odds = p / (1 - p)
    factor = (deploy_prevalence / (1 - deploy_prevalence)) / (train_prevalence / (1 - train_prevalence))
    o = odds * factor
    return o / (1 + o)


@dataclass
class Indicator:
    id: str
    title: str
    detail: str
    weight: int
    source: str  # url | domain | redirect | threat_intel | model

    @property
    def severity(self) -> str:
        if self.weight >= 15:
            return "high"
        if self.weight >= 8:
            return "medium"
        if self.weight >= 4:
            return "low"
        return "info"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity
        return d


# ------------------------------------------------------------------ URL rules
def url_indicators(f: dict[str, float]) -> list[Indicator]:
    """Deterministic rules over the lexical features (independent of the model)."""
    out: list[Indicator] = []
    add = lambda *a: out.append(Indicator(*a, source="url"))  # noqa: E731

    if f["is_obfuscated_ip"]:
        add("obfuscated_ip", "Obfuscated IP address", "The host is an IP written in hex/decimal/octal form to evade filters.", 20)
    elif f["is_ip_host"]:
        add("ip_host", "IP address instead of domain name", "Legitimate services rarely ask users to sign in on a raw IP address.", 15)
    if f["has_userinfo"] or f["has_at_symbol"]:
        add("at_symbol", "'@' in the URL", "Browsers ignore everything before '@', which can disguise the real destination.", 12)
    if f["has_punycode"]:
        add("punycode", "Internationalised (punycode) host", "The host can contain characters that look like Latin letters.", 10)
    if f["is_brand_lookalike"]:
        add("brand_lookalike", "Look-alike of a well-known brand", "The domain is a near-miss spelling or character swap of a famous brand.", 20)
    if f["brand_in_subdomain"]:
        add("brand_in_subdomain", "Brand name in a subdomain of an unrelated site", "The real site is the registered domain on the right, not the brand on the left.", 14)
    if f["brand_in_domain_label"] and not f["is_brand_lookalike"]:
        add("brand_in_domain", "Brand name inside an unofficial domain", "The domain embeds a brand name but is not one of the brand's own domains.", 12)

    corroborated = (f["keyword_count_path"] or f["keyword_count_host"] or not f["is_https"]
                    or f["is_shared_hosting"] or f["risky_tld"])
    if f["brand_in_path"] and corroborated and not f["brand_in_subdomain"]:
        add("brand_in_path", "Brand name in URL path of an unrelated site", "A brand appears in the path, alongside other suspicious traits.", 8)

    if f["keyword_count_host"] >= 2:
        add("keywords_host", "Sensitive words in host name", "Words like 'login', 'secure' or 'verify' in the host name are common in phishing.", 8)
    elif f["keyword_count_host"] == 1 and (f["brand_in_subdomain"] or f["brand_in_domain_label"] or f["risky_tld"]):
        add("keywords_host", "Sensitive word in host name", "A sign-in/security word appears in an otherwise suspicious host name.", 4)
    if f["num_subdomain_labels"] >= 4:
        add("many_subdomains", "Unusually many subdomains", f"{int(f['num_subdomain_labels'])} subdomain levels can bury the real domain.", 8)
    if f["risky_tld"]:
        add("risky_tld", "Frequently abused top-level domain", "This TLD is over-represented in throw-away phishing domains.", 6)
    if f["is_shortener"]:
        add("shortener", "URL shortener", "The final destination is hidden behind a shortening service.", 6)
    if f["nonstandard_port"]:
        add("nonstandard_port", "Non-standard port", "The URL uses an unusual port.", 6)
    if f["executable_extension"]:
        add("executable", "Executable or archive download", "The URL points at a program or archive file.", 10)
    if f["num_percent_encoded"] >= 5:
        add("heavy_encoding", "Heavy URL encoding", f"{int(f['num_percent_encoded'])} percent-encoded characters can hide the real target.", 5)
    if f["has_double_slash_path"]:
        add("double_slash", "Double slash in path", "Often used in open-redirect tricks.", 3)
    if not f["is_https"]:
        add("no_https", "Connection is not encrypted", "The page is loaded over plain HTTP.", 5)
    return out


# --------------------------------------------------------------- domain rules
def domain_indicators(report: dict | None) -> list[Indicator]:
    if not report:
        return []
    out: list[Indicator] = []
    add = lambda *a: out.append(Indicator(*a, source="domain"))  # noqa: E731

    rdap = report.get("rdap") or {}
    age = rdap.get("age_days")
    if rdap.get("status") == "ok" and age is not None:
        if age < 7:
            add("domain_age_lt7", "Domain registered in the last week", f"Registered {age} day(s) ago.", 25)
        elif age < 30:
            add("domain_age_lt30", "Very new domain", f"Registered {age} days ago.", 18)
        elif age < 90:
            add("domain_age_lt90", "Recently registered domain", f"Registered {age} days ago.", 8)

    tls = report.get("tls") or {}
    if tls.get("status") == "verify_failed":
        add("tls_invalid", "Invalid TLS certificate", tls.get("error") or "The certificate could not be verified.", 15)
    elif tls.get("status") == "ok":
        cert_age = tls.get("cert_age_days")
        if cert_age is not None and cert_age < 7:
            add("tls_new_cert", "Certificate issued in the last week", f"Issued {cert_age} day(s) ago (weak signal on its own).", 4)

    dns = report.get("dns") or {}
    if dns.get("private_ip"):
        add("private_ip", "Resolves to a private/internal address", "Public sites should not resolve to internal IP ranges.", 10)
    return out


def redirect_indicators(final_registered_domain: str, chain: list[dict]) -> list[Indicator]:
    """*chain* = [{"host":..., "registered_domain":..., "is_shortener":bool, "is_ip":bool}, ...]
    describing hosts the browser passed through before the final page."""
    if not chain:
        return []
    out: list[Indicator] = []
    domains = {h["registered_domain"] for h in chain} | {final_registered_domain}
    if len(domains) >= 3:
        out.append(Indicator("redirect_chain", "Redirected through several unrelated domains",
                             f"The page passed through {len(domains)} different sites before loading.", 8, "redirect"))
    elif len(domains) == 2 and len(chain) >= 3:
        out.append(Indicator("redirect_long", "Long redirect chain", f"{len(chain)} redirects before this page.", 4, "redirect"))
    if any(h.get("is_ip") or h.get("is_shortener") for h in chain):
        out.append(Indicator("redirect_obscured", "Redirect via shortener or IP address",
                             "An intermediate hop hid its identity behind a shortener or raw IP.", 6, "redirect"))
    return out


# ---------------------------------------------------------------------- score
@dataclass
class IntelResult:
    exact_match: bool = False
    host_match: bool = False
    allowlisted: bool = False
    sources: list[str] = field(default_factory=list)


@dataclass
class RiskResult:
    score: int
    level: str
    ml_component: int
    heuristic_component: int
    intel_component: int
    override: str | None
    scoring_version: str = SCORING_VERSION

    def components(self) -> dict:
        return {"ml": self.ml_component, "heuristics": self.heuristic_component,
                "threat_intel": self.intel_component, "override": self.override,
                "scoring_version": self.scoring_version}


def level_for(score: int) -> str:
    return "high" if score >= HIGH_THRESHOLD else "medium" if score >= MEDIUM_THRESHOLD else "low"


def compute_risk(p_adj: float | None, indicators: list[Indicator], intel: IntelResult) -> RiskResult:
    ml = round(ML_MAX * p_adj) if p_adj is not None else 0
    cap = HEURISTIC_MAX if p_adj is not None else HEURISTIC_MAX_NO_MODEL
    heur = min(cap, sum(i.weight for i in indicators if i.source in {"url", "domain", "redirect"}))
    intel_pts = HOST_INTEL_POINTS if (intel.host_match and not intel.exact_match) else 0
    score = min(100, max(0, ml + heur + intel_pts))
    override = None
    if intel.exact_match:
        score, override = max(score, EXACT_INTEL_FLOOR), "threat_intel_exact_match"
    elif intel.allowlisted:
        score, override = min(score, ALLOWLIST_CAP), "admin_allowlist"
    return RiskResult(score, level_for(score), ml, heur, intel_pts, override)
