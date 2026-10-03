"""Scan orchestration: URL analysis -> ML -> domain/DNS/TLS -> threat intel -> risk engine."""
from __future__ import annotations

import logging
import time
import uuid

from sqlalchemy.orm import Session, sessionmaker

from ..config import Settings
from ..database.models import Scan
from ..models.schemas import ScanRequest
from . import threat_intel
from .domain_analysis import DomainAnalyzer
from .features import extract_features
from .ml_service import MLModel
from .reference_data import URL_SHORTENERS
from .risk_engine import (ML_MAX, Indicator, IntelResult, RiskResult, adjust_for_prevalence,
                          compute_risk, domain_indicators, redirect_indicators, url_indicators)
from .url_utils import get_host, is_local_host, sanitize_hostname, split_host, sanitize_url

log = logging.getLogger("phishguard.scan")

LABELS = {"low": "LOW RISK", "medium": "SUSPICIOUS", "high": "HIGH RISK"}
SUMMARIES = {
    "low": "No strong signs of phishing were found. This is not a guarantee of safety.",
    "medium": "Some signs are unusual. Be careful before signing in, paying or sharing personal information.",
    "high": "This page shows several strong signs of phishing. Do not enter passwords or personal information.",
}


class Scanner:
    def __init__(self, settings: Settings, session_factory: sessionmaker[Session],
                 ml: MLModel | None, analyzer: DomainAnalyzer):
        self.settings, self.session_factory, self.ml, self.analyzer = settings, session_factory, ml, analyzer

    # ---------------------------------------------------------------- checks
    def _checks(self, f: dict, url_inds: list[Indicator], intel: IntelResult,
                domain: dict | None, p_adj: float | None) -> list[dict]:
        checks: list[dict] = []
        checks.append({"name": "HTTPS", "status": "pass" if f["is_https"] else "warn",
                       "detail": "Connection is encrypted." if f["is_https"]
                       else "Connection is not encrypted. (HTTPS alone never proves a site is legitimate.)"})
        worst = max((i.weight for i in url_inds), default=0)
        checks.append({"name": "Domain structure",
                       "status": "fail" if worst >= 15 else "warn" if worst >= 8 else "pass",
                       "detail": "Structure of the address looks ordinary." if worst < 8
                       else "The address has unusual structure (see indicators)."})
        if intel.exact_match:
            rep = ("fail", "Listed as a known phishing URL.")
        elif intel.host_match:
            rep = ("warn", "Other pages on this site are listed as phishing.")
        elif intel.allowlisted:
            rep = ("pass", "Allow-listed by an administrator.")
        else:
            rep = ("pass", "Not found in the threat-intelligence data.")
        checks.append({"name": "Reputation", "status": rep[0], "detail": rep[1]})

        age = ((domain or {}).get("rdap") or {}).get("age_days")
        if age is None:
            checks.append({"name": "Domain age", "status": "unknown", "detail": "Registration date unavailable."})
        else:
            st = "fail" if age < 30 else "warn" if age < 90 else "pass"
            checks.append({"name": "Domain age", "status": st, "detail": f"Registered {age} days ago."})
        tls = (domain or {}).get("tls") or {}
        tls_status = tls.get("status")
        if tls_status == "ok":
            checks.append({"name": "Certificate", "status": "pass", "detail": f"Valid certificate from {tls.get('issuer') or 'unknown issuer'}."})
        elif tls_status == "verify_failed":
            checks.append({"name": "Certificate", "status": "fail", "detail": tls.get("error", "Certificate invalid.")})
        else:
            checks.append({"name": "Certificate", "status": "unknown", "detail": "Certificate could not be checked."})
        if p_adj is None:
            checks.append({"name": "Classifier", "status": "unknown", "detail": "Model unavailable; using rules only."})
        else:
            checks.append({"name": "Classifier", "status": "fail" if p_adj >= 0.6 else "warn" if p_adj >= 0.3 else "pass",
                           "detail": "URL resembles known phishing patterns." if p_adj >= 0.3
                           else "URL does not resemble known phishing patterns."})
        return checks

    # ------------------------------------------------------------------ scan
    def scan(self, req: ScanRequest, key_id: str) -> dict:
        t0 = time.monotonic()
        url = sanitize_url(req.url)  # raises InvalidURL
        host = get_host(url)
        hp = split_host(host)

        if is_local_host(host):
            # Never assess or store private/intranet addresses.
            return {
                "scan_id": None, "url": f"{url.split('://')[0]}://{host}/", "host": host,
                "registered_domain": hp.registered_domain, "risk_score": 0, "risk_level": "low",
                "label": "NOT ASSESSED", "summary": "Local and private-network addresses are not assessed or sent anywhere.",
                "indicators": [], "checks": [{"name": "Address", "status": "info", "detail": "Local or private address."}],
                "evidence": {}, "scoring": {}, "degraded": False, "not_applicable": True,
                "latency_ms": int((time.monotonic() - t0) * 1000),
            }

        feats = extract_features(url, sanitized=True)

        # --- ML layer
        p_raw = p_adj = None
        top_features: list[dict] = []
        if self.ml is not None:
            p_raw = self.ml.predict(feats)
            p_adj = adjust_for_prevalence(p_raw, self.settings.assumed_prevalence)
            if p_raw >= 0.3:
                top_features = self.ml.explain(feats, base_p=p_raw)

        # --- deterministic rules
        url_inds = url_indicators(feats)
        chain = []
        for h in req.redirect_hosts:
            clean = sanitize_hostname(h)
            if clean:
                hop = split_host(clean)
                chain.append({"host": clean, "registered_domain": hop.registered_domain,
                              "is_shortener": hop.registered_domain in URL_SHORTENERS,
                              "is_ip": hop.is_ip})
        redir_inds = redirect_indicators(hp.registered_domain, chain)

        # --- domain / DNS / TLS
        domain_report = None
        if self.settings.enable_network_checks:
            domain_report = self.analyzer.analyze(host, hp.registered_domain, self.settings.scan_deadline)
        dom_inds = domain_indicators(domain_report)

        # --- threat intelligence
        with self.session_factory() as session:
            intel = threat_intel.lookup(session, url)
        intel_inds: list[Indicator] = []
        if intel.exact_match:
            intel_inds.append(Indicator("intel_exact", "Listed as a known phishing site",
                                        f"Reported by: {', '.join(intel.sources) or 'threat intelligence'}.", 40, "threat_intel"))
        elif intel.host_match:
            intel_inds.append(Indicator("intel_host", "Other pages on this site are listed as phishing",
                                        f"Reported by: {', '.join(intel.sources) or 'threat intelligence'}.", 30, "threat_intel"))
        if intel.allowlisted:
            intel_inds.append(Indicator("allowlisted", "Allow-listed by an administrator",
                                        "An administrator marked this domain as trusted.", 0, "threat_intel"))

        all_inds = url_inds + redir_inds + dom_inds
        risk: RiskResult = compute_risk(p_adj, all_inds, intel)

        model_inds: list[Indicator] = []
        if p_adj is not None and risk.ml_component >= 8:
            model_inds.append(Indicator("model_signal", "Classifier: address resembles known phishing",
                                        f"The machine-learning model contributed {risk.ml_component} of {ML_MAX} possible points.",
                                        risk.ml_component, "model"))

        indicators = sorted(intel_inds + model_inds + all_inds, key=lambda i: -i.weight)
        scan_id = str(uuid.uuid4())
        latency = int((time.monotonic() - t0) * 1000)

        with self.session_factory() as session:
            session.add(Scan(
                id=scan_id, url=url[:2100], host=host[:255], registered_domain=hp.registered_domain[:255],
                risk_score=risk.score, risk_level=risk.level, ml_probability=p_adj,
                model_version=self.ml.version if self.ml else None,
                indicators=[{"id": i.id, "weight": i.weight, "source": i.source, "title": i.title} for i in indicators],
                intel_match=("exact" if intel.exact_match else "host" if intel.host_match
                             else "allow" if intel.allowlisted else None),
                client_key_id=key_id, latency_ms=latency))
            session.commit()

        return {
            "scan_id": scan_id, "url": url, "host": host, "registered_domain": hp.registered_domain,
            "risk_score": risk.score, "risk_level": risk.level, "label": LABELS[risk.level],
            "summary": SUMMARIES[risk.level],
            "indicators": [i.to_dict() for i in indicators],
            "checks": self._checks(feats, url_inds, intel, domain_report, p_adj),
            "evidence": {
                "model": None if self.ml is None else {
                    "algorithm": self.ml.algorithm, "version": self.ml.version,
                    "probability_raw": round(p_raw, 4), "probability_adjusted": round(p_adj, 4),
                    "assumed_prevalence": self.settings.assumed_prevalence, "top_features": top_features},
                "threat_intel": {"exact_match": intel.exact_match, "host_match": intel.host_match,
                                 "allowlisted": intel.allowlisted, "sources": intel.sources},
                "domain": domain_report,
                "redirect_chain": [c["host"] for c in chain],
            },
            "scoring": risk.components(),
            "degraded": self.ml is None,
            "not_applicable": False,
            "latency_ms": latency,
        }
