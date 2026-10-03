import pytest

from backend.services.features import extract_features
from backend.services.risk_engine import (ALLOWLIST_CAP, EXACT_INTEL_FLOOR, HEURISTIC_MAX, HEURISTIC_MAX_NO_MODEL,
                                          HIGH_THRESHOLD, ML_MAX, Indicator, IntelResult, adjust_for_prevalence,
                                          compute_risk, domain_indicators, level_for, redirect_indicators,
                                          url_indicators)


def ids(url):
    return {i.id for i in url_indicators(extract_features(url))}


def test_prior_shift_properties():
    assert adjust_for_prevalence(0.5, 0.5) == pytest.approx(0.5)
    assert adjust_for_prevalence(0.9, 0.05) < 0.9          # lower deployment prior shrinks probability
    assert adjust_for_prevalence(0.9, 0.9) > 0.9
    assert adjust_for_prevalence(0.0, 0.1) >= 0 and adjust_for_prevalence(1.0, 0.1) <= 1
    a, b = adjust_for_prevalence(0.3, 0.2), adjust_for_prevalence(0.7, 0.2)
    assert a < b                                            # monotone


def test_formula_components():
    inds = [Indicator("x", "t", "d", 10, "url"), Indicator("y", "t", "d", 12, "domain")]
    r = compute_risk(0.5, inds, IntelResult())
    assert (r.ml_component, r.heuristic_component, r.intel_component) == (30, 22, 0)
    assert r.score == 52 and r.level == "medium"


def test_heuristic_cap_and_ml_max():
    big = [Indicator(str(i), "t", "d", 20, "url") for i in range(5)]
    r = compute_risk(1.0, big, IntelResult())
    assert r.ml_component == ML_MAX and r.heuristic_component == HEURISTIC_MAX and r.score == 90


def test_degraded_mode_raises_heuristic_cap():
    big = [Indicator(str(i), "t", "d", 20, "url") for i in range(5)]
    r = compute_risk(None, big, IntelResult())
    assert r.ml_component == 0 and r.heuristic_component == HEURISTIC_MAX_NO_MODEL and r.level == "high"


def test_model_and_intel_indicators_do_not_double_count():
    inds = [Indicator("m", "t", "d", 50, "model"), Indicator("i", "t", "d", 40, "threat_intel")]
    assert compute_risk(0.0, inds, IntelResult()).heuristic_component == 0


def test_exact_match_floor_and_host_match_points():
    assert compute_risk(0.0, [], IntelResult(exact_match=True)).score == EXACT_INTEL_FLOOR
    r = compute_risk(0.1, [], IntelResult(host_match=True))
    assert r.intel_component == 30 and r.score == 36 and r.level == "medium"


def test_allowlist_caps_but_exact_match_wins():
    hot = [Indicator(str(i), "t", "d", 20, "url") for i in range(3)]
    assert compute_risk(1.0, hot, IntelResult(allowlisted=True)).score == ALLOWLIST_CAP
    assert compute_risk(1.0, hot, IntelResult(allowlisted=True, exact_match=True)).score >= EXACT_INTEL_FLOOR


def test_levels():
    assert (level_for(29), level_for(30), level_for(59), level_for(60)) == ("low", "medium", "medium", "high")
    assert HIGH_THRESHOLD == 60


def test_https_is_not_a_positive_signal():
    a = compute_risk(0.0, url_indicators(extract_features("https://example.com/")), IntelResult())
    assert a.score == 0
    b = compute_risk(0.0, url_indicators(extract_features("http://example.com/")), IntelResult())
    assert b.score == 5  # small penalty for missing HTTPS only


def test_url_rules_fire_on_classic_phish():
    got = ids("http://paypal.com.secure-login.evil-site.top/signin/verify.php")
    assert {"brand_in_subdomain", "risky_tld", "no_https", "keywords_host"} <= got
    assert "ip_host" in ids("http://203.0.113.9/login.php")
    assert "obfuscated_ip" in ids("http://2130706433/")
    assert "brand_lookalike" in ids("https://paypa1.com/login")


def test_legit_pages_stay_quiet():
    assert ids("https://www.paypal.com/signin") == set()
    assert ids("https://en.wikipedia.org/wiki/Google") == set()   # brand-in-path needs corroboration
    assert ids("https://github.com/login") == set()


def test_brand_in_path_needs_corroboration():
    assert "brand_in_path" in ids("http://random-site.example.net/paypal/login")


@pytest.mark.parametrize("age,expected", [(3, "domain_age_lt7"), (20, "domain_age_lt30"), (60, "domain_age_lt90"), (400, None)])
def test_domain_age_rules(age, expected):
    got = {i.id for i in domain_indicators({"rdap": {"status": "ok", "age_days": age}})}
    assert got == ({expected} if expected else set())


def test_domain_tls_and_private_ip_rules():
    got = {i.id for i in domain_indicators({"tls": {"status": "verify_failed", "error": "self-signed"},
                                            "dns": {"private_ip": True}})}
    assert got == {"tls_invalid", "private_ip"}
    assert domain_indicators({"rdap": {"status": "unavailable"}, "tls": {"status": "no_tls"}}) == []
    assert domain_indicators(None) == []


def test_redirect_rules():
    chain = [{"host": "bit.ly", "registered_domain": "bit.ly", "is_shortener": True, "is_ip": False},
             {"host": "t.evil.top", "registered_domain": "evil.top", "is_shortener": False, "is_ip": False}]
    got = {i.id for i in redirect_indicators("victim.com", chain)}
    assert got == {"redirect_chain", "redirect_obscured"}
    assert redirect_indicators("a.com", []) == []
