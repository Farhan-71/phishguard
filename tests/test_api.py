import pytest

from backend.config import Settings, load_settings
from backend.database.models import Scan, SecurityEvent
from tests.conftest import ADMIN, ADMIN_KEY, HDR, SCAN_KEY, FakeAnalyzer, make_settings

PHISH = "http://paypal.com.secure-login.evil-site.top/signin/verify.php?session=SECRET123&email=victim@example.com"


def scan(client, url, headers=HDR, **extra):
    return client.post("/api/v1/scan", json={"url": url, **extra}, headers=headers)


# ----------------------------------------------------------------- auth
def test_health_is_public(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200 and r.json()["model_loaded"] is True


@pytest.mark.parametrize("hdrs", [{}, {"X-API-Key": "wrong-key-wrong-key-1234"}, {"X-API-Key": ""}])
def test_scan_requires_valid_key(client, hdrs):
    assert scan(client, "https://example.com", headers=hdrs).status_code == 401


def test_scan_key_cannot_reach_admin(client):
    assert client.get("/api/v1/admin/stats", headers=HDR).status_code == 403
    assert client.get("/api/v1/admin/stats").status_code == 401
    assert client.get("/api/v1/admin/stats", headers=ADMIN).status_code == 200


def test_admin_key_may_scan(client):
    assert scan(client, "https://example.com", headers=ADMIN).status_code == 200


def test_auth_failures_are_logged_but_capped(client):
    for _ in range(12):
        client.post("/api/v1/scan", json={"url": "https://x.com"}, headers={"X-API-Key": "bad-bad-bad-bad-bad-1"})
    with client.app.state.session_factory() as s:
        n = s.query(SecurityEvent).filter_by(event_type="auth_failure").count()
    assert 1 <= n <= 5


def test_key_never_appears_in_events_or_responses(client):
    client.post("/api/v1/scan", json={"url": "https://x.com"}, headers={"X-API-Key": "super-secret-wrong-key-1"})
    with client.app.state.session_factory() as s:
        assert all("super-secret" not in (e.detail + e.actor) for e in s.query(SecurityEvent))


# --------------------------------------------------------- rate limiting
def test_per_key_rate_limit(make_client):
    c = make_client(scan_rate_limit=3)
    codes = [scan(c, "https://example.com").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    r = scan(c, "https://example.com")
    assert "Retry-After" in r.headers
    with c.app.state.session_factory() as s:
        assert s.query(SecurityEvent).filter_by(event_type="rate_limited").count() == 1  # logged once, not per request


def test_ip_rate_limit_applies_before_auth(make_client):
    c = make_client(ip_rate_limit=4)
    codes = [c.post("/api/v1/scan", json={"url": "https://x.com"}).status_code for _ in range(6)]
    assert 429 in codes


# ------------------------------------------------------------ validation
@pytest.mark.parametrize("payload", [{}, {"url": ""}, {"url": "x" * 3000}, {"url": "https://a.com", "evil": 1},
                                     {"url": "https://a.com", "redirect_hosts": ["a.com"] * 11}, {"url": 123}])
def test_request_schema_rejections(client, payload):
    assert client.post("/api/v1/scan", json=payload, headers=HDR).status_code == 422


@pytest.mark.parametrize("url", ["javascript:alert(1)", "ftp://x.com/a", "http://", "http://a b\x00c.com"])
def test_invalid_urls_rejected_and_logged(client, url):
    assert scan(client, url).status_code == 422


def test_sql_injection_strings_are_inert(client):
    r = scan(client, "http://x.com/'; DROP TABLE scans;--?q=1' OR '1'='1")
    assert r.status_code == 200
    with client.app.state.session_factory() as s:
        assert s.query(Scan).count() == 1


# -------------------------------------------------------------- scanning
def test_phishing_url_is_flagged_with_explanations(client):
    r = scan(client, PHISH).json()
    assert r["risk_level"] == "high" and r["risk_score"] >= 60 and r["label"] == "HIGH RISK"
    ids = {i["id"] for i in r["indicators"]}
    assert {"brand_in_subdomain", "risky_tld", "no_https"} <= ids
    assert r["evidence"]["model"]["top_features"] and r["evidence"]["model"]["algorithm"]
    assert r["scoring"]["ml"] + r["scoring"]["heuristics"] + r["scoring"]["threat_intel"] >= r["risk_score"] or r["risk_score"] == 100
    assert {c["name"] for c in r["checks"]} >= {"HTTPS", "Domain structure", "Reputation", "Classifier"}


def test_benign_url_is_low(client):
    r = scan(client, "https://www.wikipedia.org/").json()
    assert r["risk_level"] == "low" and r["risk_score"] < 30
    assert all(c["status"] != "fail" for c in r["checks"])


def test_scan_response_separates_model_from_intel_evidence(client):
    ev = scan(client, PHISH).json()["evidence"]
    assert set(ev) >= {"model", "threat_intel", "domain"}
    assert ev["threat_intel"]["exact_match"] is False


def test_privacy_query_values_never_stored_or_returned(client):
    r = scan(client, PHISH).json()
    assert "SECRET123" not in r["url"] and "victim@example.com" not in r["url"]
    with client.app.state.session_factory() as s:
        row = s.query(Scan).one()
        assert "SECRET123" not in row.url and "victim" not in row.url
        assert row.client_key_id and SCAN_KEY not in row.client_key_id


def test_local_addresses_are_not_assessed_or_stored(client):
    for u in ("http://localhost:3000/login", "http://192.168.0.1/", "http://intranet/x", "http://169.254.169.254/latest"):
        r = scan(client, u).json()
        assert r["not_applicable"] and r["risk_score"] == 0 and r["scan_id"] is None
    with client.app.state.session_factory() as s:
        assert s.query(Scan).count() == 0


def test_degraded_mode_without_model(make_client):
    c = make_client(ml=None)
    assert c.get("/api/v1/health").json()["model_loaded"] is False
    r = scan(c, PHISH).json()
    assert r["degraded"] is True and r["evidence"]["model"] is None
    assert r["risk_level"] in {"medium", "high"} and r["risk_score"] >= 30   # rules alone still flag it, less confidently


def test_redirect_hosts_raise_score_and_are_sanitised(client):
    base = scan(client, "https://landing.example.net/page").json()["risk_score"]
    r = scan(client, "https://landing.example.net/page", redirect_hosts=["bit.ly", "t.tracker.top", "not a host"]).json()
    assert r["risk_score"] > base and "redirect_chain" in {i["id"] for i in r["indicators"]}
    assert r["evidence"]["redirect_chain"] == ["bit.ly", "t.tracker.top"]


def test_domain_layer_new_domain_and_bad_cert(make_client):
    rep = {"status": "ok", "dns": {"status": "ok"}, "rdap": {"status": "ok", "age_days": 3},
           "tls": {"status": "verify_failed", "error": "self-signed certificate"}}
    fa = FakeAnalyzer(rep)
    c = make_client(analyzer=fa, enable_network_checks=True)
    r = scan(c, "https://totally-normal-shop.example.com/").json()
    assert {"domain_age_lt7", "tls_invalid"} <= {i["id"] for i in r["indicators"]}
    assert r["risk_level"] in {"medium", "high"} and fa.calls == ["totally-normal-shop.example.com"]
    assert next(x for x in r["checks"] if x["name"] == "Domain age")["status"] == "fail"


def test_network_checks_can_be_disabled(make_client):
    fa = FakeAnalyzer()
    c = make_client(analyzer=fa, enable_network_checks=False)
    scan(c, "https://example.com")
    assert fa.calls == []


# ---------------------------------------------- intel through the API
def test_exact_intel_match_overrides_and_is_reported(client):
    url = "https://harmless-looking.example.org/page"
    assert scan(client, url).json()["risk_level"] == "low"
    r = client.post("/api/v1/admin/indicators/import", json={"source": "unit-feed", "urls": [url + "?a=1"]}, headers=ADMIN)
    assert r.json()["added"] == 1
    res = scan(client, url).json()
    assert res["risk_score"] >= 95 and res["risk_level"] == "high" and res["scoring"]["override"] == "threat_intel_exact_match"
    assert res["evidence"]["threat_intel"]["sources"] == ["unit-feed"]
    assert {"intel_exact"} <= {i["id"] for i in res["indicators"]}


def test_allowlist_via_api_and_platform_protection(client):
    r = client.post("/api/v1/admin/indicators", json={"kind": "domain", "value": "trusted-corp.com", "verdict": "allow"}, headers=ADMIN)
    assert r.status_code == 201
    assert client.post("/api/v1/admin/indicators", json={"kind": "domain", "value": "github.io", "verdict": "allow"}, headers=ADMIN).status_code == 422
    assert scan(client, "http://trusted-corp.com/login.php?x=1").json()["risk_score"] <= 15


# ------------------------------------------------------------- reports
def test_report_flow_and_admin_triage(client):
    sid = scan(client, "https://www.wikipedia.org/").json()["scan_id"]
    r = client.post("/api/v1/report", json={"scan_id": sid, "report_type": "false_negative", "comment": "looks phishy"}, headers=HDR)
    assert r.status_code == 201
    rid = r.json()["id"]
    assert client.post("/api/v1/report", json={"scan_id": "0" * 36, "report_type": "false_positive"}, headers=HDR).status_code == 404
    assert client.post("/api/v1/report", json={"report_type": "false_positive"}, headers=HDR).status_code == 422
    assert client.post("/api/v1/report", json={"url": "https://a.com/x?t=secret", "report_type": "false_positive"}, headers=HDR).status_code == 201
    lst = client.get("/api/v1/admin/reports?status=open", headers=ADMIN).json()
    assert len(lst) == 2 and all("secret" not in x["url"] for x in lst)
    assert client.patch(f"/api/v1/admin/reports/{rid}", json={"status": "resolved"}, headers=ADMIN).json()["status"] == "resolved"
    assert client.get("/api/v1/admin/reports?status=open", headers=ADMIN).json().__len__() == 1


def test_report_rate_limit(client):
    codes = [client.post("/api/v1/report", json={"url": "https://a.com", "report_type": "false_positive"}, headers=HDR).status_code
             for _ in range(12)]
    assert codes.count(201) == 10 and codes[-1] == 429


# ---------------------------------------------------------------- admin
def test_admin_stats_and_lists(client):
    scan(client, PHISH); scan(client, "https://www.wikipedia.org/"); scan(client, "https://www.wikipedia.org/wiki/X")
    st = client.get("/api/v1/admin/stats?days=7", headers=ADMIN).json()
    assert st["totals"]["scans"] == 3 and st["totals"]["high"] == 1 and st["totals"]["low"] == 2
    assert st["timeline"] and st["recent_threats"] and st["top_indicators"]
    assert st["model"]["selected_algorithm"] and st["latency_ms"]["samples"] == 3
    assert len(client.get("/api/v1/admin/scans?level=high", headers=ADMIN).json()) == 1
    assert client.get("/api/v1/admin/scans?level=bogus", headers=ADMIN).status_code == 422
    assert client.get("/api/v1/admin/events", headers=ADMIN).status_code == 200
    assert client.get("/api/v1/admin/model", headers=ADMIN).json()["model_version"]


def test_indicator_crud_is_audited(client):
    c = client.post("/api/v1/admin/indicators", json={"kind": "url", "value": "http://evil.top/x", "verdict": "malicious"}, headers=ADMIN)
    iid = c.json()["id"]
    assert len(client.get("/api/v1/admin/indicators?verdict=malicious", headers=ADMIN).json()) == 1
    assert client.delete(f"/api/v1/admin/indicators/{iid}", headers=ADMIN).status_code == 204
    assert client.delete(f"/api/v1/admin/indicators/{iid}", headers=ADMIN).status_code == 404
    ev = client.get("/api/v1/admin/events", headers=ADMIN).json()
    assert sum(e["type"] == "admin_action" for e in ev) >= 2


# ------------------------------------------------------ headers / config
def test_security_headers_and_no_docs_in_prod(make_client):
    c = make_client(env="prod")
    r = c.get("/api/v1/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert c.get("/api/docs").status_code == 404 and c.get("/api/openapi.json").status_code == 404
    d = c.get("/dashboard/")
    assert "script-src 'self'" in d.headers.get("Content-Security-Policy", "")


def test_prod_refuses_to_start_without_keys(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_ENV", "prod")
    monkeypatch.delenv("PHISHGUARD_SCAN_KEYS", raising=False)
    monkeypatch.delenv("PHISHGUARD_ADMIN_KEYS", raising=False)
    with pytest.raises(RuntimeError):
        load_settings()


def test_short_keys_rejected(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_SCAN_KEYS", "short")
    monkeypatch.setenv("PHISHGUARD_ADMIN_KEYS", "a" * 24)
    with pytest.raises(RuntimeError):
        load_settings()
