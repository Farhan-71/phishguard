import socket
import ssl
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from backend.services.domain_analysis import DomainAnalyzer, TTLCache


@pytest.fixture(scope="module")
def tls_server(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    cert, key = d / "c.pem", d / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", "30", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    stop = threading.Event()

    def loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with ctx.wrap_socket(c, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    yield {"port": srv.getsockname()[1], "cert": str(cert)}
    stop.set()
    srv.close()


def test_tls_self_signed_fails_verification(tls_server):
    a = DomainAnalyzer(tls_port=tls_server["port"], timeout=2)
    r = a._tls("localhost", ["127.0.0.1"])
    assert r["status"] == "verify_failed" and r["error"]


def test_tls_valid_when_ca_trusted(tls_server):
    a = DomainAnalyzer(tls_port=tls_server["port"], timeout=2, tls_cafile=tls_server["cert"])
    r = a._tls("localhost", ["127.0.0.1"])
    assert r["status"] == "ok" and r["cert_age_days"] in (0, 1) and 28 <= r["days_to_expiry"] <= 30
    assert r["tls_version"].startswith("TLS")


def test_tls_hostname_mismatch_is_detected(tls_server):
    a = DomainAnalyzer(tls_port=tls_server["port"], timeout=2, tls_cafile=tls_server["cert"])
    assert a._tls("not-localhost.example", ["127.0.0.1"])["status"] == "verify_failed"


def test_tls_closed_port_reports_no_tls():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    assert DomainAnalyzer(tls_port=port, timeout=1)._tls("localhost", ["127.0.0.1"])["status"] == "no_tls"


def test_ssrf_guard_never_connects_to_private_addresses(monkeypatch):
    a = DomainAnalyzer(timeout=1)
    connected = []
    monkeypatch.setattr(socket, "create_connection", lambda *x, **k: connected.append(x) or (_ for _ in ()).throw(OSError))
    monkeypatch.setattr(a, "_rdap", lambda d: {"status": "unavailable"})
    # attacker-controlled DNS answers with an internal address
    monkeypatch.setattr(a, "_dns", lambda h, d: {"status": "ok", "a": ["169.254.169.254"], "aaaa": [], "ns": [],
                                                 "has_mx": False, "min_ttl": 60, "private_ip": True, "public_ips": []})
    rep = a.analyze("innocent-looking.example.com", "example.com", deadline=2)
    assert connected == []
    assert rep["tls"]["status"] == "skipped" and rep["dns"]["private_ip"] is True


def test_private_ip_literal_host_is_flagged_not_contacted():
    r = DomainAnalyzer()._dns("10.0.0.5", "10.0.0.5")
    assert r["private_ip"] is True and r["public_ips"] == []
    r = DomainAnalyzer()._dns("93.184.216.34", "93.184.216.34")
    assert r["private_ip"] is False and r["public_ips"] == ["93.184.216.34"]


def test_rdap_parsing():
    created = (datetime.now(timezone.utc) - timedelta(days=12)).isoformat().replace("+00:00", "Z")
    doc = {"events": [{"eventAction": "registration", "eventDate": created}, {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}],
           "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]]}]}
    r = DomainAnalyzer._parse_rdap(doc)
    assert r["status"] == "ok" and r["age_days"] == 12 and r["registrar"] == "Example Registrar"
    assert DomainAnalyzer._parse_rdap({})["status"] == "no_data"


def test_disabled_analyzer_makes_no_calls(monkeypatch):
    a = DomainAnalyzer(enabled=False)
    monkeypatch.setattr(a, "_dns", lambda *x: pytest.fail("should not be called"))
    assert a.analyze("example.com", "example.com") == {"status": "disabled"}


def test_deadline_yields_partial_report_not_hang(monkeypatch):
    a = DomainAnalyzer(timeout=1)
    monkeypatch.setattr(a, "_dns", lambda h, d: time.sleep(1.5) or {"status": "ok"})
    monkeypatch.setattr(a, "_rdap", lambda d: time.sleep(1.5) or {"status": "ok"})
    t0 = time.monotonic()
    rep = a.analyze("slow.example.com", "example.com", deadline=0.3)
    assert time.monotonic() - t0 < 1.0
    assert rep["dns"]["status"] == "timeout" and rep["tls"]["status"] == "skipped"


def test_complete_reports_are_cached_incomplete_are_not(monkeypatch):
    a = DomainAnalyzer(timeout=1)
    n = {"dns": 0}

    def dns_ok(h, d):
        n["dns"] += 1
        return {"status": "ok", "a": [], "public_ips": [], "private_ip": False}
    monkeypatch.setattr(a, "_dns", dns_ok)
    monkeypatch.setattr(a, "_rdap", lambda d: {"status": "ok", "age_days": 500})
    a.analyze("h.example.com", "example.com"); a.analyze("h.example.com", "example.com")
    assert n["dns"] == 1


def test_ttl_cache_expiry_and_bound():
    c = TTLCache(ttl=0.05, max_items=2)
    c.set("a", 1); c.set("b", 2); c.set("c", 3)
    assert sum(c.get(k) is not None for k in "abc") == 2
    time.sleep(0.08)
    assert c.get("c") is None
