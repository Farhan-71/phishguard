from datetime import timedelta

import pytest

from backend.database.models import ThreatIndicator, utcnow
from backend.database.session import init_db, make_engine, make_session_factory
from backend.services import threat_intel as ti
from backend.services.url_utils import sanitize_url


@pytest.fixture
def session():
    engine = make_engine("sqlite://")
    init_db(engine)
    with make_session_factory(engine)() as s:
        yield s


def L(session, url):
    return ti.lookup(session, sanitize_url(url))


def test_exact_url_match_ignores_scheme_query_www(session):
    ti.bulk_add(session, [sanitize_url("http://evil.example.top/login.php?id=5")], "test")
    assert L(session, "https://www.evil.example.top/login.php?other=1").exact_match
    assert not L(session, "https://evil.example.top/other.php").exact_match


def test_host_match_is_weaker_and_separate(session):
    ti.bulk_add(session, [sanitize_url("http://evil.example.top/a.php")], "feedA")
    r = L(session, "http://evil.example.top/b.php")
    assert r.host_match and not r.exact_match and r.sources == ["feedA"]


def test_no_host_match_on_large_platforms(session):
    ti.bulk_add(session, [sanitize_url("https://docs.google.com/forms/d/e/abc/viewform")], "feed")
    assert L(session, "https://docs.google.com/forms/d/e/abc/viewform").exact_match
    r = L(session, "https://docs.google.com/document/d/legit/edit")
    assert not r.host_match and not r.exact_match


def test_shared_hosting_tenant_host_match_allowed(session):
    ti.bulk_add(session, [sanitize_url("https://evil-shop.github.io/a")], "feed")
    assert L(session, "https://evil-shop.github.io/b").host_match
    assert not L(session, "https://good-project.github.io/b").host_match


def test_expired_indicators_ignored_and_purged(session):
    ti.bulk_add(session, [sanitize_url("http://old.example.top/x")], "feed", ttl_days=1)
    row = session.query(ThreatIndicator).one()
    row.expires_at = utcnow() - timedelta(minutes=1)
    session.commit()
    assert not L(session, "http://old.example.top/x").exact_match
    assert ti.purge_expired(session) == 1


def test_bulk_add_dedups_and_refreshes(session):
    u = sanitize_url("http://a.example.top/x")
    assert ti.bulk_add(session, [u, u], "f") == (1, 0)
    assert ti.bulk_add(session, [u], "f") == (0, 1)


def test_admin_domain_block_and_allow(session):
    ti.add_indicator(session, "domain", "bad-domain.top", "malicious", "admin", "k1")
    assert L(session, "http://bad-domain.top/x").exact_match
    assert L(session, "http://sub.bad-domain.top/x").exact_match   # a domain block covers its subdomains
    assert not L(session, "http://other-domain.top/x").exact_match
    ti.add_indicator(session, "domain", "trusted-shop.com", "allow", "admin", "k1")
    assert L(session, "https://www.trusted-shop.com/").allowlisted


def test_cannot_allowlist_shared_or_platform(session):
    for d in ("github.io", "docs.google.com", "google.com", "evil.netlify.app"):
        with pytest.raises(ValueError):
            ti.add_indicator(session, "domain", d, "allow", "admin", "k1")


def test_allow_only_for_domains(session):
    with pytest.raises(ValueError):
        ti.add_indicator(session, "url", "http://x.com/a", "allow", "admin", "k1")


def test_feed_parsers():
    assert ti.parse_plain_feed("# c\nhttp://a.top/x\n\njavascript:alert(1)\nhttps://b.top/y?z=1") == \
        ["http://a.top/x", "https://b.top/y?z="]
    csv_text = ("phish_id,url,phish_detail_url,submission_time,verified,online,target\n"
                "1,http://a.top/x,u,t,yes,yes,PayPal\n2,http://b.top/x,u,t,yes,no,X\n3,http://c.top/x,u,t,no,yes,X\n")
    assert ti.parse_phishtank_csv(csv_text) == ["http://a.top/x"]
