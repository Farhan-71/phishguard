import json
from pathlib import Path

import pytest

from backend.services.url_utils import (InvalidURL, is_local_host, match_key, parse_ip_host,
                                        sanitize_hostname, sanitize_url, split_host)

VEC = json.loads((Path(__file__).parent / "vectors" / "sanitize.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", VEC["valid"], ids=lambda c: c["input"][:40])
def test_shared_vectors(case):
    assert sanitize_url(case["input"]) == case["expected"]


@pytest.mark.parametrize("bad", VEC["invalid"] + ["http://a b\x00c.com", "http://" + "a" * 300 + ".com",
                                                  "http://exa mple..com/", "x" * 3000, "http://[::1"])
def test_rejects_invalid(bad):
    with pytest.raises(InvalidURL):
        sanitize_url(bad)


def test_idempotent():
    for c in VEC["valid"]:
        s = sanitize_url(c["input"])
        assert sanitize_url(s) == s


def test_scheme_less_input_gets_http():
    assert sanitize_url("example.com:8080/a b") == "http://example.com:8080/a%20b"


def test_secrets_are_dropped():
    s = sanitize_url("https://bob:hunter2@shop.example.com/cb?session=abc123&email=a@b.c#access_token=xyz")
    assert "hunter2" not in s and "abc123" not in s and "a@b.c" not in s and "xyz" not in s
    assert "session=" in s  # names are kept


def test_at_sign_trick_keeps_real_host():
    assert split_host("evil.com").registered_domain == "evil.com"
    assert sanitize_url("http://google.com@evil.com/").startswith("http://google.com@evil.com")


@pytest.mark.parametrize("host,obf", [("192.168.0.1", False), ("2130706433", True), ("0x7f000001", True),
                                     ("0177.0.0.1", True), ("[::1]", False), ("example.com", None)])
def test_ip_parsing(host, obf):
    ip, o = parse_ip_host(host)
    if obf is None:
        assert ip is None
    else:
        assert ip is not None and o is obf


@pytest.mark.parametrize("host,local", [("localhost", True), ("192.168.1.1", True), ("10.0.0.5", True),
                                       ("127.0.0.1", True), ("169.254.169.254", True), ("2130706433", True),
                                       ("intranet", True), ("printer.local", True), ("::1", True),
                                       ("8.8.8.8", False), ("example.com", False), ("evil.github.io", False)])
def test_is_local_host(host, local):
    assert is_local_host(host) is local


def test_split_host_private_suffix():
    hp = split_host("paypal.com.evil.co.uk")
    assert (hp.domain, hp.suffix, hp.subdomain) == ("evil", "co.uk", "paypal.com")
    assert split_host("someone.github.io").registered_domain == "someone.github.io"


def test_match_key_ignores_scheme_query_www_trailing_slash():
    a = match_key(sanitize_url("https://www.Evil.com/a/b/?x=1"))
    b = match_key(sanitize_url("http://evil.com/a/b"))
    assert a == b == "evil.com/a/b"


def test_sanitize_hostname():
    assert sanitize_hostname("Bit.LY") == "bit.ly"
    assert sanitize_hostname("not a host") is None
