import pytest

from backend.services.features import FEATURE_NAMES, extract_features, levenshtein, lookalike_brand


def f(url):
    return extract_features(url)


def test_vector_shape_and_types():
    feats = f("https://www.example.com/a?b=1")
    assert tuple(feats) == FEATURE_NAMES
    assert all(isinstance(v, float) for v in feats.values())


def test_ip_and_obfuscated_ip():
    assert f("http://203.0.113.9/login")["is_ip_host"] == 1
    x = f("http://2130706433/")
    assert x["is_ip_host"] == 1 and x["is_obfuscated_ip"] == 1
    assert f("https://example.com/")["is_ip_host"] == 0


def test_brand_in_subdomain_vs_real_brand():
    fake = f("http://paypal.com.secure-login.evil-site.top/signin")
    assert fake["brand_in_subdomain"] == 1 and fake["risky_tld"] == 1 and fake["keyword_count_host"] >= 1
    real = f("https://www.paypal.com/signin")
    assert real["brand_in_subdomain"] == 0 and real["brand_in_domain_label"] == 0
    assert f("https://accounts.google.com/signin")["brand_in_subdomain"] == 0


def test_brand_on_untrusted_suffix_or_shared_hosting():
    assert f("https://www.roblox.com.bi/games/1")["brand_in_domain_label"] == 1
    assert f("https://paypal.github.io/x")["brand_in_domain_label"] == 1
    assert f("https://www.amazon.co.uk/dp/1")["brand_in_domain_label"] == 0


@pytest.mark.parametrize("label,brand", [("paypa1", "paypal"), ("paypall", "paypal"), ("arnazon", "amazon"),
                                         ("g00gle", "google"), ("micros0ft", "microsoft")])
def test_lookalikes(label, brand):
    assert lookalike_brand(label) == brand


@pytest.mark.parametrize("label", ["paypal", "example", "purchase", "google", "chasing"])
def test_not_lookalikes(label):
    assert lookalike_brand(label) is None


def test_short_brand_word_not_matched_inside_longer_words():
    assert f("https://shop.example.com/purchase/checkout")["brand_in_path"] == 0


def test_query_values_do_not_influence_features():
    a = f("https://example.com/p?token=aaaaaaaaaaaaaaaaaaaaa")
    b = f("https://example.com/p?token=b")
    assert a == b


def test_userinfo_punycode_port_shared():
    x = f("http://google.com@evil.com:8081/")
    assert x["has_userinfo"] == 1 and x["nonstandard_port"] == 1
    assert f("http://xn--pypal-4ve.com/")["has_punycode"] == 1
    assert f("https://someone.netlify.app/")["is_shared_hosting"] == 1
    assert f("https://example.com/")["is_shared_hosting"] == 0


def test_https_flag():
    assert f("https://example.com/")["is_https"] == 1 and f("http://example.com/")["is_https"] == 0


def test_levenshtein():
    assert levenshtein("kitten", "sitting") == 3 and levenshtein("", "abc") == 3 and levenshtein("a", "a") == 0
