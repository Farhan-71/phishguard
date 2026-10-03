"""URL feature engine.

The *same* function is used by the training pipeline and by the live API, which
is what prevents train/serve skew. Only lexical, offline-computable features are
used here: they are fast (microseconds), need no network access, and are
available for every URL in a training set. Domain age, DNS and TLS signals are
gathered separately at scan time and enter the score through the risk engine
(see ``docs/scoring.md``).
"""
from __future__ import annotations

import math
import re
from collections import Counter
from functools import lru_cache
from urllib.parse import urlsplit

from .reference_data import (
    BRANDS,
    EXECUTABLE_EXTENSIONS,
    HOMOGLYPHS,
    PHISHING_KEYWORDS,
    RISKY_TLDS,
    SHARED_HOSTING_SUFFIXES,
    TRUSTED_BRAND_SUFFIXES,
    URL_SHORTENERS,
)
from .url_utils import HostParts, sanitize_url, split_host

FEATURE_NAMES: tuple[str, ...] = (
    "url_length", "host_length", "path_length", "query_length", "num_query_params",
    "num_dots_host", "num_subdomain_labels", "num_hyphens_host", "num_hyphens_url",
    "num_digits_host", "digit_ratio_url", "num_special_chars", "has_at_symbol",
    "has_userinfo", "is_ip_host", "is_obfuscated_ip", "keyword_count_host",
    "keyword_count_path", "num_percent_encoded", "nonstandard_port", "path_depth",
    "has_punycode", "is_https", "risky_tld", "tld_length", "host_entropy",
    "longest_label_length", "brand_in_subdomain", "brand_in_path", "brand_in_domain_label",
    "is_brand_lookalike", "is_shortener", "has_double_slash_path", "executable_extension",
    "registered_label_hyphens", "registered_label_digit_ratio", "is_shared_hosting",
)

_SPECIAL = frozenset("@?&=_%~$!*+;,")
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
_PERCENT = re.compile(r"%[0-9a-fA-F]{2}")


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def is_legit_brand_domain(brand: str, hp: HostParts) -> bool:
    """Is this host a genuine property of *brand*?"""
    if hp.is_ip:
        return False
    if hp.registered_domain in BRANDS.get(brand, ()):
        return True
    return hp.domain == brand and hp.suffix in TRUSTED_BRAND_SUFFIXES


def _token_matches_brand(token: str, brand: str) -> bool:
    if token == brand:
        return True
    # Longer brand names are matched as prefix/suffix of a token to catch
    # "paypal-secure" / "securepaypal" / "paypalverify" without flagging
    # unrelated words that merely end in a short brand ("purchase" vs "chase").
    return len(brand) >= 6 and (token.startswith(brand) or token.endswith(brand))


def brand_hits(text: str) -> set[str]:
    tokens = [t for t in _TOKEN_SPLIT.split(text.lower()) if t]
    hits: set[str] = set()
    for brand in BRANDS:
        if any(_token_matches_brand(t, brand) for t in tokens):
            hits.add(brand)
    return hits


@lru_cache(maxsize=4096)
def lookalike_brand(label: str) -> str | None:
    """Return the brand that *label* impersonates via typo/homoglyph, if any."""
    if not label or len(label) < 4:
        return None
    norm = label.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    for brand in BRANDS:
        if label == brand:
            continue
        if norm == brand:
            return brand
        n = len(brand)
        limit = 2 if n >= 8 else (1 if n >= 5 else 0)
        if limit and abs(len(label) - n) <= limit and levenshtein(norm, brand) <= limit:
            return brand
    return None


def keyword_hits(text: str) -> list[str]:
    t = text.lower()
    return [k for k in PHISHING_KEYWORDS if k in t]


def extract_features(url: str, *, sanitized: bool = False) -> dict[str, float]:
    """Return the feature dict for *url* (sanitises first unless told it's done)."""
    if not sanitized:
        url = sanitize_url(url)
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    hp = split_host(host)
    path, query = p.path, p.query
    label = hp.domain
    suffix_tld = hp.suffix.split(".")[-1] if hp.suffix else ""

    letters_digits = sum(c.isdigit() for c in url)
    brands_sub = brand_hits(hp.subdomain) if hp.subdomain else set()
    brands_path = brand_hits(path)
    brands_label = brand_hits(label) if not hp.is_ip else set()

    def impersonates(brands: set[str]) -> bool:
        return any(not is_legit_brand_domain(b, hp) for b in brands)

    feats: dict[str, float] = {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_query_params": len([q for q in query.split("&") if q]),
        "num_dots_host": host.count("."),
        "num_subdomain_labels": len(hp.subdomain_labels),
        "num_hyphens_host": host.count("-"),
        "num_hyphens_url": url.count("-"),
        "num_digits_host": sum(c.isdigit() for c in host),
        "digit_ratio_url": letters_digits / max(len(url), 1),
        "num_special_chars": sum(c in _SPECIAL for c in url),
        "has_at_symbol": "@" in url,
        "has_userinfo": "@" in p.netloc,
        "is_ip_host": hp.is_ip,
        "is_obfuscated_ip": hp.is_obfuscated_ip,
        "keyword_count_host": len(keyword_hits(host)),
        "keyword_count_path": len(keyword_hits(path + "?" + query)),
        "num_percent_encoded": len(_PERCENT.findall(url)),
        "nonstandard_port": p.port is not None,
        "path_depth": len([s for s in path.split("/") if s]),
        "has_punycode": "xn--" in host,
        "is_https": p.scheme == "https",
        "risky_tld": suffix_tld in RISKY_TLDS,
        "tld_length": len(suffix_tld),
        "host_entropy": _entropy(host),
        "longest_label_length": max((len(x) for x in host.split(".")), default=0),
        "brand_in_subdomain": impersonates(brands_sub),
        "brand_in_path": impersonates(brands_path),
        # impersonates() already accepts the brand's genuine domains, so an exact
        # brand label on a risky TLD / shared-hosting suffix is (correctly) flagged.
        "brand_in_domain_label": (not hp.is_ip) and impersonates(brands_label),
        "is_brand_lookalike": (not hp.is_ip) and lookalike_brand(label) is not None,
        "is_shortener": hp.registered_domain in URL_SHORTENERS,
        "has_double_slash_path": "//" in path,
        "executable_extension": path.lower().endswith(EXECUTABLE_EXTENSIONS),
        "registered_label_hyphens": label.count("-"),
        "registered_label_digit_ratio": (
            sum(c.isdigit() for c in label) / max(len(label), 1)
        ),
        "is_shared_hosting": (
            hp.suffix in SHARED_HOSTING_SUFFIXES
            or hp.registered_domain in SHARED_HOSTING_SUFFIXES
        ),
    }
    return {k: float(feats[k]) for k in FEATURE_NAMES}


def feature_vector(url: str, *, sanitized: bool = False) -> list[float]:
    f = extract_features(url, sanitized=sanitized)
    return [f[n] for n in FEATURE_NAMES]


# Human-readable descriptions used when explaining which features drove the model.
# name -> (title, detail template; "{v}" is replaced by the feature value)
FEATURE_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "is_ip_host": ("IP address used as host", "The address is a raw IP instead of a domain name."),
    "is_obfuscated_ip": ("Obfuscated IP address", "The host is an IP written in hex/decimal/octal form."),
    "has_at_symbol": ("'@' character in URL", "Browsers ignore text before '@', which attackers use to disguise the real destination."),
    "has_userinfo": ("Credentials-style prefix in URL", "The URL contains 'user@' before the host name."),
    "num_subdomain_labels": ("Many subdomain levels", "{v} subdomain levels before the registered domain."),
    "num_dots_host": ("Many dots in host name", "{v} dots in the host name."),
    "num_hyphens_host": ("Hyphens in host name", "{v} hyphens in the host name, often used to mimic brands."),
    "num_hyphens_url": ("Many hyphens in URL", "{v} hyphens in the URL."),
    "keyword_count_host": ("Sensitive keywords in host", "Host contains {v} words such as 'login', 'secure' or 'verify'."),
    "keyword_count_path": ("Sensitive keywords in path", "Path/query contains {v} words such as 'login', 'verify' or 'account'."),
    "brand_in_subdomain": ("Brand name in subdomain", "A well-known brand appears in a subdomain of an unrelated domain."),
    "brand_in_path": ("Brand name in URL path", "A well-known brand appears in the path of an unrelated domain."),
    "brand_in_domain_label": ("Brand name inside domain", "The domain embeds a brand name but is not the brand's own domain."),
    "is_brand_lookalike": ("Look-alike of a known brand", "The domain is a near-miss spelling or character swap of a well-known brand."),
    "risky_tld": ("Frequently abused top-level domain", "This TLD is disproportionately used for throw-away domains."),
    "has_punycode": ("Internationalised (punycode) host", "The host uses xn-- encoding, which can hide look-alike characters."),
    "nonstandard_port": ("Non-standard port", "The URL uses an unusual port."),
    "num_percent_encoded": ("Heavy URL encoding", "{v} percent-encoded characters."),
    "url_length": ("Very long URL", "The URL is {v} characters long."),
    "path_depth": ("Deep URL path", "The path has {v} levels."),
    "is_https": ("Connection is not HTTPS", "The page is loaded over plain HTTP."),
    "is_shortener": ("URL shortener", "The link goes through a shortening service that hides the destination."),
    "executable_extension": ("Executable/archive download", "The path ends in an executable or archive extension."),
    "host_entropy": ("Random-looking host name", "The host name looks machine-generated."),
    "registered_label_digit_ratio": ("Digits inside domain name", "A large share of the domain name is digits."),
    "num_digits_host": ("Digits in host name", "{v} digits in the host name."),
    "is_shared_hosting": ("Free/shared hosting platform", "Anyone can publish a site on this platform."),
    "has_double_slash_path": ("Double slash in path", "The path contains '//', a common redirect trick."),
    "longest_label_length": ("Very long host label", "A host label is {v} characters long."),
    "num_special_chars": ("Many special characters", "{v} special characters in the URL."),
}
