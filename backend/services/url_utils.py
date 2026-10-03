"""URL validation, normalisation and privacy-preserving sanitisation.

Every URL entering the system (API, training pipeline, feed import) goes
through :func:`sanitize_url` first. It:

* accepts only http/https and rejects control characters and oversized input,
* lower-cases the host and converts IDNs to punycode,
* drops the fragment (``#...``) and any password in the userinfo,
* keeps query parameter *names* but discards their *values*
  (``?token=abc&id=7`` -> ``?token=&id=``), because values are where session
  tokens, e-mail addresses and one-time codes live.

The function is idempotent, and the browser extension applies an equivalent
transformation client-side (see ``extension/shared/url.js`` and the shared test
vectors in ``tests/vectors/sanitize.json``).
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit

import tldextract

MAX_URL_LENGTH = 2048
MAX_QUERY_PARAMS = 50
ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):(?!\d)")
_HOST_CHARS = re.compile(r"^[a-z0-9._\-]+$")
_OBFUSCATED_IPV4 = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.I)


class InvalidURL(ValueError):
    """Raised when a submitted URL cannot be accepted."""


@dataclass(frozen=True)
class HostParts:
    host: str
    subdomain: str
    domain: str  # the registrable label, e.g. "paypal" in paypal.com
    suffix: str  # public suffix, e.g. "com" or "co.uk"
    registered_domain: str  # domain + suffix, or the IP literal itself
    is_ip: bool
    is_obfuscated_ip: bool

    @property
    def subdomain_labels(self) -> list[str]:
        return [s for s in self.subdomain.split(".") if s]


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    # suffix_list_urls=() -> use the snapshot bundled with the package, no
    # network access at runtime. Private suffixes (github.io, pages.dev, ...) are
    # included so that user-controlled subdomains are treated as separate sites.
    return tldextract.TLDExtract(
        suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
    )


def parse_ip_host(host: str) -> tuple[ipaddress._BaseAddress | None, bool]:
    """Return (ip, obfuscated) if *host* is an IP literal in any common notation."""
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h), False
    except ValueError:
        pass
    if _OBFUSCATED_IPV4.match(h):
        try:
            packed = socket.inet_aton(h)  # accepts decimal/hex/octal shorthand
            return ipaddress.IPv4Address(packed), True
        except OSError:
            return None, False
    return None, False


def split_host(host: str) -> HostParts:
    ip, obfuscated = parse_ip_host(host)
    if ip is not None:
        return HostParts(host, "", host, "", host, True, obfuscated)
    ext = _extractor()(host)
    domain, suffix = ext.domain, ext.suffix
    registered = f"{domain}.{suffix}" if suffix else domain
    return HostParts(host, ext.subdomain, domain, suffix, registered, False, False)


def redact_query(query: str) -> str:
    """Keep parameter names, drop values."""
    parts: list[str] = []
    for seg in query.split("&"):
        if not seg:
            continue
        name, sep, _ = seg.partition("=")
        parts.append(f"{name}=" if sep else name)
        if len(parts) >= MAX_QUERY_PARAMS:
            break
    return "&".join(parts)


def sanitize_url(raw: str) -> str:
    """Validate and sanitise a URL. Raises :class:`InvalidURL` on rejection."""
    if not isinstance(raw, str):
        raise InvalidURL("URL must be a string")
    url = raw.strip()
    if not url:
        raise InvalidURL("URL is empty")
    if len(url) > MAX_URL_LENGTH:
        raise InvalidURL("URL exceeds maximum length")
    if _CONTROL_CHARS.search(url):
        raise InvalidURL("URL contains control characters")
    url = url.replace(" ", "%20")

    if "://" not in url:
        m = _SCHEME_RE.match(url)
        if m and m.group(1).lower() not in ALLOWED_SCHEMES:
            raise InvalidURL(f"Unsupported scheme: {m.group(1).lower()}")
        url = "http://" + url.lstrip("/")

    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise InvalidURL("Malformed URL") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidURL(f"Unsupported scheme: {scheme}")

    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise InvalidURL("URL has no host")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidURL("Invalid internationalised host") from exc
    if len(host) > 253:
        raise InvalidURL("Host too long")
    if ":" in host:  # IPv6 literal
        try:
            host = ipaddress.IPv6Address(host).compressed
        except ValueError as exc:
            raise InvalidURL("Invalid IPv6 address") from exc
        netloc_host = f"[{host}]"
    else:
        if not _HOST_CHARS.match(host) or ".." in host:
            raise InvalidURL("Host contains invalid characters")
        netloc_host = host

    netloc = netloc_host
    if parts.username:
        netloc = f"{parts.username}@{netloc}"  # password intentionally dropped
    if port is not None and port != DEFAULT_PORTS[scheme]:
        netloc += f":{port}"

    path = parts.path or "/"
    query = redact_query(parts.query)
    out = f"{scheme}://{netloc}{path}"
    if query:
        out += f"?{query}"
    return out


def get_host(sanitized_url: str) -> str:
    return (urlsplit(sanitized_url).hostname or "").lower()


def match_key(sanitized_url: str) -> str:
    """Canonical key for threat-intel lookups: host + path, no scheme/query/www."""
    p = urlsplit(sanitized_url)
    host = (p.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = p.path.rstrip("/")
    return f"{host}{path}"[:1024]


def sanitize_hostname(raw: str) -> str | None:
    """Validate a bare hostname (used for client-supplied redirect hops)."""
    try:
        return get_host(sanitize_url(f"http://{raw}/"))
    except (InvalidURL, TypeError):
        return None


def is_public_ip(ip: ipaddress._BaseAddress) -> bool:
    """True only for globally routable unicast addresses (SSRF guard)."""
    return bool(ip.is_global and not ip.is_multicast)


_LOCAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".intranet", ".test")


def is_local_host(host: str) -> bool:
    """True for hosts that are not on the public internet (never scanned or sent to APIs):
    localhost, single-label intranet names, private/loopback/link-local IPs."""
    host = host.lower().rstrip(".")
    ip, _ = parse_ip_host(host)
    if ip is not None:
        return not is_public_ip(ip)
    return host == "localhost" or "." not in host or host.endswith(_LOCAL_SUFFIXES)
