"""Threat-intelligence layer: local indicator store + feed import + lookup.

Design
------
* Feeds (PhishTank, OpenPhish, ...) are **imported into the local database** by
  ``scripts/sync_feeds.py`` on a schedule that respects each provider's terms and
  rate limits. Scans never call third-party feed APIs, so a user's browsing is not
  leaked to a feed provider and scan latency does not depend on them.
* Matching levels (strongest first):
    exact   -- this exact URL (host+path, query ignored) is listed as malicious
    domain  -- an administrator listed the whole domain as malicious
    host    -- *other* URLs on this very host are listed (weaker; disabled for shared
               hosting and very large platforms, where one bad page says nothing
               about the rest of the site)
    allow   -- an administrator allow-listed the registered domain (never possible for
               shared hosting / large platforms)
* Imported feed entries expire (default 30 days) because phishing sites are short-lived.
"""
from __future__ import annotations

import csv
import io
from datetime import timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from ..database.models import ThreatIndicator, utcnow
from .reference_data import LARGE_PLATFORM_DOMAINS, SHARED_HOSTING_SUFFIXES
from .risk_engine import IntelResult
from .url_utils import InvalidURL, get_host, match_key, sanitize_url, split_host


def is_shared_or_platform(registered_domain: str, suffix: str = "") -> bool:
    return (registered_domain in SHARED_HOSTING_SUFFIXES or suffix in SHARED_HOSTING_SUFFIXES
            or registered_domain in LARGE_PLATFORM_DOMAINS)


def _active(now):
    return or_(ThreatIndicator.expires_at.is_(None), ThreatIndicator.expires_at > now)


def lookup(session: Session, sanitized_url: str) -> IntelResult:
    host = get_host(sanitized_url)
    hp = split_host(host)
    key = match_key(sanitized_url)
    now = utcnow()
    result = IntelResult()

    rows = session.execute(
        select(ThreatIndicator.kind, ThreatIndicator.value, ThreatIndicator.host,
               ThreatIndicator.verdict, ThreatIndicator.source)
        .where(_active(now))
        .where(or_(
            and_(ThreatIndicator.kind == "url", ThreatIndicator.value == key),
            and_(ThreatIndicator.kind == "domain", ThreatIndicator.value.in_([hp.registered_domain, host])),
            and_(ThreatIndicator.kind == "url", ThreatIndicator.verdict == "malicious",
                 ThreatIndicator.host == host),
        ))
        .limit(50)
    ).all()

    # Host-level matches say "other pages on this host were reported". That is meaningful
    # for an ordinary site and for a specific shared-hosting tenant (evil.github.io), but
    # not for a very large multi-tenant platform (docs.google.com) or a bare hosting suffix.
    host_level_ok = (hp.registered_domain not in LARGE_PLATFORM_DOMAINS
                     and hp.registered_domain not in SHARED_HOSTING_SUFFIXES)

    for kind, value, ihost, verdict, source in rows:
        if verdict == "malicious":
            if kind == "url" and value == key:
                result.exact_match = True
            elif kind == "domain":
                if is_shared_or_platform(hp.registered_domain, hp.suffix) and value != host:
                    continue  # never block a whole platform by its registered domain
                result.exact_match = True
            elif kind == "url" and ihost == host and host_level_ok:
                result.host_match = True
            else:
                continue
            result.sources.append(source)
        elif verdict == "allow" and kind == "domain" and value == hp.registered_domain:
            if not is_shared_or_platform(hp.registered_domain, hp.suffix):
                result.allowlisted = True
    result.sources = sorted(set(result.sources))
    return result


# ------------------------------------------------------------------- feed parsing
def parse_plain_feed(text: str) -> list[str]:
    """One URL per line (OpenPhish / Phishing.Database style)."""
    urls = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            urls.append(sanitize_url(line))
        except InvalidURL:
            continue
    return urls


def parse_phishtank_csv(text: str) -> list[str]:
    """PhishTank ``verified_online.csv``: keep entries that are verified *and* online."""
    urls = []
    for row in csv.DictReader(io.StringIO(text)):
        if (row.get("verified") or "").lower() == "yes" and (row.get("online") or "").lower() == "yes":
            try:
                urls.append(sanitize_url(row.get("url", "")))
            except InvalidURL:
                continue
    return urls


def bulk_add(session: Session, sanitized_urls: list[str], source: str, ttl_days: int | None = 30,
             added_by: str = "system") -> tuple[int, int]:
    """Insert URL indicators, skipping ones already present (their expiry is refreshed)."""
    expires = utcnow() + timedelta(days=ttl_days) if ttl_days else None
    entries: dict[str, str] = {}
    for u in sanitized_urls:
        entries.setdefault(match_key(u), get_host(u))
    keys = list(entries)
    existing: set[str] = set()
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        for row in session.execute(select(ThreatIndicator).where(
                ThreatIndicator.kind == "url", ThreatIndicator.verdict == "malicious",
                ThreatIndicator.value.in_(chunk))).scalars():
            existing.add(row.value)
            row.expires_at = expires
    added = 0
    for key in keys:
        if key in existing:
            continue
        session.add(ThreatIndicator(kind="url", value=key, host=entries[key], verdict="malicious",
                                    source=source[:64], expires_at=expires, added_by=added_by))
        added += 1
    session.commit()
    return added, len(keys) - added


def add_indicator(session: Session, kind: str, value: str, verdict: str, source: str,
                  added_by: str, ttl_days: int | None = None) -> ThreatIndicator:
    """Admin-managed indicator with validation."""
    if kind not in {"url", "domain"} or verdict not in {"malicious", "allow"}:
        raise ValueError("kind must be url|domain and verdict malicious|allow")
    if kind == "url":
        if verdict == "allow":
            raise ValueError("Allow-listing is only supported for whole domains")
        s = sanitize_url(value)
        stored, host = match_key(s), get_host(s)
    else:
        host = value.strip().lower().rstrip(".")
        hp = split_host(sanitize_url(f"http://{host}/").split("//", 1)[1].split("/", 1)[0])
        stored = hp.registered_domain if verdict == "allow" else host
        if verdict == "allow" and is_shared_or_platform(hp.registered_domain, hp.suffix):
            raise ValueError("Shared-hosting and large platform domains cannot be allow-listed")
    ind = session.execute(select(ThreatIndicator).where(
        ThreatIndicator.kind == kind, ThreatIndicator.value == stored,
        ThreatIndicator.verdict == verdict)).scalar_one_or_none()
    if ind is None:
        ind = ThreatIndicator(kind=kind, value=stored, host=host, verdict=verdict)
        session.add(ind)
    ind.source, ind.added_by = source[:64], added_by
    ind.expires_at = utcnow() + timedelta(days=ttl_days) if ttl_days else None
    session.commit()
    return ind


def purge_expired(session: Session) -> int:
    rows = session.execute(select(ThreatIndicator).where(
        ThreatIndicator.expires_at.is_not(None), ThreatIndicator.expires_at <= utcnow())).scalars().all()
    for r in rows:
        session.delete(r)
    session.commit()
    return len(rows)
