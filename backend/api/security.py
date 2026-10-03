"""API security primitives: authentication, authorisation, rate limiting, audit events."""
from __future__ import annotations

import hashlib
import hmac
import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request
from sqlalchemy.orm import Session, sessionmaker

from ..config import Settings, key_id
from ..database.models import SecurityEvent

log = logging.getLogger("phishguard.security")


class RateLimiter:
    """In-process sliding-window limiter.

    Limitation (documented in docs/threat-model.md): state is per process, so with N
    worker processes the effective limit is N times higher. Put a shared limiter
    (Redis, or the reverse proxy) in front for multi-worker deployments.
    """

    def __init__(self, max_keys: int = 50_000):
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._max_keys = max_keys

    def hit(self, bucket: str, limit: int, window: float = 60.0) -> tuple[bool, int, float]:
        """Record a hit. Returns (allowed, count_in_window, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > self._max_keys:
                for k in [k for k, q in self._hits.items() if not q or q[-1] < now - window]:
                    del self._hits[k]
            q = self._hits[bucket]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False, len(q), max(0.0, window - (now - q[0]))
            q.append(now)
            return True, len(q), 0.0


@dataclass(frozen=True)
class Principal:
    key_id: str
    role: str  # "scan" | "admin"


def _digest(s: str) -> bytes:
    return hashlib.sha256(s.encode()).digest()


def identify(api_key: str | None, settings: Settings) -> Principal | None:
    """Constant-time comparison against *all* configured keys (no early exit)."""
    if not api_key:
        return None
    d = _digest(api_key)
    role = None
    for k in settings.admin_api_keys:
        if hmac.compare_digest(d, _digest(k)):
            role = "admin"
    for k in settings.scan_api_keys:
        if hmac.compare_digest(d, _digest(k)) and role is None:
            role = "scan"
    return Principal(key_id(api_key), role) if role else None


def actor_hash(request: Request, settings: Settings) -> str:
    ip = request.client.host if request.client else "unknown"
    return hashlib.sha256((settings.log_salt + ip).encode()).hexdigest()[:12]


def log_event(session_factory: sessionmaker[Session], event_type: str, severity: str = "info",
              actor: str = "", detail: str = "") -> None:
    """Persist a security event. ``detail`` must never contain secrets or full URLs."""
    log.info("security_event type=%s severity=%s actor=%s", event_type, severity, actor)
    try:
        with session_factory() as s:
            s.add(SecurityEvent(event_type=event_type, severity=severity, actor=actor[:24],
                                detail=detail[:500]))
            s.commit()
    except Exception:  # logging must never break request handling
        log.exception("failed to persist security event")


def _enforce(request: Request, api_key: str | None, need_admin: bool) -> Principal:
    st = request.app.state
    settings: Settings = st.settings
    limiter: RateLimiter = st.limiter
    actor = actor_hash(request, settings)

    ok, _, retry = limiter.hit(f"ip:{actor}", settings.ip_rate_limit)
    if not ok:
        if limiter.hit(f"rlog-ip:{actor}", 1)[0]:
            log_event(st.session_factory, "rate_limited", "warning", actor, "per-address limit exceeded")
        raise HTTPException(429, "Too many requests", headers={"Retry-After": str(int(retry) + 1)})

    principal = identify(api_key, settings)
    if principal is None:
        allowed, count, retry = limiter.hit(f"authfail:{actor}", 20)
        if count <= 5 and allowed:  # cap how many failures we write to the DB
            log_event(st.session_factory, "auth_failure", "warning", actor,
                      "missing API key" if not api_key else "invalid API key")
        if not allowed:
            raise HTTPException(429, "Too many failed attempts", headers={"Retry-After": str(int(retry) + 1)})
        raise HTTPException(401, "Invalid or missing API key", headers={"WWW-Authenticate": "ApiKey"})

    if need_admin and principal.role != "admin":
        log_event(st.session_factory, "forbidden", "warning", principal.key_id, "scan key used on admin endpoint")
        raise HTTPException(403, "Administrator key required")

    limit = settings.admin_rate_limit if principal.role == "admin" else settings.scan_rate_limit
    ok, _, retry = limiter.hit(f"key:{principal.key_id}", limit)
    if not ok:
        if limiter.hit(f"rlog:{principal.key_id}", 1)[0]:
            log_event(st.session_factory, "rate_limited", "warning", principal.key_id, "per-key limit exceeded")
        raise HTTPException(429, "Rate limit exceeded", headers={"Retry-After": str(int(retry) + 1)})
    return principal


def require_scan(request: Request, x_api_key: str | None = Header(default=None, max_length=256)) -> Principal:
    return _enforce(request, x_api_key, need_admin=False)


def require_admin(request: Request, x_api_key: str | None = Header(default=None, max_length=256)) -> Principal:
    return _enforce(request, x_api_key, need_admin=True)
