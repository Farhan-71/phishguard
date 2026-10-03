"""Domain, DNS, RDAP and TLS-certificate analysis.

Security properties (this module makes outbound connections to attacker-chosen
hostnames, so it is the most sensitive part of the backend):

* **SSRF guard** -- the host is resolved *by us*, and TLS is only attempted against
  globally routable addresses. Loopback/private/link-local/multicast results are
  never connected to (and are reported as an indicator instead). The TCP connection
  goes to the address we validated, not to a second DNS lookup (no DNS rebinding).
* Only port 443 is contacted; only a TLS handshake is performed -- no HTTP request is
  ever sent to the target and no page content is downloaded or executed.
* RDAP goes to one fixed, public bootstrap service, never to the target.
* Every step has a short timeout, results are cached, and the caller enforces an
  overall deadline. Any failure degrades to ``status != "ok"`` and adds no risk.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import httpx

from .url_utils import is_public_ip, parse_ip_host

log = logging.getLogger("phishguard.domain")
_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="pg-net")
RDAP_URL = "https://rdap.org/domain/{domain}"
MAX_RDAP_BYTES = 1_000_000


class TTLCache:
    """Tiny thread-safe TTL cache with a size bound."""

    def __init__(self, ttl: float, max_items: int = 2048):
        self.ttl, self.max_items = ttl, max_items
        self._d: dict[str, tuple[float, object]] = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            hit = self._d.get(key)
            if hit and hit[0] > time.monotonic():
                return hit[1]
            self._d.pop(key, None)
            return None

    def set(self, key: str, value: object) -> None:
        with self._lock:
            if len(self._d) >= self.max_items:
                oldest = min(self._d, key=lambda k: self._d[k][0])
                self._d.pop(oldest, None)
            self._d[key] = (time.monotonic() + self.ttl, value)


def _parse_iso(s: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class DomainAnalyzer:
    def __init__(self, enabled: bool = True, timeout: float = 2.5,
                 tls_port: int = 443, tls_cafile: str | None = None,
                 allow_private_targets: bool = False):
        self.enabled = enabled
        self.timeout = timeout
        self.tls_port = tls_port  # overridable for tests only
        self.tls_cafile = tls_cafile
        self.allow_private_targets = allow_private_targets  # tests only
        self._host_cache = TTLCache(ttl=600)
        self._rdap_cache = TTLCache(ttl=86400)

    # ------------------------------------------------------------------ DNS
    def _dns(self, host: str, registered_domain: str) -> dict:
        ip, _ = parse_ip_host(host)
        if ip is not None:
            pub = is_public_ip(ip)
            return {"status": "ok", "a": [str(ip)], "aaaa": [], "ns": [], "has_mx": False,
                    "min_ttl": None, "private_ip": not pub, "public_ips": [str(ip)] if pub else []}
        res = dns.resolver.Resolver()
        res.timeout = res.lifetime = self.timeout
        addrs: list[str] = []
        ttls: list[int] = []
        try:
            for rtype in ("A", "AAAA"):
                try:
                    ans = res.resolve(host, rtype)
                    addrs += [r.to_text() for r in ans]
                    ttls.append(ans.rrset.ttl)
                except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                    continue
        except dns.resolver.NXDOMAIN:
            return {"status": "nxdomain"}
        except dns.exception.Timeout:
            return {"status": "unavailable", "error": "dns timeout"}
        except Exception as exc:  # resolver misconfiguration, no network, ...
            return {"status": "unavailable", "error": type(exc).__name__}

        def optional(rtype: str, name: str):
            try:
                return res.resolve(name, rtype)
            except Exception:
                return None

        ns = optional("NS", registered_domain)
        mx = optional("MX", registered_domain)
        ips = []
        for a in addrs:
            try:
                ips.append(ipaddress.ip_address(a))
            except ValueError:
                pass
        public = [str(i) for i in ips if is_public_ip(i)]
        return {
            "status": "ok",
            "a": [a for a in addrs if ":" not in a], "aaaa": [a for a in addrs if ":" in a],
            "ns": sorted(r.to_text().rstrip(".") for r in ns) if ns else [],
            "has_mx": bool(mx), "min_ttl": min(ttls) if ttls else None,
            "private_ip": bool(ips) and not public,
            "public_ips": public,
        }

    # ------------------------------------------------------------------ RDAP
    def _rdap(self, registered_domain: str) -> dict:
        cached = self._rdap_cache.get(registered_domain)
        if cached is not None:
            return cached  # type: ignore[return-value]
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True, max_redirects=3,
                              headers={"Accept": "application/rdap+json"}) as c:
                r = c.get(RDAP_URL.format(domain=registered_domain))
            if r.status_code == 404:
                out = {"status": "not_found"}
            elif r.status_code != 200 or len(r.content) > MAX_RDAP_BYTES:
                out = {"status": "unavailable", "error": f"http {r.status_code}"}
            else:
                out = self._parse_rdap(r.json())
        except (httpx.HTTPError, ValueError) as exc:
            return {"status": "unavailable", "error": type(exc).__name__}  # not cached
        self._rdap_cache.set(registered_domain, out)
        return out

    @staticmethod
    def _parse_rdap(doc: dict) -> dict:
        created = None
        for ev in doc.get("events", []):
            if ev.get("eventAction") == "registration":
                created = _parse_iso(ev.get("eventDate", ""))
        registrar = None
        for ent in doc.get("entities", []):
            if "registrar" in ent.get("roles", []):
                for item in (ent.get("vcardArray") or [None, []])[1]:
                    if item and item[0] == "fn":
                        registrar = item[3]
        age = (datetime.now(timezone.utc) - created).days if created else None
        return {"status": "ok" if created else "no_data", "created": created.isoformat() if created else None,
                "age_days": age, "registrar": registrar}

    # ------------------------------------------------------------------- TLS
    def _tls(self, host: str, public_ips: list[str]) -> dict:
        targets = list(public_ips)
        if not targets:
            return {"status": "skipped", "reason": "no globally routable address"}
        ctx = ssl.create_default_context(cafile=self.tls_cafile)
        try:
            with socket.create_connection((targets[0], self.tls_port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    cert = s.getpeercert()
                    version = s.version()
        except ssl.SSLCertVerificationError as exc:
            return {"status": "verify_failed", "error": exc.verify_message or "certificate verification failed"}
        except ssl.SSLError as exc:
            return {"status": "verify_failed", "error": (exc.reason or "TLS handshake failed")}
        except OSError:
            return {"status": "no_tls", "error": "port 443 not reachable"}
        now = time.time()
        nb, na = ssl.cert_time_to_seconds(cert["notBefore"]), ssl.cert_time_to_seconds(cert["notAfter"])
        issuer = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
        return {
            "status": "ok", "tls_version": version,
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "not_before": datetime.fromtimestamp(nb, timezone.utc).isoformat(),
            "not_after": datetime.fromtimestamp(na, timezone.utc).isoformat(),
            "cert_age_days": int((now - nb) // 86400),
            "days_to_expiry": int((na - now) // 86400),
        }

    # ----------------------------------------------------------- orchestrator
    def analyze(self, host: str, registered_domain: str, deadline: float = 4.0) -> dict:
        if not self.enabled:
            return {"status": "disabled"}
        cached = self._host_cache.get(host)
        if cached is not None:
            return cached  # type: ignore[return-value]

        ip, _ = parse_ip_host(host)
        t0 = time.monotonic()
        f_dns = _EXECUTOR.submit(self._dns, host, registered_domain)
        f_rdap = _EXECUTOR.submit(self._rdap, registered_domain) if ip is None else None
        report: dict = {"status": "ok", "dns": {"status": "timeout"}, "rdap": {"status": "skipped" if ip else "timeout"},
                        "tls": {"status": "timeout"}}

        wait([f_dns], timeout=max(0.1, deadline - (time.monotonic() - t0)))
        if f_dns.done():
            report["dns"] = f_dns.result()
            pub = report["dns"].get("public_ips", [])
            if self.allow_private_targets and not pub:
                pub = report["dns"].get("a", [])
            f_tls = _EXECUTOR.submit(self._tls, host, pub) if report["dns"].get("status") == "ok" else None
            if f_tls is None:
                report["tls"] = {"status": "skipped", "reason": "host did not resolve"}
        else:
            f_tls = None
            report["tls"] = {"status": "skipped", "reason": "dns timeout"}

        pending = [f for f in (f_rdap, f_tls) if f is not None]
        if pending:
            wait(pending, timeout=max(0.1, deadline - (time.monotonic() - t0)))
        if f_rdap is not None and f_rdap.done():
            report["rdap"] = f_rdap.result()
        if f_tls is not None and f_tls.done():
            report["tls"] = f_tls.result()

        incomplete = any(report[k].get("status") in {"timeout", "unavailable"} for k in ("dns", "rdap", "tls"))
        if not incomplete:
            self._host_cache.set(host, report)
        return report
