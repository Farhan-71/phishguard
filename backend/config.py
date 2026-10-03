"""Runtime configuration, loaded from environment variables.

Secrets (API keys) are never hard-coded. See ``.env.example``.
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("phishguard.config")

REPO_ROOT = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _csv(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    return tuple(p.strip() for p in raw.split(",") if p.strip())


def key_id(api_key: str) -> str:
    """Stable, non-reversible identifier for logging (never log the key itself)."""
    return hashlib.sha256(api_key.encode()).hexdigest()[:10]


@dataclass(frozen=True)
class Settings:
    env: str = "dev"
    database_url: str = f"sqlite:///{REPO_ROOT / 'phishguard.db'}"
    scan_api_keys: tuple[str, ...] = ()
    admin_api_keys: tuple[str, ...] = ()
    # Requests per minute, per API key.
    scan_rate_limit: int = 60
    admin_rate_limit: int = 120
    # Requests per minute per client address, applied before authentication so
    # unauthenticated floods are cheap to reject.
    ip_rate_limit: int = 240
    enable_network_checks: bool = True
    network_timeout: float = 2.5
    scan_deadline: float = 4.0
    cors_origins: tuple[str, ...] = ()
    model_path: Path = REPO_ROOT / "ml" / "models" / "model.joblib"
    model_metrics_path: Path = REPO_ROOT / "ml" / "models" / "metrics.json"
    intel_ttl_days: int = 30
    # Operating point for prior-shift correction of the model probability (see docs/scoring.md).
    assumed_prevalence: float = 0.3
    log_salt: str = field(default_factory=lambda: secrets.token_hex(16))

    @property
    def is_dev(self) -> bool:
        return self.env == "dev"


def load_settings() -> Settings:
    env = os.environ.get("PHISHGUARD_ENV", "dev").lower()
    scan_keys = _csv("PHISHGUARD_SCAN_KEYS")
    admin_keys = _csv("PHISHGUARD_ADMIN_KEYS")

    if not scan_keys or not admin_keys:
        if env != "dev":
            raise RuntimeError(
                "PHISHGUARD_SCAN_KEYS and PHISHGUARD_ADMIN_KEYS must be set "
                "when PHISHGUARD_ENV is not 'dev'. Run `python scripts/gen_keys.py`."
            )
        # Dev convenience only: generate ephemeral keys and print them once.
        if not scan_keys:
            scan_keys = (secrets.token_urlsafe(24),)
            log.warning("DEV MODE: ephemeral scan key generated: %s", scan_keys[0])
        if not admin_keys:
            admin_keys = (secrets.token_urlsafe(24),)
            log.warning("DEV MODE: ephemeral admin key generated: %s", admin_keys[0])

    for k in (*scan_keys, *admin_keys):
        if len(k) < 16:
            raise RuntimeError("API keys must be at least 16 characters long.")

    return Settings(
        env=env,
        database_url=os.environ.get("DATABASE_URL", Settings.database_url),
        scan_api_keys=scan_keys,
        admin_api_keys=admin_keys,
        scan_rate_limit=_int("PHISHGUARD_SCAN_RATE_LIMIT", 60),
        admin_rate_limit=_int("PHISHGUARD_ADMIN_RATE_LIMIT", 120),
        ip_rate_limit=_int("PHISHGUARD_IP_RATE_LIMIT", 240),
        enable_network_checks=_bool("PHISHGUARD_NETWORK_CHECKS", True),
        network_timeout=_float("PHISHGUARD_NETWORK_TIMEOUT", 2.5),
        scan_deadline=_float("PHISHGUARD_SCAN_DEADLINE", 4.0),
        cors_origins=_csv("PHISHGUARD_CORS_ORIGINS"),
        model_path=Path(os.environ.get("PHISHGUARD_MODEL_PATH", Settings.model_path)),
        model_metrics_path=Path(
            os.environ.get("PHISHGUARD_METRICS_PATH", Settings.model_metrics_path)
        ),
        intel_ttl_days=_int("PHISHGUARD_INTEL_TTL_DAYS", 30),
        assumed_prevalence=min(0.9, max(0.001, _float("PHISHGUARD_ASSUMED_PREVALENCE", 0.3))),
        log_salt=os.environ.get("PHISHGUARD_LOG_SALT") or secrets.token_hex(16),
    )
