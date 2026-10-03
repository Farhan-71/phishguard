"""Database schema (SQLAlchemy 2.0).

All access goes through the ORM / bound parameters, so there is no string-built SQL
anywhere in the code base. Timestamps are naive UTC. Privacy notes:

* ``Scan.url`` stores the *sanitised* URL (no query values, fragment or password).
* Client IP addresses are never stored; ``SecurityEvent.actor`` holds a salted,
  truncated hash for correlating repeated abuse only.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    url: Mapped[str] = mapped_column(String(2100))
    host: Mapped[str] = mapped_column(String(255), index=True)
    registered_domain: Mapped[str] = mapped_column(String(255), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String(8), index=True)
    ml_probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    indicators: Mapped[list] = mapped_column(JSON, default=list)
    intel_match: Mapped[str | None] = mapped_column(String(16), nullable=True)  # exact|host|allow
    client_key_id: Mapped[str] = mapped_column(String(16))
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    __table_args__ = (UniqueConstraint("kind", "value", "verdict", name="uq_indicator"),
                      Index("ix_indicator_host", "host"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(8))          # url | domain
    value: Mapped[str] = mapped_column(String(1024))      # match_key() or registered domain
    host: Mapped[str] = mapped_column(String(255), default="")
    verdict: Mapped[str] = mapped_column(String(10))      # malicious | allow
    source: Mapped[str] = mapped_column(String(64))
    added_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    added_by: Mapped[str] = mapped_column(String(16), default="system")


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    url: Mapped[str] = mapped_column(String(2100))
    report_type: Mapped[str] = mapped_column(String(16))  # false_positive | false_negative
    comment: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(10), default="open", index=True)
    client_key_id: Mapped[str] = mapped_column(String(16))


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(8), default="info")
    actor: Mapped[str] = mapped_column(String(24), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
