"""API schemas. Strict input validation: unknown fields are rejected and every
string has an explicit length bound."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanRequest(Strict):
    url: str = Field(min_length=1, max_length=2048)
    # Hostnames (no paths/queries) the browser passed through before this page.
    redirect_hosts: list[str] = Field(default_factory=list, max_length=10)
    client_version: str | None = Field(default=None, max_length=32)


class IndicatorOut(BaseModel):
    id: str
    title: str
    detail: str
    severity: Literal["info", "low", "medium", "high"]
    source: Literal["url", "domain", "redirect", "threat_intel", "model"]
    weight: int


class CheckOut(BaseModel):
    name: str
    status: Literal["pass", "warn", "fail", "unknown", "info"]
    detail: str = ""


class ScanResponse(BaseModel):
    scan_id: str | None
    url: str
    host: str
    registered_domain: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["low", "medium", "high"]
    label: str
    summary: str
    indicators: list[IndicatorOut]
    checks: list[CheckOut]
    evidence: dict
    scoring: dict
    degraded: bool = False
    not_applicable: bool = False
    latency_ms: int


class ReportRequest(Strict):
    scan_id: str | None = Field(default=None, min_length=36, max_length=36)
    url: str | None = Field(default=None, max_length=2048)
    report_type: Literal["false_positive", "false_negative"]
    comment: str = Field(default="", max_length=500)


class IndicatorCreate(Strict):
    kind: Literal["url", "domain"]
    value: str = Field(min_length=3, max_length=1024)
    verdict: Literal["malicious", "allow"]
    source: str = Field(default="admin", max_length=64)
    ttl_days: int | None = Field(default=None, ge=1, le=3650)


class FeedImport(Strict):
    source: str = Field(min_length=1, max_length=64)
    urls: list[str] = Field(min_length=1, max_length=5000)
    ttl_days: int | None = Field(default=30, ge=1, le=365)


class ReportUpdate(Strict):
    status: Literal["open", "resolved", "rejected"]
