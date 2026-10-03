"""Aggregations for the security dashboard (all via the ORM; no raw SQL)."""
from __future__ import annotations

import json
from collections import Counter
from datetime import timedelta
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database.models import Report, Scan, SecurityEvent, ThreatIndicator, utcnow


def _percentile(values: list[int], q: float) -> int:
    if not values:
        return 0
    s = sorted(values)
    return s[min(len(s) - 1, int(q * len(s)))]


def load_model_metrics(path: Path) -> dict | None:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def dashboard_stats(session: Session, days: int, metrics_path: Path) -> dict:
    now = utcnow()
    since = now - timedelta(days=days)
    in_window = Scan.created_at >= since

    total = session.scalar(select(func.count()).select_from(Scan).where(in_window)) or 0
    by_level = {"low": 0, "medium": 0, "high": 0}
    for level, n in session.execute(select(Scan.risk_level, func.count()).where(in_window)
                                    .group_by(Scan.risk_level)).all():
        by_level[level] = n

    day = func.date(Scan.created_at)
    timeline: dict[str, dict[str, int]] = {}
    for d, level, n in session.execute(select(day, Scan.risk_level, func.count()).where(in_window)
                                       .group_by(day, Scan.risk_level).order_by(day)).all():
        timeline.setdefault(str(d), {"low": 0, "medium": 0, "high": 0})[level] = n

    recent = session.execute(select(Scan).where(in_window).order_by(Scan.created_at.desc()).limit(3000)).scalars().all()
    ind_counter: Counter = Counter()
    for s in recent:
        for i in s.indicators or []:
            if i.get("source") in {"url", "domain", "redirect", "threat_intel"} and i.get("weight", 0) > 0:
                ind_counter[(i["id"], i["title"])] += 1
    latencies = [s.latency_ms for s in recent[:1000]]

    threats = session.execute(select(Scan).where(Scan.risk_level == "high").order_by(Scan.created_at.desc())
                              .limit(15)).scalars().all()

    reports: dict[str, dict[str, int]] = {}
    for rtype, status, n in session.execute(select(Report.report_type, Report.status, func.count())
                                            .group_by(Report.report_type, Report.status)).all():
        reports.setdefault(rtype, {})[status] = n

    ev24 = {t: n for t, n in session.execute(select(SecurityEvent.event_type, func.count())
            .where(SecurityEvent.created_at >= now - timedelta(hours=24)).group_by(SecurityEvent.event_type)).all()}

    intel = [{"kind": k, "verdict": v, "source": src, "count": n} for k, v, src, n in session.execute(
        select(ThreatIndicator.kind, ThreatIndicator.verdict, ThreatIndicator.source, func.count())
        .group_by(ThreatIndicator.kind, ThreatIndicator.verdict, ThreatIndicator.source)).all()]

    return {
        "window_days": days,
        "totals": {"scans": total, **by_level},
        "timeline": [{"date": d, **v} for d, v in sorted(timeline.items())],
        "top_indicators": [{"id": k[0], "title": k[1], "count": n} for k, n in ind_counter.most_common(10)],
        "recent_threats": [{"id": t.id, "created_at": t.created_at.isoformat() + "Z", "url": t.url,
                            "risk_score": t.risk_score, "intel_match": t.intel_match} for t in threats],
        "latency_ms": {"mean": round(sum(latencies) / len(latencies)) if latencies else 0,
                       "p95": _percentile(latencies, 0.95), "samples": len(latencies)},
        "scan_distribution": [s.risk_score for s in recent[:400]],
        "reports": reports,
        "security_events_24h": ev24,
        "threat_intel": intel,
        "model": load_model_metrics(metrics_path),
    }
