"""HTTP routes. All handlers are synchronous (run in FastAPI's threadpool)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, text

from ..database.models import Report, Scan, SecurityEvent, ThreatIndicator
from ..models.schemas import (FeedImport, IndicatorCreate, ReportRequest, ReportUpdate, ScanRequest,
                              ScanResponse)
from ..services import threat_intel
from ..services.risk_engine import SCORING_VERSION
from ..services.stats import dashboard_stats, load_model_metrics
from ..services.url_utils import InvalidURL, sanitize_url
from .security import Principal, log_event, require_admin, require_scan

router = APIRouter(prefix="/api/v1")


# ------------------------------------------------------------------- public
@router.get("/health")
def health(request: Request) -> dict:
    st = request.app.state
    try:
        with st.session_factory() as s:
            s.execute(text("SELECT 1"))
        db = "ok"
    except Exception:
        db = "error"
    return {"status": "ok" if db == "ok" else "degraded", "database": db,
            "model_loaded": st.ml is not None, "model_version": st.ml.version if st.ml else None,
            "network_checks": st.settings.enable_network_checks, "scoring_version": SCORING_VERSION}


# --------------------------------------------------------------------- scan
@router.post("/scan", response_model=ScanResponse)
def scan(body: ScanRequest, request: Request, principal: Principal = Depends(require_scan)) -> dict:
    st = request.app.state
    try:
        return st.scanner.scan(body, principal.key_id)
    except InvalidURL as exc:
        if st.limiter.hit(f"invalid:{principal.key_id}", 5)[0]:
            log_event(st.session_factory, "invalid_url", "info", principal.key_id, str(exc))
        raise HTTPException(422, f"Invalid URL: {exc}")


@router.post("/report", status_code=201)
def report(body: ReportRequest, request: Request, principal: Principal = Depends(require_scan)) -> dict:
    st = request.app.state
    ok, _, retry = st.limiter.hit(f"report:{principal.key_id}", 10)
    if not ok:
        raise HTTPException(429, "Too many reports", headers={"Retry-After": str(int(retry) + 1)})
    with st.session_factory() as s:
        scan_row = s.get(Scan, body.scan_id) if body.scan_id else None
        if body.scan_id and scan_row is None:
            raise HTTPException(404, "Unknown scan_id")
        if scan_row is not None:
            url = scan_row.url
        elif body.url:
            try:
                url = sanitize_url(body.url)
            except InvalidURL as exc:
                raise HTTPException(422, f"Invalid URL: {exc}")
        else:
            raise HTTPException(422, "Provide scan_id or url")
        r = Report(scan_id=body.scan_id, url=url, report_type=body.report_type,
                   comment=body.comment.strip(), client_key_id=principal.key_id)
        s.add(r)
        s.commit()
        return {"id": r.id, "status": r.status}


# -------------------------------------------------------------------- admin
def _scan_row(x: Scan) -> dict:
    return {"id": x.id, "created_at": x.created_at.isoformat() + "Z", "url": x.url, "host": x.host,
            "risk_score": x.risk_score, "risk_level": x.risk_level, "intel_match": x.intel_match,
            "model_version": x.model_version, "latency_ms": x.latency_ms}


@router.get("/admin/stats")
def admin_stats(request: Request, days: int = Query(30, ge=1, le=365), _: Principal = Depends(require_admin)) -> dict:
    st = request.app.state
    with st.session_factory() as s:
        return dashboard_stats(s, days, st.settings.model_metrics_path)


@router.get("/admin/scans")
def admin_scans(request: Request, level: str | None = Query(None, pattern="^(low|medium|high)$"),
                limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                _: Principal = Depends(require_admin)) -> list[dict]:
    q = select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    if level:
        q = q.where(Scan.risk_level == level)
    with request.app.state.session_factory() as s:
        return [_scan_row(x) for x in s.execute(q).scalars()]


@router.get("/admin/reports")
def admin_reports(request: Request, status: str | None = Query(None, pattern="^(open|resolved|rejected)$"),
                  limit: int = Query(50, ge=1, le=200), _: Principal = Depends(require_admin)) -> list[dict]:
    q = select(Report).order_by(Report.created_at.desc()).limit(limit)
    if status:
        q = q.where(Report.status == status)
    with request.app.state.session_factory() as s:
        return [{"id": r.id, "created_at": r.created_at.isoformat() + "Z", "url": r.url, "scan_id": r.scan_id,
                 "report_type": r.report_type, "comment": r.comment, "status": r.status}
                for r in s.execute(q).scalars()]


@router.patch("/admin/reports/{report_id}")
def admin_update_report(report_id: int, body: ReportUpdate, request: Request,
                        p: Principal = Depends(require_admin)) -> dict:
    st = request.app.state
    with st.session_factory() as s:
        r = s.get(Report, report_id)
        if r is None:
            raise HTTPException(404, "Report not found")
        r.status = body.status
        s.commit()
    log_event(st.session_factory, "admin_action", "info", p.key_id, f"report {report_id} -> {body.status}")
    return {"id": report_id, "status": body.status}


@router.get("/admin/indicators")
def admin_indicators(request: Request, verdict: str | None = Query(None, pattern="^(malicious|allow)$"),
                     limit: int = Query(100, ge=1, le=500), _: Principal = Depends(require_admin)) -> list[dict]:
    q = select(ThreatIndicator).order_by(ThreatIndicator.added_at.desc()).limit(limit)
    if verdict:
        q = q.where(ThreatIndicator.verdict == verdict)
    with request.app.state.session_factory() as s:
        return [{"id": i.id, "kind": i.kind, "value": i.value, "verdict": i.verdict, "source": i.source,
                 "added_at": i.added_at.isoformat() + "Z", "added_by": i.added_by,
                 "expires_at": i.expires_at.isoformat() + "Z" if i.expires_at else None}
                for i in s.execute(q).scalars()]


@router.post("/admin/indicators", status_code=201)
def admin_add_indicator(body: IndicatorCreate, request: Request, p: Principal = Depends(require_admin)) -> dict:
    st = request.app.state
    try:
        with st.session_factory() as s:
            ind = threat_intel.add_indicator(s, body.kind, body.value, body.verdict, body.source,
                                             p.key_id, body.ttl_days)
            out = {"id": ind.id, "kind": ind.kind, "value": ind.value, "verdict": ind.verdict}
    except (ValueError, InvalidURL) as exc:
        raise HTTPException(422, str(exc))
    log_event(st.session_factory, "admin_action", "info", p.key_id, f"indicator added: {body.kind}/{body.verdict}")
    return out


@router.post("/admin/indicators/import")
def admin_import(body: FeedImport, request: Request, p: Principal = Depends(require_admin)) -> dict:
    st = request.app.state
    urls = threat_intel.parse_plain_feed("\n".join(body.urls))
    with st.session_factory() as s:
        added, existing = threat_intel.bulk_add(s, urls, body.source, body.ttl_days, added_by=p.key_id)
    log_event(st.session_factory, "admin_action", "info", p.key_id,
              f"feed import '{body.source}': {added} added, {existing} refreshed")
    return {"received": len(body.urls), "valid": len(urls), "added": added, "refreshed": existing}


@router.delete("/admin/indicators/{indicator_id}", status_code=204)
def admin_delete_indicator(indicator_id: int, request: Request, p: Principal = Depends(require_admin)) -> None:
    st = request.app.state
    with st.session_factory() as s:
        ind = s.get(ThreatIndicator, indicator_id)
        if ind is None:
            raise HTTPException(404, "Indicator not found")
        s.delete(ind)
        s.commit()
    log_event(st.session_factory, "admin_action", "info", p.key_id, f"indicator {indicator_id} deleted")


@router.get("/admin/events")
def admin_events(request: Request, limit: int = Query(50, ge=1, le=200), _: Principal = Depends(require_admin)) -> list[dict]:
    with request.app.state.session_factory() as s:
        rows = s.execute(select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(limit)).scalars()
        return [{"id": e.id, "created_at": e.created_at.isoformat() + "Z", "type": e.event_type,
                 "severity": e.severity, "actor": e.actor, "detail": e.detail} for e in rows]


@router.get("/admin/model")
def admin_model(request: Request, _: Principal = Depends(require_admin)) -> dict:
    m = load_model_metrics(request.app.state.settings.model_metrics_path)
    if m is None:
        raise HTTPException(404, "No model metrics available")
    return m
