"""Application factory.

Run with:  uvicorn --factory backend.api.main:app_factory --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from ..config import REPO_ROOT, Settings, load_settings
from ..database.session import init_db, make_engine, make_session_factory
from ..services.domain_analysis import DomainAnalyzer
from ..services.ml_service import MLModel, ModelIntegrityError
from ..services.scanner import Scanner
from .routes import router
from .security import RateLimiter

log = logging.getLogger("phishguard")
DASHBOARD_DIR = REPO_ROOT / "dashboard"

DASHBOARD_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                 "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def create_app(settings: Settings | None = None, *, ml: MLModel | None | str = "auto",
               analyzer: DomainAnalyzer | None = None) -> FastAPI:
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        app.state.engine.dispose()

    app = FastAPI(
        title="PhishGuard Detection API", version="1.0.0", lifespan=lifespan,
        docs_url="/api/docs" if settings.is_dev else None,
        redoc_url=None, openapi_url="/api/openapi.json" if settings.is_dev else None,
    )

    engine = make_engine(settings.database_url)
    init_db(engine)
    session_factory = make_session_factory(engine)

    if ml == "auto":
        try:
            ml = MLModel.load(settings.model_path)
            log.info("Loaded model %s", ml.version)
        except FileNotFoundError:
            log.warning("No model at %s: running in rules-only (degraded) mode. "
                        "Train one with `python -m ml.training.train`.", settings.model_path)
            ml = None
        except ModelIntegrityError:
            log.critical("Model integrity check failed; refusing to start.")
            raise
    analyzer = analyzer or DomainAnalyzer(enabled=settings.enable_network_checks, timeout=settings.network_timeout)

    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.ml = ml
    app.state.analyzer = analyzer
    app.state.limiter = RateLimiter()
    app.state.scanner = Scanner(settings, session_factory, ml, analyzer)

    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                           allow_methods=["GET", "POST", "PATCH", "DELETE"],
                           allow_headers=["X-API-Key", "Content-Type"], max_age=600)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        elif request.url.path.startswith("/dashboard"):
            resp.headers["Content-Security-Policy"] = DASHBOARD_CSP
        return resp

    app.include_router(router)

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/dashboard/")

    if DASHBOARD_DIR.exists():
        app.mount("/dashboard", StaticFiles(directory=DASHBOARD_DIR, html=True), name="dashboard")
    return app


def app_factory() -> FastAPI:
    """Entry point for uvicorn:  uvicorn --factory backend.api.main:app_factory"""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return create_app()
