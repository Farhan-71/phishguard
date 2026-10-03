from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.main import create_app
from backend.config import Settings
from backend.services.ml_service import MLModel

MODEL_PATH = Path(__file__).resolve().parent.parent / "ml" / "models" / "model.joblib"
SCAN_KEY = "s" * 24
ADMIN_KEY = "a" * 24


@pytest.fixture(scope="session")
def model() -> MLModel:
    if not MODEL_PATH.exists():
        pytest.skip("trained model not present (run: python -m ml.training.train)")
    return MLModel.load(MODEL_PATH)


class FakeAnalyzer:
    """Stands in for DomainAnalyzer so API tests never touch the network."""
    def __init__(self, report=None):
        self.report = report or {"status": "ok", "dns": {"status": "ok", "a": ["93.184.216.34"], "private_ip": False},
                                 "rdap": {"status": "ok", "age_days": 4000, "registrar": "Test"},
                                 "tls": {"status": "ok", "issuer": "Test CA", "cert_age_days": 60}}
        self.calls = []

    def analyze(self, host, registered_domain, deadline=4.0):
        self.calls.append(host)
        return self.report


def make_settings(**kw) -> Settings:
    base = dict(env="test", database_url="sqlite://", scan_api_keys=(SCAN_KEY,), admin_api_keys=(ADMIN_KEY,),
                enable_network_checks=False, scan_rate_limit=1000, admin_rate_limit=1000, ip_rate_limit=10000)
    base.update(kw)
    return Settings(**base)


@pytest.fixture
def make_client(model):
    def _make(ml="model", analyzer=None, **settings_kw) -> TestClient:
        app = create_app(make_settings(**settings_kw), ml=model if ml == "model" else ml, analyzer=analyzer)
        return TestClient(app)
    return _make


@pytest.fixture
def client(make_client):
    return make_client()


HDR = {"X-API-Key": SCAN_KEY}
ADMIN = {"X-API-Key": ADMIN_KEY}
