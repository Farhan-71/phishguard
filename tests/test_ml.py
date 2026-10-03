import shutil
from pathlib import Path

import pytest

from backend.services.features import FEATURE_NAMES, extract_features
from backend.services.ml_service import MLModel, ModelIntegrityError
from ml.dataset.synthetic import generate
from ml.training.train import grouped_split, train

MODEL_DIR = Path(__file__).resolve().parent.parent / "ml" / "models"


def test_phishing_scores_higher_than_benign(model):
    bad = model.predict(extract_features("http://paypal.com.secure-login.evil-site.top/signin/verify.php"))
    good = model.predict(extract_features("https://www.wikipedia.org/"))
    assert bad > 0.8 and good < 0.2


def test_explanations_name_real_drivers(model):
    f = extract_features("http://203.0.113.9:8080/secure/login.php")
    ex = model.explain(f)
    assert ex and ex == sorted(ex, key=lambda d: -d["contribution"])
    assert {"is_ip_host", "nonstandard_port", "is_https", "keyword_count_path"} & {e["feature"] for e in ex}
    assert all(e["title"] and e["detail"] and e["contribution"] >= 0.03 for e in ex)


def test_explain_is_empty_for_benign_baseline(model):
    assert model.explain(extract_features("https://www.example.com/"), min_contribution=0.2) == []


def test_tampered_model_is_refused(tmp_path):
    for n in ("model.joblib", "model.joblib.sha256"):
        shutil.copy(MODEL_DIR / n, tmp_path / n)
    with (tmp_path / "model.joblib").open("ab") as fh:
        fh.write(b"\x00tampered")
    with pytest.raises(ModelIntegrityError):
        MLModel.load(tmp_path / "model.joblib")


def test_missing_digest_is_refused(tmp_path):
    shutil.copy(MODEL_DIR / "model.joblib", tmp_path / "model.joblib")
    with pytest.raises(ModelIntegrityError):
        MLModel.load(tmp_path / "model.joblib")


def test_grouped_split_has_no_domain_leakage():
    import numpy as np
    groups = np.array([f"d{i % 300}" for i in range(3000)])
    tr, va, te = grouped_split(groups, seed=1)
    s = lambda idx: set(groups[idx])  # noqa: E731
    assert not (s(tr) & s(te)) and not (s(va) & s(te)) and not (s(tr) & s(va))


def test_generator_is_reproducible_and_overlapping():
    a, b = generate(300, seed=5), generate(300, seed=5)
    assert a.equals(b)
    assert set(a.label) == {0, 1} and a.url.is_unique


def test_training_smoke_run(tmp_path):
    """End-to-end on a tiny dataset: trains, writes artefact + digest + metrics, reloads."""
    csv = tmp_path / "urls.csv"
    generate(700, seed=3).to_csv(csv, index=False)
    rep = train(csv, tmp_path / "out", seed=1, fast=True)
    assert set(rep["test_metrics_candidates"]) == {"logistic_regression", "decision_tree", "random_forest"}
    m = rep["test_metrics_final"]
    for k in ("precision", "recall", "f1", "average_precision", "confusion_matrix", "false_positive_rate", "false_negative_rate"):
        assert k in m
    assert m["f1"] > 0.7 and rep["warning"]
    loaded = MLModel.load(tmp_path / "out" / "model.joblib")
    assert 0 <= loaded.predict(extract_features("http://1.2.3.4/login")) <= 1
    assert list(loaded.feature_names) == list(FEATURE_NAMES)
