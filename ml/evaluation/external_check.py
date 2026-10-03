"""Out-of-distribution sanity check on REAL URLs.

* Phishing side: a snapshot of a public phishing feed (e.g. OpenPhish community
  feed, one URL per line), split into a *dev* half (inspected while tuning) and a
  *holdout* half (scored only after tuning). Positives only, so this
  measures *recall*.
* Benign side: ``ml/dataset/external/legit_urls.txt``, a small hand-curated list
  of genuine sites including login/account pages. Measures *false-positive rate*.

Neither set was used for training and neither was produced by the synthetic
generator, so this is the honest indicator of whether the model transfers. The
benign list is small (~90 URLs): treat the result as a smoke test, not a benchmark.

    python -m ml.evaluation.external_check --phish-dev dev.txt --phish-holdout holdout.txt
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from backend.config import Settings
from backend.services.features import extract_features
from backend.services.ml_service import MLModel
from backend.services.risk_engine import IntelResult, adjust_for_prevalence, compute_risk, url_indicators
from backend.services.url_utils import InvalidURL, get_host, is_local_host, sanitize_url
from ml.dataset.build_dataset import read_urls
from ml.training.train import MODELS_DIR

EXT = Path(__file__).resolve().parent.parent / "dataset" / "external"
LEGIT_DEV = EXT / "legit_urls.txt"          # inspected while tuning
LEGIT_HOLDOUT = EXT / "legit_holdout_urls.txt"  # written afterwards, never used to tune


def score(model: MLModel, urls: list[str]) -> list[tuple[str, float]]:
    out = []
    for u in urls:
        try:
            s = sanitize_url(u)
        except InvalidURL:
            continue
        out.append((s, model.predict(extract_features(s, sanitized=True))))
    return out


def pipeline_levels(model: MLModel, path: Path, prevalence: float) -> dict:
    """Level distribution of the full offline pipeline (ML + URL rules + prior correction).
    Network-derived signals (domain age, TLS) and threat intel are NOT included: this is the
    floor of what the deployed system sees. Private/local addresses are skipped, as the API does."""
    scores = []
    for u in read_urls(path):
        try:
            s = sanitize_url(u)
        except InvalidURL:
            continue
        if is_local_host(get_host(s)):
            continue
        f = extract_features(s, sanitized=True)
        p = adjust_for_prevalence(model.predict(f), prevalence)
        scores.append(compute_risk(p, url_indicators(f), IntelResult()).score)
    a = np.array(scores)
    return {"n": len(a), "prevalence_setting": prevalence,
            "share_medium_or_high": float((a >= 30).mean()), "share_high": float((a >= 60).mean())}


def _benign_report(model: MLModel, path: Path) -> dict:
    res = score(model, read_urls(path))
    p = np.array([v for _, v in res])
    return {
        "n": len(res),
        "false_positive_rate@0.5": float((p >= 0.5).mean()),
        "share_at_or_above_0.3": float((p >= 0.3).mean()),
        "median_probability": float(np.median(p)),
        "worst": [{"url": u, "p": round(v, 3)} for u, v in sorted(res, key=lambda t: -t[1])[:8]],
    }


def _phish_report(model: MLModel, path: Path) -> dict:
    res = score(model, read_urls(path))
    p = np.array([v for _, v in res])
    return {
        "n": len(res),
        "recall@0.5": float((p >= 0.5).mean()),
        "recall@0.3": float((p >= 0.3).mean()),
        "median_probability": float(np.median(p)),
        "lowest_scored": [{"url": u, "p": round(v, 3)} for u, v in sorted(res, key=lambda t: t[1])[:8]],
    }


def run(phish_dev: Path | None = None, phish_holdout: Path | None = None,
        model_dir: Path = MODELS_DIR) -> dict:
    model = MLModel.load(model_dir / "model.joblib")
    prev = Settings.assumed_prevalence
    result: dict = {"model_version": model.version,
                    "benign_dev": _benign_report(model, LEGIT_DEV),
                    "benign_holdout": _benign_report(model, LEGIT_HOLDOUT),
                    "pipeline": {"benign_dev": pipeline_levels(model, LEGIT_DEV, prev),
                                 "benign_holdout": pipeline_levels(model, LEGIT_HOLDOUT, prev)}}
    if phish_dev and phish_dev.exists():
        result["phishing_dev"] = _phish_report(model, phish_dev)
        result["pipeline"]["phishing_dev"] = pipeline_levels(model, phish_dev, prev)
    if phish_holdout and phish_holdout.exists():
        result["phishing_holdout"] = _phish_report(model, phish_holdout)
        result["pipeline"]["phishing_holdout"] = pipeline_levels(model, phish_holdout, prev)
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phish-dev", type=Path, help="phishing URLs used while tuning")
    ap.add_argument("--phish-holdout", type=Path, help="phishing URLs never used for tuning")
    ap.add_argument("--out", type=Path, help="write JSON result here")
    a = ap.parse_args()
    res = run(a.phish_dev, a.phish_holdout)
    print(json.dumps(res, indent=2))
    if a.out:
        a.out.write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
