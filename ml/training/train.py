"""Train and compare Random Forest, Logistic Regression and Decision Tree.

Protocol
--------
* URLs are split into train / validation / test **by registered domain**
  (``GroupShuffleSplit``) so no domain appears on both sides of a boundary.
* The three candidate models are fitted on *train* and compared on *validation*
  (F1, ties broken by average precision). The winner is probability-calibrated
  (sigmoid) on validation, because the risk engine consumes the probability.
* All reported metrics are computed on the untouched *test* split. Accuracy is
  recorded but never used for selection; precision, recall, F1, PR-AUC, the
  confusion matrix and FP/FN rates are the headline numbers.
* The artefact is written together with a SHA-256 digest; the API refuses to
  load a model file whose digest does not match (pickle files are code).

Usage::

    python -m ml.training.train                # generates synthetic data if needed
    python -m ml.training.train --data my.csv  # any csv with columns url,label
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, brier_score_loss, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from backend.services.features import FEATURE_NAMES
from ml.dataset.build_dataset import DATA_DIR
from ml.dataset.synthetic import generate
from ml.preprocessing.build_features import build_feature_frame

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
SEED = 42


def candidate_models(seed: int = SEED, fast: bool = False) -> dict:
    return {
        "logistic_regression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=3000, C=1.0, class_weight="balanced")),
        "decision_tree": DecisionTreeClassifier(
            max_depth=8, min_samples_leaf=25, class_weight="balanced", random_state=seed),
        "random_forest": RandomForestClassifier(
            n_estimators=60 if fast else 300, min_samples_leaf=3, max_features="sqrt",
            class_weight="balanced_subsample", n_jobs=-1, random_state=seed),
    }


def metrics_at(y, p, threshold: float = 0.5) -> dict:
    pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "threshold": threshold,
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "accuracy": float((tp + tn) / len(y)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "false_negative_rate": float(fn / max(fn + tp, 1)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def full_metrics(y, p) -> dict:
    m = metrics_at(y, p, 0.5)
    m["roc_auc"] = float(roc_auc_score(y, p))
    m["average_precision"] = float(average_precision_score(y, p))
    m["brier"] = float(brier_score_loss(y, p))
    m["threshold_sweep"] = [metrics_at(y, p, t) for t in (0.3, 0.5, 0.7, 0.9)]
    return m


def importances(name: str, model) -> dict[str, float]:
    if name == "logistic_regression":
        coef = model[-1].coef_[0]  # standardised features => comparable magnitudes
        vals = np.abs(coef)
    else:
        vals = model.feature_importances_
    vals = vals / (vals.sum() or 1.0)
    return dict(sorted(zip(FEATURE_NAMES, map(float, vals)), key=lambda kv: -kv[1]))


def grouped_split(groups, seed: int, test_size=0.2, val_size=0.15):
    idx = np.arange(len(groups))
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    trainval, test = next(gss.split(idx, groups=groups))
    rel_val = val_size / (1 - test_size)
    gss2 = GroupShuffleSplit(n_splits=1, test_size=rel_val, random_state=seed + 1)
    tr, va = next(gss2.split(trainval, groups=groups[trainval]))
    return trainval[tr], trainval[va], test


def train(data_path: Path, out_dir: Path = MODELS_DIR, seed: int = SEED, fast: bool = False) -> dict:
    df = pd.read_csv(data_path)
    source = ",".join(sorted(df["source"].unique())) if "source" in df else "unknown"
    print(f"Loaded {len(df):,} rows from {data_path} (source: {source})")
    feat = build_feature_frame(df)
    X = feat[list(FEATURE_NAMES)].to_numpy(float)
    y = feat["label"].to_numpy(int)
    groups = feat["group"].to_numpy()

    tr, va, te = grouped_split(groups, seed)
    assert not (set(groups[tr]) & set(groups[te])) and not (set(groups[va]) & set(groups[te])), \
        "domain leakage between splits"
    print(f"Split (by domain): train={len(tr):,} val={len(va):,} test={len(te):,}")

    fitted, val_scores = {}, {}
    for name, model in candidate_models(seed, fast).items():
        model.fit(X[tr], y[tr])
        p = model.predict_proba(X[va])[:, 1]
        val_scores[name] = (f1_score(y[va], p >= 0.5), average_precision_score(y[va], p))
        fitted[name] = model
        print(f"  {name:20s} val F1={val_scores[name][0]:.4f} AP={val_scores[name][1]:.4f}")
    best = max(val_scores, key=lambda n: val_scores[n])
    print(f"Selected: {best}")

    calibrated = CalibratedClassifierCV(FrozenEstimator(fitted[best]), method="sigmoid")
    calibrated.fit(X[va], y[va])

    test_metrics = {n: full_metrics(y[te], m.predict_proba(X[te])[:, 1]) for n, m in fitted.items()}
    p_cal = calibrated.predict_proba(X[te])[:, 1]
    final_metrics = full_metrics(y[te], p_cal)
    print(f"Final (calibrated {best}) test: P={final_metrics['precision']:.3f} "
          f"R={final_metrics['recall']:.3f} F1={final_metrics['f1']:.3f} "
          f"PR-AUC={final_metrics['average_precision']:.3f}")

    benign_train = X[tr][y[tr] == 0]
    baseline = dict(zip(FEATURE_NAMES, map(float, np.median(benign_train, axis=0))))
    version = datetime.now(timezone.utc).strftime("%Y%m%d") + f"-{best}"

    out_dir.mkdir(parents=True, exist_ok=True)
    artifact = {"model": calibrated, "feature_names": list(FEATURE_NAMES),
                "baseline": baseline, "version": version, "algorithm": best}
    model_path = out_dir / "model.joblib"
    joblib.dump(artifact, model_path)
    digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
    (out_dir / "model.joblib.sha256").write_text(digest + "\n")

    pd.DataFrame({"url": feat["url"].to_numpy()[te], "label": y[te], "p": p_cal}) \
        .to_csv(out_dir / "test_predictions.csv", index=False)

    synthetic = "synthetic" in source
    report = {
        "model_version": version,
        "selected_algorithm": best,
        "calibration": "sigmoid (fitted on validation split)",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "sklearn": sklearn.__version__, "python": platform.python_version(),
        "dataset": {
            "source": source, "rows": int(len(feat)), "phishing": int(y.sum()),
            "benign": int((1 - y).sum()),
            "split_rows": {"train": len(tr), "val": len(va), "test": len(te)},
            "split_domains": {"train": len(set(groups[tr])), "val": len(set(groups[va])),
                              "test": len(set(groups[te]))},
            "split_strategy": "GroupShuffleSplit by registered domain",
        },
        "validation_f1_ap": {n: list(v) for n, v in val_scores.items()},
        "test_metrics_candidates": test_metrics,
        "test_metrics_final": final_metrics,
        "feature_importance": {n: importances(n, m) for n, m in fitted.items()},
        "warning": ("Trained on SYNTHETIC data: these numbers describe how well the pipeline "
                    "learned the generator's patterns, NOT real-world phishing detection. "
                    "Retrain on real labelled data (see ml/dataset/build_dataset.py).")
        if synthetic else None,
    }
    (out_dir / "metrics.json").write_text(json.dumps(report, indent=2))
    print(f"Saved model + metrics to {out_dir}")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, default=DATA_DIR / "urls.csv")
    ap.add_argument("--out", type=Path, default=MODELS_DIR)
    ap.add_argument("--n", type=int, default=12000, help="per-class size if data must be generated")
    ap.add_argument("--seed", type=int, default=SEED)
    a = ap.parse_args()
    if not a.data.exists():
        a.data.parent.mkdir(parents=True, exist_ok=True)
        generate(a.n).to_csv(a.data, index=False)
        print(f"Generated synthetic dataset at {a.data}")
    train(a.data, a.out, a.seed)


if __name__ == "__main__":
    main()
