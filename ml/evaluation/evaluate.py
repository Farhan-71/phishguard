"""Generate docs/ml-report.md plus figures from the training artefacts.

    python -m ml.evaluation.evaluate

Reads ``ml/models/metrics.json`` and ``ml/models/test_predictions.csv`` (written by
training) and, if present, ``docs/external-check.json`` (written by
``ml.evaluation.external_check``).
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import precision_recall_curve  # noqa: E402

from backend.services.features import extract_features  # noqa: E402
from ml.training.train import MODELS_DIR  # noqa: E402

DOCS = Path(__file__).resolve().parents[2] / "docs"
INK, TEAL, RED, AMBER = "#14262B", "#0E4F5C", "#B3372B", "#B7791F"


def _plots(m: dict, preds: pd.DataFrame) -> None:
    (DOCS / "img").mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "axes.edgecolor": INK, "axes.labelcolor": INK,
                         "xtick.color": INK, "ytick.color": INK, "axes.spines.top": False, "axes.spines.right": False})
    cm = m["test_metrics_final"]["confusion_matrix"]
    fig, ax = plt.subplots(figsize=(3.6, 3.2))
    grid = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
    ax.imshow(grid, cmap="Blues")
    for (i, j), v in np.ndenumerate(grid):
        ax.text(j, i, f"{v:,}", ha="center", va="center", color="white" if v > grid.max() / 2 else INK, fontsize=12)
    ax.set_xticks([0, 1], ["benign", "phishing"]); ax.set_yticks([0, 1], ["benign", "phishing"])
    ax.set_xlabel("predicted"); ax.set_ylabel("actual"); ax.set_title("Confusion matrix (test, p ≥ 0.5)", fontsize=10, color=INK)
    fig.tight_layout(); fig.savefig(DOCS / "img" / "confusion-matrix.png", dpi=160); plt.close(fig)

    p, r, _ = precision_recall_curve(preds["label"], preds["p"])
    fig, ax = plt.subplots(figsize=(4.2, 3.2))
    ax.plot(r, p, color=TEAL, lw=2); ax.set_xlabel("recall"); ax.set_ylabel("precision")
    ax.set_ylim(0.4, 1.02); ax.set_title("Precision-recall (test)", fontsize=10, color=INK)
    fig.tight_layout(); fig.savefig(DOCS / "img" / "pr-curve.png", dpi=160); plt.close(fig)

    imp = m["feature_importance"][m["selected_algorithm"]]
    top = list(imp.items())[:12][::-1]
    fig, ax = plt.subplots(figsize=(5.2, 3.8))
    ax.barh([k for k, _ in top], [v for _, v in top], color=TEAL)
    ax.set_title(f"Top features ({m['selected_algorithm']})", fontsize=10, color=INK)
    fig.tight_layout(); fig.savefig(DOCS / "img" / "feature-importance.png", dpi=160); plt.close(fig)


def _fmt(x: float) -> str:
    return f"{x:.3f}"


def _errors(preds: pd.DataFrame, n: int = 8) -> tuple[pd.DataFrame, pd.DataFrame]:
    fp = preds[(preds.label == 0) & (preds.p >= 0.5)].sort_values("p", ascending=False).head(n)
    fn = preds[(preds.label == 1) & (preds.p < 0.5)].sort_values("p").head(n)
    return fp, fn


def _error_profile(preds: pd.DataFrame) -> str:
    """What do the model's mistakes have in common? Compare a few flags between error and correct groups."""
    flags = ["is_https", "is_shared_hosting", "keyword_count_path", "brand_in_path", "is_shortener", "path_depth"]
    rows = []
    for name, mask in (("false positives", (preds.label == 0) & (preds.p >= 0.5)),
                       ("false negatives", (preds.label == 1) & (preds.p < 0.5)),
                       ("correct phishing", (preds.label == 1) & (preds.p >= 0.5)),
                       ("correct benign", (preds.label == 0) & (preds.p < 0.5))):
        sub = preds[mask]
        if sub.empty:
            continue
        feats = pd.DataFrame([extract_features(u, sanitized=True) for u in sub.url.head(400)])
        rows.append(f"| {name} | {len(sub):,} | " + " | ".join(f"{feats[f].mean():.2f}" for f in flags) + " |")
    head = "| group | n | " + " | ".join(flags) + " |\n|---|---|" + "---|" * len(flags)
    return head + "\n" + "\n".join(rows)


def main() -> None:
    m = json.loads((MODELS_DIR / "metrics.json").read_text())
    preds = pd.read_csv(MODELS_DIR / "test_predictions.csv")
    _plots(m, preds)
    fin, ds = m["test_metrics_final"], m["dataset"]
    fp, fn = _errors(preds)

    cand = "\n".join(
        f"| {name.replace('_', ' ')} | {_fmt(v['precision'])} | {_fmt(v['recall'])} | {_fmt(v['f1'])} | "
        f"{_fmt(v['average_precision'])} | {_fmt(v['false_positive_rate'])} | {_fmt(v['false_negative_rate'])} | "
        f"{_fmt(v['accuracy'])} |" for name, v in m["test_metrics_candidates"].items())
    sweep = "\n".join(f"| {t['threshold']} | {_fmt(t['precision'])} | {_fmt(t['recall'])} | {_fmt(t['f1'])} | "
                      f"{_fmt(t['false_positive_rate'])} |" for t in fin["threshold_sweep"])
    fplist = "\n".join(f"- `{r.url}` (p={r.p:.2f})" for r in fp.itertuples()) or "- none"
    fnlist = "\n".join(f"- `{r.url}` (p={r.p:.2f})" for r in fn.itertuples()) or "- none"

    ext = ""
    ext_path = DOCS / "external-check.json"
    if ext_path.exists():
        e = json.loads(ext_path.read_text())
        pl = e["pipeline"]
        line = lambda k, label: (f"| {label} | {pl[k]['n']} | {100 * pl[k]['share_medium_or_high']:.1f}% | "  # noqa: E731
                                 f"{100 * pl[k]['share_high']:.1f}% |") if k in pl else ""
        ext = f"""
## 5. Reality check on real URLs

The synthetic test split above says how well the model learned the generator. It says
*nothing* about real phishing. So the model was also scored on **real URLs it never trained on**:

* phishing: a snapshot of the public OpenPhish community feed, split into a **dev** half
  (first 150 URLs, inspected while improving the generator) and a **holdout** half (last 150,
  scored only after tuning was finished);
* benign: 89 hand-picked real URLs (**dev**, inspected while tuning) and 79 more (**holdout**,
  written after tuning without consulting model output), including login and account pages.

Full offline pipeline (classifier + URL rules + prior-shift correction at
`assumed_prevalence={pl['benign_dev']['prevalence_setting']}`), **without** domain-age, TLS or
threat-intelligence signals, which add detection on top of these figures:

| slice | n | flagged medium or high | flagged high |
|---|---|---|---|
{line('benign_dev', 'benign (dev)')}
{line('benign_holdout', 'benign (holdout)')}
{line('phishing_dev', 'phishing (dev)')}
{line('phishing_holdout', 'phishing (holdout)')}

Reading this honestly:

* **Recall on real phishing is far below the synthetic number** (roughly half of holdout URLs
  reach "suspicious", about a fifth "high risk"). Many real phishing URLs are lexically
  indistinguishable from ordinary sites (`fortgrind.com/`, a Blogspot subdomain, a random
  path on a compromised site). A URL-only model cannot see them; that is exactly why the
  design layers domain age, certificate checks and threat intelligence on top.
* **False alarms are the bigger product risk.** The classifier is trained on a 50/50 mix, but
  real browsing is overwhelmingly benign, so raw probabilities overstate risk. At even a 5% false
  positive rate and ~1% real prevalence, most warnings would be false. The risk engine therefore
  applies a prior-shift correction; the dev sweep behind the default is in `docs/scoring.md`.
* Remaining benign false alarms are free-hosting personal sites (`*.netlify.app`, `*.github.io`).
  They can only reach "suspicious" (never "high") without corroborating evidence.
* The benign sets are small (89 and 79 URLs), so these percentages have wide error bars
  (roughly +/-5 points). Treat this as a smoke test, not a benchmark.
* The holdout phishing half shares a snapshot (and therefore some campaigns) with the dev half.
  The failure categories were first observed on a run over the whole snapshot before it was split,
  so the holdout figures are slightly optimistic.
"""

    report = f"""# ML report

> {m.get('warning') or 'Trained on user-provided data.'}

Model version: `{m['model_version']}` · selected: **{m['selected_algorithm']}** ({m['calibration']}) ·
scikit-learn {m['sklearn']} · trained {m['trained_at'][:10]}

## 1. Data and split

| | rows | domains |
|---|---|---|
| train | {ds['split_rows']['train']:,} | {ds['split_domains']['train']:,} |
| validation | {ds['split_rows']['val']:,} | {ds['split_domains']['val']:,} |
| test | {ds['split_rows']['test']:,} | {ds['split_domains']['test']:,} |

Source: `{ds['source']}` ({ds['phishing']:,} phishing / {ds['benign']:,} benign). Split strategy:
{ds['split_strategy']} (no domain appears in more than one split; asserted in the training script).
Features: 37 lexical URL features computed by the same function the API uses (`backend/services/features.py`).

## 2. Model comparison (test split, threshold 0.5, uncalibrated)

| model | precision | recall | F1 | PR-AUC | FPR | FNR | accuracy |
|---|---|---|---|---|---|---|---|
{cand}

Selection used validation F1 (ties: average precision). Accuracy is shown for completeness only.

## 3. Final model (calibrated) on the test split

| precision | recall | F1 | PR-AUC | ROC-AUC | Brier | FPR | FNR |
|---|---|---|---|---|---|---|---|
| {_fmt(fin['precision'])} | {_fmt(fin['recall'])} | {_fmt(fin['f1'])} | {_fmt(fin['average_precision'])} | {_fmt(fin['roc_auc'])} | {_fmt(fin['brier'])} | {_fmt(fin['false_positive_rate'])} | {_fmt(fin['false_negative_rate'])} |

![confusion matrix](img/confusion-matrix.png) ![pr curve](img/pr-curve.png)

Threshold sweep:

| threshold | precision | recall | F1 | FPR |
|---|---|---|---|---|
{sweep}

## 4. Error analysis (synthetic test split)

Highest-confidence **false positives** (benign scored as phishing):

{fplist}

Highest-confidence **false negatives** (phishing scored as benign):

{fnlist}

Mean of selected features per group (what do mistakes have in common?):

{_error_profile(preds)}

![feature importance](img/feature-importance.png)
{ext}
"""
    (DOCS / "ml-report.md").write_text(report)
    print("Wrote docs/ml-report.md and docs/img/*.png")


if __name__ == "__main__":
    main()
