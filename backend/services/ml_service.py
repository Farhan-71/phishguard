"""Model loading, inference and per-prediction explanation."""
from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np

from .features import FEATURE_EXPLANATIONS, FEATURE_NAMES

log = logging.getLogger("phishguard.ml")


class ModelIntegrityError(RuntimeError):
    pass


@dataclass
class MLModel:
    model: object
    feature_names: list[str]
    baseline: dict[str, float]
    version: str
    algorithm: str

    # ------------------------------------------------------------- loading
    @classmethod
    def load(cls, path: Path) -> "MLModel":
        """Load a model artefact after verifying its SHA-256 digest.

        A joblib file is a pickle, i.e. executable on load. The digest file is
        written by the training script; deployments should treat the model
        directory as trusted, write-protected storage (see docs/threat-model.md).
        """
        path = Path(path)
        digest_file = path.with_name(path.name + ".sha256")
        if not path.exists():
            raise FileNotFoundError(path)
        if not digest_file.exists():
            raise ModelIntegrityError(f"Missing digest file {digest_file.name}; refusing to load model")
        expected = digest_file.read_text().strip().lower()
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if not hmac.compare_digest(expected, actual):
            raise ModelIntegrityError("Model file digest mismatch; refusing to load model")
        art = joblib.load(path)
        if list(art["feature_names"]) != list(FEATURE_NAMES):
            raise ModelIntegrityError(
                "Model feature set does not match the feature engine; retrain the model")
        return cls(art["model"], list(art["feature_names"]), art["baseline"],
                   art["version"], art["algorithm"])

    # ------------------------------------------------------------ inference
    def _row(self, feats: dict[str, float]) -> np.ndarray:
        return np.array([feats[n] for n in self.feature_names], dtype=float)

    def predict(self, feats: dict[str, float]) -> float:
        return float(self.model.predict_proba(self._row(feats).reshape(1, -1))[0, 1])

    def explain(self, feats: dict[str, float], base_p: float | None = None,
                top_k: int = 5, min_contribution: float = 0.03) -> list[dict]:
        """Counterfactual occlusion: replace one feature at a time with the typical
        benign value and measure how far the phishing probability falls.

        Model-agnostic, so it works identically for all three model families. It
        attributes each feature independently, so interactions between correlated
        features (e.g. many subdomains *and* a brand in a subdomain) are
        under-counted -- documented in docs/scoring.md.
        """
        x = self._row(feats)
        if base_p is None:
            base_p = self.predict(feats)
        changed = [i for i, n in enumerate(self.feature_names)
                   if x[i] != self.baseline[n]]
        if not changed:
            return []
        rows = np.tile(x, (len(changed), 1))
        for r, i in enumerate(changed):
            rows[r, i] = self.baseline[self.feature_names[i]]
        p_cf = self.model.predict_proba(rows)[:, 1]
        out = []
        for r, i in enumerate(changed):
            contrib = base_p - float(p_cf[r])
            if contrib < min_contribution:
                continue
            name = self.feature_names[i]
            title, detail = FEATURE_EXPLANATIONS.get(
                name, (name.replace("_", " ").capitalize(), "This feature moved the score toward phishing."))
            v = x[i]
            out.append({
                "feature": name,
                "value": v,
                "contribution": round(contrib, 3),
                "title": title,
                "detail": detail.replace("{v}", f"{v:.0f}" if float(v).is_integer() else f"{v:.2f}"),
            })
        out.sort(key=lambda d: -d["contribution"])
        return out[:top_k]
