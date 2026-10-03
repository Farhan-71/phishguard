"""Turn a (url, label) table into a model-ready feature matrix.

URLs are sanitised with the *same* function the API uses, so the model is trained
on exactly what it will see in production (query values redacted, fragments
dropped, IDNs punycoded).
"""
from __future__ import annotations

import pandas as pd

from backend.services.features import FEATURE_NAMES, extract_features
from backend.services.url_utils import InvalidURL, get_host, sanitize_url, split_host


def build_feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Return DataFrame with columns: url, label, group, <features...>.

    ``group`` is the registered domain; splitting by it keeps every URL of a
    domain on one side of the train/test boundary (prevents leakage).
    """
    rows, dropped = [], 0
    seen: set[str] = set()
    for url, label in zip(df["url"], df["label"]):
        try:
            s = sanitize_url(url)
        except InvalidURL:
            dropped += 1
            continue
        if s in seen:
            continue
        seen.add(s)
        feats = extract_features(s, sanitized=True)
        rows.append({"url": s, "label": int(label),
                     "group": split_host(get_host(s)).registered_domain, **feats})
    out = pd.DataFrame(rows, columns=["url", "label", "group", *FEATURE_NAMES])
    if dropped:
        print(f"Dropped {dropped} invalid URLs during preprocessing")
    return out
