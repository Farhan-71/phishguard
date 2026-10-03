"""Build the labelled URL dataset used for training.

Examples
--------
Bootstrap (synthetic, reproducible)::

    python -m ml.dataset.build_dataset --mode synthetic --n 12000

Real data (recommended for any claim about real-world performance)::

    python -m ml.dataset.build_dataset --mode files \\
        --phish-file phishing_urls.txt --benign-file benign_urls.txt

Suggested real sources (check each licence / terms of use before use):
  * phishing: PhishTank verified-online export, OpenPhish community feed
  * benign:   Tranco top-sites list *combined with real crawled paths* -- see the
              warning below about domain-only benign lists.

Input files are one URL per line (``#`` comments allowed).
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from .synthetic import generate

DATA_DIR = Path(__file__).parent / "data"


def read_urls(path: Path) -> list[str]:
    return [ln.strip() for ln in path.read_text(errors="ignore").splitlines()
            if ln.strip() and not ln.startswith("#")]


def build_from_files(phish: Path, benign: Path) -> pd.DataFrame:
    p, b = read_urls(phish), read_urls(benign)
    df = pd.DataFrame({"url": p + b, "label": [1] * len(p) + [0] * len(b)})
    df["source"] = "files"
    # Guard against the classic dataset artefact: benign lists made of bare domains
    # next to phishing URLs with long paths teach the model "has a path => phishing".
    def has_path(u: str) -> bool:
        rest = u.split("://", 1)[-1]
        return "/" in rest.rstrip("/")
    frac_b = sum(map(has_path, b)) / max(len(b), 1)
    frac_p = sum(map(has_path, p)) / max(len(p), 1)
    if abs(frac_b - frac_p) > 0.3:
        print(f"WARNING: URLs with a path: benign {frac_b:.0%} vs phishing {frac_p:.0%}. "
              "The model may learn this dataset artefact instead of real phishing signals.")
    return df.drop_duplicates("url").sample(frac=1.0, random_state=1).reset_index(drop=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["synthetic", "files"], default="synthetic")
    ap.add_argument("--n", type=int, default=12000, help="URLs per class (synthetic)")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--phish-file", type=Path)
    ap.add_argument("--benign-file", type=Path)
    ap.add_argument("--out", type=Path, default=DATA_DIR / "urls.csv")
    a = ap.parse_args()

    if a.mode == "synthetic":
        df = generate(a.n, a.seed)
    else:
        if not (a.phish_file and a.benign_file):
            ap.error("--mode files requires --phish-file and --benign-file")
        df = build_from_files(a.phish_file, a.benign_file)

    a.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(a.out, index=False)
    print(f"Wrote {len(df):,} rows to {a.out} "
          f"({int(df.label.sum()):,} phishing / {int((1 - df.label).sum()):,} benign)")


if __name__ == "__main__":
    main()
