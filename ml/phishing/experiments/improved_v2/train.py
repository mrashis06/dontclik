#!/usr/bin/env python3
"""Offline second experiment; only train/validation tune, one held-out evaluation."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import scipy
import sklearn
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.naive_bayes import MultinomialNB

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from train_phishing import SOURCE_FILES, FEATURE_NAMES, load_rows, parse_url, sha256  # noqa: E402

SEED = 42
FINAL_FOLD = 4
VALIDATION_FOLD = 3
DIAGNOSTICS = ("google.com", "github.com", "microsoft.com", "wikipedia.org", "cloudflare.com")
LR_NAMES = (
    "host_length", "path_length", "query_length", "digit_density", "hyphen_density",
    "dot_count", "subdomain_depth", "at_count", "percent_count", "path_depth",
    "query_pair_count", "host_entropy", "url_length", "is_ip_host",
)
NB_NAMES = (
    "host_long", "host_very_long", "path_short", "path_long", "has_query",
    "digit_dense", "hyphen_heavy", "deep_subdomain", "is_ip_host", "has_percent",
)
# Fixed domain-informed caps are independent of validation/test labels.
CAPS = np.asarray((64, 256, 256, 1, 1, 8, 5, 4, 8, 12, 12, 5, 512, 1), dtype=np.float32)


def numeric_views(old_log_numeric):
    raw = np.expm1(np.asarray(old_log_numeric, dtype=np.float32))
    host_len, path_len, query_len, digit, hyphen, dots, subdepth, at, pct, depth, pairs, entropy, total, is_ip = raw
    ratios = np.asarray((host_len, path_len, query_len, digit / max(total, 1),
                         hyphen / max(total, 1), dots, subdepth, at, pct,
                         depth, pairs, entropy, total, is_ip), dtype=np.float32)
    lr = 0.25 * np.minimum(ratios / CAPS, 1.0)
    nb = np.asarray((
        host_len >= 25, host_len >= 40, path_len <= 8, path_len >= 40,
        query_len > 0, digit / max(total, 1) >= 0.15, hyphen >= 3,
        subdepth >= 2, is_ip > 0, pct > 0,
    ), dtype=np.float32)
    return lr, nb


def metrics(y, pred):
    cm = confusion_matrix(y, pred, labels=[0, 1])
    tn, fp, fn, tp = map(int, cm.ravel())
    p, r, f, support = precision_recall_fscore_support(y, pred, labels=[0, 1], zero_division=0)
    return {
        "support": {"benign": int(support[0]), "phishing": int(support[1])},
        "confusion_matrix_order": ["benign", "phishing"],
        "confusion_matrix": cm.tolist(),
        "benign": {"precision": float(p[0]), "recall": float(r[0]), "f1": float(f[0])},
        "phishing": {"precision": float(p[1]), "recall": float(r[1]), "f1": float(f[1])},
        "benign_fpr": fp / (tn + fp) if tn + fp else None,
        "phishing_fnr": fn / (tp + fn) if tp + fn else None,
    }


def threshold_candidates(positive_scores):
    q = np.linspace(0, 0.15, 151)
    values = np.quantile(positive_scores, q, method="lower")
    return sorted(set(float(x) for x in np.concatenate((values, [0.0, 0.5, 0.7, 0.9]))))


def select_threshold(y, scores, recall_floor=0.90):
    options = []
    for cutoff in threshold_candidates(scores[y == 1]):
        m = metrics(y, scores >= cutoff)
        options.append((cutoff, m))
    feasible = [(t, m) for t, m in options if m["phishing"]["recall"] >= recall_floor]
    if not feasible:
        raise ValueError("No threshold satisfies recall floor")
    # Minimize benign FPR, then favor recall. No test or diagnostic predictions enter.
    threshold, selected = min(
        feasible, key=lambda z: (z[1]["benign_fpr"], -z[1]["phishing"]["recall"], z[0])
    )
    return threshold, selected


def split_summary(rows, y, groups, idx):
    return {
        "rows": int(len(idx)),
        "groups": len(set(groups[idx])),
        "benign": int(np.sum(y[idx] == 0)),
        "phishing": int(np.sum(y[idx] == 1)),
        "sources": dict(Counter(rows[int(i)]["source"] for i in idx)),
        "protocols": dict(Counter(rows[int(i)]["protocol"] for i in idx)),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, required=True)
    ap.add_argument("--output-root", type=Path, required=True)
    args = ap.parse_args()
    data_dir = args.data_dir.resolve()
    output_root = args.output_root.resolve()
    rows, exclusions, conflicts = load_rows(data_dir)
    y = np.asarray([r["label"] for r in rows], dtype=np.int8)
    groups = np.asarray([r["group"] for r in rows], dtype=object)
    folds = list(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
                 .split(np.zeros(len(rows)), y, groups))
    final_idx = folds[FINAL_FOLD][1]
    val_idx = folds[VALIDATION_FOLD][1]
    train_idx = np.setdiff1d(np.arange(len(rows)), np.concatenate((final_idx, val_idx)))
    indexes = {"train": train_idx, "validation": val_idx, "final": final_idx}
    group_sets = {name: set(groups[idx]) for name, idx in indexes.items()}
    assert not (group_sets["train"] & group_sets["validation"])
    assert not (group_sets["train"] & group_sets["final"])
    assert not (group_sets["validation"] & group_sets["final"])
    summaries = {name: split_summary(rows, y, groups, idx) for name, idx in indexes.items()}
    if any(not z["benign"] or not z["phishing"] for z in summaries.values()):
        raise ValueError("A split has only one label")

    # Original load_rows supplies scheme-free host+path+query and deterministic raw counts.
    texts = [r["text"] for r in rows]
    lr_numeric, nb_numeric = zip(*(numeric_views(r["numeric"]) for r in rows))
    lr_numeric = np.asarray(lr_numeric, dtype=np.float32)
    nb_numeric = np.asarray(nb_numeric, dtype=np.float32)
    vectorizer = CountVectorizer(analyzer="char", ngram_range=(3, 4), binary=True,
                                 min_df=5, max_features=75000, dtype=np.float32)
    char_train = vectorizer.fit_transform([texts[int(i)] for i in train_idx])
    matrices = {"lr": {}, "nb": {}}
    matrices["lr"]["train"] = hstack((char_train, csr_matrix(lr_numeric[train_idx])), format="csr")
    matrices["nb"]["train"] = hstack((char_train, csr_matrix(nb_numeric[train_idx])), format="csr")
    del char_train
    for split in ("validation", "final"):
        idx = indexes[split]
        chars = vectorizer.transform([texts[int(i)] for i in idx])
        matrices["lr"][split] = hstack((chars, csr_matrix(lr_numeric[idx])), format="csr")
        matrices["nb"][split] = hstack((chars, csr_matrix(nb_numeric[idx])), format="csr")
        del chars

    trials = {"lr": [], "nb": []}
    selected = {}
    for kind in ("lr", "nb"):
        best = None
        if kind == "lr":
            configs = [
                {"C": c, "class_weight": weight}
                for c in (0.05, 0.2, 1.0) for weight in (None, "balanced")
            ]
        else:
            configs = [{"alpha": a} for a in (0.5, 1.0, 5.0)]
        for config in configs:
            if kind == "lr":
                model = LogisticRegression(
                    solver="liblinear", max_iter=300, random_state=SEED, **config
                )
            else:
                model = MultinomialNB(**config)
            model.fit(matrices[kind]["train"], y[train_idx])
            scores = model.predict_proba(matrices[kind]["validation"])[:, 1]
            threshold, val_metrics = select_threshold(y[val_idx], scores)
            entry = {"parameters": config, "threshold": threshold, "validation": val_metrics}
            trials[kind].append(entry)
            ranking = (val_metrics["benign_fpr"], -val_metrics["phishing"]["recall"],
                       -val_metrics["phishing"]["precision"])
            if best is None or ranking < best[0]:
                best = (ranking, model, threshold, entry)
        selected[kind] = {"model": best[1], "threshold": best[2], "validation": best[3]}
        print(f"Selected {kind}: {best[3]['parameters']} threshold={best[2]:.8f} "
              f"validation FPR={best[3]['validation']['benign_fpr']:.4f}", flush=True)

    # The final fold is scored exactly once after both candidates and cutoffs freeze.
    final_results = {}
    for kind in ("lr", "nb"):
        model = selected[kind]["model"]
        cutoff = selected[kind]["threshold"]
        scores = model.predict_proba(matrices[kind]["final"])[:, 1]
        pred = scores >= cutoff
        by_source = {}
        for source in sorted({rows[int(i)]["source"] for i in final_idx}):
            mask = np.asarray([rows[int(i)]["source"] == source for i in final_idx])
            by_source[source] = metrics(y[final_idx][mask], pred[mask])
        final_results[kind] = {
            "parameters": selected[kind]["validation"]["parameters"],
            "threshold_frozen_from_validation": cutoff,
            "validation": selected[kind]["validation"]["validation"],
            "final": metrics(y[final_idx], pred),
            "final_by_source": by_source,
        }

    diagnostic = {}
    for domain in DIAGNOSTICS:
        parsed, reason = parse_url("https://" + domain)
        if reason:
            raise ValueError(f"Sanity parse error: {domain}, {reason}")
        text, _, _, old_numeric = parsed
        chars = vectorizer.transform([text])
        lr_num, nb_num = numeric_views(old_numeric)
        diagnostic[domain] = {}
        for kind, numeric in (("lr", lr_num), ("nb", nb_num)):
            matrix = hstack((chars, csr_matrix(numeric.reshape(1, -1))), format="csr")
            score = float(selected[kind]["model"].predict_proba(matrix)[0, 1])
            diagnostic[domain][kind] = {
                "phishing_score": score,
                "selected_threshold": selected[kind]["threshold"],
                "prediction": "phishing" if score >= selected[kind]["threshold"] else "benign",
            }

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = output_root / stamp
    outdir.mkdir(parents=True, exist_ok=False)
    joblib.dump(vectorizer, outdir / "char_vectorizer.joblib")
    for kind in ("lr", "nb"):
        joblib.dump(selected[kind]["model"], outdir / (kind + ".joblib"))
    model_sizes = {name: (outdir / name).stat().st_size for name in
                   ("char_vectorizer.joblib", "lr.joblib", "nb.joblib")}
    manifest = {
        "run_utc": stamp,
        "seed": SEED,
        "prior_run": "20261122T141850Z",
        "independence_disclosure": (
            "Final fold 4 was not previously evaluated, but its rows were in the prior "
            "baseline training pool. Earlier model analysis informed feature design. "
            "This is an internal holdout, not a fully independent final test."
        ),
        "versions": {"python": sys.version, "numpy": np.__version__,
                     "scipy": scipy.__version__, "sklearn": sklearn.__version__},
        "sha256": {"new_script": sha256(Path(__file__)),
                   "loader_script": sha256(HERE.parent / "train_phishing.py"),
                   **{k: sha256(data_dir / f) for k, f in SOURCE_FILES.items()}},
        "input_exclusions": {k: {**v, "invalid_reasons": dict(v["invalid_reasons"]),
                                  "labels": dict(v["labels"])} for k, v in exclusions.items()},
        "exact_conflicting_urls_removed": conflicts,
        "split_method": "StratifiedGroupKFold(5, shuffle=True, seed=42); final fold 4, validation fold 3, remaining train; conservative final-two-label group",
        "splits": summaries,
        "features": {"scheme_removed": True, "source_feature": False,
                     "char_ngrams": [3, 4], "vocabulary": len(vectorizer.vocabulary_),
                     "lr_numeric_names": LR_NAMES, "lr_numeric_caps": CAPS.tolist(),
                     "lr_numeric_max_value": 0.25,
                     "nb_binary_names": NB_NAMES},
        "selection_rule": "lowest validation benign FPR with phishing recall >=0.90; ties prefer recall then precision",
        "validation_trials": trials,
        "results": final_results,
        "diagnostic_not_statistical_test": diagnostic,
        "artifact_bytes": model_sizes,
        "production_ready": False,
        "limitations": [
            "No independently verified benign HTTPS cohort",
            "Original sources still associate scheme with class",
            "Internal holdout was part of previous baseline training",
            "No prospective performance or Android ARM parity/latency measurement",
        ],
    }
    (outdir / "metrics.json").write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"output": str(outdir), "final": {k: v["final"] for k, v in final_results.items()},
                      "artifact_bytes": model_sizes}, indent=2), flush=True)


if __name__ == "__main__":
    main()
