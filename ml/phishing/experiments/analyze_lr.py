#!/usr/bin/env python3
"""Read-only analysis of the fixed LR run; no fit, network, or URL fetch."""
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
from scipy.sparse import csr_matrix, hstack
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from train_phishing import FEATURE_NAMES, load_rows, parse_url, sha256  # noqa: E402

DIAGNOSTIC_DOMAINS = (
    "google.com", "wikipedia.org", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "cloudflare.com", "mozilla.org",
)


def rates(labels, scores, threshold):
    predicted = (scores >= threshold).astype(np.int8)
    tn, fp, fn, tp = map(int, confusion_matrix(labels, predicted, labels=[0, 1]).ravel())
    return {
        "threshold": float(threshold),
        "confusion_matrix_benign_phishing": [[tn, fp], [fn, tp]],
        "benign_fpr": fp / (tn + fp) if tn + fp else None,
        "phishing_recall": tp / (tp + fn) if tp + fn else None,
        "phishing_fnr": fn / (tp + fn) if tp + fn else None,
        "phishing_precision": tp / (tp + fp) if tp + fp else None,
    }


def contribution_report(model, vectorizer, row):
    names = list(vectorizer.get_feature_names_out()) + list(FEATURE_NAMES)
    active = row.indices
    values = row.data
    weights = model.coef_[0, active]
    terms = [(names[int(i)], float(v), float(w), float(v * w))
             for i, v, w in zip(active, values, weights)]
    pos = sorted((z for z in terms if z[3] > 0), key=lambda z: z[3], reverse=True)[:12]
    neg = sorted((z for z in terms if z[3] < 0), key=lambda z: z[3])[:12]
    format_terms = lambda group: [
        {"feature": name, "value": value, "weight": weight, "logit_contribution": effect}
        for name, value, weight, effect in group
    ]
    return {
        "active_feature_count": len(terms),
        "intercept_logit": float(model.intercept_[0]),
        "sum_feature_logit": float(sum(z[3] for z in terms)),
        "top_phishing_contributions": format_terms(pos),
        "top_benign_contributions": format_terms(neg),
    }


def aggregate_numeric(rows, indexes, mask):
    selected = np.asarray(indexes)[mask]
    raw = np.expm1(np.stack([rows[int(i)]["numeric"] for i in selected]))
    result = {"count": len(selected), "distinct_groups": len({rows[int(i)]["group"] for i in selected})}
    for col, name in enumerate(FEATURE_NAMES):
        result[name] = {
            "median": float(np.median(raw[:, col])),
            "p90": float(np.quantile(raw[:, col], 0.9)),
            "mean": float(np.mean(raw[:, col])),
        }
    counts = Counter(rows[int(i)]["group"] for i in selected)
    result["top_10_groups_row_share"] = sum(n for _, n in counts.most_common(10)) / len(selected)
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--run-dir", type=Path, required=True)
    p.add_argument("--data-dir", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    args = p.parse_args()
    run_dir, data_dir = args.run_dir.resolve(), args.data_dir.resolve()
    prior = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    script = HERE / "train_phishing.py"
    if sha256(script).lower() != prior["script_sha256"].lower():
        raise ValueError("Training script differs from saved run; split replay refused")
    for source, digest in prior["input_sha256"].items():
        filename = {"mixed": "mixed_phishing_urls.csv",
                    "phishtank": "phishtank_phishing_urls.csv",
                    "openphish": "openphish_phishing_urls.csv"}[source]
        if sha256(data_dir / filename).lower() != digest.lower():
            raise ValueError(f"{source} CSV differs from saved run; split replay refused")
    rows, _, conflicts = load_rows(data_dir)
    if len(rows) != prior["unique_valid_labeled_rows"] or conflicts != prior["exact_conflicting_urls_excluded"]:
        raise ValueError("Preprocessed row count differs from saved run")
    labels = np.asarray([r["label"] for r in rows], dtype=np.int8)
    groups = np.asarray([r["group"] for r in rows], dtype=object)
    folds = list(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
                 .split(np.zeros(len(rows)), labels, groups))
    test_idx, val_idx = folds[0][1], folds[1][1]
    for name, idx in (("test", test_idx), ("validation", val_idx)):
        original = prior["splits"][name]
        if len(idx) != original["rows"] or int(np.sum(labels[idx] == 1)) != original["phishing"]:
            raise ValueError(f"{name} split mismatch")
    model = joblib.load(run_dir / "logistic_regression.joblib")
    vectorizer = joblib.load(run_dir / "char_vectorizer.joblib")
    if list(model.classes_) != [0, 1] or len(vectorizer.vocabulary_) != prior["feature_spec"]["vocabulary_size"]:
        raise ValueError("Model/vectorizer mismatch")
    diagnostic = {}
    for domain in DIAGNOSTIC_DOMAINS:
        parsed, reason = parse_url("https://" + domain)
        if reason:
            raise ValueError(f"Diagnostic parse failed: {domain}, {reason}")
        text, _, _, numeric = parsed
        matrix = hstack((vectorizer.transform([text]),
                         csr_matrix(numeric.reshape(1, -1))), format="csr")
        score = float(model.predict_proba(matrix)[0, 1])
        diagnostic[domain] = {
            "phishing_score": score,
            "prediction_at_0_5": "phishing" if score >= 0.5 else "benign",
            "contributions": contribution_report(model, vectorizer, matrix),
        }
    output = {
        "source_run": str(run_dir), "source_model_sha256": sha256(run_dir / "logistic_regression.joblib"),
        "source_vectorizer_sha256": sha256(run_dir / "char_vectorizer.joblib"),
        "analysis_script_sha256": sha256(Path(__file__)),
        "diagnostic_not_test_evidence": diagnostic,
    }
    val_matrix = hstack((
        vectorizer.transform([rows[int(i)]["text"] for i in val_idx]),
        csr_matrix(np.stack([rows[int(i)]["numeric"] for i in val_idx]))
    ), format="csr")
    val_scores = model.predict_proba(val_matrix)[:, 1]
    val_labels = labels[val_idx]
    cutoffs = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99]
    benign_scores = val_scores[val_labels == 0]
    for target in (0.02, 0.01):
        quantile = float(np.quantile(benign_scores, 1 - target, method="higher"))
        cutoffs.append(float(np.nextafter(quantile, np.inf)))
    output["validation_only_thresholds"] = [rates(val_labels, val_scores, t) for t in sorted(set(cutoffs))]
    output["validation_note"] = "Candidate thresholds and FPR-target cutoffs derived only from validation benign scores. No threshold was evaluated on the test set."
    del val_matrix, val_scores
    test_matrix = hstack((
        vectorizer.transform([rows[int(i)]["text"] for i in test_idx]),
        csr_matrix(np.stack([rows[int(i)]["numeric"] for i in test_idx]))
    ), format="csr")
    test_scores = model.predict_proba(test_matrix)[:, 1]
    test_labels = labels[test_idx]
    baseline = rates(test_labels, test_scores, 0.5)
    if baseline["confusion_matrix_benign_phishing"] != prior["results"]["logistic_regression"]["test"]["confusion_matrix"]:
        raise ValueError("Test replay does not match saved confusion matrix")
    fp = (test_labels == 0) & (test_scores >= 0.5)
    tn = (test_labels == 0) & (test_scores < 0.5)
    output["test_default_threshold_only"] = {
        "replayed_confusion_matrix": baseline["confusion_matrix_benign_phishing"],
        "false_positives": aggregate_numeric(rows, test_idx, fp),
        "true_negatives": aggregate_numeric(rows, test_idx, tn),
        "false_positive_score_median": float(np.median(test_scores[fp])),
        "false_positive_score_p90": float(np.quantile(test_scores[fp], 0.9)),
        "false_positive_source_counts": dict(Counter(rows[int(i)]["source"] for i in test_idx[fp])),
        "false_positive_protocol_counts": dict(Counter(rows[int(i)]["protocol"] for i in test_idx[fp])),
    }
    output["limits"] = [
        "Diagnostic domains are a small hand-picked sanity list, not a statistical test set",
        "No independently verified representative benign HTTPS URLs",
        "Aggregate test false positives come only from scheme-less mixed-source benign labels",
        "Validation threshold trade-offs may not transfer to real traffic",
    ]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = args.output_root.resolve() / stamp
    outdir.mkdir(parents=True, exist_ok=False)
    (outdir / "analysis.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps({"output_dir": str(outdir),
                      "diagnostic_scores": {d: x["phishing_score"] for d, x in diagnostic.items()},
                      "validation_thresholds": output["validation_only_thresholds"],
                      "test_false_positives": output["test_default_threshold_only"]["false_positives"]["count"]},
                     indent=2))


if __name__ == "__main__":
    main()
