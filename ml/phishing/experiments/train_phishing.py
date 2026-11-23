#!/usr/bin/env python3
"""Offline phishing URL experiment. Never fetches or opens URLs."""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import math
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import scipy
from scipy.sparse import csr_matrix, hstack
import sklearn
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.naive_bayes import MultinomialNB

SEED = 42
SOURCE_FILES = {
    "mixed": "mixed_phishing_urls.csv",
    "phishtank": "phishtank_phishing_urls.csv",
    "openphish": "openphish_phishing_urls.csv",
}
DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
FEATURE_NAMES = (
    "host_length", "path_length", "query_length", "digit_count", "hyphen_count",
    "dot_count", "subdomain_depth", "at_count", "percent_count", "path_depth",
    "query_pair_count", "host_entropy", "url_length", "is_ip_host",
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


def parse_url(raw: str):
    if not raw or len(raw) > 4096:
        return None, "empty_or_overlong"
    if CONTROL_OR_SPACE.search(raw):
        return None, "control_or_space"
    if SCHEME.match(raw):
        try:
            split = urlsplit(raw)
        except ValueError:
            return None, "malformed_url"
        if split.scheme.lower() not in ("http", "https"):
            return None, "unsupported_scheme"
        protocol = split.scheme.lower()
    else:
        if "://" in raw:
            return None, "malformed_scheme"
        try:
            split = urlsplit("http://" + raw)
        except ValueError:
            return None, "malformed_url"
        protocol = "none"
    try:
        host = (split.hostname or "").rstrip(".").lower().encode("idna").decode("ascii")
        _ = split.port
    except (ValueError, UnicodeError):
        return None, "bad_host_or_port"
    if not host:
        return None, "missing_host"
    if split.username or split.password:
        return None, "userinfo"
    try:
        ipaddress.ip_address(host.strip("[]"))
        group = "ip:" + host
        is_ip = 1.0
    except ValueError:
        labels = host.split(".")
        if len(labels) < 2 or any(not DNS_LABEL.fullmatch(label) for label in labels):
            return None, "bad_dns_name"
        # Coarse suffix-pair groups keep each registrable domain in one split.
        group = ".".join(labels[-2:])
        is_ip = 0.0
    # Scheme is deliberately absent from model features. No source ID is included.
    text = host + (split.path or "/") + (("?" + split.query) if split.query else "")
    subdepth = max(0, len(host.split(".")) - len(group.split(".")))
    nums = (
        len(host), len(split.path), len(split.query), sum(c.isdigit() for c in text),
        text.count("-"), host.count("."), subdepth, text.count("@"), text.count("%"),
        split.path.count("/"), split.query.count("&") + bool(split.query),
        entropy(host), len(text), is_ip,
    )
    # Log scaling keeps all numeric features nonnegative for MultinomialNB.
    numeric = np.log1p(np.asarray(nums, dtype=np.float32))
    return (text, group, protocol, numeric), None


def load_rows(data_dir: Path):
    records = {}
    counts = {}
    for source, filename in SOURCE_FILES.items():
        path = data_dir / filename
        if not path.is_file():
            raise FileNotFoundError(path)
        stats = {"input_rows": 0, "invalid_reasons": Counter(),
                 "duplicate_rows": 0, "labels": Counter()}
        with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as stream:
            reader = csv.DictReader(stream)
            required = {"url"} if source == "phishtank" else {"URL", "Label"}
            if not required.issubset(reader.fieldnames or []):
                raise ValueError(f"{filename}: required columns absent: {required}")
            for row in reader:
                stats["input_rows"] += 1
                raw = row["url"] if source == "phishtank" else row["URL"]
                label = "bad" if source == "phishtank" else row["Label"].strip().lower()
                if label == "phishing":
                    label = "bad"
                if label not in ("good", "bad"):
                    stats["invalid_reasons"]["unknown_label"] += 1
                    continue
                parsed, reason = parse_url(raw)
                if reason:
                    stats["invalid_reasons"][reason] += 1
                    continue
                stats["labels"][label] += 1
                if raw in records:
                    stats["duplicate_rows"] += 1
                    records[raw]["labels"].add(label)
                    records[raw]["sources"].add(source)
                else:
                    text, group, protocol, numeric = parsed
                    records[raw] = {"text": text, "group": group, "protocol": protocol,
                                    "numeric": numeric, "labels": {label}, "sources": {source}}
        counts[source] = stats
    conflicting = [raw for raw, item in records.items() if len(item["labels"]) != 1]
    for raw in conflicting:
        del records[raw]
    rows = list(records.values())
    for item in rows:
        item["label"] = int("bad" in item["labels"])
        item["source"] = "+".join(sorted(item["sources"]))
        del item["labels"]
        del item["sources"]
    return rows, counts, len(conflicting)


def metric_block(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = map(int, cm.ravel())
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=[0, 1], zero_division=0
    )
    return {
        "support": {"benign": int(support[0]), "phishing": int(support[1])},
        "confusion_matrix_order": ["benign", "phishing"],
        "confusion_matrix": cm.tolist(),
        "benign": {"precision": float(precision[0]), "recall": float(recall[0]),
                   "f1": float(f1[0])},
        "phishing": {"precision": float(precision[1]), "recall": float(recall[1]),
                     "f1": float(f1[1])},
        "phishing_false_negative_rate": fn / (tp + fn) if tp + fn else None,
        "benign_false_positive_rate": fp / (tn + fp) if tn + fp else None,
    }


def slice_metrics(rows, indexes, y_true, y_pred, key):
    output = {}
    keys = sorted({rows[int(i)][key] for i in indexes})
    for value in keys:
        positions = [j for j, i in enumerate(indexes) if rows[int(i)][key] == value]
        output[value] = metric_block(y_true[positions], y_pred[positions])
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    data_dir = args.data_dir.resolve()
    output_root = args.output_root.resolve()
    rows, counts, conflict_count = load_rows(data_dir)
    if not rows or {row["label"] for row in rows} != {0, 1}:
        raise ValueError("Both classes are required after exclusions")
    y = np.asarray([row["label"] for row in rows], dtype=np.int8)
    groups = np.asarray([row["group"] for row in rows], dtype=object)
    folds = list(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
                 .split(np.zeros(len(rows)), y, groups))
    test_idx = folds[0][1]
    val_idx = folds[1][1]
    train_idx = np.setdiff1d(np.arange(len(rows)), np.concatenate([test_idx, val_idx]))
    split_indexes = {"train": train_idx, "validation": val_idx, "test": test_idx}
    split_groups = {k: set(groups[v]) for k, v in split_indexes.items()}
    assert not (split_groups["train"] & split_groups["validation"])
    assert not (split_groups["train"] & split_groups["test"])
    assert not (split_groups["validation"] & split_groups["test"])
    split_summary = {}
    for name, idx in split_indexes.items():
        split_summary[name] = {
            "rows": int(len(idx)), "groups": len(split_groups[name]),
            "benign": int(np.sum(y[idx] == 0)), "phishing": int(np.sum(y[idx] == 1)),
            "sources": dict(Counter(rows[int(i)]["source"] for i in idx)),
            "protocols": dict(Counter(rows[int(i)]["protocol"] for i in idx)),
        }
        if not split_summary[name]["benign"] or not split_summary[name]["phishing"]:
            raise ValueError(f"{name} split lacks a class; inspect group balance")
    texts = [row["text"] for row in rows]
    numeric = np.stack([row["numeric"] for row in rows])
    vectorizer = CountVectorizer(analyzer="char", ngram_range=(3, 4),
                                 min_df=5, max_features=75000, binary=True,
                                 dtype=np.float32, lowercase=True)
    train_text = vectorizer.fit_transform([texts[int(i)] for i in train_idx])
    train_matrix = hstack((train_text, csr_matrix(numeric[train_idx])), format="csr")
    del train_text
    matrices = {"train": train_matrix}
    for name in ("validation", "test"):
        idx = split_indexes[name]
        matrices[name] = hstack((
            vectorizer.transform([texts[int(i)] for i in idx]),
            csr_matrix(numeric[idx])
        ), format="csr")
    models = {
        "logistic_regression": LogisticRegression(
            solver="liblinear", max_iter=300, class_weight="balanced", random_state=SEED
        ),
        "multinomial_nb": MultinomialNB(alpha=1.0),
    }
    results = {}
    for name, model in models.items():
        model.fit(matrices["train"], y[train_idx])
        pred_val = model.predict(matrices["validation"])
        pred_test = model.predict(matrices["test"])
        results[name] = {
            "validation": metric_block(y[val_idx], pred_val),
            "test": metric_block(y[test_idx], pred_test),
            "test_by_source": slice_metrics(rows, test_idx, y[test_idx], pred_test, "source"),
            "test_by_protocol": slice_metrics(rows, test_idx, y[test_idx], pred_test, "protocol"),
        }
    sanity = {}
    for domain in ("google.com", "wikipedia.org", "github.com"):
        sanity[domain] = {}
        for scheme in ("none", "https"):
            raw = domain if scheme == "none" else "https://" + domain
            parsed, reason = parse_url(raw)
            if reason:
                raise ValueError(f"sanity input parse failed: {reason}")
            text, _, _, features = parsed
            matrix = hstack((vectorizer.transform([text]),
                             csr_matrix(features.reshape(1, -1))), format="csr")
            sanity[domain][scheme] = {
                name: {"predicted_class": "phishing" if model.predict(matrix)[0] else "benign",
                       "phishing_probability": float(model.predict_proba(matrix)[0, 1])}
                for name, model in models.items()
            }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_root / stamp
    if run_dir.exists():
        raise FileExistsError(run_dir)
    run_dir.mkdir(parents=True)
    for name, model in models.items():
        joblib.dump(model, run_dir / (name + ".joblib"))
    joblib.dump(vectorizer, run_dir / "char_vectorizer.joblib")
    report = {
        "run_utc": stamp, "seed": SEED,
        "versions": {"python": sys.version, "numpy": np.__version__,
                     "scipy": scipy.__version__, "sklearn": sklearn.__version__,
                     "domain_grouping": "final_two_dns_labels_conservative"},
        "script_sha256": sha256(Path(__file__)),
        "input_sha256": {name: sha256(data_dir / filename)
                         for name, filename in SOURCE_FILES.items()},
        "tranco_policy": "Excluded: unlabeled domains, not verified benign URLs",
        "input_counts": {
            name: {**stats, "invalid_reasons": dict(stats["invalid_reasons"]),
                   "labels": dict(stats["labels"])}
            for name, stats in counts.items()
        },
        "exact_conflicting_urls_excluded": conflict_count,
        "unique_valid_labeled_rows": len(rows),
        "splits": split_summary,
        "feature_spec": {"text": "lowercase host+path+query without scheme",
                         "character_ngrams": [3, 4], "min_df": 5, "max_features": 75000,
                         "binary_counts": True, "structure_features": FEATURE_NAMES,
                         "structure_transform": "log1p", "vocabulary_size": len(vectorizer.vocabulary_)},
        "model_parameters": {name: model.get_params() for name, model in models.items()},
        "results": results,
        "sanity_checks_not_accuracy_evidence": sanity,
        "production_ready": False,
        "limitations": [
            "No independently verified benign HTTPS URL corpus",
            "Source/protocol association remains in available labels",
            "Conservative suffix-pair grouping is coarser than Public Suffix List registrable domains and does not prove campaign independence",
            "No Android parity, size, latency, or prospective false-positive validation",
        ],
    }
    (run_dir / "metrics.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"run_dir": str(run_dir), "test": {n: z["test"] for n, z in results.items()},
                      "blocker": "No verified benign HTTPS test coverage"}, indent=2))


if __name__ == "__main__":
    main()
