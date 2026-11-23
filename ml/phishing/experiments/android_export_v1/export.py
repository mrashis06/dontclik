#!/usr/bin/env python3
"""Export selected LR to a deterministic gzip binary; no runtime pickle required."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import struct
import sys
from pathlib import Path

import joblib
import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "improved_v2"))
from train import CAPS, LR_NAMES  # noqa: E402

MAGIC = b"PHURLLR1"
VERSION = 1


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    args = ap.parse_args()
    run = args.run_dir.resolve()
    output = args.output_dir.resolve()
    metrics = json.loads((run / "metrics.json").read_text(encoding="utf-8"))
    model = joblib.load(run / "lr.joblib")
    vectorizer = joblib.load(run / "char_vectorizer.joblib")
    assert list(model.classes_) == [0, 1]
    assert vectorizer.analyzer == "char" and vectorizer.ngram_range == (3, 4)
    assert vectorizer.binary and vectorizer.lowercase
    assert vectorizer.strip_accents is None and vectorizer.preprocessor is None
    assert len(LR_NAMES) == len(CAPS) == 14
    vocab = vectorizer.get_feature_names_out()
    assert len(vocab) == 75000
    assert model.coef_.shape == (1, len(vocab) + 14)
    assert metrics["features"]["vocabulary"] == len(vocab)
    assert metrics["results"]["lr"]["threshold_frozen_from_validation"] > 0
    threshold = float(metrics["results"]["lr"]["threshold_frozen_from_validation"])
    assert metrics["features"]["lr_numeric_max_value"] == 0.25
    assert np.allclose(CAPS, np.asarray(metrics["features"]["lr_numeric_caps"]))
    output.mkdir(parents=True, exist_ok=True)
    artifact = output / "phishing_lr_v1.bin.gz"
    if artifact.exists():
        raise FileExistsError(artifact)
    with artifact.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as stream:
            stream.write(MAGIC)
            stream.write(struct.pack(">5I3d", VERSION, len(vocab), len(CAPS), 3, 4,
                                     float(model.intercept_[0]), threshold, 0.25))
            stream.write(struct.pack(">" + "f" * len(CAPS), *map(float, CAPS)))
            stream.write(struct.pack(">" + "d" * len(CAPS),
                                     *map(float, model.coef_[0, len(vocab):])))
            for index, feature in enumerate(vocab):
                encoded = feature.encode("utf-8")
                if len(encoded) > 65535:
                    raise ValueError("Oversized character n-gram")
                stream.write(struct.pack(">H", len(encoded)))
                stream.write(encoded)
                stream.write(struct.pack(">d", float(model.coef_[0, index])))
    manifest = {
        "format": "PHURLLR1",
        "version": VERSION,
        "artifact": artifact.name,
        "artifact_bytes": artifact.stat().st_size,
        "artifact_sha256": sha256(artifact),
        "source_model_sha256": sha256(run / "lr.joblib"),
        "source_vectorizer_sha256": sha256(run / "char_vectorizer.joblib"),
        "source_metrics_sha256": sha256(run / "metrics.json"),
        "classes": ["benign", "phishing"],
        "positive_class": "phishing",
        "threshold": threshold,
        "intercept": float(model.intercept_[0]),
        "char_feature_count": len(vocab),
        "char_ngrams": [3, 4],
        "binary_character_features": True,
        "numeric_feature_order": LR_NAMES,
        "numeric_caps": CAPS.tolist(),
        "numeric_scale": 0.25,
        "normalization": "training parse_url: lowercase IDNA host + path or slash + optional question-mark/query; no scheme",
        "limitations": [
            "Prototype rejects non-ASCII input for exact parity in this version",
            "Independent representative benign HTTPS evaluation is missing",
            "Artifact is not approved for security decisions or APK inclusion",
        ],
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"artifact": str(artifact), "bytes": artifact.stat().st_size,
                      "sha256": manifest["artifact_sha256"], "threshold": threshold,
                      "features": len(vocab) + len(CAPS)}, indent=2))


if __name__ == "__main__":
    main()
