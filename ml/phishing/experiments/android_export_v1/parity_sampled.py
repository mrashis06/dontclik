#!/usr/bin/env python3
"""Expand parity fixtures with deterministic source samples; raw URLs stay in memory."""
from __future__ import annotations

import csv
import argparse
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
import sys
sys.path.insert(0, str(HERE))
from parity import CASES, main  # noqa: E402
sys.path.insert(0, str(HERE.parent))
from train_phishing import parse_url  # noqa: E402

SOURCES = (
    ("mixed", "mixed_phishing_urls.csv", "URL", 80),
    ("phishtank", "phishtank_phishing_urls.csv", "url", 30),
    ("openphish", "openphish_phishing_urls.csv", "URL", 20),
)


def reservoir(path, column, count, seed):
    rng = random.Random(seed)
    samples = []
    eligible = 0
    with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as stream:
        for row in csv.DictReader(stream):
            raw = row[column]
            if not raw.isascii() or parse_url(raw)[1] is not None:
                continue
            eligible += 1
            if len(samples) < count:
                samples.append(raw)
            else:
                target = rng.randrange(eligible)
                if target < count:
                    samples[target] = raw
    return samples


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True,
                        help="Directory containing the three labeled phishing CSVs")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--prototype-jar", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for index, (source, filename, column, count) in enumerate(SOURCES):
        for number, raw in enumerate(reservoir(args.data_dir / filename, column, count, 20261122 + index)):
            CASES.append((f"{source}_sample_{number:03d}", raw))
    main(args.run_dir, args.artifact, args.prototype_jar, args.output)
