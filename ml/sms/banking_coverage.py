"""Aggregate banking-term coverage; no dataset message output."""
import collections
import argparse
import json
from pathlib import Path
import train

parser = argparse.ArgumentParser()
parser.add_argument("--data-dir", type=Path,
                    default=Path(__file__).resolve().parents[2] / "data" / "raw" / "sms")
args = parser.parse_args()
rows, _ = train.load(args.data_dir)
clean, groups, _ = train.dedup_and_group(rows)
splits = train.split_groups(clean, groups)
terms = ("bank", "otp", "account", "debit", "credit", "upi", "statement", "app")
result = {}
for split, ids in splits.items():
    if split == "test":
        continue
    result[split] = {"class_counts": dict(collections.Counter(clean[i][1] for i in ids)),
                     "term_counts": {term: {str(label): sum(term in set(train.tokens(clean[i][0]))
                        for i in ids if clean[i][1] == label) for label in (0, 1)} for term in terms}}
print(json.dumps(result, indent=2))
