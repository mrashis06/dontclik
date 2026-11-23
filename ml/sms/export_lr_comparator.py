"""Recreate validation-selected LR from the fixed split; does not touch test."""
import argparse
from pathlib import Path
import train

ROOT = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument("--data-dir", type=Path, default=ROOT.parents[1] / "data" / "raw" / "sms")
parser.add_argument("--output", type=Path, required=True,
                    help="Output artifact path; existing files are never overwritten")
args = parser.parse_args()
OUT = args.output
if OUT.exists():
    raise FileExistsError(OUT)
rows, _ = train.load(args.data_dir)
clean, groups, _ = train.dedup_and_group(rows)
splits = train.split_groups(clean, groups)
vocab = train.vocabulary(clean, splits["train"])
training = train.matrix(clean, splits["train"], vocab)
validation = train.matrix(clean, splits["validation"], vocab)
choices = []
for penalty in (0.0001, 0.001, 0.01):
    model = train.fit_lr(training, len(vocab), penalty)
    threshold, metrics = train.choose_threshold(model, validation)
    choices.append((model, threshold, metrics))
model, threshold, _ = max(choices, key=lambda row: (row[2]["spam_f1"], -row[2]["ham_false_positive_rate"], row[2]["spam_recall"]))
OUT.parent.mkdir(parents=True, exist_ok=True)
train.export(OUT, model, vocab, threshold)
print({"model": "lr", "penalty": model["penalty"], "threshold": threshold, "bytes": OUT.stat().st_size})
