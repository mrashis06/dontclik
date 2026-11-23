"""Offline, dependency-free experimental SMS spam training and export.

No message bodies or identifying text are written to reports or logs.
"""
import argparse
import collections
import csv
import difflib
import gzip
import hashlib
import json
import math
import random
import re
import struct
from pathlib import Path

SEED = 20261123
TOKEN = re.compile(r"[A-Za-z0-9]+")
MASK_DIGITS = re.compile(r"\d+")
SOURCES = (("spam_ham_india.csv", "Msg", "Label"), ("spam_utf8.csv", "v2", "v1"))
MAGIC = b"SMS1"
VERSION = 1


def tokens(text):
    return [MASK_DIGITS.sub("0", term) for term in TOKEN.findall(text.lower())]


def canonical(text):
    return " ".join(tokens(text))


def template(text):
    return MASK_DIGITS.sub("#", canonical(text))


def label_of(value):
    value = str(value).strip().lower()
    return {"ham": 0, "spam": 1}.get(value)


def fingerprint(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load(data_dir):
    rows, inventory = [], {}
    for name, text_col, label_col in SOURCES:
        path = data_dir / name
        if not path.is_file():
            raise FileNotFoundError(str(path))
        counts = collections.Counter()
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if text_col not in reader.fieldnames or label_col not in reader.fieldnames:
                raise ValueError(f"Unexpected columns in {name}: {reader.fieldnames}")
            columns = reader.fieldnames
            for row in reader:
                counts["total"] += 1
                raw = row.get(text_col) or ""
                label = label_of(row.get(label_col))
                if label is None:
                    counts["unknown_label"] += 1
                    continue
                counts["spam" if label else "ham"] += 1
                if any((row.get(column) or "").strip() for column in columns if column not in (text_col, label_col)):
                    counts["extra_columns_nonempty_excluded"] += 1
                    continue
                if any(ord(c) > 127 for c in raw):
                    counts["non_ascii"] += 1
                    if any("\u0900" <= c <= "\u097f" for c in raw):
                        counts["devanagari"] += 1
                if not raw.strip() or not tokens(raw):
                    counts["empty_or_no_ascii_tokens"] += 1
                    continue
                rows.append((raw, label, name))
        inventory[name] = {"columns": columns, **dict(counts)}
    return rows, inventory


class UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        self.parent[self.find(a)] = self.find(b)


def dedup_and_group(rows):
    # Exact text with both labels is excluded in full, including all copies.
    by_exact = collections.defaultdict(list)
    for item in rows:
        by_exact[fingerprint(item[0])].append(item)
    conflicting = {key for key, values in by_exact.items() if len({v[1] for v in values}) > 1}
    clean = []
    for key, values in by_exact.items():
        if key not in conflicting:
            clean.append(values[0])
    exact_removed = len(rows) - len(clean)
    uf = UnionFind(len(clean))
    by_template = {}
    for i, (message, _, _) in enumerate(clean):
        key = template(message)
        if key in by_template:
            uf.union(i, by_template[key])
        else:
            by_template[key] = i
    # Candidate near duplicates share a rare-enough 3-token shingle.
    index = collections.defaultdict(list)
    shingles = []
    for i, (message, _, _) in enumerate(clean):
        t = tokens(message)
        sh = {" ".join(t[j:j+3]) for j in range(max(0, len(t)-2))}
        shingles.append(sh)
        if len(canonical(message)) < 25 or not sh:
            continue
        candidates = set()
        for gram in sh:
            if len(index[gram]) <= 100:
                candidates.update(index[gram])
        for j in candidates:
            a, b = canonical(message), canonical(clean[j][0])
            if abs(len(a)-len(b)) > max(len(a), len(b))*0.25:
                continue
            if len(sh & shingles[j]) / len(sh | shingles[j]) >= 0.80 or difflib.SequenceMatcher(None, a, b).ratio() >= 0.90:
                uf.union(i, j)
        for gram in sh:
            if len(index[gram]) <= 100:
                index[gram].append(i)
    groups = collections.defaultdict(list)
    for i in range(len(clean)):
        groups[uf.find(i)].append(i)
    stats = {"input_rows": len(rows), "exact_duplicate_or_conflict_rows_removed": exact_removed,
             "conflicting_exact_texts": len(conflicting), "unique_exact_texts_kept": len(clean),
             "near_duplicate_groups": len(groups), "groups_with_multiple_texts": sum(len(g)>1 for g in groups.values())}
    return clean, list(groups.values()), stats


def split_groups(clean, groups):
    rng = random.Random(SEED)
    rng.shuffle(groups)
    groups.sort(key=len, reverse=True)
    targets = {"train": .70, "validation": .15, "test": .15}
    total_by_label = collections.Counter(row[1] for row in clean)
    sets = {key: [] for key in targets}
    counts = {key: collections.Counter() for key in targets}
    for group in groups:
        labels = collections.Counter(clean[i][1] for i in group)
        def deficit(key):
            return sum(labels[c] * (targets[key]*total_by_label[c] - counts[key][c])
                       / max(targets[key]*total_by_label[c], 1) for c in (0, 1))
        key = max(targets, key=deficit)
        sets[key].extend(group)
        counts[key].update(labels)
    for key in sets:
        rng.shuffle(sets[key])
    if any(not sets[key] or len({clean[i][1] for i in sets[key]}) < 2 for key in sets):
        raise ValueError("Unable to make class-inclusive group splits")
    return sets


def features(message):
    t = tokens(message)
    return collections.Counter(t + [t[i] + "_" + t[i+1] for i in range(len(t)-1)])


def vocabulary(clean, train_ids, limit=8000):
    df = collections.Counter()
    for i in train_ids:
        df.update(features(clean[i][0]))
    terms = [term for term, count in df.items() if count >= 2 and count <= .98*len(train_ids)]
    terms.sort(key=lambda term: (-df[term], term))
    return {term: i for i, term in enumerate(terms[:limit])}


def matrix(clean, ids, vocab):
    return [({vocab[t]: n for t, n in features(clean[i][0]).items() if t in vocab}, clean[i][1]) for i in ids]


def sigmoid(x):
    if x >= 0:
        z = math.exp(-x)
        return 1/(1+z)
    z = math.exp(x)
    return z/(1+z)


def fit_mnb(data, size, alpha):
    counts = [[0.0]*size for _ in range(2)]
    totals = [0.0, 0.0]
    class_counts = [0, 0]
    for x, y in data:
        class_counts[y] += 1
        for j, n in x.items():
            counts[y][j] += n
            totals[y] += n
    weights = [math.log((counts[1][j]+alpha)/(totals[1]+alpha*size)) - math.log((counts[0][j]+alpha)/(totals[0]+alpha*size)) for j in range(size)]
    bias = math.log(class_counts[1]/class_counts[0])
    return {"kind": "mnb", "weights": weights, "bias": bias, "alpha": alpha}


def fit_lr(data, size, penalty, epochs=160):
    weights = [0.0]*size
    bias = 0.0
    for epoch in range(epochs):
        grad = [0.0]*size
        gb = 0.0
        for x, y in data:
            score = bias + sum(weights[j] for j in x)
            error = sigmoid(score) - y
            gb += error
            for j in x:
                grad[j] += error
        rate = 1.0 / (1.0 + epoch/40)
        scale = rate/len(data)
        for j in range(size):
            weights[j] -= scale*grad[j] + rate*penalty*weights[j]
        bias -= scale*gb
    return {"kind": "lr", "weights": weights, "bias": bias, "penalty": penalty, "epochs": epochs}


def score(model, x):
    weights = model["weights"]
    value = model["bias"] + sum(weights[j]*(1 if model["kind"] == "lr" else n) for j, n in x.items())
    return sigmoid(value)


def metrics(model, data, threshold):
    tp = fp = tn = fn = 0
    for x, y in data:
        pred = int(score(model, x) >= threshold)
        if y and pred: tp += 1
        elif y: fn += 1
        elif pred: fp += 1
        else: tn += 1
    precision = tp/(tp+fp) if tp+fp else 0
    recall = tp/(tp+fn) if tp+fn else 0
    return {"confusion_matrix_ham_spam": [[tn, fp], [fn, tp]],
            "spam_precision": precision, "spam_recall": recall,
            "spam_f1": 2*precision*recall/(precision+recall) if precision+recall else 0,
            "ham_false_positive_rate": fp/(fp+tn) if fp+tn else 0,
            "spam_false_negative_rate": fn/(fn+tp) if fn+tp else 0}


def choose_threshold(model, val):
    choices = []
    for threshold in [x/100 for x in range(5, 96, 5)]:
        m = metrics(model, val, threshold)
        choices.append((threshold, m))
    eligible = [(t, m) for t, m in choices if m["ham_false_positive_rate"] <= .02]
    pool = eligible or choices
    return max(pool, key=lambda item: (item[1]["spam_f1"], -item[1]["ham_false_positive_rate"], item[1]["spam_recall"]))


def export(path, model, vocab, threshold):
    ordered = sorted(vocab, key=vocab.get)
    with gzip.open(path, "wb", compresslevel=9) as out:
        out.write(MAGIC)
        out.write(struct.pack(">BBIdd", VERSION, 1 if model["kind"] == "lr" else 2, len(ordered), model["bias"], threshold))
        for term, weight in zip(ordered, model["weights"]):
            value = term.encode("ascii")
            out.write(struct.pack(">H", len(value)))
            out.write(value)
            out.write(struct.pack(">d", weight))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--data-dir", type=Path,
        default=Path(__file__).resolve().parents[2] / "data" / "raw" / "sms",
        help="Directory containing spam_ham_india.csv and spam_utf8.csv "
             "(default: repository data/raw/sms; override for a local dataset path)",
    )
    ap.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / "run")
    args = ap.parse_args()
    if args.output.exists():
        raise FileExistsError(f"Refusing to overwrite existing experiment: {args.output}")
    rows, inventory = load(args.data_dir)
    clean, groups, quality = dedup_and_group(rows)
    splits = split_groups(clean, groups)
    vocab = vocabulary(clean, splits["train"])
    train, val, test = (matrix(clean, splits[key], vocab) for key in ("train", "validation", "test"))
    candidates = [fit_mnb(train, len(vocab), alpha) for alpha in (0.5, 1.0, 2.0)]
    candidates += [fit_lr(train, len(vocab), penalty) for penalty in (0.0001, 0.001, 0.01)]
    validation = []
    for model in candidates:
        threshold, m = choose_threshold(model, val)
        validation.append({"model": model, "threshold": threshold, "metrics": m})
    selected = max(validation, key=lambda row: (row["metrics"]["spam_f1"], -row["metrics"]["ham_false_positive_rate"], row["metrics"]["spam_recall"]))
    # The test is touched once, only after candidate and threshold selection.
    comparison = []
    for row in validation:
        model = row["model"]
        comparison.append({"kind": model["kind"], "alpha": model.get("alpha"), "penalty": model.get("penalty"),
                           "threshold": row["threshold"], "validation": row["metrics"],
                           "test": metrics(model, test, row["threshold"])})
    args.output.mkdir(parents=True)
    artifact = args.output / "sms_spam_v1.bin.gz"
    export(artifact, selected["model"], vocab, selected["threshold"])
    # JSON for reproducibility; no raw messages or word vocabulary in report.
    report = {"seed": SEED, "inventory": inventory, "quality": quality,
              "split": {key: {"count": len(ids), "ham": sum(clean[i][1] == 0 for i in ids), "spam": sum(clean[i][1] == 1 for i in ids)} for key, ids in splits.items()},
              "vocab_size": len(vocab), "comparison": comparison,
              "selected_index": validation.index(selected), "artifact_bytes": artifact.stat().st_size,
              "limitations": ["Labels denote spam, not verified financial scams", "Non-ASCII text is unsupported at inference", "Near-duplicate detection is heuristic and may miss paraphrases", "Scores are uncalibrated"]}
    (args.output / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    # Privacy-safe parity inputs are synthetic. These are not accuracy evidence.
    examples = ["Your OTP is 123456. Do not share it.", "URGENT verify KYC now to avoid account block", "Congratulations you won a prize claim now", "Your bank statement is ready in the app", "Are we meeting at 6 tonight?", "", "नमस्ते"]
    parity = []
    for message in examples:
        if not message.isascii() or not message.strip():
            parity.append({"supported": False})
        else:
            x = {vocab[t]: n for t, n in features(message).items() if t in vocab}
            parity.append({"supported": True, "score": score(selected["model"], x), "spam": score(selected["model"], x) >= selected["threshold"]})
    (args.output / "parity_expected.json").write_text(json.dumps(parity, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
