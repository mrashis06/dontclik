"""Privacy-safe frozen-model banking false-positive analysis.

Reads training CSVs only to reconstruct the original validation split. Never
prints or saves dataset message bodies. No training or test-set scoring.
"""
import json
import argparse
from pathlib import Path

import parity
import train

ROOT = Path(__file__).resolve().parent

DIAGNOSTICS = [
    ("bank_statement_original", "Your bank statement is ready in the app"),
    ("otp_do_not_share", "Your OTP is 123456. Do not share it."),
    ("otp_login_expiry", "Your OTP for login is 482991. It expires in 5 minutes."),
    ("debit_notice", "Rs 500 was debited from your account ending 1234."),
    ("credit_notice", "Rs 7500 was credited to your account."),
    ("monthly_statement", "Your monthly bank statement is available in the app."),
    ("card_payment", "Your card payment of Rs 299 succeeded."),
    ("account_balance", "Your account balance is Rs 1050."),
    ("card_purchase", "Your debit card was used at a store for Rs 200."),
    ("upi_payment", "Your UPI payment of Rs 250 to a friend is complete."),
    ("loan_emi", "Your loan EMI of Rs 3000 was paid."),
    ("transaction_advice", "If you did not authorize this transaction, contact your bank using the number on your card."),
]


def model(path):
    kind, vocab, weights, bias, threshold = parity.read_model(path)
    return {"kind": "lr" if kind == 1 else "mnb", "vocab": vocab,
            "weights": weights, "bias": bias, "threshold": threshold,
            "parity_tuple": (kind, vocab, weights, bias, threshold)}


def contributions(m, text):
    counts = train.features(text)
    entries = []
    for term, count in counts.items():
        index = m["vocab"].get(term)
        if index is not None:
            value = m["weights"][index] * (1 if m["kind"] == "lr" else count)
            entries.append({"term": term, "count": count, "logit_contribution": value})
    return {"intercept": m["bias"], "matched_features": len(entries),
            "unmatched_features": len(counts) - len(entries),
            "positive": sorted((e for e in entries if e["logit_contribution"] > 0),
                               key=lambda e: -e["logit_contribution"])[:10],
            "negative": sorted((e for e in entries if e["logit_contribution"] < 0),
                               key=lambda e: e["logit_contribution"])[:10],
            "sum_logit_contribution": sum(e["logit_contribution"] for e in entries)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=ROOT.parents[1] / "data" / "raw" / "sms")
    parser.add_argument("--run-dir", type=Path, required=True,
                        help="Directory containing frozen MNB and LR comparator artifacts")
    parser.add_argument("--output", type=Path, required=True,
                        help="New output directory; existing paths are never overwritten")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"Refusing overwrite: {args.output}")
    models = {
        "mnb": model(args.run_dir / "sms_spam_v1.bin.gz"),
        "lr": model(args.run_dir / "sms_spam_lr_comparator_v1.bin.gz"),
    }
    rows, _ = train.load(args.data_dir)
    clean, groups, _ = train.dedup_and_group(rows)
    splits = train.split_groups(clean, groups)
    report = {"validation_rows": len(splits["validation"]),
              "test_data_used": False,
              "diagnostic_messages_are_synthetic": True,
              "diagnostics": [], "models": {}}
    for identifier, text in DIAGNOSTICS:
        report["diagnostics"].append({"id": identifier, "intended_label": "benign",
            **{name: {"score": parity.predict(m["parity_tuple"], text)[0],
                      "spam_like": parity.predict(m["parity_tuple"], text)[1]}
               for name, m in models.items()}})
    for name, m in models.items():
        validation = train.matrix(clean, splits["validation"], m["vocab"])
        tm = {"kind": m["kind"], "weights": m["weights"], "bias": m["bias"]}
        thresholds = ([.95, .98, .99, .995, .999, .9991, .9995, .9999]
                      if name == "mnb" else [.45, .55, .65, .75, .85, .95, .99])
        report["models"][name] = {
            "frozen_threshold": m["threshold"],
            "original_banking_alert": {
                "score": parity.predict(m["parity_tuple"], DIAGNOSTICS[0][1])[0],
                **contributions(m, DIAGNOSTICS[0][1])},
            "validation_threshold_sweep": [
                {"threshold": threshold, **train.metrics(tm, validation, threshold)}
                for threshold in thresholds],
        }
    args.output.mkdir(parents=True)
    (args.output / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    # The report contains only synthetic diagnostic IDs/tokens and aggregate
    # validation metrics, never messages from the CSVs.
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
