#!/usr/bin/env python3
"""Python/Kotlin parity fixtures; no URL fetch or raw URL logging."""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import joblib
from scipy.sparse import csr_matrix, hstack

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "improved_v2"))
sys.path.insert(0, str(HERE.parent))
from train_phishing import parse_url  # noqa: E402
from train import numeric_views  # noqa: E402

CASES = [
    ("google_https", "https://google.com"),
    ("github_https", "https://github.com"),
    ("microsoft_https", "https://microsoft.com"),
    ("wikipedia_https", "https://wikipedia.org"),
    ("cloudflare_https", "https://cloudflare.com"),
    ("google_bare", "google.com"),
    ("github_http", "http://github.com/"),
    ("uppercase_host", "HTTPS://WWW.Example.COM/Account/Login"),
    ("trailing_dot", "https://example.com./index.html"),
    ("explicit_port", "https://example.com:443/path"),
    ("synthetic_login", "https://secure-login-account-verify.example.com/login?token=synthetic123"),
    ("synthetic_payment", "http://billing-update.example.net/confirm/card"),
    ("ipv4", "http://192.0.2.5/login"),
    ("query_fragment", "https://example.org/a/b?x=123&y=abc#fragment"),
    ("encoded_path", "https://example.org/%2Fadmin%20login"),
    ("digits_hyphens", "https://a1-b2-c3.example.org/u/123456"),
    ("empty_path_query", "example.org?ref=synthetic"),
    ("long_path", "https://example.org/" + "a" * 800),
    ("empty", ""),
    ("spaces", "https://exa mple.org/path"),
    ("control", "https://example.org/\x01"),
    ("missing_host", "https://"),
    ("bad_port", "https://example.org:99999/path"),
    ("userinfo", "https://user:pass@example.org/"),
    ("ftp_scheme", "ftp://example.org/"),
    ("javascript_scheme", "javascript://example.org/"),
    ("bad_dns_label", "https://bad_name.example.org/"),
    ("malformed_scheme", "ht!tp://example.org/"),
    ("too_long", "https://example.org/" + "x" * 4100),
    ("unicode_path", "https://example.org/café"),
    ("ipv6", "http://[2001:db8::1]/path"),
]


def main(run_dir: Path, artifact: Path, prototype_jar: Path, output: Path):
    run_dir = run_dir.resolve()
    artifact = artifact.resolve()
    prototype_jar = prototype_jar.resolve()
    output = output.resolve()
    model = joblib.load(run_dir / "lr.joblib")
    vectorizer = joblib.load(run_dir / "char_vectorizer.joblib")
    threshold = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))["results"]["lr"]["threshold_frozen_from_validation"]
    stdin = "".join(
        case_id + "\t" + base64.b64encode(raw.encode("utf-8")).decode("ascii") + "\n"
        for case_id, raw in CASES
    )
    result = subprocess.run(
        ["java", "-jar", str(prototype_jar), str(artifact)],
        input=stdin, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
    )
    kotlin = {}
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        case_id = fields[0]
        kotlin[case_id] = (
            {"status": "ok", "score": float(fields[2]), "label": fields[3]}
            if fields[1] == "OK" else {"status": "error", "reason": fields[2]}
        )
    if len(kotlin) != len(CASES):
        raise RuntimeError("Kotlin did not return every case")
    details = []
    supported_differences = []
    label_disagreements = []
    acceptance_disagreements = []
    unsupported = []
    for case_id, raw in CASES:
        parsed, reason = parse_url(raw)
        if reason:
            python = {"status": "error", "reason": reason}
        else:
            text, _, _, old_numeric = parsed
            lr_numeric, _ = numeric_views(old_numeric)
            matrix = hstack((vectorizer.transform([text]),
                             csr_matrix(lr_numeric.reshape(1, -1))), format="csr")
            score = float(model.predict_proba(matrix)[0, 1])
            python = {"status": "ok", "score": score,
                      "label": "phishing" if score >= threshold else "benign"}
        kt = kotlin[case_id]
        item = {"case": case_id, "python": python, "kotlin": kt}
        if kt["status"] == "error" and kt["reason"].startswith("unsupported_"):
            unsupported.append(case_id)
        elif python["status"] != kt["status"]:
            acceptance_disagreements.append(case_id)
        elif python["status"] == "ok":
            diff = abs(python["score"] - kt["score"])
            item["absolute_score_difference"] = diff
            supported_differences.append(diff)
            if python["label"] != kt["label"]:
                label_disagreements.append(case_id)
        details.append(item)
    report = {
        "case_count": len(CASES),
        "supported_scored_count": len(supported_differences),
        "both_rejected_count": sum(1 for d in details if d["python"]["status"] == d["kotlin"]["status"] == "error"),
        "unsupported_kotlin_cases": unsupported,
        "acceptance_disagreements": acceptance_disagreements,
        "label_disagreements": label_disagreements,
        "max_absolute_score_difference": max(supported_differences) if supported_differences else None,
        "cases": details,
        "notes": "Only case IDs and scores are saved; no raw URL or query is logged.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite parity report: {output}")
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in (
        "case_count", "supported_scored_count", "both_rejected_count",
        "unsupported_kotlin_cases", "acceptance_disagreements",
        "label_disagreements", "max_absolute_score_difference"
    )}, indent=2))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--prototype-jar", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    main(args.run_dir, args.artifact, args.prototype_jar, args.output)
