"""Compare bounded synthetic Python and Kotlin inference; prints no messages."""
import gzip
import math
import re
import struct
import subprocess
import sys
from pathlib import Path

EXAMPLES = [
    "Your OTP is 123456. Do not share it.",
    "URGENT verify KYC now to avoid account block",
    "Congratulations you won a prize claim now",
    "Your bank statement is ready in the app",
    "Are we meeting at 6 tonight?",
    "", "नमस्ते", "Hello!", "Please call me tomorrow", "Your package arrives today",
    "Claim your cash reward now", "Update your account details immediately",
    "Your salary was deposited", "Meeting moved to 10 AM", "A", "123456", "http://example.invalid",
    "\x00", " ", "x" * 4097,
]


def read_model(path):
    with gzip.open(path, "rb") as inp:
        assert inp.read(4) == b"SMS1"
        version, kind, n, bias, threshold = struct.unpack(">BBIdd", inp.read(22))
        assert version == 1 and kind in (1, 2)
        vocab, weights = {}, []
        for i in range(n):
            length = struct.unpack(">H", inp.read(2))[0]
            term = inp.read(length).decode("ascii")
            vocab[term] = i
            weights.append(struct.unpack(">d", inp.read(8))[0])
    return kind, vocab, weights, bias, threshold


def predict(model, message):
    kind, vocab, weights, bias, threshold = model
    if not message.strip() or len(message) > 4096 or any(ord(c) > 127 or (ord(c) < 32 and c not in "\n\r\t") for c in message):
        return None
    words = [re.sub(r"[0-9]+", "0", word) for word in re.findall(r"[A-Za-z0-9]+", message.lower())]
    if not words:
        return None
    counts = {}
    for term in words + [words[i] + "_" + words[i+1] for i in range(len(words)-1)]:
        if term in vocab:
            j = vocab[term]
            counts[j] = counts.get(j, 0) + 1
    raw = bias + sum(weights[j] * (1 if kind == 1 else counts[j]) for j in sorted(counts))
    score = 1/(1+math.exp(-raw)) if raw >= 0 else math.exp(raw)/(1+math.exp(raw))
    return score, score >= threshold


def main():
    artifact, jar = map(Path, sys.argv[1:3])
    model = read_model(artifact)
    completed = subprocess.run(["java", "-jar", str(jar), str(artifact)], capture_output=True, text=True, check=True)
    lines = completed.stdout.splitlines()
    assert len(lines) == len(EXAMPLES), (len(lines), len(EXAMPLES))
    differences, disagreements, unsupported = [], 0, 0
    for i, (message, line) in enumerate(zip(EXAMPLES, lines)):
        expected = predict(model, message)
        if expected is None:
            assert line.startswith("UNSUPPORTED\t"), i
            unsupported += 1
            continue
        score, label = line.split("\t")
        differences.append(abs(float(score) - expected[0]))
        disagreements += (label.lower() == "true") != expected[1]
    print({"cases": len(EXAMPLES), "supported": len(differences), "unsupported": unsupported,
           "max_absolute_score_difference": max(differences), "label_disagreements": disagreements})


if __name__ == "__main__":
    main()
