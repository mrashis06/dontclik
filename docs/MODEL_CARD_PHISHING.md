# Phishing URL model card (experimental)

The app contains a lightweight URL classifier alongside a separate deterministic URL heuristic. The available labeled corpus is source/protocol biased and has no independently verified benign HTTPS cohort. Previously inspected test examples are no longer independent final evidence. Do not use this model as an authoritative verdict or claim production readiness.

Keep metrics tied to the exact run, split, threshold, and artifact hashes. Any future evaluation should use domain-grouped splits and a separately collected, reviewed benign HTTPS cohort, including realistic URL paths and compromised-host cases.
