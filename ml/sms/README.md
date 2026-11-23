# SMS spam-pattern experiments

The selected classifier is an experimental spam/ham model, not a verified scam detector. It does not support non-ASCII inference and a synthetic banking diagnostic previously exposed false positives. The Android integration is designed to abstain conservatively for banking/OTP-related content.

Place the two reviewed CSVs in `data/raw/sms/` or provide `--data-dir PATH` to `train.py`, `banking_coverage.py`, `banking_diagnostics.py`, or `export_lr_comparator.py`. Expected files and schemas are `spam_ham_india.csv` (`Msg`, `Label`) and `spam_utf8.csv` (`v2`, `v1`). Do not commit the CSVs. Use a new `--output` path for every experiment; scripts refuse to overwrite existing outputs. Kotlin parity can be run with an explicit model artifact and Kotlin prototype JAR as positional arguments to `parity.py`.

Historical scores in `REPORT.md` refer to the original local experiment. Their run artifacts and data are not included here, so those results are not independently reproducible from this staging copy until reviewed CSVs and a compatible runtime are supplied.
