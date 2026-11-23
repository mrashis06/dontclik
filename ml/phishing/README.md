# Phishing URL experiments

This folder contains selected training, analysis, export/parity source, and the existing dataset audit. It intentionally excludes raw CSVs, original pickle/joblib files, and generated run outputs. Python dependencies for training include NumPy, SciPy, scikit-learn, and joblib; install only from a reviewed, pinned environment described by the experiment owner.

The current data has no independently verified benign HTTPS cohort, and prior train/test findings have already been inspected. Do not describe internal test metrics as independent real-world validation. Use explicit `--data-dir` and fresh `--output-root` arguments; inspect each script's `--help` before running.
