# Don'tClik

Don'tClik is an offline-first Android security assistant. The current app provides deterministic URL indicators, experimental URL and pasted-SMS classification, and optional local ExecuTorch Llama advice. Classifier labels are heuristic/model assessments, not verified threat determinations. SMS labels represent spam/ham training labels, not confirmed scams. No SMS inbox permission or automatic blocking is used. The Malware scan lets a user select one APK and inspects bounded ZIP metadata locally; it does not extract, install, launch, or determine whether an app is malicious.

## Repository areas

- [`android/`](android/README.md) — Android Studio project, build/test instructions, and local ML asset setup.
- [`ml/phishing/`](ml/phishing/README.md) — phishing URL training, analysis, export, and dataset audit.
- [`ml/sms/`](ml/sms/README.md) — offline SMS spam experiments and Kotlin parity prototype.
- [`ml/malware/`](ml/malware/README.md) — offline APK static archive inspection; it is not verified malware detection.
- [`docs/`](docs/ARCHITECTURE.md) — architecture, data provenance, privacy, and model limitations.

Raw datasets, exported model weights, signing keys, local SDK settings, and Llama files are intentionally excluded. See the ML README files for local data setup. The Android app may still build without ML assets, but those model assessments will return unavailable until reviewed local assets are provisioned.

## Licensing and release scope

The repository's existing MIT `LICENSE` applies to project-owned code. ExecuTorch-derived source retains its upstream notices under [`LICENSES/`](LICENSES/); Android libraries, model weights, datasets, and tokenizer files retain their own terms and are not relicensed by that MIT notice. No Llama weights, tokenizer, raw datasets, or experimental classifier assets are included. See [`NOTICE.md`](NOTICE.md) before redistribution.

The approved Don'tClik branding is used for the Home wordmark and launcher mark. The launcher symbol is a simplified text-free derivative of the supplied shield/broken-link mark.
