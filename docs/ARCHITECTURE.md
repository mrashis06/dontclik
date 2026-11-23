# Architecture overview

`android/app` contains the Compose application, deterministic URL scanner, experimental local URL/SMS classifiers, and optional ExecuTorch Llama flow. The URL heuristic remains distinct from the experimental phishing assessment. Pasted SMS stays on-device and is not sent to the Llama prompt. ML training and export code lives under `ml/`; datasets and model run artifacts are external local inputs.

The `malware/`, SMS inbox monitoring, and network-monitoring features are not implemented. Do not present them as active protection.
