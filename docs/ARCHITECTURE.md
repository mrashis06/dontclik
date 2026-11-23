# Architecture overview

`android/app` contains the Compose application, deterministic URL scanner, experimental local URL/SMS classifiers, and optional ExecuTorch Llama flow. The URL heuristic remains distinct from the experimental phishing assessment. Pasted SMS stays on-device and is not sent to the Llama prompt. ML training and export code lives under `ml/`; datasets and model run artifacts are external local inputs.

`android/app` includes a user-selected offline APK static inspector that reads bounded ZIP metadata only; it is not a malware detector. SMS inbox monitoring and network monitoring are not implemented. Do not present these features as active protection.
