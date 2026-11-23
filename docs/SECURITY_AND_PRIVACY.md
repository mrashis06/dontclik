# Security and privacy

Treat all scanned URL and SMS text as untrusted. The app is designed for offline inference; do not add network transmission, raw-message logging, URL fetching, automatic message blocking/deletion, or user-text prompts to Llama. Model outputs are experimental and not calibrated threat probabilities. A benign-like result is not a guarantee of safety; a spam-like result is not a confirmed scam.

The URL model lacks independent, representative benign HTTPS validation. The SMS model does not support non-ASCII languages and has known false-positive risk. Malware and network monitoring are not implemented.
