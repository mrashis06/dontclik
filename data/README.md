# Local datasets

No raw datasets are included. Keep local files under ignored `data/raw/` or `data/private/` paths and never add personal SMS messages, raw URLs containing query parameters, or private logs to version control.

Expected local inputs:

- Phishing: `mixed_phishing_urls.csv`, `phishtank_phishing_urls.csv`, `openphish_phishing_urls.csv`, `tranco_phishing_urls.csv` under `data/raw/phishing/`.
- SMS: `spam_ham_india.csv` and `spam_utf8.csv` under `data/raw/sms/`.

Before using or redistributing any dataset, record exact source, capture date, license/terms, hash, labeling limits, and whether personal data may be present. Tranco domains are not verified benign URLs, and spam/ham labels do not establish scam truth.
