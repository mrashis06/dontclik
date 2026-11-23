# Phishing URL dataset audit — 2026-11-22

Read-only local inspection; no URL was visited, no network request or retraining occurred, and no CSV or pickle was changed. Statistics use a local CSV parser and WHATWG URL parser. Raw URLs and query strings are omitted.

## Files and environment

| File | Bytes | Data rows | Columns | Missing fields / malformed CSV rows |
| --- | ---: | ---: | --- | ---: |
| mixed_phishing_urls.csv | 31,567,326 | 549,346 | URL, Label | 0 / 0 |
| phishtank_phishing_urls.csv | 14,649,659 | 76,660 | phish_id, url, phish_detail_url, submission_time, verified, verification_time, online, target | 0 / 0 |
| openphish_phishing_urls.csv | 20,199 | 300 | URL, Label | 0 / 0 |
| tranco_phishing_urls.csv | 22,606,046 | 1,000,000 including first line | rank, domain; no header | 0 / 0 |

CSV fields were parsed as strings; the PhishTank ID/rank and timestamps still need typed validation. The Tranco first line is rank 1 plus a domain; default header inference incorrectly makes it column names, leaving 999,999 rows. Subsequent ranks 2–1,000,000 are consecutive. PhishTank has 76,660 `verified=yes` and `online=yes` entries; submission dates span 2011-02-18 to 2026-10-01. These flags were not independently verified.

The supplied `.venv311\Scripts\python.exe` does not start: `No Python at '"C:\Users\Mr Ashis\AppData\Local\Programs\Python\Python311\python.exe'`. The system `py -3.13` launcher returned `Access is denied`. No inference about installed packages is possible.

## Labels and scheme prevalence

| Source | Benign | Phishing | HTTP | HTTPS | Scheme-less |
| --- | ---: | ---: | ---: | ---: | ---: |
| Mixed | 392,924 good | 156,422 bad | 100 bad | 7 bad | 392,924 good; 156,293 bad |
| PhishTank | 0 | 76,660 (notebook-assigned bad) | 6,851 | 69,809 | 0 |
| OpenPhish | 0 | 300 phishing | 117 | 183 | 0 |
| Tranco | unlabeled domains | unlabeled domains | n/a | n/a | n/a |

The mixed file has another 22 bad rows with other or malformed scheme prefixes. Overall, explicit HTTPS occurs in **0/392,924 benign** rows and **69,999/233,382 phishing** rows. Thus `https` largely identifies the positive-only feed format. This strongly explains the earlier reported negative LR coefficient for the good class; the coefficient was not remeasured because Python cannot start. The training set has no benign HTTPS examples to establish behavior on ordinary secure sites.

## Quality and leakage signals

| Source | Repeated exact URL rows | Conflicting exact labels | URL-shape failures | Distinct valid hosts | Approx. distinct registrable domains |
| --- | ---: | ---: | ---: | ---: | ---: |
| Mixed | 42,151 | 2 | 5,179 (4,702 bad; 477 good) | 188,069 | 145,952 |
| PhishTank | 3 | 0 | 35 | 41,549 | 15,039 |
| OpenPhish | 0 | 0 | 0 | 268 | 120 |

Two exact URLs recur across OpenPhish and another source, without cross-source label conflicts. The two mixed-file conflicts need provenance review, not first-row-wins deduplication. The validity screen required a parseable dotted ASCII hostname, and rejected whitespace and control characters. It is a screening rule, not an exhaustive URL standard; review unusual schemes, IP literals, IDNs, and encoded forms separately. Mixed rows include 91 with controls and 1,174 with whitespace; PhishTank has 1 and 8 respectively. Reasons overlap.

Across labeled sources, 621,092 rows pass the URL screen, with 229,822 hosts and about 160,825 registrable domains. **518,114 valid rows (83.42%)** share an approximate domain with another row; 358,950 lie on domains occurring at least ten times. There are 465 approximate domains with both labels (69,201 rows) and 81 exact hosts with both labels. Different paths on one host can legitimately differ, so these are review targets. The largest domain group has 13,416 rows.

A near-duplicate screening key of lowercased host plus path, ignoring scheme and query, finds 45,713 multirow groups (142,467 rows), including 2 mixed-label groups (7 rows), 17 cross-source groups (186 rows), and 2,129 cross-scheme groups (4,594 rows). This key is only for leakage analysis because scheme/query can change security meaning. Approximate domain overlaps: mixed–PhishTank 243, mixed–OpenPhish 11, PhishTank–OpenPhish 43. These findings make a random row split unsafe.

Registrable-domain counts used a limited suffix heuristic. Recompute with a vetted Public Suffix List parser before any grouped split; do not use these approximate groups as final split assignments.

## Tranco

Tranco provides ranked **domains**, not verified benign URLs. Among the 999,999 lines after the first, seven fail the audit's domain-shape screen and none duplicate another domain string. Exact host overlap with labeled URL data is 15,934 benign, 509 phishing, and 22 seen with both labels. Popular or compromised domains and hosting platforms can contain malicious paths. Keep Tranco unlabeled until a specific benign host/URL claim is independently reviewed; it cannot supply a blanket benign label or benign URL-path coverage.

## Corrected evaluation design and Android candidates

1. Preserve raw files and record hashes, acquisition dates, licenses, and source versions. Repair the interpreter; validate label provenance and PhishTank fields. Quarantine malformed rows and the two exact-label conflicts. Obtain verified benign HTTPS URLs with representative paths and capture dates.
2. Use a Public Suffix List parser to group by registrable domain and related campaign variants. Freeze train/validation/test groups before fitting any vectorizer. Use group-aware stratification where feasible and disclose class/source counts. Add a later-time phishing holdout and separate PhishTank/OpenPhish tests. A phishing-only slice cannot measure benign false positive rate.
3. Fit vocabulary on train only; tune models and thresholds on validation only. Report confusion matrices, phishing recall, benign false-positive rate, precision, uncertainty, and source/protocol/domain slices on untouched tests. Include reviewed benign bare domains and HTTPS paths; compare against the Android heuristic scanner.
4. Candidate lightweight models: regularized LR or MNB with bounded character/word n-grams plus explicit URL-structure features, and a small constrained tree on numeric features. Character features retain digit and obfuscation cues discarded by the original alphabetic tokenizer. Measure size, latency, calibration, and parity in a Java/native Android ARM implementation before deployment. No Python runtime or unverified pickle should ship.

**Decision:** The source/protocol bias and leakage risks prevent any claim of improvement or Android model integration now.
