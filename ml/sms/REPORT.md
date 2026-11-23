# Experimental offline SMS spam classifier

Run: `run-20261123-final`. The earlier `run-20261123` was a preliminary run, superseded after inspection found 50 ambiguous CSV rows with populated extra columns. No Android or phishing files were changed. No network or package installation was used.

## Data and split

| Source | Schema used | Rows | Ham | Spam | Data issues |
|---|---|---:|---:|---:|---|
| `spam_ham_india.csv` | `Msg`, `Label` | 2,267 | 1,522 | 745 | 46 messages excluded for empty/no ASCII tokens |
| `spam_utf8.csv` | `v2`, `v1` | 5,572 | 4,825 | 747 | 50 rows excluded because `Unnamed: 2`–`4` held content; 2 more had no usable ASCII tokens |

Both CSVs loaded as UTF-8 with no missing text or label fields. Labels were exactly `ham` and `spam`; `spam` is **not** a verified scam subtype. The sources have different spam prevalence (32.9% versus 13.4%), so source/style bias remains possible. No language labels exist. Among rows past the malformed-extra-column check, 178 India rows and 477 UTF8 rows contained non-ASCII characters. This is a script-coverage proxy, not a language classification. The inference prototype explicitly returns unavailable for non-ASCII messages, including Hindi. The dataset cannot validate multilingual performance.

After exclusions, 7,741 usable rows entered duplicate handling. There were 577 repeated exact-text rows removed, zero exact-text label conflicts, and zero case/punctuation-normalized label conflicts. The retained 7,164 unique texts comprised 5,779 ham and 1,385 spam. Digit-masked templates and candidate near duplicates were grouped before splitting: 6,711 groups, 268 with more than one distinct text. The fixed-seed split was train 5,014 (4,045 ham/969 spam), validation 1,075 (867/208), test 1,075 (867/208). Canonical-text and digit-masked-template overlap across all split pairs measured zero. The near-duplicate search uses shared three-token shingles and a 0.80 Jaccard or 0.90 sequence-similarity threshold; paraphrases outside those candidates may still leak.

The final test was read once after validation selection within the final run. An earlier preliminary run evaluated largely overlapping source data before the malformed-row correction. Accordingly, these numbers are **internal held-out estimates, not an independent final validation**.

## Training and measured comparison

ASCII word unigrams and adjacent bigrams were lowercased; each digit run became `0`. The 8,000-term vocabulary was fit on train only (minimum document frequency 2). MNB used term counts; LR used binary term presence with L2 regularization. Candidate settings and thresholds were chosen on validation only, with a 2% ham false-positive-rate cap and spam F1 as the selection objective within that cap. Scores are uncalibrated.

| Frozen candidate | Threshold | Test spam precision | Test spam recall | Test spam F1 | Test ham FPR | Test matrix `[[TN,FP],[FN,TP]]` | Export size |
|---|---:|---:|---:|---:|---:|---|---:|
| MNB, alpha 1.0 **selected** | 0.95 | 97.95% | 91.83% | 94.79% | 0.46% | `[[863,4],[17,191]]` | 49,650 B |
| LR, L2 penalty 0.001 | 0.45 | 98.45% | 91.35% | 94.76% | 0.35% | `[[864,3],[18,190]]` | 99,313 B |

The selected MNB had validation F1 96.31%, spam recall 94.23%, and ham FPR 0.35%. It was chosen before the final test because it had the highest validation spam F1 under the FPR cap, with one extra validation ham false positive versus LR but six additional caught spam messages. Full six-candidate validation and test metrics, including confusion matrices and false-negative rates, are in `run-20261123-final/metrics.json`.

Synthetic sanity cases were **not** used to tune or estimate accuracy. The MNB marked the OTP example ham (score 0.413), fake KYC spam (0.995), prize scam spam (>0.999), a normal banking alert **spam** (0.999), and a personal meeting message ham (<0.001). The banking false positive is a substantive blocker for security-facing use. These scores are model outputs, not calibrated probabilities or verified scam likelihood.

## Export and parity

Selected Android-compatible artifact: `run-20261123-final/sms_spam_v1.bin.gz`. Comparator: `run-20261123-final/sms_spam_lr_comparator_v1.bin.gz`. The binary is gzip-compressed, big-endian: ASCII magic `SMS1`, 1-byte version, 1-byte model kind (1 LR, 2 MNB), 4-byte vocabulary count, 8-byte bias, 8-byte threshold, then per term a 2-byte ASCII byte length, term bytes and 8-byte weight. It needs no Python, pickle, joblib, cloud service or network at runtime.

`SmsSpamPrototype.kt` loaded the selected artifact and matched Python on 20 bounded synthetic/edge cases: 15 supported, 5 explicitly unavailable, maximum absolute score difference `2.78e-17`, zero label disagreements. Unsupported inputs include blank, control-character, over-4,096-character and non-ASCII messages. The parity test does not validate spam accuracy. The compiled parity jar is 4,826,676 bytes; it is test tooling, not a proposed APK dependency. Vocabulary terms in the artifact can still reveal recurring words from training messages; review licensing and data privacy before redistribution.

## Reproduction

Use the working local Python 3.13 standard library and installed Android Studio Kotlin compiler. The old `phishing-detector/.venv311` cannot launch because its original Python 3.11 base interpreter is missing. No pandas or scikit-learn was required.

```cmd
py -3.13 ml\sms\train.py --data-dir data\raw\sms --output ml\sms\runs\run-NEW
"<KOTLINC_PATH>\kotlinc.bat" ml\sms\SmsSpamPrototype.kt -include-runtime -d ml\sms\runs\run-NEW\sms-prototype.jar
py -3.13 ml\sms\parity.py ml\sms\runs\run-NEW\sms_spam_v1.bin.gz ml\sms\runs\run-NEW\sms-prototype.jar
```

Dataset SHA-256: India `E6A28126D1C4EC9D805A10CD89F2DE2BB63650532102E9F35AB05C909C3A79F3`; UTF8 `3240C31697C991F396E1C2C40029F3648787FEC891E8A88E5B549C101E0176C8`.

**Recommended next action:** obtain a consented, independently labeled and representative benign banking/OTP SMS set, including Indian languages, and evaluate it before any Sentra integration. This classifier is experimental and is not a verified financial-scam detector.
