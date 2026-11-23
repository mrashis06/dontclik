# Don'tClik publication preparation summary

**Status:** reviewed source files are prepared for a first source commit on the existing `main` history. Nothing has been committed or pushed.

## Android branding changes

- Replaced the previous unverified launcher artwork with the approved Don'tClik branding supplied for this release.
- The Home header uses the approved wordmark crop and the simplified shield/broken-link mark; launcher icons contain the symbol only, without product text.
- Added adaptive launcher icons with a dark background, safe-bounds foreground, and monochrome variant, plus legacy density icons at mdpi, hdpi, xhdpi, xxhdpi, and xxxhdpi.
- Removed unused copies of the former logo and launcher artwork. No Kotlin inference, URL/SMS classification, model weights, package name, namespace, or application ID was changed.

## Verification

- Offline JVM tests: **31 tests, 0 failures, 0 errors, 0 skipped**.
- Android instrumented test sources compiled successfully. UI tests were not run on a device; no phone installation was authorized or attempted.
- Offline debug APK build succeeded with a temporary 1 GB Gradle heap: `android/app/build/outputs/apk/debug/app-debug.apk` (102,509,520 bytes). The APK was verified to contain no optional phishing or SMS classifier model assets.
- The JVM parity tests require local model assets. They were provisioned from the existing local source only for tests, then removed from the release checkout. Without provisioned assets, the app builds, while experimental ML assessments report unavailable. The local-only provisioning instructions remain in `android/README.md`.
- The approved image generator is `android/generate_brand_assets.ps1`; generated icon PNGs and the wordmark crop were visually inspected. No UI/device screenshot test was performed.

## License and attribution

- The remote initial `main` commit, existing README history, and root MIT `LICENSE` are preserved unchanged in the release history. The README and NOTICE clarify that MIT applies to project-owned code and does not relicense third-party components, datasets, model files, or tokenizers.
- ExecuTorch-derived code retains its source copyright headers. The upstream BSD-style notice is preserved at `LICENSES/EXECUTORCH_LICENSE`; the project does not imply Meta endorsement.
- The previous artwork has been removed. The replacement uses the approved Don'tClik brand image supplied for this release.
- No model weights, Llama `.pte`, tokenizer, raw phishing/SMS datasets, or derived experimental classifier assets are included. Their rights remain outside this source commit and must be reviewed before separate redistribution.
- Third-party Android dependencies remain governed by their own terms. This source preparation does not constitute a full license inventory for distributing an APK.

## Excluded from the staged source

`.gitignore` excludes Gradle/build/IDE outputs, `local.properties`, Android APK/AAB outputs, virtual environments/caches, raw data/logs, model-weight and tokenizer formats, signing keys, credentials, and secret configuration. The generated build directory remains local and ignored. The temporary classifier assets are absent from source assets and the APK.

## Remaining release work

- Run Compose/UI tests and visual device inspection before any device release; the instrumented tests were only compiled here.
- Complete a third-party dependency license inventory before distributing a built APK.
- Independently verify model/dataset rights before adding any excluded model or training data. The experimental detectors remain subject to the accuracy/coverage caveats in their model cards.

The checkout is staged only. Review `git status` and the staged file list before the first commit; no commit, push, or force operation was performed.
