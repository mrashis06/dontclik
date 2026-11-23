# Android app

Open this directory (`android/`) in Android Studio. It contains the Gradle root project, wrapper, version catalog, and `:app` module. The wrapper is Gradle 8.11.1; plugin/library versions remain in `gradle/libs.versions.toml`. Configure the local Android SDK through an untracked `local.properties` file or Android Studio.

From this directory, run `gradlew.bat --offline :app:testDebugUnitTest :app:assembleDebug` on Windows after dependencies are available in the local Gradle cache. No application ID, namespace, package names, or device model paths were changed by staging.

## Optional experimental classifier assets

The small phishing and SMS model files are deliberately excluded from version control until their data provenance and redistribution rights are reviewed. Without them the app's ML engines report model unavailable; the deterministic URL scanner and other app code remain buildable. For local testing only, run:

```powershell
.\provision_ml_assets.ps1 -AssetDirectory 'C:\path\to\reviewed-assets'
```

The input directory must contain `phishing_lr_v1.model` and `sms_spam_v1.model`. The script refuses to overwrite existing destination assets. These destination files are ignored by Git. Do not obtain these files from an untrusted source or commit them without documented approval. Remove local copies manually after testing if they are no longer needed.

The approved Don'tClik wordmark and launcher density assets can be regenerated on Windows with `.\generate_brand_assets.ps1 -SourcePng <approved-png-path>`. The adaptive foreground/background and monochrome vector resources are maintained as Android XML under `app/src/main/res/`.
