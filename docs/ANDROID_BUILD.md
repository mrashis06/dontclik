# Android build and tests

Open `android/` in Android Studio or use its checked-in Gradle wrapper. The wrapper JAR and properties, launch scripts, root Gradle settings/build files, version catalog, and `app/` module must remain together. Supply a local SDK path; `local.properties` is excluded.

On Unix-like systems, ensure the tracked wrapper has its executable bit set (`chmod +x android/gradlew`) when preparing the first Git commit; Windows CMD uses `gradlew.bat`.

Windows offline commands (after required dependencies are cached):

```cmd
gradlew.bat --offline --no-daemon -Dorg.gradle.jvmargs=-Xmx1024m :app:testDebugUnitTest
gradlew.bat --offline --no-daemon -Dorg.gradle.jvmargs=-Xmx1024m :app:assembleDebug
```

Model-dependent JVM tests require the ignored local ML assets provisioned by `android/provision_ml_assets.ps1`. Instrumented tests require a configured emulator/device and may have external fixture requirements; do not run tasks that download models unless explicitly intended.
