## 0.2.0

* `--apk`: audit the release APK, alone or together with the source. aegis reads the zip, binary XML manifests and v1/v2/v3 signing certificates itself, with no external tools.
* 11 APK rules (AEG-B01..B11): debug builds, merged manifest, library-added components and permissions, build-time secrets in libapp.so / dex / resources / assets, real obfuscation, debug certificate, freeRASP hash mismatch, SDK levels.
* Source and APK findings are de-duplicated.
* Reports show the APK signing certificate SHA-256 in Base64 (the value freeRASP expects).
* Git and path dependencies (your own packages) are scanned with the app (`scan_packages`, on by default); reports list them.
* Debug-only guards such as `if (config.enableLogging)` are recognized, not just `kDebugMode`.
* AEG-P08 is "not applicable" instead of passing when no `authenticate()` call is visible.
* Passed rules show a "healthy" title (e.g. "App Transport Security is enabled").

## 0.1.0

* First release.
* 36 rules across protection correctness (freeRASP wiring/config/reactions, App Check, pinning, local_auth, screen protection, obfuscation), Android, iOS, Dart code and dependencies.
* OWASP MAS profiles (L1, L2, R) with presets, severity caps and MASVS coverage.
* Console, JSON, Markdown, HTML and SARIF reports in English and Arabic.
* `aegis.yaml` configuration and inline `aegis:ignore` suppression.
