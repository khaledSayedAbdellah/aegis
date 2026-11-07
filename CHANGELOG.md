## 0.5.0

* `aegis init`: asks what kind of app it is (or takes `--profile`/`--lang`) and writes aegis.yaml.
* `aegis run [--mode all|code|apk|aab]`: friendly defaults for people, not CI. It finds the newest release APK/AAB under `build/app/outputs/` by itself, prints the report, writes `build/aegis-report.html` in the project (`--open` opens it), and follows the system language when aegis.yaml has no `lang:`.
* Plain `aegis` with options is unchanged, for scripts and CI.

## 0.4.0

* Android App Bundles: `--apk` also takes an `.aab`. aegis decodes the protobuf manifest and res/xml files (aapt2 format) in pure Dart, scans the base and feature modules' code, resource table and assets, and skips `BUNDLE-METADATA/`. All APK rules apply.
* AEG-B10 knows that Google Play re-signs bundles: it fails when freeRASP's `signingCertHashes` only has the upload key, and is not applicable when the upload key is not listed.
* Reports label the binary as "App bundle (AAB)" and mark its certificate as the upload key; JSON `binary.kind` is `APK` or `AAB`.
* Binary rule titles, descriptions and findings say "AAB" instead of "APK" when a bundle is audited.
* Baselines: `x.aab!/...` and `x.apk!/...` findings match each other.

## 0.3.0

* Baselines: `--update-baseline` records today's findings in `aegis-baseline.json`; later runs report **new**, **known** and **fixed** findings separately and `--fail-on` only reacts to new ones. Matching ignores line numbers and the APK file name. Known findings still count in the score.
* `--baseline <file>`, `--ignore-baseline` and `baseline:` in `aegis.yaml`.
* JSON findings carry a stable `fingerprint`; SARIF results carry `partialFingerprints` and `baselineState`.
* Azure Pipelines: `ci/azure-pipelines/aegis-steps.yml` steps template (install from pub.dev/git/path, build annotations, summary tab, report artifact, optional Scans tab and Advanced Security) and a full example pipeline.
* `-f azure` prints Azure Pipelines annotations for new findings and marks the step "succeeded with issues" when they are below `--fail-on`.
* A run without `--apk` no longer lists the baseline's APK findings as fixed.

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
