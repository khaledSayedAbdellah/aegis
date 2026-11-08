## 0.6.0

* `aegis probe`: verify an app's anti-tampering on an emulator. It installs the app on the `aegis-probe` AVD, checks it stays alive on a clean emulator (the baseline gate), then applies each standard OWASP MASTG resilience condition — root (MASTG-TEST-0048), debugger (0045), Frida instrumentation (0046) and a re-signed build (0047) — and reports whether the app's own protection reacted (blocked), did not (notBlocked) or the check was inconclusive, mapped to MASVS-RESILIENCE. Vendor-agnostic: it sets the standard condition and observes, it does not try to defeat a specific protection. A gap is a finding only under a profile that includes MAS-R. Observations come only from the device (process state, logcat) and only from the app's own process, never assumed; on a crash after re-signing it shows the app's crash line and whether it points to an integrity check or a signature-bound service. Takes an APK or an AAB (converted to a universal APK with bundletool). Reads the profile from the app's own project (`--project`/`--profile` to override), stops frida-server before the baseline and after the Frida check, and ends with a static line saying whether the build is obfuscated.

* `aegis doctor` and `aegis setup`: prepare the toolchain for the resilience probe. `doctor` checks Java, the Android SDK and its command-line/platform/build tools, the emulator and an Android 14 image, the `aegis-probe` AVD, Python, Frida and `frida-server` (and bundletool with `--aab`), reporting each as present, installable or install-it-yourself; it changes nothing. `setup` installs the missing ones and skips the present ones, so a second run does nothing. The Android SDK and JDK are resolved the way Flutter resolves them (`flutter config`, then the usual locations, then `flutter doctor -v`), and are never installed by aegis. What aegis installs lives under `~/.aegis`; the SDK packages are installed with one `sdkmanager` call that asks you to accept the licenses. Downloads (frida-server, bundletool) are pinned and checked against their SHA-256; a mismatch is deleted and the step fails. `aegis setup --remove` deletes what aegis installed under `~/.aegis` and the `aegis-probe` AVD, never your Java or Android SDK. Resolved paths are cached in `~/.aegis/tools.json`. New dependency: `archive` (unpacks `frida-server`'s `.xz`).

## 0.5.0

* `aegis init`: asks what kind of app it is (or takes `--profile`/`--lang`) and writes aegis.yaml.
* `aegis run [--mode all|code|apk|aab]`: friendly defaults for people, not CI. It finds the newest release APK/AAB under `build/app/outputs/` by itself, prints the report, writes `build/aegis-report.html` in the project and opens it in the browser when run in a terminal (`--no-open` to skip), and follows the system language when aegis.yaml has no `lang:`.
* Plain `aegis` with options is unchanged, for scripts and CI.
* AEG-D01: values assigned to names ending in `Hash`, `Digest`, `Sha256`, `Checksum` or `Fingerprint` are hashes, not secrets (storing a password's hash instead of the password is the fix D01 asks for).
* **New score.** The worst open problem picks the band (none 100, low 90–99, medium 70–89, high 40–69, critical 0–39) and the grade (A, A, B/C, D, F); inside the band every failing rule lowers the score (`band start + width × e^(−penalty/20)`, penalty critical 10 / high 6 / medium 3 / low 1, more findings of one rule up to ×2). Apps with the same worst problem but more other problems now score lower, more profile rules show up in the number, and fixing anything never lowers it. Scores are lower than with 0.4 while a high or critical problem is open: check `min_score`.
* Reports say which rules keep the score in its band, the score once they are fixed, and the single fixes worth most points. JSON score: `worstSeverity`, `band`, `blockingRules`, `afterBlockingFixed`, `gains`, `penalty`.
* Categories use the same formula and are coloured by their worst open problem (console, HTML, Markdown 🔴🟠🟡✅), listing their failing rules; JSON categories get `failedRuleIds` and `worstSeverity`.
* MASVS coverage table (Markdown, Azure summary tab): a control is ✅ only when all its rules passed and ❌ when one failed (known findings included), with the failing rules in bold. It used to show ✅ for every control that was merely checked. JSON controls get `failedRules`.

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
