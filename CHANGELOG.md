## 0.11.0

* `aegis run` also saves a short PDF report named `<mode>-<profile>-<date>.pdf` (for example `apk-L2+R-2026-11-12.pdf`) next to the other reports. It contains the score, the category scores and the open findings only, new and previously known, each with its details. The new `pdf` format is on by default for `run` and available with `-f pdf` everywhere. It is printed in the report language with a headless Chrome, Edge, Chromium or Brave, or the browser in `AEGIS_BROWSER` / `CHROME_PATH`. Without a browser the PDF is skipped with a message and the run continues.
* The HTML report has print styles: light colors, A4 pages and no cards split across pages.

## 0.10.2

* The README starts with a table of contents linking every section. The translation catalog and extended MASVS analysis sections now come before License.

## 0.10.1

* The README installs aegis from pub.dev (`dart pub global activate aegis`), shows the pub.dev version, pub points and CI badges, and documents the release steps. Installing from GitHub or a local clone remains available.
* Releases are published from version tags through pub.dev's GitHub Actions publishing.

## 0.10.0

### Breaking changes

* Remove `run --mode all` and automatic artifact selection. `run` now asks for `code`, `apk`, `aab` or `ipa` when no mode is supplied; non-interactive runs must pass `--mode`. Explicit artifact overrides must match the chosen mode.
* Ask IPA runtime audits to choose iOS Simulator or a physical iPhone/iPad. Add `--ios-target simulator|device` for explicit/CI selection, isolate the chosen environment from the other YAML settings, reject conflicting CLI options and never fall back to another target. Static-only `--no-probe` runs need no target.
* Keep terminal messages, menus and console summaries in English regardless of `--lang`, YAML or system locale. HTML and Markdown report files retain the selected language.

### Added and changed

* Discover React Native/Expo and other JavaScript/TypeScript source trees plus KMP shared/target sources. Add lexical secret/logging, TLS, WebView, crypto and direct sensitive-storage checks, preserve native bridge/configuration inspection, and report source inventory and unsupported inputs without awarding score for discovery.
* Build native Xcode Simulator apps automatically, matching IPA identity and version with explicit ambiguity handling, verified output receipts and optional project/scheme/configuration settings.
* Discover standalone Kotlin/Java/Swift/Objective-C projects, inspect native modules and platform configuration, reuse native security checks and add redacted source-secret/sensitive-logging rules. Keep Flutter-only rules out of native audits and preserve incomplete coverage for unreadable inputs.
* Label scores from incomplete audits as provisional beside the score in HTML, Markdown and terminal output, with matching JSON/SARIF flags; preserve scoring and verified failures.
* Group supporting security evidence into one expandable HTML card or Markdown heading per rule, preserving each observation and source without changing findings or JSON data.
* Show verified Simulator jailbreak/signing failure verdicts before coverage limitations in report summaries and probe evidence, consistently in Arabic and English.
* Prevent reuse of incomplete Simulator app bundles after failed or interrupted automatic builds, including disk-full failures during Flutter's final copy.
* Observe both UIApplication and UIScene background transitions with bounded polling on iOS Simulator.
* Add six generic platform protection check families (`AEG-P11`, `AEG-N05`–`AEG-N07`, `AEG-I12`, `AEG-A14`) for screen exposure, backup policy, key access, iOS Universal Links, WebViews and Android obscured-touch filtering. Collect bounded launch-time facts without app-specific inputs and leave host security unchanged. Without a requested runtime observation their output is evidence only: outside the score, never a pass, and not an incomplete audit, so static audits still complete under `--strict` and `--update-baseline`. A concrete finding fails the rule and stays in the score even with partial coverage; a requested observation that returned nothing or stopped at a collector bound stays incomplete. The probe records which automatic observers it started (`platformObserverAttempts` in JSON), so an observer that failed is distinguished from one that never ran: the optional Android instrumented observer is requested only once it started, which happens only when the app kept running under the Frida check.
* Add the `evidenceOnly` rule status for rules that finish with review evidence and no verdict (the platform protection rules, `AEG-T01`, compiled-reference-only native checks, a finished `AEG-R09` scenario without interception). It is outside the score and MASVS coverage, is never a pass, and does not make the audit incomplete. JSON reports it as `"status": "evidenceOnly"` with a `summary.evidenceOnly` count; the console lists these rules under their own heading.
* Extend offline IPA analysis with built-in Objective-C relationships, Swift context/type-reference metadata, conservative nominal-name demangling and expanded protection references. Reports retain provenance and localized extraction limits; no external backend or runtime verdict changes.
* Show explicit Simulator jailbreak/signing verdicts and scoped failure findings when execution continues; preserve full-iOS coverage limitations and strict incompleteness.
* Add AEG-A11–A13, N01–N04, I10–I11, B12 and T01: final-manifest link/permission checks, bounded domain association verification, native API/configuration analysis, entitlement/ATS review, ELF hardening and tracker inventory.
* Add bilingual evidence outside scoring/coverage, and bounded ZIP decompression for binary inspection.
* Add opt-in R09/R10 runtime scenario orchestration, certificate-substitution capture and redacted synthetic-marker collection; absent evidence and unsupported channels remain incomplete. The scenario runs a command and tool paths taken from the project's `aegis.yaml`, so it executes only when `aegis run --runtime-scenario` is passed; `enabled: true` in the file alone never runs it. A finished scenario ends R09 as failed (interception accepted) or evidence only (silence is never a pinning pass); it stays incomplete only when a requested phase, the baseline or cleanup did not finish. A scenario part with nothing configured (`hosts` for R09, `marker_env` for R10) is not applicable rather than incomplete.
* Include all new configuration in `init`; keep terminal output English and report translations in ARB.
* Add device-independent IPA Mach-O checks for PIE, executable-memory requests and source debug entries, plus a separate static resilience-reference inventory. Inspect bundled frameworks and extensions; keep runtime verdicts distinct and report encrypted, missing or unreadable evidence.

## 0.9.0

* Make `setup` ask for Android, iOS or Both. `--android` prepares both Android AVDs and bundletool; `--ios` stays iOS-only; `--both` runs independent stages in Android-first order and reports unsupported iOS on non-Mac hosts without undoing Android setup. Keep `--aab` as an Android alias; CI must select a platform explicitly.
* Honor explicit Simulator flavor/target changes for automatically discovered products, and retain verified build inputs for reuse. Correct release installation references and declare synthetic credential fixtures for Pub validation.
* Move report, rule and setup/doctor translations to validated ARB catalogs with generated Dart accessors. Translate iOS probe evidence, limitations, finding excerpts and incomplete/skip reasons in Arabic reports while preserving English JSON evidence and original code/tool output.
* Add partial Xcode Simulator jailbreak-file-indicator and ad-hoc signing-metadata experiments, with verified controls, separate observations and explicit Arabic/English limitations. Full jailbreak/signing checks remain incomplete in strict mode; no macOS security settings are changed.
* `aegis init` now writes every supported YAML setting, with defaults and editable placeholders for unknown paths, device IDs, flavors, and fingerprints. Unfilled placeholders are treated as unset.
* Automatically build missing or mismatched Flutter iOS Simulator apps during `run`/`probe`, using the IPA version/build, verifying the generated platform and identity, and retaining build logs. Add optional `ios_simulator_flavor` and `ios_simulator_target` settings to `init`.
* Audit iOS IPAs with `--ipa` or `aegis run --mode ipa`. The iOS runtime probe uses Xcode on dedicated devices for jailbreak, Frida, LLDB, and signing identity changes. Configure `ios_simulator` and `ios_simulator_app` in `aegis.yaml` to run LLDB and Frida automatically on a matching Simulator build.
* `aegis setup --ios` installs Frida and the pinned iOS Gadget. A provisioned Development IPA can be probed for Frida on a stock USB-connected device configured as `ios_control_device`.
* `aegis setup` prepares separate rooted and unrooted Android 14 emulators. APK and AAB audits use both by default. The runtime probe verifies each test condition and reports continued execution under verified conditions as a process-level finding under MAS-R. Android self-exit records provide process-level blocking evidence. Optional app events provide a verdict on a specific operation.
* AAB probes accept a signed companion APK, a bundletool `.apks` archive or a folder with one device-specific set of signed APKs. Aegis verifies the first-install APKs for each emulator and can require an expected app-signing certificate fingerprint. Set `probe_apk` and `probe_cert_sha256` in `aegis.yaml` or override them on the command line. `aegis init` includes both settings as active keys with editable placeholders.
* `--strict` rejects an incomplete requested probe under any MAS profile. Reports distinguish incomplete checks from checks outside the profile or checks that do not apply.
* The binary audit rejects unreadable Android manifests and resolves the network security configuration referenced by the manifest, including resource aliases and configuration variants.

## 0.7.0

* **The resilience probe is part of `aegis run`.** `aegis run --mode apk|aab|all` runs the probe on the emulator first, then the static audit, and writes one report with both. Its results are new rules **AEG-R01** (root, RESILIENCE-1), **AEG-R02** (Frida, RESILIENCE-4), **AEG-R03** (debugger, RESILIENCE-4) and **AEG-R04** (re-signed copy, RESILIENCE-2), profile MAS-R: a gap is an ordinary finding that lowers the score, enters the baseline and triggers `fail_on`; an inconclusive check, a skipped probe or an app that does not stay alive on a clean emulator is not applicable, with the reason. Findings point to `<app>!/runtime`, so the baseline matches across builds.
* Every report format has a probe section: the baseline, each check's result, what was observed, its MASVS/MASTG controls and rule, or why the probe was skipped. JSON has a `probe` object.
* **The APK/AAB comes from aegis.yaml.** New keys `apk:` and `aab:` (relative to the project, or absolute). `--mode apk`/`aab` require them and stop with the line to add, or the build command when the file is missing; `--mode all` uses `apk:`, else `aab:`, else audits the code only. `aegis run` no longer picks the newest file in `build/` by itself (build names change with flavors and versions). `aegis init` writes both keys as commented examples.
* Missing probe tools, an unreadable package name or an AAB that won't convert: the probe is skipped with the reason and the static audit continues. `--no-probe` skips it on purpose. Plain `aegis` (CI) never runs the probe, even with `--apk`.
* `aegis probe` stays as a probe-only shortcut. Without a path it uses `apk:`/`aab:` from the project's aegis.yaml instead of searching `build/`.

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
