## Unreleased

* Windows: finding paths and `exclude:` patterns use `/` for native files too, so excludes work and baselines match across systems; a Firebase rules file named in `firebase.json` is no longer counted twice; `--changed-since` reads git's output as UTF-8. CI now tests on Windows.
* `AEG-N08` also reads `AndroidManifest.xml`, `Info.plist` and `res/values*/*.xml` for known key formats, so a Google Maps key in a manifest `<meta-data>` is reported like the same key in Swift code. Firebase's `google-services.json` and `GoogleService-Info.plist` stay out (public by design), as do debug and test source sets. `AEG-B06` reports a Google API key in the APK's manifest `<meta-data>` too.
* `AEG-P03` and `AEG-B08` read `signingCertHashes` given as `const [...]`, `<String>[...]` or a variable declared in any file, not only as a `[...]` literal.
* `AEG-D11` knows more numbers: class fields and top-level values that are `const`, `final` with a literal, or declared `int`/`double`/`bool`, and Kotlin, Java and Swift values declared with number types (`id: Int`, `long id`, `id: Int32`) or counts (`.size`, `.length`).
* `AEG-D12` accepts a value encoded into a variable first (`final json = jsonEncode(data); runJavaScript('set($json)')`).
* `AEG-D07` no longer takes Flutter widget keys (`super.key`, `ValueKey`) or map keys for crypto keys near `Random()`.
* Value flow: `uri.toString().isEmpty` is a presence test, not a check of the value; a helper that checks a link before returning it no longer passes link data on.
* Docs: every rule has a row in the README rule tables (a test keeps it so), `aegis init` writes a commented `custom_rules` example, the native and cross-platform guides list the Dart rules that now read native code, and the Azure Pipelines template has a `changedOnly` option for pull requests.
* Fewer false positives, found by auditing well-kept public apps (Now in Android, LocalSend, Ice Cubes, Bluesky): `AEG-I14` no longer reports a model property named `creationDate`, the macOS target, or an Expo app that declares its manifest in `app.config.js`; `AEG-A02` no longer reports a library module that leaves backup unset; `AEG-N09` no longer reports a yes/no flag named like a secret (`pin`).

## 0.17.2

* Fixed: the HTML, Markdown and console reports crashed when evidence came from a rule without extra metadata (`AEG-B17` library loaders, `AEG-C04` update tools, `AEG-C05` local unarchiving), since 0.16.0. The benchmark now renders every report format for every app.
* `AEG-D19` no longer treats building query parameters as link data (`replace(queryParameters: ...)`, a variable named `queryParameters`); only `uri.queryParameters` read from a Uri counts.
* Value flow takes a called function from the calling file first, keeps `_private` functions to their own file, and leaves a name declared in several files unknown. Before, a same-named function elsewhere could hide an injection.
* `AEG-D08` follows a logged variable only when its text was built from a secret (`'password=$password'`, `+`, or a project function that returns it pasted in), not when a secret was only an argument (`signIn(email, password)`) or became a number or a yes/no.
* Manual check `AEG-M08` is replaced by `AEG-D19` only when the Dart code reads links through a link API (`uni_links`, `app_links`, go_router, `onGenerateRoute`), and the report says so in `AEG-D19`'s evidence.
* `--changed-since` reads file names outside ASCII correctly (git's quoted paths), and refuses a ref that starts with `-`.
* Native `AEG-D19`: handing data to one of the app's own screens (`Intent(this, X::class.java)`) is not reported; Java's `getIntent().getData()`, `getDataString()` and `getExtras()` are sources.
* Custom `pattern` rules no longer match `aegis.yaml`, the baseline or aegis's reports.
* Releases wait until pub.dev really serves the new version before the GitHub Action is updated, and the action retries the install for about five minutes.

## 0.17.1

* New `AEG-C05` (high): unsafe deserialization in Kotlin, Java, Swift, Objective-C and JavaScript. Data from another app (Intents, links), the network or shared storage that reaches `ObjectInputStream`, `XMLDecoder`, XStream's `fromXML` or `NSKeyedUnarchiver.unarchiveObject` is reported, and so are untyped `getSerializableExtra(name)`, Jackson default typing and `node-serialize`. A class filter (`ObjectInputFilter`, `resolveClass`) makes it safe; unsafe calls on the app's own data are listed as evidence.
* `AEG-D19` in native code also reports Intent data that reaches a call on the line where it is assigned (`val file = File(filesDir, requested)`).

## 0.17.0

* Value flow inside a function: aegis now follows `final x = ...`, reassignments, `for (... in ...)`, parameters and closures, and knows where data comes from (deep links, typed text, HTTP responses, platform channels, push messages).
  * `AEG-D11` and `AEG-D12` also report a query or script variable built from data earlier in the function, and no longer report numbers, `int` parameters and local constants.
  * New `AEG-D19` (medium, high for L2): deep-link data (`uni_links`, `app_links`, go_router `state`) that reaches `launchUrl`, a WebView, a file path or an HTTP request without an `if`/`switch` check. When it can decide and the app handles no push payloads, it replaces manual check `AEG-M08`.
  * `AEG-D08` also reports a log line built from secrets earlier in the function.
* Custom rules in `aegis.yaml` under `custom_rules:`: an `X-` id, a title, a severity, a regex (`pattern`) or a call with argument conditions (`call`, `receiver`, `args`), and the message and fix. They show in every report, count in the score, and work with `aegis:ignore`, baselines and `--fail-on`.
* `--changed-since <git-ref>` lists and fails only on findings on lines changed since that ref (uncommitted and new files included); the score still covers the whole project. The GitHub Action does this for pull requests with `changed-only: true`.
* Found by auditing public vulnerable apps (DVMA, InsecureBankv2, AndroGoat, DVIA-v2, DVRN, the OWASP MASTG demos and their releases):
  * `AEG-D11` also reads Kotlin and Java `rawQuery`, `execSQL` and `compileStatement`, and runs on native Android projects.
  * `AEG-D06` also finds Kotlin and Java keys written as strings that become `SecretKeySpec` bytes, and fixed IVs, and runs on native Android projects.
  * `AEG-A01` reads the release source-set manifest (`src/release/AndroidManifest.xml`).
  * `AEG-A15` follows flags returned by a helper function in the same file, and uses the nearest declaration of a flags variable.
  * `AEG-D16` names the value behind `.text` (`_secret.text` is `_secret`).
  * `AEG-D12` treats the app's own escape helpers as encoding, and no longer splits a call like `value.substring('javascript:'.length)` as a template.
  * `AEG-B12` asks for RELRO only when the library has relocations; Flutter's `libapp.so` has none and was reported in every Flutter app.
  * `AEG-B17`: classes that R8 renamed (for example with `-repackageclasses`) are matched to their owner by the package names in their strings; with no clue they are listed for review instead of reported.
  * `AEG-I14` ignores header files.
  * `AEG-B04` is now called "Exported component without permission in the final manifest": without source it lists every exported component, not only those added by libraries.
* Value flow follows calls into the project's own functions and static methods, in any file: a helper that returns link data passes it on, and one that checks it first does not.
* `AEG-D19` also reads Flutter route names (`onGenerateRoute`), and Kotlin, Java and Swift: Intent extras and data, `getQueryParameter`, `open url:` handlers and `onOpenURL` that reach `loadUrl`, `startActivity`, files or a WebView without a check.
* Native code in more rules: `AEG-D07` (`java.util.Random`, `kotlin.random.Random`, `Math.random()` near security code), `AEG-D15` (Jetpack Compose text fields and XML `EditText`s for secrets with suggestions on), `AEG-D17` (Android and iOS notifications showing codes or tokens), `AEG-N03` (RSA keys under 2048 bits, symmetric keys under 128 bits) and `AEG-D11` (Swift `sqlite3_exec` / `sqlite3_prepare_v2` and FMDB with `\(x)` interpolation). They run on native projects too.
* `AEG-B17` reads R8's `mapping.txt` next to the APK or in Gradle's `outputs/mapping/<variant>/` to name renamed classes.
* The benchmark (`dart run benchmark/run.dart`) runs weekly in CI.

## 0.16.0

* New rules for sign-in and platform IPC:
  * `AEG-P13` (high): unsafe OAuth flows: the implicit flow (`response_type=token`), a `client_secret` sent from the app, and a code flow without PKCE when `flutter_web_auth` drives it by hand.
  * `AEG-A15` (medium): `PendingIntent` that is mutable (`FLAG_MUTABLE`, or no flag below targetSdk 31) and wraps an Intent without an explicit target.
  * `AEG-A16` (medium): FileProvider paths that share the whole storage (`<root-path>`, or `path="."`, `"/"`, `""`).
  * `AEG-A17` (low): task hijacking setups (custom `taskAffinity` with `singleTask`, or `allowTaskReparenting`) while minSdk is below 30.
  * `AEG-B15` (high): an APK signed with the v1 scheme only while it supports Android before 7.0 (Janus, CVE-2017-13156). App bundles are skipped.
  * `AEG-I14` (low): the app's own iOS code uses a required-reason API without `PrivacyInfo.xcprivacy` (source and IPA).
  * `AEG-C04` (high): code loaded from outside the app: dex loaders, `System.load` and `PathClassLoader` on external or downloaded paths, `dlopen` outside the app bundle, and `eval` of non-literal JavaScript.
* New `AEG-B16` (medium): FileProvider paths in an APK's merged resources that share the whole storage, including paths added by libraries. New `AEG-B17` (high): app classes in an APK that create a `DexClassLoader` or `InMemoryDexClassLoader`; Play services, Firebase, AndroidX and Flutter are listed as evidence, not reported.
* `AEG-P13` also reports hand-built code flows without PKCE (any flow not using `flutter_appauth` or `oauth2`) and `AuthorizationCodeGrant(secret: ...)`. `AEG-A15` follows flags kept in a variable. `AEG-I14` also reports a privacy manifest that doesn't declare a category the code uses. `AEG-C04` lists CodePush, Expo Updates and Shorebird as evidence.
* `AEG-P01` also lists emulator and app-virtualization (cloner) checks in its evidence. They are extras and not required for a pass.

## 0.15.0

* `AEG-C01` also looks up native dependencies in OSV: Maven libraries from Gradle files, version catalogs, `gradle.lockfile` and the Android code of the app's Flutter plugins; npm packages from `package-lock.json` and `yarn.lock`; Swift packages from `Package.resolved`. OSV has no CocoaPods data, so a `Podfile.lock` is listed as not checked. Dart findings keep their message. `AEG-C01` now also runs for native Android and iOS projects.
* New `AEG-B14` (APK, AAB) and `AEG-I13` (IPA), medium (high for L2): outdated C libraries compiled into the app, from their version strings: end-of-life OpenSSL branches, zlib before 1.2.13, libpng before 1.6.37, libcurl before 8.4.0. All versions found are listed as evidence. The Flutter engine's own copies are skipped.
* New `AEG-C03` (low): direct dependencies discontinued on pub.dev (with their replacement), and Dart or npm package names one letter away from a popular package (a swapped pair of letters counts as one), which may be a typo or an imitation. The pub.dev lookup is skipped with `--offline`.
* `AEG-C01` resolves Gradle versions written as variables (`$okhttpVersion`, `ext {}` blocks, `gradle.properties`). `AEG-B14` and `AEG-I13` also date bundled SQLite by its source id (before 3.39.2: CVE-2022-35737), and treat every OpenSSL branch except the supported 3.5, 4.0 and 4.1 as end of life.

## 0.14.0

* New rules for data leaking through the UI and local storage:
  * `AEG-D15` (medium): password, PIN, card or similar fields with keyboard suggestions and autocorrect on, so the keyboard can learn them.
  * `AEG-D16` (medium): tokens, passwords or keys copied to the clipboard.
  * `AEG-D17` (low, listed for review): `flutter_local_notifications` notifications that may show codes, balances or tokens on the lock screen.
  * `AEG-D18` (low): `flutter_secure_storage` items saved with an accessibility that isn't `_this_device`, or as synchronizable.
  * `AEG-D20` (medium, high for L2): crypto keys the app generates, or key material, written to SharedPreferences, Hive or files instead of the Keystore or Keychain.
  * `AEG-P14` (low, listed for review): card and identity number fields that accessibility services can read.
* `AEG-D04` also reports Hive boxes named for secrets opened without `encryptionCipher`, and SQLite tables, drift tables, Isar collections and ObjectBox entities with password or token fields when the database isn't encrypted (no SQLCipher, no Isar `encryptionKey`).
* `AEG-D16` and `AEG-D20` also read Swift, Objective-C, Kotlin and Java: `UIPasteboard` and `ClipData` with secrets, and raw key bytes (`key.encoded`, `rawRepresentation`, `SecKeyCopyExternalRepresentation`) saved with `putString`, `UserDefaults` or file writes. Both now also run for native Android and iOS projects.

## 0.13.0

* `aegis.yaml` can tell `AEG-P01` about runtime protection it doesn't know (`rasp: packages:`) and about libraries whose device checks are not protection (`rasp: not_protection:`). Names are Dart packages, Android class prefixes or iOS frameworks and class prefixes, and work for source, APK and IPA audits. `aegis init` writes the section.
* `AEG-D02` now also reports `ws://`, `ftp://` and `mqtt://` URLs, gRPC channels with `ChannelCredentials.insecure()` and `mqtt_client` connections without `secure = true`, outside debug-only code. Its title is now "Cleartext traffic in code"; existing `http://` findings keep their message, so baselines still match.
* New `AEG-D14` (medium): a security decision (`hasPermission`, `isAuthenticated`, `verify...`, `isRooted`, ...) made only inside `assert()`, which release builds remove. Not reported when the same check is also made outside an assert.
* New `AEG-D13` (medium): debug tools that ship in release builds. Dart: Alice, DevicePreview, Stetho and Flipper used outside a `kDebugMode` check (files and folders named dev, debug, mock or staging are skipped), and Chucker with `showOnRelease = true`. Gradle: Chucker, Stetho, Flipper and LeakCanary added with `implementation` instead of `debugImplementation`. New `AEG-B13` finds them inside an APK or AAB from their manifest entries and classes; Chucker's `library-no-op` passes.
* New `AEG-D11` (high): SQL built by pasting values into the query text in sqflite, drift and sqlite3 (`rawQuery`, `execute`, `customSelect`, the `where:` of `query`, ...), where SQL expects a value (`= $id`, `LIKE '%$q%'`, `IN (...)`, `VALUES (...)`). Table and column names and constants are not reported.
* New `AEG-D12` (medium, high for L2): values pasted without encoding into code run by a WebView (`runJavaScript`, `runJavaScriptReturningResult`, `evaluateJavascript`, `loadHtmlString`, `loadData`). `jsonEncode`, `htmlEscape` and similar encodings pass.
* New `AEG-P12` (critical): Firebase security rules that let anyone, without signing in, read or write all data in Cloud Firestore, Cloud Storage or the Realtime Database, including test-mode rules (`request.time < timestamp.date(...)`) until they expire. New `AEG-P15` (medium, high for L2): rules that let any signed-in user reach all data, or let anyone write to a path. The rules files are found through `firebase.json` and by name; when the app uses these services but the rules are not in the repository, `AEG-P12` lists that for review. These rules add findings to existing reports; use `--update-baseline` to accept them.
* IPA audits now read Swift's short string literals (up to 15 bytes), which the compiler keeps inside arm64 instructions instead of the string table. An app's own check such as `name.contains("FridaGadget")` is now found by `AEG-P01` and listed in the iOS binary evidence. Checked on real release builds.
* [MASWE coverage](doc/maswe-coverage.md) lists every OWASP MASWE weakness with the aegis rules that check it. It is generated from the rules (`dart run tool/maswe_coverage.dart`) and a test keeps it current.
* 31 rules that cited no MASWE weakness now do, so their findings show it in the HTML, Markdown and JSON reports: the native and platform checks (`AEG-A11` to `AEG-A14`, `AEG-N01` to `AEG-N09`, `AEG-P11`, `AEG-I12`), the IPA checks (`AEG-I06` to `AEG-I09`), `AEG-B12`, the runtime scenarios (`AEG-R09`, `AEG-R10`) and the resilience probe results (`AEG-R01` to `AEG-R08`).
* The GitHub Action retries installing aegis when pub.dev is briefly unreachable, and a release now updates the action only once pub.dev serves the new version.

## 0.12.1

* The README opens with a screenshot of the HTML report, and pub.dev shows it as the package screenshot.
* New [GitHub Action](https://github.com/khaledSayedAbdellah/aegis-action): `uses: khaledSayedAbdellah/aegis-action@v1` runs aegis and reports to code scanning, annotations, the job summary and a reports artifact, with the score and counts as step outputs. It is kept in `action/` and published with each release.

## 0.12.0

* `AEG-P01` (no runtime protection) no longer checks only for a few RASP packages in `pubspec.yaml`. It looks at Android and iOS separately and counts a Dart package only when the code imports it: known RASP packages, packages named for it, and any package whose own native code checks for root or jailbreak. It also finds native SDKs (freeRASP, RootBeer, IOSSecuritySuite, DTTJailbreakDetection, Approov, Zimperium, DexGuard, DexProtector) declared in Gradle, CocoaPods, Swift Package Manager or package.json and used by the native code, and the app's own root/jailbreak, debugger and hooking checks in Dart, Kotlin/Java or Swift/Objective-C. Own checks that cover only some of these are reported with what is missing, and declared but unused protection is reported as such. What was found is listed as evidence.
* `AEG-P01` now also runs for native Android and iOS projects.
* `AEG-P01` now also runs when only an APK, AAB or IPA is audited. It reads the DEX files, the native libraries and the iOS binaries and attributes each root, jailbreak, debugger and hooking check to the code that holds it: a RASP SDK (passes), the app's own classes or compiled Dart code (judged like own checks in source), or a crash or analytics library.
* Root and jailbreak checks of crash and analytics libraries (Sentry, Firebase Crashlytics, Bugsnag, Instabug, Datadog, AppsFlyer, Adjust, New Relic, App Center, Embrace) are never counted as runtime protection, in source or in a binary: they only label that library's reports. When they are the only checks the finding says so. When a binary's checks are in renamed or unidentifiable code next to one of these libraries, the rule gives no verdict and lists them for review. An encrypted App Store IPA makes the rule incomplete.
* To read the native code of packages, aegis now also finds them in the pub cache at the versions in `pubspec.lock`, and runs `flutter pub get` or `dart pub get` when the dependencies are not resolved (with `--enforce-lockfile` when a lock file exists, and `--offline` in an offline audit). The new `--no-pub-get` flag turns this off. The evidence section says when pub get ran and which packages could not be read.

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
