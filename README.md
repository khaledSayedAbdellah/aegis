# aegis 🛡

**Security audit for Flutter apps that checks whether your protections actually work — not just whether they exist.**

Most scanners ask *"do you have RASP?"*. aegis also asks *"is it started, configured for your app, and does a detected threat trigger a real reaction?"* Every rule is mapped to **OWASP MASVS v2**, **MASWE** and **CWE**, and the score adapts to the **OWASP MAS profile** your app needs (L1, L2, R).

```text
🛡  Aegis security audit  ·  aegis 0.1.0
────────────────────────────────────────────────────────────────
Project: my_bank
MAS profile: L2+R

Security score: 49/100 (F)  ██████████░░░░░░░░░░
  ↳ capped because a CRITICAL finding is open
MASVS coverage: 17 of 24 controls checked automatically (71%)

✗ Needs fixing (6)
[1]  CRITICAL  Missing freeRASP startup wiring  AEG-P02 · MASVS-RESILIENCE-1
    • lib/main.dart:42  No ThreatCallback is attached ...
    Why: freeRASP only protects the app after Talsec.instance.start(config) runs ...
    Fix: In main(): WidgetsFlutterBinding.ensureInitialized(); ...
[2]  HIGH  Threats are detected but nothing happens  AEG-P04
    • lib/main.dart:51  These callbacks only log or do nothing: onPrivilegedAccess, onHooks
...
```

## Why aegis

| | Typical scanner | aegis |
|---|---|---|
| RASP present? | ✅ | ✅ |
| Direct startup and listener calls in Flutter entry point | ❌ | ✅ `AEG-P02` |
| RASP config matches **your** applicationId, bundle id, signing hashes, `isProd` | ❌ | ✅ `AEG-P03` |
| Callbacks do something other than `print` | ❌ | ✅ `AEG-P04` |
| App Check debug provider leaking into release | ❌ | ✅ `AEG-P06` |
| Pinning that still trusts system CAs | ❌ | ✅ `AEG-P07` |
| Biometrics that are only a boolean | ❌ | ✅ `AEG-P08` |
| Score depends on the kind of app (MAS L1 / L2 / R) | ❌ | ✅ |
| Reports in English **and Arabic** | ❌ | ✅ |

It also covers the classics: debuggable builds, backups, cleartext traffic, network security config, exported components, debug-signed releases, hardcoded secrets (redacted in the report), insecure storage, weak crypto, hardcoded keys/IVs, sensitive logs, WebView bridges, bundled `.env` files, ATS, entitlements, vulnerable dependencies (OSV) and more.

aegis has **no dependency on `package:analyzer`**: it uses its own Dart tokenizer, so it runs on any Dart 3 SDK and never conflicts with your app's dependencies.

## Install

aegis is a Dart command-line tool. It needs the Dart 3 SDK (the one inside Flutter is fine).

**1. Activate it.** Pick one:

```bash
# A released version, from GitHub
dart pub global activate --source git https://github.com/khaledSayedAbdellah/aegis.git --git-ref v0.9.0

# Or your local clone: every change in the clone is used right away, no reinstall
dart pub global activate --source path ~/path/to/aegis
```

**2. Put `~/.pub-cache/bin` on your PATH** (once), so the shell finds `aegis`:

```bash
# zsh (macOS default); for bash use ~/.bashrc
grep -q 'pub-cache/bin' ~/.zshrc || echo 'export PATH="$PATH:$HOME/.pub-cache/bin"' >> ~/.zshrc
source ~/.zshrc
```

**3. Check it.**

```bash
aegis --version            # prints the installed version
dart pub global list       # shows where it was activated from
```

| Problem | Fix |
|---|---|
| `command not found: aegis` | `~/.pub-cache/bin` is not on your PATH (step 2), or `~/.pub-cache` was deleted: activate again (step 1). |
| `aegis --version` shows an older version than `dart pub global list` | An old compiled copy is cached. Run `dart pub global deactivate aegis`, delete `.dart_tool/pub/bin` in the aegis clone (for a path activation), activate again and `hash -r`. |
| Errors like `No such file or directory` for packages | The pub cache was cleaned. Run `dart pub get` in the aegis clone, then activate again. |

Update: run the same `activate` command with the new tag (a path activation needs nothing). Uninstall: `dart pub global deactivate aegis`, and `aegis setup --remove` first if you installed the probe tools.

## Quick start

In your Flutter project (after `flutter pub get`):

```bash
aegis init                 # 1. once per project: asks what kind of app it is, writes aegis.yaml
aegis setup                # 2. choose Android, iOS or Both for this machine
aegis run                  # 3. choose code, apk, aab or ipa, then audit
```

**Don't skip environment setup.** Choose Android in `aegis setup`, or run `aegis setup --android`, to prepare both Android emulators that `aegis run --mode apk|aab` uses to check whether your app's anti-tampering actually reacts (rules AEG-R01..R04). Without it, the APK/AAB gets the static checks only and the report says the probe was skipped. It installs only what's missing, so running it again is harmless; `aegis doctor` shows what's there. Details in [The resilience probe](#the-resilience-probe).

`aegis run` prints the report, writes `build/aegis-report.html` and opens it in your browser (`--no-open` to skip; it never opens in CI). Choose what to audit with `--mode`:

| Command | Audits |
|---|---|
| `aegis run` | Asks which mode to audit: `code`, `apk`, `aab` or `ipa` |
| `aegis run --mode code` | Dart code, your git/path packages, Android and iOS configuration |
| `aegis run --mode apk` | the code + the APK at `apk:` in aegis.yaml + the resilience probe on it |
| `aegis run --mode aab` | the code + the AAB at `aab:` in aegis.yaml, with a resilience probe when a matching signed APK is supplied |
| `aegis run --mode ipa` | the code + the IPA at `ipa:` in aegis.yaml, with the iOS resilience probe |

There is no `all` mode and no automatic artifact-priority selection. Without
`--mode`, an interactive terminal offers the four choices (names or numbers).
In CI/non-interactive use, specify a mode, for example
`aegis run --mode apk --strict --no-open`; omitting it exits with code `2`
before any audit or probe. `--apk`/`--ipa` path overrides also require an explicit
mode and must match its platform; `code` does not accept a binary override.
`aegis run --help` and `--version` do not ask for a mode. The plain `aegis`
command retains its existing CI behavior.

For `ipa`, runtime tests require a second explicit choice: **iOS Simulator** or
**a physical iPhone/iPad**. `aegis run --mode ipa` asks even if target settings are
already in YAML. To skip the question or run in CI, use:

```bash
aegis run --mode ipa --ios-target simulator
aegis run --mode ipa --ios-target device
```

The selected environment uses only its own YAML settings. Simulator needs
`ios_simulator` (and optionally the Simulator app/build settings); a physical
device needs `ios_control_device` and any relevant jailbreak/re-signing options.
Both groups may be configured, but only one is used per run. Missing settings
produce an incomplete probe instead of falling back to the other environment.
Conflicting command-line target options are rejected. `--no-probe` runs static
IPA checks only and does not ask for a runtime target. The standalone `probe`
command also accepts `--ios-target`; existing unambiguous target selection there
is retained for compatibility.

The APK/AAB path is yours to set, relative to the project, because build names change with flavors and versions; aegis never guesses one from `build/`:

```yaml
# aegis.yaml
apk: build/app/outputs/flutter-apk/app-prod-release.apk
aab: build/app/outputs/bundle/prodRelease/app-prod-release.aab
```

`--mode apk` or `aab` without that line, or with a file that isn't there, stops with the line to add or the build command to run.

Terminal messages, menus and console summaries are always in English. HTML and Markdown report files follow `lang:` in aegis.yaml (or `--lang`), else your system language. If `~/.pub-cache/bin` is not on your PATH, add `export PATH="$PATH:$HOME/.pub-cache/bin"` to your shell profile.

### Selecting the setup platform

```bash
aegis setup                 # interactive menu: Android / iOS / Both
aegis setup --android       # Android only: two AVDs, Frida/server and bundletool
aegis setup --ios           # iOS only: Xcode check, Frida and device/Simulator Gadgets
aegis setup --both          # Android first, then iOS
```

Each platform is checked and prepared independently. Both runs Android first;
iOS failures never undo Android preparation. On a known non-macOS host, Android
still runs and iOS is reported as unsupported. If OS detection is unavailable,
Android runs first and the iOS tool checks run afterward. A partial or failed
setup returns exit code `1`, with a separate result for each requested platform.

In CI or a non-interactive shell, specify the platform, for example
`aegis setup --android --yes` or `aegis setup --both --yes` on macOS. `--yes`
only skips installation confirmation; it does not choose a platform. Missing or
conflicting platform flags in non-interactive use return exit code `2` before
installation. Use one selector at a time; use `--remove` separately.

The iOS setup installs probe tools; Xcode and an iOS Simulator runtime must
already be installed, and the dedicated Simulator must be created/booted and
selected in `aegis.yaml`. It does not change macOS security settings or install
Android components. Python/Frida are shared prerequisites and are reused when
already present.

## The resilience probe

With an APK, `aegis run` runs the resilience probe and includes its observations in the audit. The probe uses a dedicated Android emulator and first checks whether the original APK can launch and stay alive. Each check requires evidence that its condition was applied.

| Id | Condition | MASVS · Related MASTG reference |
|---|---|---|
| AEG-R01 | Root available on a separate emulator | RESILIENCE-1 · TEST-0325 |
| AEG-R02 | Frida attached to the app | RESILIENCE-4 · TEST-0341 |
| AEG-R03 | JDWP debugger attached to a debuggable APK | RESILIENCE-4 · TEST-0353 |
| AEG-R04 | APK installed with a different signing certificate | RESILIENCE-2 |

The probe works with the APK as supplied. When the condition is verified and the same app process stays alive, the report records `notBlocked` with process scope. This is a finding under MAS-R and describes continued execution during the probe window. If Android records a fresh self-exit for the tested process after the condition, the probe records `blocked` with process scope. Optional app events extend the evidence to a particular operation. An unexplained process exit, conflicting events or a condition that could not be applied is inconclusive.

For a result about a specific operation, a test build can optionally emit a logcat event from the audited app process with the tag `AegisProbe` and the message `<check> blocked` or `<check> not-blocked`. Emit it after the tested operation is blocked or allowed. The check names are `root`, `hooking`, `debugger` and `repackage`. Use test-only instrumentation and avoid logging secrets. An explicit `not-blocked` verdict triggers a finding under a MAS-R profile.

By default, `aegis run` uses `aegis-probe-control` for the control launch, JDWP and re-signing. It compares both AVDs for root and uses `aegis-probe` for Frida, with a separate pre-attachment baseline on that device. Use `--control-avd` and `--root-avd` to override the defaults. Keep the two images and configurations comparable. The standalone `aegis probe` command accepts the same options.

The probe needs a few tools. aegis finds them the way Flutter does and installs only what you don't already have:

```bash
aegis doctor               # lists each tool: present, aegis can install it, or install it yourself
aegis setup --android      # Android tools + both emulators + bundletool; --yes skips installation confirmation
```

`aegis setup --android` uses the Android SDK and JDK from your Flutter setup. It installs the emulator and Android 14 Google APIs and Google Play images through the SDK, then creates `aegis-probe` and `aegis-probe-control`. It also installs Frida and its server under `~/.aegis`. The Android SDK tools prompt for any required licenses. Repeat setup to install missing items. It includes bundletool for AAB/`.apks` support. The old `--aab` flag remains a compatibility alias for `--android`. `aegis setup --remove` removes Aegis tools and AVDs it created while retaining SDK packages and a manually created control AVD.

* Tools missing or the emulator unavailable: `aegis run` does the static checks only and the report says why the probe was skipped.
* `--no-probe` skips it on purpose (static checks only).
* Plain `aegis` (CI) never runs the probe, even with `--apk`.
* For an AAB, supply a signed APK or a bundletool-format `.apks` archive from the same build using `--probe-apk` or `probe_apk` in `aegis.yaml`. Aegis selects the first-install APKs for each emulator and installs its base and splits together. It checks the package name and version code of each selected APK and verifies that all selected APKs have the same signers. The probe covers first-install modules. For a Play release, use Play-signed artifacts and set `probe_cert_sha256` or `--probe-cert-sha256` to the **App signing key certificate** fingerprint (plain or colon-separated SHA-256 hex). The report lists the verified signer and the split files selected for each emulator. YAML paths are relative to the project, and CLI flags override YAML. Without a companion artifact, the AAB receives static checks and the runtime probe is incomplete.

For a device-specific download from Play Console, put the base APK and its splits from one device configuration in the same folder and pass that folder as `probe_apk`, for example `probe_apk: dist/play-splits`. Use a set compatible with both AVDs. Aegis verifies and installs the same preselected set on each emulator. [Play Console download instructions](https://support.google.com/googleplay/android-developer/answer/9844279)

`aegis probe` runs only the probe, on the same `apk:`/`aab:` (or a path you pass), and prints its result without a report: a quick check while you work on the protection. It reads the profile from the project's aegis.yaml (`--project`/`--profile` to override) and ends with a static line saying whether the build is obfuscated.

To exercise the real emulator with disposable test apps, set `ANDROID_SDK_ROOT` and `JAVA_HOME`, then run `bash tool/probe_smoke.sh`. Pass `debugger` or `hooking` to run one attachment check, or `paired` to exercise root and Frida on the two Aegis AVDs. Pass `run` to check the default APK and AAB audit paths. The `protected`, `protected-root` and `splits` modes exercise protection without AegisProbe events. The GitHub Actions `android-probe` job runs `protected-root` and `splits` on both AVDs.

## Full control (CI)

Plain `aegis` takes every setting as an option and only prints to the console unless asked, which is what CI scripts want:

```bash
aegis                                   # audit the current folder
aegis --profile banking --lang ar      # banking app, Arabic report
aegis -f console,html,sarif -o build/aegis
```

`-f/--format` picks the outputs: `console` (the terminal), `html` (a page to open in a browser), `md`, `json`, `sarif` (code-scanning dashboards) and `azure` (Azure Pipelines annotations). `-o` is the file name without extension.

## Commands

Run `aegis --help`, or `aegis <command> --help`, for every option.

| Command | What it does |
|---|---|
| `aegis init` | Once per project: asks what kind of app it is and writes `aegis.yaml` (`--profile`, `--lang` to skip the questions, `--force` to overwrite). |
| `aegis setup` | Choose Android, iOS or Both. Use `--android`, `--ios` or `--both` to select directly; `--yes` confirms installation, `--remove` uninstalls Aegis tools. |
| `aegis doctor` | Lists the tools the probe needs and whether each is present. Changes nothing. |
| `aegis run` | Audits with the settings in `aegis.yaml`, prints the report, writes `build/aegis-report.html` and opens it. |
| `aegis run --mode code\|apk\|aab\|ipa` | What to audit (see Quick start). `apk`/`aab`/`ipa` select their respective YAML artifact paths. |
| `aegis run --no-probe` | Audit the APK/AAB without running the resilience probe. |
| `aegis run --no-open` | Don't open the HTML report in the browser. |
| `aegis run --lang ar` / `--profile banking` | Override aegis.yaml for this run. |
| `aegis run -f console,html,md,json,sarif` | Choose the report formats. |
| `aegis probe` | Only the resilience probe, on `apk:`/`aab:` or a path you pass (`--only root,hooking`, `--project`, `--profile`). |
| `aegis [path] [options]` | Full control for CI: console only unless `-f`, never runs the probe. |
| `aegis --apk app-release.apk` | CI: also audit a built APK or AAB. |
| `aegis --update-baseline` | Accept today's findings; later runs fail only on new ones. |
| `aegis --list-rules` | Lists every rule with its MASVS control. |

Exit codes are `0` for success, `1` for findings at or above `fail_on` or a score below `min_score`, and `2` for invalid input or an incomplete audit in `--strict` mode. Reports list incomplete checks separately. An audit with zero completed rules cannot get a score of 100. Use `--strict` in CI when the audit must complete. A requested probe that was skipped or left an applicable check inconclusive fails strict mode under any MAS profile. Explicit opt-outs such as `--offline` and `--no-probe` remain available.

## Scan the release APK or App Bundle

The source is only half the story. Values injected with `--dart-define`, permissions and components merged from plugins, the certificate that actually signed the build, and whether `--obfuscate` really happened are only visible in the compiled app:

```bash
flutter build apk --release
aegis --apk build/app/outputs/flutter-apk/app-release.apk        # source + APK
aegis /some/empty/folder --apk app-release.apk                   # APK only

flutter build appbundle --release
aegis --apk build/app/outputs/bundle/release/app-release.aab     # source + AAB
```

`--apk` takes an App Bundle too. aegis reads its protobuf manifest and resources, the code of the base and feature modules and the bundle signature. Two differences from an APK:

* **The certificate is your upload key.** Google Play re-signs what it installs with the app signing key, which is not in the bundle. `AEG-B10` therefore fails when freeRASP's `signingCertHashes` contains **only** the upload key (every install from Play would trigger `onAppIntegrity`), passes when it also has another key, and is not applicable when the upload key is absent; check the app signing key in Play Console (`AEG-M04`).
* `BUNDLE-METADATA/` (R8 mapping, native debug symbols) goes to Play only and is not scanned.

Findings use APK-style paths (`app-release.aab!/AndroidManifest.xml`), so a baseline made from an APK also matches the AAB.

With both, aegis compares them and does not count a problem twice: if `android:debuggable` is already reported from your source manifest, the APK rule stays quiet; if it only appears in the APK, the finding says a library or build variant added it.

The report also prints the **signing certificate SHA-256 in Base64**, the exact value freeRASP expects in `signingCertHashes`, and `AEG-B10` fails when your freeRASP config does not contain it (which would make every install trigger `onAppIntegrity`).

| Id | Rule (APK) | MASVS |
|---|---|---|
| AEG-B01 | Debug (JIT) Flutter build shipped (`kernel_blob.bin`) | RESILIENCE-4 |
| AEG-B02 | Final manifest is debuggable | RESILIENCE-4 |
| AEG-B03 | Final manifest / network config weakens backup or TLS | NETWORK-1 |
| AEG-B04 | Library adds an exported component without permission | PLATFORM-1 |
| AEG-B05 | Sensitive permissions added by libraries | PRIVACY-1 |
| AEG-B06 | Secrets in libapp.so, dex, the resource table or assets (catches `--dart-define`) | STORAGE-1 |
| AEG-B07 | Dart code not really obfuscated | RESILIENCE-3 |
| AEG-B08 | Secret files inside flutter_assets | STORAGE-1 |
| AEG-B09 | Signed with the Android debug certificate | RESILIENCE-2 |
| AEG-B10 | freeRASP `signingCertHashes` / `packageName` don't match the APK | RESILIENCE-2 |
| AEG-B11 | Old targetSdk / minSdk in the final manifest | CODE-1 |

aegis reads APKs and AABs itself (zip, binary XML, protobuf XML, v1/v2/v3 signatures) in pure Dart, with no external tools.

## iOS IPA audit and resilience probe

`aegis --ipa path/to/app.ipa` audits the packaged application, with source checks when a Flutter project is supplied. It reads the final `Info.plist`, Mach-O architecture and entitlements, and checks ATS, file sharing, debug permissions and potential bundled secret files. On macOS it uses Apple `codesign` to verify the app and nested code. Other hosts report signature verification as incomplete. [Apple code-signing documentation](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)

```yaml
ipa: build/ios/ipa/app.ipa
ios_control_device: <stock-device-udid>
ios_jailbreak_device: <jailbroken-device-udid>
ios_resigned_ipa: build/ios/ipa/app-resigned.ipa
```

Run `aegis run --mode ipa --ios-target device --strict` for the combined report or `aegis probe path/to/app.ipa --only debugger` for one runtime check. CLI flags `--ios-control-device`, `--ios-jailbreak-device` and `--ios-resigned-ipa` override YAML. Use `xcrun devicectl list devices` to find the device identifier. The devices must be available to Xcode, unlocked, and provisioned for the test app. Use dedicated devices. Aegis refuses to replace an existing installation of the same bundle ID and removes the test installation afterward. [Xcode device setup](https://developer.apple.com/documentation/Xcode/running-your-app-on-simulated-or-physical-devices)

For Frida on a regular iPhone or iPad, configure `ios_control_device` alone and connect it over USB with Developer Mode enabled. Export a Development IPA for that device with `get-task-allow` enabled. Flutter supports `flutter build ipa --export-method development`. Run `aegis doctor --ios` to check the Mac tools and `aegis setup --ios` to install the pinned Frida client and iOS Gadget. Run `aegis probe path/to/app.ipa --only hooking` for Frida alone. Aegis uses Frida's injection through the iOS debugger service and verifies that a script runs inside the observed PID. The verdict applies to that Development build. [Flutter export options](https://docs.flutter.dev/deployment/ios#add-an-app-bundle) · [Frida iOS setup](https://frida.re/docs/ios/)

* **Jailbreak** uses a separate USB-connected jailbroken device. Install `iproxy` from libusbmuxd and configure key-based root SSH on device port 22. Register the device's independently verified SSH host key under `aegis-<hardware-UDID>` in `known_hosts`. Aegis verifies UID 0 through the selected USB device. When `ios_jailbreak_device` is set, the Frida check also uses that device and needs a compatible `frida-server`. Aegis uses `~/.aegis/venv/bin/python` when available. [Frida iOS setup](https://frida.re/docs/ios/)
* **Debugger** uses LLDB and verifies it attached to the observed PID.
* **Signing identity change** requires a second unencrypted IPA exported from the same build with a different valid Apple signing certificate. Both exports must install on the stock device. Aegis compares payload files with signing data removed before attempting the alternate install. Rejection by iOS during install is reported as incomplete.

### Device-independent iOS binary checks

Every IPA audit also inspects the packaged executable, bundled frameworks,
`.dylib` libraries and app extensions locally. No iPhone, Simulator, MobSF server
or extra dependency is needed for these checks:

* `AEG-I07`: missing `MH_PIE` on executable slices; shared libraries are excluded.
* `AEG-I08`: executable-stack requests or initial writable+executable segment permissions.
* `AEG-I09` (MAS-R): retained source debugging entries (`N_STAB`); ordinary exports and the linker strip marker are excluded.
* A separate **iOS static binary analysis** section inventories jailbreak,
  debugger, Frida/hooking and signing-related references, plus stack-canary and
  ARC symbol references. It reports the binary, architecture and evidence source.
  `sysctl`, for example, can be used for ordinary system information. A Frida
  reference can belong to instrumentation. Neither establishes anti-debugging
  or anti-Frida protection.

```bash
aegis run --mode ipa --no-probe
```

This still produces the static checks and evidence inventory without asking for
an iOS target. Normal IPA runs include the same analysis alongside their selected
runtime tests. HTML, Markdown and JSON include the new section; JSON uses
`iosStaticAnalysis` with `runtimeVerified: false`. The terminal remains English.
The new concrete build findings participate in the usual profile, rule override,
score and `--strict` handling. The reference inventory does not change scoring
or turn `AEG-R05`–`AEG-R08` into passes.

The built-in reader also extracts Objective-C class/category names, instance and
class methods, protocol requirements and adopted-protocol relationships. Swift
context descriptors provide module-qualified classes, structs, enums and protocols;
`__swift5_typeref` is parsed with awareness of embedded symbolic references, rather
than splitting pointer payloads at zero bytes. Simple Swift nominal type symbols
are demangled internally. Complex function/generic/substitution manglings remain
searchable in their original form and are reported as a limitation.

JSON includes `binaries[].slices[].metadata.entries` with kind, name, owner where
known, originating section and slice-relative byte offset (symbol-table name
references have no byte offset). HTML/Markdown summarize counts and show matching
protection references with their owners. Name strings and protocol requirements
are distinguished from class/method definitions. These are metadata relationships,
not recovered source, method bodies, call graphs, or Flutter Dart AOT decompilation.
The expanded jailbreak/integrity reference patterns remain informational.

No external backend, `class-dump`, server, subprocess tool or additional install
is used. Supported layouts include 32/64-bit and both endiannesses, absolute and
relative Objective-C method lists, and dyld chained rebase formats 2 and 6.
Unsupported chained formats (including arm64e authenticated pointers), external
bindings, malformed/cyclic metadata and unsupported Swift descriptor versions are
reported as limited. Metadata work is bounded to 30,000 entries and 2,000,000
reader operations per slice, with 4 KiB strings and 32-level context ancestry.
Encrypted metadata is skipped. Original symbol/string analysis remains available.
The implementation follows the published
[Objective-C runtime layouts](https://github.com/apple-oss-distributions/objc4/blob/main/runtime/objc-runtime-new.h),
[Swift metadata ABI](https://github.com/swiftlang/swift/blob/main/include/swift/ABI/Metadata.h),
[Swift mangling ABI](https://github.com/swiftlang/swift/blob/main/docs/ABI/Mangling.rst)
and [dyld fixup layouts](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h).

Presence of a symbol or string is **not proof that protection executes**, and
absence is **not proof that protection is missing**. Encryption, missing symbol
tables, malformed files and analysis limits are reported explicitly. FairPlay
ciphertext is not scanned as plaintext. Inspecting a signature blob is separate
from `AEG-I05` cryptographic verification and from testing the app's reaction to
re-signing. Header permissions do not prove the operating system's runtime
memory policy. ARC and canary references do not prove protection of every function.

The review used [MobSF's Mach-O analysis](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/StaticAnalyzer/views/common/binary/macho.py)
and [iOS binary rule matcher](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/StaticAnalyzer/views/ios/binary_rule_matcher.py)
to identify coverage gaps. The implementation is independent Dart code using
[Apple's Mach-O layout](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h).
MobSF's [iOS dynamic setup](https://github.com/MobSF/docs/blob/master/dynamic_analyzer_docker.md)
documents Corellium or a jailbroken device; it does not establish full jailbreak
or Apple signing-identity enforcement tests on Xcode Simulator. Aegis's existing
partial Simulator results keep their limitations.

### Automatic platform protection checks

`AEG-P10`, `AEG-N05`–`AEG-N07`, `AEG-I12` and `AEG-A14` add screen,
backup, key-access/biometric, Universal Links, WebView and Android tapjacking
inspection. They require no app-specific configuration or credentials. Existing
`run` probes collect available launch-time metadata, including a separate iOS
Simulator observer and an Android synthetic security-filter comparison when
instrumentation is available. Static references and partial runtime observations
remain distinct; unknown screens or unexercised behavior do not pass.
See [exact coverage, limits and safety](doc/platform-protection.md).
Applicable incomplete checks remain incomplete under `--strict`, including when
runtime testing is disabled with `--no-probe`.

### iOS Simulator

Run `aegis setup --ios` once and boot a dedicated iOS Simulator. Get its UDID with `xcrun simctl list devices booted`. From a Flutter project, `run` builds the Simulator app automatically when it is missing or its identity, version, build number, or platform does not match the IPA. A matching existing app is reused. The build uses `flutter build ios --simulator --debug` with the IPA version and build number; the generated app is verified before installation.

```yaml
ipa: build/ios/ipa/app.ipa
ios_simulator: <booted-simulator-udid>
# Optional; run also finds Flutter's generated Simulator app automatically.
ios_simulator_app: build/ios/iphonesimulator/Runner.app
# Set once for projects using custom build inputs:
# ios_simulator_flavor: prod
# ios_simulator_target: lib/main_prod.dart
```

Automatic building requires the Flutter source project, Flutter SDK and Xcode dependencies. It respects the project's FVM/Flutter SDK, previous `FLUTTER_TARGET` and `DART_DEFINES`, and `flutter.default-flavor`; a matching local Xcode archive can supply the flavor. Use `ios_simulator_flavor` and `ios_simulator_target` to override these inputs. Build output is saved to `.dart_tool/aegis/ios-simulator-build.log`; a failed or mismatched build leaves the runtime checks incomplete. A configured `.app` path is tried first, then Flutter's generated output. Native projects or IPA-only audits need a separately built `ios_simulator_app`. Matching version metadata does not prove identical source or protection settings: runtime results describe the Simulator debug build, while static checks describe the original IPA. [Flutter iOS build modes](https://docs.flutter.dev/testing/build-modes) · [Flutter flavors](https://docs.flutter.dev/deployment/flavors-ios)

When `ios_simulator_flavor` or `ios_simulator_target` is explicitly set, an
automatically discovered product is reused only if its recorded Aegis build
inputs and full product-content fingerprint match. Otherwise it is rebuilt and the verified inputs are recorded for
later reuse. An explicitly supplied, matching `ios_simulator_app` remains the
artifact selected by the user; build options apply when a build is needed.

`aegis run --mode ipa --ios-target simulator` audits the IPA statically and runs LLDB and Frida on the Simulator build. `--ios-simulator` and `--ios-simulator-app` override the YAML fields. Use `--ios-target device` to choose the physical-device environment; conflicting CLI options are rejected. For just Frida, run `aegis probe path/to/app.ipa --only hooking` with the Simulator configured. The Simulator uses a separately pinned Frida Gadget `16.5.9`, loaded at app launch. Aegis verifies a fresh script response from the observed PID. `run` also executes two partial Simulator experiments automatically:

* **Jailbreak file indicators:** a temporary native helper simulates Cydia/MobileSubstrate and `/var/jb` paths through `NSFileManager.fileExistsAtPath` and libc `access/stat/lstat`. It first runs a control with the same helper and indicators disabled, then verifies helper self-tests in the observed PID and records queried paths and process behavior. Direct syscalls, URL schemes, kernel state and sandbox escape are outside this test. A normal exit after querying an indicator can establish a partial process reaction; unexplained crashes remain inconclusive. Zero recorded queries is explicitly reported and does not establish that the IPA has no jailbreak protection.
* **Ad-hoc signing metadata:** a disposable copy of the matching Simulator `.app` receives a different CodeDirectory identifier. Aegis verifies the signature/hash change, unchanged unsigned payload and the installed signature before observing the app. The original `.app` and IPA are left intact. This tests neither a different Apple certificate/Team ID nor provisioning or App Store validation.

Reports show an explicit **Simulator-scoped verdict** and a red/green/inconclusive mark from the observed behavior. Continued execution produces a scoped AEG-R05/AEG-R08 finding and affects the score/fail-on policy; it does not claim that the device IPA lacks protection. JSON `status` is the observed Simulator verdict, with `partialStatus`, `scope: ios-simulator`, `coverage: partial`, `fullConditionStatus: inconclusive` and limitations retained. Full MASVS coverage is not granted and `run --strict` remains incomplete. Simulator builds can disable protections present in device builds. These experiments do not change macOS SIP, AMFI or Research Guests settings. [Simulator Gadget compatibility](https://github.com/frida/frida/issues/3551)

The iOS probe uses fresh application-console output. An app can report `AegisProbe <check> blocked` or `AegisProbe <check> not-blocked` on stdout after applying its policy, with `jailbreak`, `hooking`, `debugger` or `repackage` as the check. Flush stdout before exiting. A normal exit confirmed by LLDB after debugger attachment, or the same PID remaining alive after a verified condition, provides process-level evidence. An unexplained exit or an unverified condition is inconclusive and fails `--strict`.

To verify automatic Flutter builds, changed IPA build numbers, and reuse with real LLDB/Frida probes, run `bash tool/ios_simulator_build_smoke.sh <booted-simulator-udid>` after `aegis setup --ios`. This creates a temporary Flutter project and a synthetic IPA metadata fixture, and retains reports/logs in the printed temporary directory.

For disposable positive and negative controls of the partial experiments, run `AEGIS_SMOKE_PARTIAL_ONLY=1 AEGIS_SMOKE_IOS_FRIDA=1 bash tool/ios_probe_smoke.sh <booted-simulator-udid>`. The jailbreak positive controls exit after real NSFileManager/POSIX indicator queries without app-event markers; the signing positive control explicitly reports the modified CodeDirectory.

For a disposable test of IPA parsing and LLDB attachment, run `bash tool/ios_probe_smoke.sh <booted-simulator-udid>` on macOS. Set `AEGIS_SMOKE_IOS_FRIDA=1` after `aegis setup --ios` to require a verified Frida result in the combined report.

## MAS profiles

| Profile | For | Presets |
|---|---|---|
| `l1` | every app (default) | `standard`, `basic` |
| `l2` | apps with high-risk sensitive data | `sensitive`, `health` |
| `l1+r` | apps whose business is at risk from tampering (games, media) | `game`, `media` |
| `l2+r` | banking, payments, government | `banking`, `fintech`, `payments`, `government` |

The profile decides which rules run and how severe some findings are. For example, data in SharedPreferences is *medium* for L1 and *high* for L2, and certificate pinning is only required from L2.

## Score

An incomplete audit labels its score **Provisional — some protections have not been verified** beside the number in HTML, Markdown and terminal output. A high provisional score uses a warning color instead of green; verified high/critical failures stay red and retain their full penalty. JSON exposes `score.provisional` and SARIF exposes `properties.scoreProvisional`. This does not change numeric scoring, `--min-score`, or `--strict`; even a completed audit only covers the selected scope, not every possible protection.

Two rules, applied to every failing rule (known baseline findings included):

**1. The worst open problem decides the band and the grade.**

| Worst open problem | Score | Grade |
|---|---|---|
| none | 100 | A |
| low | 90–99 | A |
| medium | 70–89 | B (80+) / C |
| high | 40–69 | D |
| critical | 0–39 | F |

No number of healthy checks can lift a high problem out of D, and fixing the last problem of a severity always moves the score up a band. This is how SonarQube rates security (worst issue decides) and how SSL Labs caps grades.

**2. Inside the band, every open problem costs points.** Each failing rule adds a penalty (critical 10, high 6, medium 3, low 1; ×1.4 for 3 findings of the same rule, up to ×2), and

```
score = band start + band width × e^(−penalty / 20)
```

So two apps with the same high problem but a different number of other problems get different scores, more problems always mean a lower score, and fixing anything never lowers it.

Example (a real app, source only): under L2+R it has two high problems, four medium and two low → **47 (D)**; under L1 only one high and one low are in scope → **58 (D)**. Fixing the two high problems gives **80 (B)** under L2+R; fixing the high one under L1 gives **99 (A)**.

Every report also says which rules keep the score in its band, what it becomes once they are fixed, and the single fixes worth most points. Each MASVS category is scored with the same formula, so a category's number and colour agree (a category with a high problem is red). Every report shows **MASVS coverage** and a list of **manual checks** (backend authorization, server-side attestation verification, …) so a clean score is never mistaken for a secure app.

## Configuration — `aegis.yaml`

`aegis init` writes every supported YAML setting as an editable key, including audit policy, artifacts, AAB probe settings, and physical iOS/Simulator settings. Known defaults are filled in; unknown paths use `<path-to-file>` and device IDs, flavors, and fingerprints have named placeholders. Replace only the values you need. Unfilled `<...>` placeholders are treated as unset, so optional targets stay inactive and automatic Simulator building remains available. `min_score: null` disables the optional score threshold. Existing files are preserved unless you explicitly use `aegis init --force`.

```yaml
profile: banking       # l1, l2, l1+r, l2+r or a preset
lang: ar               # en | ar
fail_on: high          # exit 1 on high or critical findings
min_score: 70          # exit 1 below this score
exclude:
  - lib/generated/**
rules:
  AEG-D07: false       # disable a rule
  AEG-C02: medium      # change a severity
scan_packages: true    # also scan git/path dependencies (default)
baseline: aegis-baseline.json   # default; see "Baselines"
apk: build/app/outputs/flutter-apk/app-release.apk          # for aegis run --mode apk
aab: build/app/outputs/bundle/release/app-release.aab       # for aegis run --mode aab
# probe_apk: dist/app-release.apks                        # signed .apk, .apks, or APK directory for an AAB
# probe_cert_sha256: "<app signing certificate SHA-256>"
```

**Your own packages are scanned too.** Many apps keep auth, networking and storage in internal packages pulled in as git or path dependencies. aegis reads `.dart_tool/package_config.json` (run `flutter pub get` first) and scans the Dart code of every git and path dependency, listing them under "Packages scanned"; findings point to `package:<name>/...`. pub.dev packages are not scanned. Turn this off with `scan_packages: false`.

Suppress a single finding with a comment on the same line or the line above (works in Dart, XML and Gradle files):

```dart
const devUrl = 'http://10.0.0.5/api'; // aegis:ignore AEG-D02
```

Use `// aegis:ignore-file AEG-D02` to suppress a rule for a whole Dart file. Suppressed findings are counted in every report.

## Baselines

An existing app usually starts with a list of findings that can't all be fixed this sprint. A baseline records them as *known* so CI only fails on **new** problems:

```bash
aegis --update-baseline        # accept everything found today, writes aegis-baseline.json
git add aegis-baseline.json    # commit it
aegis --fail-on high           # now fails only on findings that are not in the baseline
```

* Findings are matched by rule, file and message, **not by line number**, so editing code above a finding does not make it new. Renaming the APK doesn't either.
* Reports show three groups: **new issues** (fail the build), **known issues** (still listed, still count in the score) and **fixed since the baseline**. Run `--update-baseline` again to drop the fixed ones; the file is sorted so the diff shows exactly what changed.
* The score is never hidden: known issues still lower it, and `--min-score` uses the real score. Only `--fail-on` ignores known issues.
* `--baseline <file>` uses another file, `--ignore-baseline` reports everything as new. SARIF output sets `baselineState` (`new` / `unchanged`) so GitHub code scanning shows the same split.

## CI

```yaml
# GitHub Actions
- run: dart pub global activate aegis
- run: aegis --profile l2 --fail-on high -f console,sarif -o aegis
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: aegis.sarif
```

Exit codes: `0` ok, `1` `--fail-on` / `--min-score` threshold reached, `2` usage error.

### Azure Pipelines

`ci/azure-pipelines/aegis-steps.yml` is a ready-made steps template: it installs aegis, annotates the build with every new finding, adds an **aegis security audit** tab to the build summary, keeps the HTML/JSON/SARIF reports as an artifact and can feed the SARIF Scans tab or GitHub Advanced Security for Azure DevOps.

```yaml
resources:
  repositories:
  - repository: aegis
    type: github
    endpoint: <your GitHub service connection>
    name: khaledSayedAbdellah/aegis
    ref: refs/tags/v0.9.0

steps:
- template: ci/azure-pipelines/aegis-steps.yml@aegis
  parameters:
    aegisSource: git
    aegisGitUrl: https://github.com/khaledSayedAbdellah/aegis.git
    aegisGitRef: v0.9.0
    failOn: high
```

No GitHub service connection? Copy `aegis-steps.yml` into your repository and use `- template: <path>/aegis-steps.yml`.

See [ci/azure-pipelines/README.md](ci/azure-pipelines/README.md) for all parameters and a full example. `-f azure` prints the same annotations from any script.

## Rules

Run `aegis --list-rules` for the full list.

| Id | Rule | MASVS |
|---|---|---|
| AEG-P01 | No runtime protection (RASP) *(R)* | RESILIENCE-1/4 |
| AEG-P02 | freeRASP installed but not running | RESILIENCE-1 |
| AEG-P03 | freeRASP misconfigured (package name, hashes, bundle ids, team id, isProd) | RESILIENCE-2 |
| AEG-P04 | Threats detected but no reaction | RESILIENCE-1/2/4 |
| AEG-P05 | Firebase without App Check *(L2, R)* | RESILIENCE-2 |
| AEG-P06 | App Check debug provider reachable in release | RESILIENCE-2 |
| AEG-P07 | No effective certificate pinning *(L2)* | NETWORK-2 |
| AEG-P08 | Biometrics as a plain boolean *(L2)* | AUTH-2 |
| AEG-P09 | No screenshot protection *(L2)* | PLATFORM-3 |
| AEG-P10 | Release build commands without `--obfuscate` *(R)* | RESILIENCE-3 |
| AEG-A01 | Android app debuggable | RESILIENCE-4 |
| AEG-A02 | Backup allowed | STORAGE-2 |
| AEG-A03 | Cleartext traffic (manifest) | NETWORK-1 |
| AEG-A04 | Weak network security config | NETWORK-1 |
| AEG-A05 | Expired certificate pins | NETWORK-2 |
| AEG-A06 | Exported component without permission | PLATFORM-1 |
| AEG-A07 | R8 disabled | RESILIENCE-3 |
| AEG-A08 | Release signed with the debug key | RESILIENCE-2 |
| AEG-A09 | Signing secrets exposed | STORAGE-1 |
| AEG-A10 | minSdk below 24 | CODE-1 |
| AEG-I01 | ATS disabled | NETWORK-1 |
| AEG-I02 | Insecure ATS exception | NETWORK-1 |
| AEG-I03 | `get-task-allow` entitlement | RESILIENCE-4 |
| AEG-I04 | Documents folder exposed | STORAGE-2 |
| AEG-I05 | IPA code signature verification | RESILIENCE-2 |
| AEG-I06 | Potential bundled secret files in IPA | STORAGE-1 |
| AEG-I07 | Missing executable PIE flag | CODE-4 |
| AEG-I08 | Executable stack / initial W+X segments | CODE-4 |
| AEG-I09 | Retained source debug entries (MAS-R) | RESILIENCE-3 |
| AEG-D01 | Hardcoded secret (known formats, JWT/Supabase service role, high-entropy values) | STORAGE-1 |
| AEG-D02 | `http://` URL | NETWORK-1 |
| AEG-D03 | TLS validation disabled | NETWORK-1 |
| AEG-D04 | Sensitive data in SharedPreferences / GetStorage / Hive | STORAGE-1 |
| AEG-D05 | Weak cryptography | CRYPTO-1 |
| AEG-D06 | Hardcoded encryption key or IV | CRYPTO-2 |
| AEG-D07 | `Random()` for security values | CRYPTO-1 |
| AEG-D08 | Sensitive data in logs, unguarded `LogInterceptor` | STORAGE-2 |
| AEG-D09 | `.env` / keys bundled as assets | STORAGE-1 |
| AEG-D10 | WebView JS bridge without navigation limits, WebView debugging | PLATFORM-2 |
| AEG-C01 | Dependency with known vulnerabilities (OSV, skipped with `--offline`) | CODE-3 |
| AEG-C02 | Unpinned git dependencies, `dependency_overrides` | CODE-3 |

## Development: run from source and run the tests

```bash
git clone https://github.com/khaledSayedAbdellah/aegis.git
cd aegis
dart pub get

dart run bin/aegis.dart --version                       # run without activating
dart run bin/aegis.dart run ~/path/to/app --mode code   # any command, on any project

dart analyze                                            # must print "No issues found!"
dart test                                               # the whole suite
dart test test/cli_test.dart                            # one file
dart test -N "apk mode"                                 # tests whose name contains the text
```

The tests need no network, emulator or Android tools: the CLI tests run `bin/aegis.dart` on temporary projects with `--offline` and `--no-probe`, and the probe tests use a fake host and a fake device (`test/support/fake_host.dart`, `test/probe_runner_test.dart`). To try your change as the real `aegis` command, activate the clone with `--source path` (see Install).

## Use from Dart

```dart
import 'package:aegis/aegis.dart';

final report = await runAudit('path/to/app', offline: true);
print(report.score.value);
File('aegis.html').writeAsStringSync(renderHtml(report, lang: 'ar'));
```

## Demo

`example/vulnerable_app` is an intentionally insecure project where nearly every rule fires:

```bash
dart run aegis example/vulnerable_app --offline
```

## What aegis cannot see

Without `--apk` it reads source and configuration only, so build-time values, merged manifests and real obfuscation are not checked. Even with the APK, backend authorization, server-side verification of attestation tokens and runtime behavior are out of scope. The report lists these as manual checks.

## Roadmap

* `--fix` for configuration findings.
* Optional AI-assisted triage (opt-in, local model support, secrets redacted before sending).

---

## License

MIT

### Translation catalogs

Human-facing report text, rule descriptions and findings, and setup/doctor messages
are maintained in [`app_en.arb`](lib/src/l10n/app_en.arb) and
[`app_ar.arb`](lib/src/l10n/app_ar.arb). Use `--lang ar` or `lang: ar` in
`aegis.yaml` for Arabic HTML and Markdown report files. Terminal output stays in
English, including `init`, `setup`, `doctor`, `run`, `probe` and `--list-rules`.
The legacy `--lang` option on `setup`, `doctor` and `probe` is accepted but does
not change terminal output. iOS probe evidence, partial-test limitations and incomplete
reasons have explicit Arabic translations; JSON retains English fields and adds
Arabic counterparts. Tool names, paths, code excerpts and original external-tool
logs remain unchanged. Keep technical product/tool names (including full tool display names), symbols,
rule IDs, command flags and paths in their original spelling; translate the
surrounding explanation and interface prose only.

After editing a translation, regenerate and validate it:

```bash
dart run tool/generate_l10n.dart
dart run tool/generate_l10n.dart --check
dart test test/l10n_test.dart
```

Add the same key to both catalogs, a description under `@key` in the English
catalog, and matching `placeholders` metadata for any `{name}` parameters. The
small Dart-only generator supports plain messages and named placeholders; it
rejects ICU plural/select expressions instead of displaying them incorrectly.
Keep separate keys for wording variants. Commit `messages.g.dart` with the ARB
changes. Translations are compiled into the CLI, so global installations work
from any directory without Flutter or runtime access to the ARB files.

### Extended MASVS analysis and runtime scenarios

`run` now includes Android App Link/permission checks, native TLS/WebView/crypto/
storage patterns, iOS entitlement/ATS checks, ELF hardening and tracker inventory.
Reference-only evidence is separate from findings and scoring. `init` includes
`tracker_signatures` and opt-in `runtime_security` configuration.

Network interception and runtime leakage tests need an application-specific
scenario. Missing setup/traffic/channels remains incomplete, never an assumed
protection pass. `--no-probe` disables runtime tests; no host security settings
are changed. See [scope, prerequisites and scenario contract](doc/runtime-security.md).
