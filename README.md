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
[1]  CRITICAL  freeRASP is installed but not running  AEG-P02 · MASVS-RESILIENCE-1
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
| RASP actually started / listener attached | ❌ | ✅ `AEG-P02` |
| RASP config matches **your** applicationId, bundle id, signing hashes, `isProd` | ❌ | ✅ `AEG-P03` |
| Callbacks do something other than `print` | ❌ | ✅ `AEG-P04` |
| App Check debug provider leaking into release | ❌ | ✅ `AEG-P06` |
| Pinning that still trusts system CAs | ❌ | ✅ `AEG-P07` |
| Biometrics that are only a boolean | ❌ | ✅ `AEG-P08` |
| Score depends on the kind of app (MAS L1 / L2 / R) | ❌ | ✅ |
| Reports in English **and Arabic** | ❌ | ✅ |

It also covers the classics: debuggable builds, backups, cleartext traffic, network security config, exported components, debug-signed releases, hardcoded secrets (redacted in the report), insecure storage, weak crypto, hardcoded keys/IVs, sensitive logs, WebView bridges, bundled `.env` files, ATS, entitlements, vulnerable dependencies (OSV) and more.

aegis has **no dependency on `package:analyzer`**: it uses its own Dart tokenizer, so it runs on any Dart 3 SDK and never conflicts with your app's dependencies.

## Quick start

```bash
dart pub global activate --source git https://github.com/khaledSayedAbdellah/aegis.git --git-ref v0.6.0
```

In your Flutter project (after `flutter pub get`):

```bash
aegis init                 # once: asks what kind of app it is, writes aegis.yaml
aegis run                  # code + the newest release APK/AAB in build/, if any
```

`aegis run` prints the report, writes `build/aegis-report.html` and opens it in your browser (`--no-open` to skip; it never opens in CI). Choose what to audit with `--mode`:

| Command | Audits |
|---|---|
| `aegis run` | `--mode all`: the code, plus the newest release APK or AAB in `build/` (code only when none is built) |
| `aegis run --mode code` | Dart code, your git/path packages, Android and iOS configuration |
| `aegis run --mode apk` | the code + the newest `build/app/outputs/flutter-apk/*release*.apk` |
| `aegis run --mode aab` | the code + the newest `build/app/outputs/bundle/*Release/*.aab` |

The language follows `lang:` in aegis.yaml, else your system language. If `~/.pub-cache/bin` is not on your PATH, add `export PATH="$PATH:$HOME/.pub-cache/bin"` to your shell profile.

## Prepare for the resilience probe

A later command will check whether your app's anti-tampering actually resists a real attempt (run it on an emulator, try to attach and repackage, see what it blocks). That needs a few tools on your machine. aegis finds them the way Flutter does and installs only what you don't already have:

```bash
aegis doctor               # lists each tool: present, aegis can install it, or install it yourself
aegis setup                # installs the missing ones (asks once; --yes to skip the prompt)
```

`aegis setup` uses the Android SDK and JDK your Flutter build already uses (it never installs Java, the SDK or Flutter — it tells you how if they're missing). What it does install goes under `~/.aegis`: the SDK's emulator and an Android 14 image, an AVD named `aegis-probe`, a Python venv with Frida, and the matching `frida-server`. The Android SDK tools ask you to accept their licenses yourself. Anything already present is skipped, so a second `aegis setup` installs nothing. Add `--aab` to also fetch bundletool (needed only to probe an `.aab`). Downloads are checked against a pinned SHA-256. To undo it all, `aegis setup --remove` deletes what aegis installed (never your Java or Android SDK).

Then run the probe against a release build:

```bash
aegis probe build/app/outputs/flutter-apk/app-release.apk
```

It runs the app on the `aegis-probe` emulator and, for each standard OWASP MASTG resilience condition (root, debugger, Frida instrumentation, a re-signed build), reports whether the app's own protection reacted (✅), did not react (❌) or the check was inconclusive (⏸️). It checks first that the app even stays alive on a clean emulator; if it doesn't, every check is inconclusive and the report says so. A gap counts as a finding only when the active profile includes MAS-R. The probe tests your own build — it sets the standard condition and watches, it does not try to defeat any protection. It reads the profile from the app's own project (the `aegis.yaml` above the APK), so you can run it from anywhere; `--project` or `--profile` override that. It also takes an `.aab` (converted to a debug-signed universal APK with bundletool, so a protection that pins your release certificate will treat it as tampered), and it ends with a static line saying whether the build is obfuscated.

## Full control (CI)

Plain `aegis` takes every setting as an option and only prints to the console unless asked, which is what CI scripts want:

```bash
aegis                                   # audit the current folder
aegis --profile banking --lang ar      # banking app, Arabic report
aegis -f console,html,sarif -o build/aegis
```

`-f/--format` picks the outputs: `console` (the terminal), `html` (a page to open in a browser), `md`, `json`, `sarif` (code-scanning dashboards) and `azure` (Azure Pipelines annotations). `-o` is the file name without extension.

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

aegis reads APKs and AABs itself (zip, binary XML, protobuf XML, v1/v2/v3 signatures) in pure Dart, with no external tools. IPAs are not supported yet.

## MAS profiles

| Profile | For | Presets |
|---|---|---|
| `l1` | every app (default) | `standard`, `basic` |
| `l2` | apps with high-risk sensitive data | `sensitive`, `health` |
| `l1+r` | apps whose business is at risk from tampering (games, media) | `game`, `media` |
| `l2+r` | banking, payments, government | `banking`, `fintech`, `payments`, `government` |

The profile decides which rules run and how severe some findings are. For example, data in SharedPreferences is *medium* for L1 and *high* for L2, and certificate pinning is only required from L2.

## Score

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
    ref: refs/tags/v0.6.0

steps:
- template: ci/azure-pipelines/aegis-steps.yml@aegis
  parameters:
    aegisSource: git
    aegisGitUrl: https://github.com/khaledSayedAbdellah/aegis.git
    aegisGitRef: v0.6.0
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

* `--ipa` support.
* `--fix` for configuration findings.
* Optional AI-assisted triage (opt-in, local model support, secrets redacted before sending).

---

## بالعربي

**aegis** أداة بتفحص أمان تطبيقات Flutter، وبتتأكد إن الحماية **شغالة فعلاً** مش بس موجودة. يعني مش بتسأل "عندك RASP؟" وبس، لكن بتسأل كمان: هل اتشغّل؟ هل إعداداته مطابقة لتطبيقك؟ وهل لما يكتشف تهديد بيعمل رد فعل حقيقي ولا بيطبع log وخلاص؟

```bash
aegis init                 # مرة واحدة: بيسألك نوع التطبيق وبيعمل aegis.yaml
aegis run                  # الكود + آخر APK/AAB متبني في build/ لو موجود
aegis run --mode code      # الكود بس
aegis run --mode apk       # الكود + آخر APK
aegis run --mode aab       # الكود + آخر AAB
```

التقرير بيظهر في الـ terminal، وبيتكتب في `build/aegis-report.html` وبيتفتح في المتصفح على طول (`--no-open` لو مش عايزه يفتح، وفي الـ CI عمره ما بيفتح).

قُدّام فيه أمر هيفحص إن حماية تطبيقك ضد التعديل شغالة فعلاً (بيشغّل التطبيق على محاكي، وبيجرّب يوصله ويعدّل عليه، ويشوف بيصد إيه). عشان كده محتاج شوية أدوات. aegis بيلاقيها بنفس طريقة Flutter، وبيسطّب اللي ناقص بس:

```bash
aegis doctor               # بيعرض كل أداة: موجودة، aegis هيسطّبها، أو سطّبها بنفسك
aegis setup                # بيسطّب الناقص (بيسأل مرة واحدة؛ --yes يلغي السؤال)
```

`aegis setup` بيستخدم الـ Android SDK والـ JDK اللي الـ build بتاعك بيستخدمهم (عمره ما بيسطّب Java ولا الـ SDK ولا Flutter — بيقولك إزاي لو ناقصين). اللي بيسطّبه بيتحط في `~/.aegis`: محاكي وصورة Android 14، وجهاز وهمي اسمه `aegis-probe`، وبيئة Python فيها Frida، و`frida-server` بنفس الإصدار. أدوات الـ SDK هتطلب منك توافق على الرخص بنفسك. أي حاجة موجودة بيتخطّاها، فتشغيل `aegis setup` تاني ميسطبش حاجة. زوّد `--aab` لو عايز bundletool كمان (بتتستخدم لفحص الـ `.aab` بس). التحميلات بتتأكد بـ SHA-256 مثبّت. وللتراجع، `aegis setup --remove` بيمسح اللي aegis سطّبه (من غير ما يلمس Java ولا الـ SDK).

وبعدين شغّل الـ probe على نسخة release:

```bash
aegis probe build/app/outputs/flutter-apk/app-release.apk
```

بيشغّل التطبيق على إيموليتر `aegis-probe`، ولكل حالة قياسية من OWASP MASTG (root، debugger، حقن Frida، نسخة معاد توقيعها) بيقول إذا كانت حماية التطبيق ردّت (✅)، مردتش (❌)، ولا الاختبار مش حاسم (⏸️). بيتأكد الأول إن التطبيق بيفضل شغّال على إيموليتر نضيف؛ لو لأ، كل الاختبارات تبقى غير حاسمة والتقرير بيقول كده. المشكلة بتتحسب كـ finding بس لو الـ profile فيه MAS-R. الـ probe بيختبر نسختك إنت — بيحط الحالة القياسية ويراقب، مش بيحاول يكسر أي حماية. بيقرا الـ profile من مشروع التطبيق نفسه (الـ `aegis.yaml` اللي فوق الـ APK)، فتقدر تشغّله من أي مكان؛ و`--project` أو `--profile` بيغيّروا ده. وبياخد `.aab` كمان (بيتحوّل لـ APK شامل متوقّع بمفتاح debug عن طريق bundletool، فالحماية اللي بتثبّت شهادة الـ release هتعتبره معدّل)، وفي الآخر بيقولك النسخة متعمّلها obfuscation ولا لأ.

مع `--apk` الأداة بتفحص الـ APK اللي اتبنى فعلاً: الأسرار اللي اتحطت بـ `--dart-define`، والصلاحيات والمكونات اللي المكتبات ضافتها، والشهادة اللي وقّعت التطبيق، وهل الـ obfuscation اتعمل بجد. وبتطبعلك الـ hash اللي تحطه في إعدادات freeRASP.

* كل قاعدة مربوطة بـ OWASP MASVS و MASWE و CWE.
* السكور بيتغير حسب نوع التطبيق (L1 لأي تطبيق، L2 للبيانات الحساسة، R للحماية من التعديل والهندسة العكسية).
* لو فيه مشكلة خطيرة جداً، السكور مش هيعدي 49 مهما كانت باقي الأقسام نضيفة.
* التقرير بيقولك نسبة التغطية، وبيديك قائمة بالحاجات اللي لازم تتأكد منها بنفسك، عشان السكور العالي ميديكش إحساس كاذب بالأمان.
* فيه template جاهز لـ Azure Pipelines في `ci/azure-pipelines/`: بيعلّم كل مشكلة جديدة في الـ build، وبيضيف تاب للتقرير في صفحة الـ build، وبيحفظ التقرير HTML كـ artifact.
* لو المشروع قديم وفيه مشاكل كتير: `aegis --update-baseline` بيسجل المشاكل الحالية في `aegis-baseline.json` كـ"معروفة"، وبعد كده الـ CI بيقع بس لو ظهرت مشكلة **جديدة**. المشاكل المعروفة بتفضل ظاهرة في التقرير وبتأثر على السكور، والتقرير بيقولك كمان إيه اللي اتصلح.

## License

MIT
