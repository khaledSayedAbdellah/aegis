# Plan: `aegis doctor` and `aegis setup` (probe toolchain)

Status: **approved by the owner 2026-11-08, in progress**. Base: `main` at `afa44a8` (v0.5.0).
Read this whole file before writing code. Follow the steps in order; each step
ends in a commit that leaves `dart analyze` and `dart test` green.

## 1. Goal

Later, `aegis probe` (a separate task, **not part of this plan**) will check
whether an app's runtime protection (freeRASP, AppSealing or any other vendor)
actually resists tampering: it runs the app on an emulator, then tries the
standard OWASP MASTG resilience tests (Frida attach, repackage + re-sign,
root, debugger) and reports which ones the app blocked.

That needs tools on the developer's machine. This plan adds two commands:

| Command | Does |
|---|---|
| `aegis doctor` | Checks every tool. Changes nothing. |
| `aegis setup` | Installs what is missing. **Anything already present is skipped and counted as installed.** Asks once before installing; `--yes` skips the question. |

Running `aegis setup` twice in a row: the second run installs nothing.

## 2. Approach (decided — do not change without asking the owner)

Use what a Flutter developer already has, install only what is new.

* **Flutter is the source of truth** for the Android SDK and Java. Every
  Flutter Android developer has Android Studio, which brings the JDK (JBR),
  the SDK, adb, build-tools (apksigner, zipalign) and the emulator. aegis
  asks Flutter where they are, so it uses the same tools the app is built
  with. aegis **never installs Java or the Android SDK** itself; when they are
  missing it prints how to get them.
* **No apktool.** The repackage test does not need decompiling. aegis already
  reads APK zips in pure Dart (`lib/src/binary/`); `aegis probe` will change
  one entry, rewrite the zip, then `zipalign` + `apksigner` with a throwaway
  key from `keytool`. All three come with the SDK/JDK above.
* **bundletool is optional**: only needed to probe an `.aab`. `doctor` shows
  it as optional; `setup` installs it only with `--aab`. `aegis probe` will
  later call the same installer on first use.
* **Frida is the only really new tool**: a Python venv in `~/.aegis/venv`
  with pinned `frida` + `frida-tools`, and the `frida-server` of the exact
  same version for the emulator.
* **Emulator**: Android 14 *Google APIs* image (not *Google Play*: Play
  images refuse `adb root`, which frida-server needs). `arm64-v8a` on Apple
  Silicon / ARM Linux, `x86_64` otherwise. AVD name `aegis-probe`.
* **Not Docker**: an emulator in a container needs KVM, which macOS doesn't
  have.

## 3. Components

`id` is stable: it is the key in `tools.json`, in tests and in messages.

| id | What | Found by | If missing |
|---|---|---|---|
| `flutter` | Flutter SDK | `flutter --version --machine` on PATH | manual: install Flutter |
| `java` | JDK 17+ (`java`, `keytool`) | see §4.1 | manual: install Android Studio, or `flutter config --jdk-dir` |
| `android-sdk` | SDK root | see §4.1 | manual: install Android Studio |
| `cmdline-tools` | `sdkmanager`, `avdmanager` | `<sdk>/cmdline-tools/latest/bin/` (then any `cmdline-tools/*/bin/`) | manual: Android Studio → Settings → Languages & Frameworks → Android SDK → SDK Tools → *Android SDK Command-line Tools (latest)* |
| `platform-tools` | `adb` | `<sdk>/platform-tools/adb` | **setup**: `sdkmanager "platform-tools"` |
| `build-tools` | `apksigner`, `zipalign` ≥ 30.0.0 | newest `<sdk>/build-tools/<ver>/` that has both | **setup**: `sdkmanager "build-tools;36.0.0"` |
| `emulator` | `<sdk>/emulator/emulator` | file exists | **setup**: `sdkmanager "emulator"` |
| `system-image` | Android 14 Google APIs image | dir `<sdk>/system-images/android-34/google_apis/<abi>/` | **setup**: `sdkmanager "system-images;android-34;google_apis;<abi>"` (~1.5 GB) |
| `avd` | AVD `aegis-probe` | dir `<avdHome>/aegis-probe.avd` + `aegis-probe.ini` | **setup**: `avdmanager create avd` (§5.3) |
| `python` | Python ≥ 3.9 with `venv` | `python3 --version`, then `python3 -c "import venv"` | manual: `brew install python` / package manager |
| `frida` | pinned Frida in `~/.aegis/venv` | `<venv>/bin/frida --version` equals the pin | **setup**: venv + pip (§5.4) |
| `frida-server` | Android binary, same version | file `~/.aegis/tools/frida-server-<ver>-android-<arch>` | **setup**: download (§5.5) |
| `bundletool` (optional) | `bundletool.jar` | file `~/.aegis/tools/bundletool-<ver>.jar` | **setup --aab**: download |

`<abi>` = `arm64-v8a` or `x86_64`; frida `<arch>` = `arm64` or `x86_64`.
`<avdHome>` = `$ANDROID_AVD_HOME`, else `~/.android/avd`.

Dependencies (a step is skipped, shown as "waiting for X", when X is missing
and not installed earlier in the same run):

```
platform-tools, build-tools, emulator, system-image  ← android-sdk, cmdline-tools, java
avd           ← system-image, emulator
frida         ← python
```

`frida-server` and `bundletool` depend on nothing: their versions are pinned,
so the download does not need Frida or Java present first.

Install order: `platform-tools`, `build-tools`, `emulator`, `system-image`,
`avd`, `frida`, `frida-server`, `bundletool`.

## 4. Detection details

### 4.1 Android SDK and Java

Use the same order Flutter itself resolves them, so aegis works with exactly
the tools the app is built with. Stop at the first that gives an existing path:

1. `flutter config --machine` → JSON; keys `android-sdk` and `jdk-dir` are
   present only when the user set them. Ignore anything else in the JSON.
   This comes first: it is what the Flutter build obeys.
2. SDK: `ANDROID_HOME`, then `ANDROID_SDK_ROOT`. Java: Android Studio's JBR
   (the default Flutter uses), then `JAVA_HOME`, then `java` on PATH.
3. SDK: the default folder (step 4). Java: already covered in step 2.
4. `flutter --no-wrap doctor -v` (slow, 5–20 s: run it **once**, only if
   1–3 didn't give both, and cache the text for the run). In a terminal
   Flutter wraps long lines at spaces (seen on the owner's Mac:
   `Java binary at: /Applications/Android` + next line
   `Studio.app/Contents/jbr/Contents/home/bin/java`), so `--no-wrap` is
   required, and the parser still joins an indented line that doesn't start
   with `•` or `[` onto the previous one with one space. Parse with tolerant
   regexes:
   * SDK: `Android SDK at (.+)$`
   * Java: `Java binary at: (.+)$` → the JDK home is two levels up (`…/bin/java`).
Default SDK folder: `~/Library/Android/sdk` (macOS), `~/Android/Sdk` (Linux),
`%LOCALAPPDATA%\Android\Sdk` (Windows). Android Studio JBR:
`/Applications/Android Studio.app/Contents/jbr/Contents/Home` on macOS,
`/opt/android-studio/jbr` and `~/android-studio/jbr` on Linux.

The owner's real outputs are the test fixtures in
`test/fixtures/toolchain/` (home replaced with `/Users/dev`). On his Mac
`flutter config --machine` already has `jdk-dir` and `android-sdk`, so step 3
never runs there. Paths may differ in case (`Contents/home` vs
`Contents/Home`): compare paths as given, don't normalise case.

Java version: run `<jdk>/bin/java -version` (prints to **stderr**). Parse
`version "21.0.3"` → 21, `version "1.8.0_382"` → 8. Below 17 → manual.

### 4.2 Machine architecture

`Platform.version` ends with e.g. `on "macos_arm64"`. `arm64`/`aarch64` →
arm64, else x86_64. Running an x86_64 Dart under Rosetta on Apple Silicon
would report x86_64; also check `sysctl -n hw.optional.arm64` on macOS
(`1` → arm64).

## 5. Install details

General rules for every step:

* Downloads go to `<dest>.part`, then rename to `<dest>`. A failed download
  leaves no file that `doctor` would count as present.
* Downloads use Dart's `HttpClient` (follows redirects). User-Agent
  `aegis/<version>`. Send nothing else about the user.
* `sdkmanager` and `pip` run with the terminal attached
  (`ProcessStartMode.inheritStdio`) so the user sees progress and **accepts
  the Android SDK licenses themselves**. Never pipe `yes` into sdkmanager.
* Run sdkmanager/avdmanager with `JAVA_HOME` set to the JDK found in §4.1
  (they fail without Java on PATH, which is common when Java only exists in
  Android Studio's JBR).
* Before `system-image`, check free disk space in the SDK folder
  (`df -k <sdk>`); below 4 GB, warn and ask again (unless `--yes`).
* After all steps, run every check again and print the final table.

### 5.1 platform-tools, build-tools, emulator, system-image

One `sdkmanager --sdk_root=<sdk> <package…>` call with all the missing
packages of this group, so the user answers the license question once.

### 5.2 Pins — `lib/src/probe/pins.dart`

One file with every version aegis installs, so results are reproducible and
upgrading is one edit:

```dart
const fridaVersion = '17.26.2';       // frida on PyPI = frida-server on GitHub
const fridaToolsVersion = '14.13.0';  // requires frida >=17.26.0 <18
const buildToolsVersion = '36.0.0';   // what Flutter 3.41 uses
const systemImageApi = 34;
const bundletoolVersion = '1.18.3';
const avdName = 'aegis-probe';
```

Checked 2026-11-08: newest on PyPI, the frida-tools wheel's `Requires-Dist`,
and both release assets
(`frida-server-17.26.2-android-arm64.xz`, `bundletool-all-1.18.3.jar`)
answer 302 on github.com. To upgrade later, repeat those three checks.

### 5.3 AVD

```
avdmanager create avd -n aegis-probe -k "system-images;android-34;google_apis;<abi>" -d pixel_6
```

It asks "Do you wish to create a custom hardware profile?": write `no\n` to
its stdin. Do not pass `--force` (it would overwrite a user's AVD with the
same name; if `aegis-probe` exists it is already "present").

### 5.4 Frida

```
python3 -m venv ~/.aegis/venv
~/.aegis/venv/bin/python -m pip install "frida==<fridaVersion>" "frida-tools==<fridaToolsVersion>"
```

Use `python -m pip`, not the `pip` script. If the venv exists but has
another Frida version, re-run the pip line only (no new venv). Never use
the system pip or `--break-system-packages`.

### 5.5 frida-server

URL: `https://github.com/frida/frida/releases/download/<v>/frida-server-<v>-android-<arch>.xz`.
Decompress with `XZDecoder` from `package:archive` (new dependency,
`archive: '>=3.4.0 <5.0.0'`), write to
`~/.aegis/tools/frida-server-<v>-android-<arch>`, `chmod 755`. Other
versions' files in that folder are left alone.

### 5.6 bundletool (`--aab` only)

`https://github.com/google/bundletool/releases/download/<v>/bundletool-all-<v>.jar`
→ `~/.aegis/tools/bundletool-<v>.jar`. Fixed URL from the pin: no GitHub API
call.

### 5.7 `~/.aegis/tools.json`

Written at the end of `setup` (also when nothing was installed) so
`aegis probe` doesn't search again:

```json
{
  "schema": 1,
  "aegis": "<aegisVersion>",
  "tools": {
    "java": {"path": "/Applications/Android Studio.app/Contents/jbr/Contents/Home", "version": "21"},
    "android-sdk": {"path": "/Users/dev/Library/Android/sdk"},
    "frida": {"path": "/Users/dev/.aegis/venv/bin/frida", "version": "16.5.2"}
  }
}
```

Only present tools are listed. `probe` must still re-check a path before
using it (the file is a cache, not the truth).

## 6. Code layout

New folder `lib/src/probe/`. Nothing outside it changes except `bin/aegis.dart`
(new commands), `pubspec.yaml` (archive), `README.md`, `CHANGELOG.md`.

| File | Contents |
|---|---|
| `host.dart` | `abstract class Host` — the only door to the machine: `env`, `home`, `os`, `arch`, `fileExists`, `dirExists`, `listDir`, `mkdirs`, `writeFile`, `rename`, `makeExecutable`, `freeBytes`, `run` (captured), `runAttached` (inheritStdio, optional stdin text), `download(url, dest)`. `class SystemHost implements Host` with `dart:io`. **No other file in `probe/` imports `dart:io`.** |
| `pins.dart` | §5.2 |
| `toolchain.dart` | `enum ToolState { present, installable, manual, optional }`, `class ToolCheck { id, title, state, path, version, detail, fix }`, `class Toolchain(Host)` with `Future<List<ToolCheck>> checkAll({bool aab = false})` and one method per component. Pure logic over `Host`. |
| `setup.dart` | `SetupPlan plan(List<ToolCheck>, {bool aab})` — **pure**, no I/O; `Future<StepResult> install(String id)`; `String toolsJson(List<ToolCheck>)`. |
| `messages.dart` | en/ar strings for doctor/setup (same style as `reporters/i18n.dart`). |

CLI (`bin/aegis.dart`): add `doctor` and `setup` with `addCommand`, and
handle them at the top of `main` like `init` (return before the audit code).
Options: `--lang en|ar` (default: system language, `_systemLang()`), `-h`;
setup also `--yes/-y` and `--aab`. Add both to the root `--help` list.

Output (en; ar the same in Egyptian Arabic):

```
Resilience probe tools
  ✅ Flutter          3.35.0
  ✅ Java             21  (Android Studio JBR)
  ✅ Android SDK      ~/Library/Android/sdk
  ⬇️  System image     Android 14 Google APIs arm64 — aegis setup installs it
  ❌ Python           not found — brew install python
  ⏸  Frida            waiting for Python
  ℹ️  bundletool       optional, for .aab — aegis setup --aab
```

Exit codes: `doctor` 0 = all required present, 1 = something missing;
`setup` 0 = all required present at the end, 1 = something still missing or
the user said no, 2 = no terminal and no `--yes`. The confirmation accepts
`y`, `yes`, `اه`, `أيوه`, `ايوه`, `نعم` (trim, lowercase).

## 7. Steps and commits

Each step: write code + tests, run the syntax check, commit (message ends
with the two attribution lines the session asks for). Do not start the next
step with a red test.

1. **Fixtures.** Get `flutter doctor -v` and `flutter config --machine` from
   the owner's Mac (§4.1). Save to `test/fixtures/toolchain/`.
2. **`host.dart` + `pins.dart`** and `test/support/fake_host.dart`: an
   in-memory `FakeHost` (files, dirs, env, canned command results keyed by
   `"exe arg1 arg2"`, a log of every command and download, downloads that
   succeed or fail on request).
3. **`toolchain.dart` + `aegis doctor`**, tests in
   `test/toolchain_test.dart`:
   * Android Studio Mac (JBR, SDK, adb, cmdline-tools, Python): the right
     rows are present/installable.
   * SDK from `ANDROID_HOME` wins over `flutter doctor`; `flutter doctor` is
     not run when env + config found both.
   * `flutter doctor -v` fixture → SDK and JDK paths.
   * Java 1.8 → manual "17+ needed".
   * SDK without cmdline-tools → manual with the Android Studio hint.
   * Newest build-tools with both apksigner and zipalign wins.
   * frida in venv with another version → installable.
   * frida-server of another version → installable; matching → present.
   * x86_64 host → `x86_64` image and frida arch.
4. **`setup.dart` plan** (pure), tests:
   * Everything present → empty plan.
   * Order and dependencies (frida-server waits for frida, frida for
     python; a dependency installed earlier in the same plan unblocks).
   * bundletool only with `aab: true`.
   * All SDK packages go in one sdkmanager call.
5. **Installers + `aegis setup`**, tests with `FakeHost`:
   * Second run after a successful run installs nothing (idempotent).
   * Failed download leaves no file at `<dest>` (only `.part` removed).
   * sdkmanager gets `JAVA_HOME` from the found JDK.
   * avdmanager gets `no\n` on stdin and no `--force`.
   * frida-server: a tiny `.xz` fixture decompresses to the expected bytes.
   * `tools.json` lists only present tools, with `schema: 1`.
   * A failed step makes its dependents "skipped", the rest continues.
   * CLI: `aegis setup` without a terminal and without `--yes` exits 2.
6. **Docs**: README section "Prepare for the probe" (en + the Arabic
   section), CHANGELOG under `## Unreleased`. Do not bump `version:` (0.6.0
   ships with `aegis probe`).
7. **Hand-off on the Mac** (owner runs, you read the output):
   `dart pub get && dart analyze && dart test`, then
   `rm -rf .dart_tool/pub/bin/aegis`, `aegis doctor`, `aegis setup`,
   `aegis setup` again (must install nothing), `aegis doctor` (exit 0).

## 8. Do not

* Do not change existing commands, rules, scoring, reporters or their tests.
  All current tests must still pass unchanged.
* Do not install Java, the Android SDK, Flutter or Python. Print how.
* Do not use `sudo`, `brew`, `apt` or any system package manager.
* Do not write outside `~/.aegis`, except what `sdkmanager`/`avdmanager`
  write into the SDK and the AVD folder.
* Do not delete or overwrite anything that exists, except the `.part` files
  aegis created and a Frida reinstall inside `~/.aegis/venv`.
* Do not accept licenses on the user's behalf.
* No network and no real processes in tests (only `FakeHost`). Tests must
  pass on the CI matrix (ubuntu-latest, macos-latest).
* Do not write `aegis probe` or any attack/test logic here. This plan ends
  when the tools are installed.
* Do not push. The owner pushes. Do not touch the Aldrees repositories.

## 9. Working environment notes (for an agent in this session)

* The cloud container has no Dart. Check syntax with
  `python3 <scratchpad>/syncheck.py lib bin test` (tree-sitter, syntax only);
  real `dart analyze`/`dart test` run on the owner's Mac or in GitHub Actions.
* Work in `/home/claude/aegis`; move commits to the Mac repo
  (`~/AndroidStudioProjects/aegis`) with the tar of `.git` →
  `git fetch <dir> main && git merge --ff-only FETCH_HEAD` procedure. Never
  overwrite the Mac's `.git`.
* The global `aegis` is path-activated: after a change the owner must
  `rm -rf .dart_tool/pub/bin/aegis` in the aegis folder.
* A first attempt exists on branch `backup/doctor-setup-v1` (different
  approach: installed Java with brew, used apktool). Do not merge it; reuse
  code from it only where it matches this plan.

## 10. Done when

* `aegis doctor` on the owner's Mac shows every row correctly.
* `aegis setup` installs the missing ones, the second run installs nothing,
  and `aegis doctor` then exits 0.
* `dart analyze` clean, `dart test` green on the Mac and in GitHub Actions.
* README and CHANGELOG updated.
