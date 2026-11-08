# Plan: `aegis probe` (resilience verification)

Status: **in progress**. Base: `main` at `73ab8dc`. Depends on the toolchain
from `probe-toolchain.md` (done): `aegis setup` has installed the emulator,
the `aegis-probe` AVD, Frida + frida-server and the SDK tools, and recorded
their paths in `~/.aegis/tools.json`.

Read this whole file first. Small steps; each ends green (`dart analyze`,
`dart test`) and in a commit.

## 1. What it is

`aegis probe` checks whether an app's anti-tampering protection (freeRASP,
AppSealing or any other RASP — this is **vendor-agnostic**) actually works,
instead of only checking that a package is declared. It runs the developer's
**own** build on the `aegis-probe` emulator and, for each standard OWASP MASTG
resilience condition, observes whether the app's own protection reacts.

It is a verification harness, the runtime counterpart of the static rules: a
RASP that doesn't react to anything is worthless, and the only way to know is
to put the app in each condition and watch what it does.

Per check the outcome is one of:

* **blocked** — the app detected the condition and reacted (exited, refused,
  showed a block screen). Protection works. ✅
* **notBlocked** — the app ran normally under the condition. The protection
  the profile expects is absent or ineffective. This is a finding.
* **inconclusive** — the check couldn't run (a tool or the baseline launch
  failed, the emulator misbehaved). Never reported as pass or fail.

**Never decide an outcome from memory or assumption.** Every outcome comes
from something actually observed on the device (process state, logcat). When
nothing was observed, the outcome is inconclusive.

## 2. Checks (mapped to this repo's MASVS controls)

| id | Condition set up | Reads as *blocked* when | MASVS | MASTG |
|---|---|---|---|---|
| `baseline` | install + launch on a clean emulator | (precondition, not scored) app stays alive ~15 s | — | — |
| `root` | launch on the rootable google_apis image | app exits / shows a block screen / logs a root verdict | RESILIENCE-1 | MASTG-TEST-0048 |
| `debugger` | mark the app debuggable and attach the JDWP debugger | app detects the debugger and reacts | RESILIENCE-4 | MASTG-TEST-0045 |
| `hooking` | start frida-server and attach to the app | app detects instrumentation and reacts | RESILIENCE-4 | MASTG-TEST-0046 |
| `repackage` | change one trivial resource, re-sign with a throwaway key, reinstall | app detects the changed signature / integrity and reacts | RESILIENCE-2 | MASTG-TEST-0047 |

RESILIENCE-3 (anti-static-analysis / obfuscation) is static and already
covered by the APK rules; the probe does not test it.

**baseline is the gate.** If the app does not stay alive on the clean
emulator (e.g. it kills itself on an emulator it detects), every other check
is inconclusive and the report says so — a RASP that refuses to run at all on
an emulator cannot be probed this way, which is itself worth telling the user.

## 3. How "the app reacted" is observed

Heuristic, and its limits are stated in the report:

* **Alive check**: after the condition, is the app's process still running
  (`adb shell pidof <pkg>`) and still the foreground/responsive app after a
  fixed wait? Gone or crash-looping → reacted.
* **logcat**: capture `adb logcat` around the condition; a crash of the app's
  process, a `Process.killProcess`, or a FATAL/AndroidRuntime from the package
  counts as a reaction. (Matching only the app's own uid/pid, not arbitrary
  text, so it isn't fooled by unrelated log lines.)

Caveats the report must print:

* A **report-only** RASP (one that just logs to a backend and keeps running)
  cannot be observed from the device: it shows as notBlocked, with a note that
  a silent/server-side reaction is not visible here.
* **Emulator detection** may kill the baseline; then results are inconclusive,
  not failures.
* The probe shows what happened on **this** emulator and build, not a proof of
  security.

## 4. Scope / Do not

* Vendor-agnostic only: no per-product signatures, no "defeat AppSealing"
  logic. The probe sets a standard condition and observes; it does not try to
  bypass, disable or evade a specific protection.
* Only the app the user passes (`aegis probe <app.apk|.aab>`), on the
  `aegis-probe` emulator. Never another device, never an app the user didn't
  provide.
* Do not add novel evasion techniques; the conditions are the standard,
  published MASTG ones. This is a self-test for the developer's own app.
* No network beyond what `setup` already fetched. No changes to the existing
  rules, scoring or reporters in the first increments (probe has its own
  report; wiring probe findings into the score is a later, separate step).
* Tests use `FakeHost` only — no real emulator, adb, frida or processes in the
  test suite. Must pass on the CI matrix (ubuntu, macos).

## 5. Code layout

New files under `lib/src/probe/`:

| File | Contents |
|---|---|
| `probe_model.dart` | `enum ProbeStatus { blocked, notBlocked, inconclusive }`, `class ProbeCheck { id, masvs, mastg }`, `class ProbeResult { check, status, evidence, note }`, `class ProbeReport { app, checks:List<ProbeResult>, baselineAlive }`. Pure. |
| `observation.dart` | Pure functions that turn a device observation (process alive? logcat lines for the app's pid?) into a `ProbeStatus`. No I/O. This is where "don't guess" lives: the mapping from evidence → status, unit-tested. |
| `device.dart` | `class Device` over `Host`: adb wrappers (install, shell, pidof, logcat, uninstall), emulator boot + wait-for-boot, frida-server push/run, resign (apktool/zipalign/apksigner/keytool), bundletool aab→universal apk. Each a thin method; one place that touches the device. |
| `probe_runner.dart` | Orchestration: boot, baseline, then each check via `Device`, collecting `ProbeResult`s. Depends on `Device` + `observation.dart`, so it's drivable with a fake `Device`/`Host`. |
| `probe_report.dart` | Renders the `ProbeReport` (console en/ar first; json later). |

CLI: `aegis probe <app>` in `bin/aegis.dart` (like `doctor`/`setup`): reads
`~/.aegis/tools.json`, resolves the app (build newest if omitted, like
`run`), runs the probe, prints the report. Exit 0 when no notBlocked for the
active profile, 1 when a profile-required protection is notBlocked, 2 when it
couldn't run (baseline inconclusive, tools missing).

## 6. Steps

1. **`probe_model.dart` + `observation.dart`** and tests: evidence → status
   (alive+no-crash → notBlocked; process gone → blocked; app-pid FATAL in
   logcat → blocked; tool/baseline failure → inconclusive). Pure, no I/O.
2. **`device.dart`** over `Host`, with a fake-host test per wrapper (correct
   adb/emulator/frida/apksigner command lines; reads paths from tools.json).
3. **`probe_runner.dart`**: baseline gate + the checks, as pure orchestration
   over a `Device` seam; tests with a fake `Device` for each outcome and for
   "baseline dead → everything inconclusive".
4. **`aegis probe` CLI + `probe_report.dart`** (console en/ar), tests.
5. **Docs** (README + CHANGELOG), then verify on the owner's Mac against a
   real build (a RASP-protected build should show blocked; a plain build
   notBlocked).
6. **Later/optional**: json report, and feeding notBlocked results into the
   score as RESILIENCE findings.

## 7. Working notes

* Same as `probe-toolchain.md` §9: no Dart in the container (syntax-check with
  the tree-sitter script), move commits to the Mac with the tar-of-`.git` +
  `git fetch <dir> main && git merge --ff-only FETCH_HEAD` procedure, the
  owner runs `dart test` and the real probe, the owner pushes.
* Attribution lines on every commit as the session's reminder gives them.
