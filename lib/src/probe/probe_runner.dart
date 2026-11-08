/// Orchestrates `aegis probe` (docs/plans/probe.md §2–3): boot, baseline gate,
/// then each resilience check, each judged only from what was observed.
///
/// Pure orchestration over the [ProbeDevice] seam and [observation.dart], so
/// it runs against a fake device in tests. It applies the standard MASTG
/// condition for each check on the developer's own app and reads the app's
/// reaction; it never tries to defeat a protection.
library;

import 'device.dart';
import 'observation.dart';
import 'probe_model.dart';

class ProbeRunner {
  ProbeRunner(
    this.dev, {
    this.wait = const Duration(seconds: 8),
    Future<void> Function(Duration)? sleep,
  }) : _sleep = sleep ?? Future<void>.delayed;

  final ProbeDevice dev;

  /// How long to let the app settle before reading its state.
  final Duration wait;
  final Future<void> Function(Duration) _sleep;

  /// Runs the probe. [only], when given, limits to those check ids. [log]
  /// receives a line at each stage, so the user sees progress.
  Future<ProbeReport> run({
    required String appPath,
    required String package,
    required String workDir,
    Set<String>? only,
    void Function(String)? log,
  }) async {
    log ??= (_) {};
    ProbeReport allInconclusive(String note,
            {bool baselineAlive = false, String? emulatorError, String? baselineNote}) =>
        ProbeReport(
          app: appPath,
          baselineAlive: baselineAlive,
          emulatorError: emulatorError,
          baselineNote: baselineNote,
          results: [
            for (final c in probeChecks)
              if (c.id != 'baseline')
                ProbeResult(c, ProbeStatus.inconclusive, note: note),
          ],
        );

    final bootErr = await dev.bootEmulator(log: log, logPath: '$workDir/emulator.log');
    if (bootErr != null) return allInconclusive(bootErr, emulatorError: bootErr);
    await dev.adbRoot();

    log('installing $package…');
    // Clear any build left by an earlier probe (a re-signed one would make
    // installing the original fail on a signature mismatch).
    await dev.uninstall(package);
    final installErr = await dev.install(appPath);
    if (installErr != null) return allInconclusive(installErr, emulatorError: installErr);

    // Baseline: does the app come up and stay alive on the clean emulator?
    log('baseline: launching on a clean emulator…');
    final launchOut = await dev.launch(package);
    final startPid = await dev.waitForProcess(package, timeoutSeconds: 60);
    var baselineAlive = startPid != null;
    if (baselineAlive) {
      await _sleep(wait); // settle, then confirm it is still up
      baselineAlive = (await dev.pidOf(package)) != null;
    }
    if (!baselineAlive) {
      final note = StringBuffer();
      if (launchOut.trim().isNotEmpty) note.writeln('launch: ${launchOut.trim()}');
      note.write(_tail(await dev.logcat()));
      return allInconclusive(
          'the app did not stay alive on a clean emulator '
          '(emulator detection, a crash, or a slow first launch)',
          baselineAlive: false,
          baselineNote: note.toString());
    }

    final results = <ProbeResult>[
      ProbeResult(checkById('baseline'), ProbeStatus.notBlocked,
          evidence: 'stayed alive ${wait.inSeconds}s'),
    ];
    bool wanted(String id) => only == null || only.contains(id);

    if (wanted('root')) {
      log('check: root detection…');
      // The emulator is already rooted (adbRoot). Relaunch and watch.
      results.add(await _observe(checkById('root'), package, () async => true));
    }
    if (wanted('hooking')) {
      log('check: Frida instrumentation…');
      results.add(await _observe(checkById('hooking'), package, () async {
        final err = await dev.startFridaServer();
        if (err != null) return false;
        await dev.fridaAttach(package);
        return true;
      }));
    }
    if (wanted('debugger')) {
      log('check: debugger…');
      final r = await _observe(checkById('debugger'), package, () async {
        final err = await dev.attachDebugger(package);
        return err == null;
      }, relaunch: false);
      await dev.clearDebugApp();
      // A debugger can only attach to a debuggable build; a release build is
      // not, so an inconclusive here usually means exactly that.
      results.add(r.status == ProbeStatus.inconclusive
          ? ProbeResult(r.check, r.status,
              evidence: r.evidence,
              note: 'a debugger can only attach to a debuggable build; '
                  'release builds are not debuggable')
          : r);
    }
    if (wanted('repackage')) {
      log('check: repackaging / integrity…');
      results.add(await _repackage(appPath, package, workDir));
    }

    return ProbeReport(app: appPath, baselineAlive: true, results: results);
  }

  /// Fresh-launches the app, applies [condition], waits, and judges the app's
  /// state. [relaunch] is false when the condition launches the app itself
  /// (the debugger case).
  Future<ProbeResult> _observe(
    ProbeCheck check,
    String package,
    Future<bool> Function() condition, {
    bool relaunch = true,
  }) async {
    int? pid;
    if (relaunch) {
      await dev.launch(package);
      pid = await dev.waitForProcess(package, timeoutSeconds: 40);
    } else {
      pid = await dev.pidOf(package);
    }
    final aliveBefore = pid != null;
    await dev.clearLogcat();
    final setupOk = await condition();
    await _sleep(wait);
    final aliveAfter = await dev.isAlive(package);
    final death = logcatShowsAppDeath(await dev.logcat(), pid: pid ?? -1, package: package);
    final status = statusOf(Observation(
        setupOk: setupOk,
        aliveBefore: aliveBefore,
        aliveAfter: aliveAfter,
        appDeathLogged: death));
    return ProbeResult(check, status, evidence: _evidence(status, aliveAfter, death));
  }

  Future<ProbeResult> _repackage(String appPath, String package, String workDir) async {
    final check = checkById('repackage');
    final out = '$workDir/aegis-resigned.apk';
    final ks = '$workDir/aegis-probe.jks';
    final signErr = await dev.resignWithNewKey(appPath, out, ks);
    if (signErr != null) {
      return ProbeResult(check, ProbeStatus.inconclusive, note: signErr);
    }
    // Remove the original first: Android rejects installing a differently
    // signed APK over it, and that rejection is Android's, not the app's
    // anti-tampering. A fresh install of the re-signed build is the real test.
    await dev.uninstall(package);
    final installErr = await dev.install(out);
    if (installErr != null) {
      return ProbeResult(check, ProbeStatus.inconclusive,
          note: 'could not install the re-signed build: $installErr');
    }
    await dev.launch(package);
    final pid = await dev.waitForProcess(package, timeoutSeconds: 40);
    final logcat = await dev.logcat();
    final death = logcatShowsAppDeath(logcat, pid: pid ?? -1, package: package);
    final status = statusOf(Observation(
        setupOk: true, aliveBefore: true, aliveAfter: pid != null, appDeathLogged: death));
    String? note;
    if (status == ProbeStatus.blocked) {
      note = switch (classifyRepackageReaction(logcat)) {
        CrashCause.integrityCheck =>
          "the crash references a signature/integrity check — likely the app's own anti-tampering",
        CrashCause.boundService =>
          'the crash references a signature-bound service (e.g. a Google API key tied to the '
              'original cert) — this may not be the app\'s own anti-tampering',
        CrashCause.unknown =>
          "cannot tell if this is the app's integrity check or a signature-bound service failing",
      };
    }
    return ProbeResult(check, status, evidence: _evidence(status, pid != null, death), note: note);
  }

  String _evidence(ProbeStatus status, bool aliveAfter, bool death) => switch (status) {
        ProbeStatus.blocked =>
          death ? 'app crashed/was killed' : 'app exited after the condition',
        ProbeStatus.notBlocked => 'app kept running normally',
        ProbeStatus.inconclusive => 'could not observe',
      };

  /// The last few non-empty lines of [logcat], for a failure note.
  static String _tail(String logcat, {int lines = 8}) {
    final ls = logcat.split('\n').map((l) => l.trimRight()).where((l) => l.isNotEmpty).toList();
    return (ls.length > lines ? ls.sublist(ls.length - lines) : ls).join('\n');
  }
}
