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
    this.rootDevice,
    this.wait = const Duration(seconds: 8),
    Future<void> Function(Duration)? sleep,
  }) : _sleep = sleep ?? Future<void>.delayed;

  final ProbeDevice dev;
  final ProbeDevice? rootDevice;

  /// How long to let the app settle before reading its state.
  final Duration wait;
  final Future<void> Function(Duration) _sleep;

  /// Runs the probe. [only], when given, limits to those check ids. [log]
  /// receives a line at each stage, so the user sees progress.
  Future<ProbeReport> run({
    required String appPath,
    String? appLabel,
    List<String> splits = const [],
    List<String>? rootedApks,
    ProbeApkIdentity? apkIdentity,
    required String package,
    required String workDir,
    Set<String>? only,
    bool? debuggable,
    void Function(String)? log,
  }) async {
    final emit = log ?? (_) {};
    ProbeReport allInconclusive(String note,
            {bool baselineAlive = false,
            String? emulatorError,
            String? baselineNote}) =>
        ProbeReport(
          app: appLabel ?? appPath,
          apkIdentity: apkIdentity,
          baselineAlive: baselineAlive,
          emulatorError: emulatorError,
          baselineNote: baselineNote,
          results: [
            for (final c in probeChecks)
              if (c.id != 'baseline' && (only == null || only.contains(c.id)))
                ProbeResult(c, ProbeStatus.inconclusive, note: note),
          ],
        );

    final controlApks = [appPath, ...splits];
    final rootApks = rootedApks ?? controlApks;
    var installedOnControl = false;
    try {
      final bootErr =
          await dev.bootEmulator(log: emit, logPath: '$workDir/emulator.log');
      if (bootErr != null) {
        return allInconclusive(bootErr, emulatorError: bootErr);
      }
      if (rootDevice != null && !await dev.rootAvailable()) {
        await dev.stopFridaServer();
      } else {
        final reset = await dev.setAdbRoot(true);
        try {
          await dev.stopFridaServer();
        } finally {
          if (reset == null) {
            final unroot = await dev.setAdbRoot(false);
            if (unroot != null) throw StateError(unroot);
          }
        }
      }
      final baselineRoot = await dev.rootAvailable();

      emit('installing $package…');
      await dev.uninstall(package);
      final installErr = await _install(dev, controlApks);
      if (installErr != null) {
        return allInconclusive(installErr, emulatorError: installErr);
      }
      installedOnControl = true;

      emit('baseline: launching on the control emulator…');
      await dev.forceStop(package);
      await dev.clearLogcat();
      final launchOut = await dev.launch(package);
      final pid = await dev.waitForProcess(package, timeoutSeconds: 60);
      if (pid != null) await _sleep(wait);
      final baselineLog = await dev.logcat();
      if (pid == null ||
          await dev.pidOf(package) != pid ||
          logcatShowsAppDeath(baselineLog, pid: pid, package: package)) {
        return allInconclusive(
            'the app did not stay alive in the control launch',
            baselineNote: '${launchOut.trim()}\n${_tail(baselineLog)}');
      }

      final results = <ProbeResult>[
        ProbeResult(checkById('baseline'), ProbeStatus.notBlocked,
            evidence: 'same process stayed alive for ${wait.inSeconds}s',
            note: baselineRoot
                ? 'Root was already available in the control environment.'
                : null),
      ];

      Future<void> check(
          String id, Future<ProbeResult> Function(ProbeCheck) run) async {
        if (only != null && !only.contains(id)) return;
        final check = checkById(id);
        emit('check: ${check.title}…');
        try {
          if (appProbeVerdict(baselineLog, package, id, pid: pid) != null) {
            results.add(ProbeResult(check, ProbeStatus.inconclusive,
                note:
                    'The app emitted a verdict for this condition during the control launch.'));
            return;
          }
          results.add(await run(check));
        } catch (e) {
          results.add(ProbeResult(check, ProbeStatus.inconclusive, note: '$e'));
        }
      }

      await check('root', (check) async {
        if (baselineRoot) {
          return ProbeResult(check, ProbeStatus.inconclusive,
              note: 'Root was already available in the control environment.');
        }
        final rooted = rootDevice;
        if (rooted == null) {
          return ProbeResult(check, ProbeStatus.inconclusive,
              note: 'Supply a separate rooted emulator with --root-avd.');
        }
        final boot = await rooted.bootEmulator(
            log: emit, logPath: '$workDir/root-emulator.log');
        if (boot != null) {
          return ProbeResult(check, ProbeStatus.inconclusive, note: boot);
        }
        if (!await rooted.rootAvailable()) {
          return ProbeResult(check, ProbeStatus.inconclusive,
              note:
                  'Root availability could not be demonstrated on the rooted emulator.');
        }
        await rooted.uninstall(package);
        final error = await _install(rooted, rootApks);
        if (error != null) {
          return ProbeResult(check, ProbeStatus.inconclusive, note: error);
        }
        try {
          return await _observe(rooted, check, package);
        } finally {
          await rooted.uninstall(package);
        }
      });
      await check('debugger', (check) async {
        if (debuggable == false) {
          return ProbeResult(check, ProbeStatus.inconclusive,
              applicable: false, note: 'The installed APK is not debuggable.');
        }
        try {
          return await _observe(dev, check, package,
              apply: () => dev.attachDebugger(package));
        } finally {
          await dev.clearDebugApp();
        }
      });
      var controlRestored = true;
      await check('hooking', (check) async {
        final fridaDevice = rootDevice ?? dev;
        final separate = rootDevice != null;
        if (separate) {
          final boot = await fridaDevice.bootEmulator(
              log: emit, logPath: '$workDir/root-emulator.log');
          if (boot != null) {
            return ProbeResult(check, ProbeStatus.inconclusive, note: boot);
          }
          await fridaDevice.uninstall(package);
          final install = await _install(fridaDevice, rootApks);
          if (install != null) {
            return ProbeResult(check, ProbeStatus.inconclusive, note: install);
          }
        }
        var hasRoot = false;
        try {
          final error = await fridaDevice.setAdbRoot(true);
          if (error != null) {
            return ProbeResult(check, ProbeStatus.inconclusive, note: error);
          }
          hasRoot = true;
          if (separate) await fridaDevice.stopFridaServer();
          return await _observe(fridaDevice, check, package,
              verifyBeforeAttach: separate,
              apply: () async =>
                  await fridaDevice.startFridaServer() ??
                  await fridaDevice.fridaAttach(package, wait),
              settleAfterApply: false);
        } finally {
          if (!separate) controlRestored = false;
          try {
            try {
              if (hasRoot) await fridaDevice.stopFridaServer();
            } finally {
              final error = await fridaDevice.setAdbRoot(false);
              if (error != null && (hasRoot || !separate)) {
                throw StateError(error);
              }
            }
            if (!separate) controlRestored = true;
          } finally {
            if (separate) await fridaDevice.uninstall(package);
          }
        }
      });
      await check('repackage', (check) async {
        if (!controlRestored) {
          return ProbeResult(check, ProbeStatus.inconclusive,
              note: 'Could not restore the control environment after Frida.');
        }
        return _repackage(check, controlApks, package, workDir);
      });
      return ProbeReport(
          app: appLabel ?? appPath, apkIdentity: apkIdentity,
          baselineAlive: true, results: results);
    } catch (e) {
      return allInconclusive('Probe setup or control launch failed: $e',
          emulatorError: '$e');
    } finally {
      if (installedOnControl) await dev.uninstall(package);
    }
  }

  Future<ProbeResult> _observe(
    ProbeDevice dev,
    ProbeCheck check,
    String package, {
    Future<String?> Function()? apply,
    bool settleAfterApply = true,
    bool verifyBeforeAttach = false,
  }) async {
    await dev.forceStop(package);
    await dev.clearLogcat();
    final earlierExits = await dev.exitInfo(package);
    final launch = await dev.launch(package);
    final pid = await dev.waitForProcess(package, timeoutSeconds: 40);
    if (apply != null) {
      if (pid == null) {
        return ProbeResult(check, ProbeStatus.inconclusive,
            note: 'App process unavailable: ${_short(launch)}');
      }
      if (verifyBeforeAttach) {
        await _sleep(wait);
        final logs = await dev.logcat();
        if (await dev.pidOf(package) != pid ||
            logcatShowsAppDeath(logs, pid: pid, package: package) ||
            appProbeVerdict(logs, package, check.id, pid: pid) != null) {
          return ProbeResult(check, ProbeStatus.inconclusive,
              note:
                  'The app did not establish a clean Frida baseline on the rooted emulator.');
        }
      }
      // A reaction to startup alone cannot prove that an attachment was detected.
      await dev.clearLogcat();
      final error = await apply();
      if (error != null) {
        return ProbeResult(check, ProbeStatus.inconclusive, note: error);
      }
    }
    if (settleAfterApply && pid != null) await _sleep(wait);
    final logs = await dev.logcat();
    final currentPid = await dev.pidOf(package);
    final alive = pid != null && currentPid == pid;
    final death = logcatShowsAppDeath(logs, pid: pid ?? -1, package: package);
    final status = appProbeVerdict(logs, package, check.id, pid: pid);
    if (status == ProbeStatus.inconclusive) {
      return ProbeResult(check, ProbeStatus.inconclusive,
          note: 'The app emitted conflicting outcomes for this condition.');
    }
    if (status != null && (status == ProbeStatus.blocked || alive && !death)) {
      final outcome = status == ProbeStatus.blocked ? 'blocked' : 'not-blocked';
      return ProbeResult(check, status,
          evidence: 'AegisProbe: ${check.id} $outcome');
    }
    if (status == null && alive && !death) {
      return ProbeResult(check, ProbeStatus.notBlocked,
          processOnly: true,
          evidence: 'The same app process stayed alive after the condition was verified.');
    }

    String? detail;
    var boundService = false;
    if (check.id == 'repackage' && (death || !alive)) {
      final cause = classifyRepackageReaction(logs, package: package, pid: pid);
      if (cause == CrashCause.boundService) {
        boundService = true;
        detail = 'A certificate-bound service failed.';
      }
      if (cause == CrashCause.integrityCheck) {
        detail = 'Logs mention an integrity check.';
      }
    }
    final observedPid = pid ?? appPids(logs, package).singleOrNull;
    if (status == null && currentPid == null && !boundService &&
        earlierExits != null && observedPid != null) {
      final exits = await dev.exitInfo(package);
      if (exits != null && observedSelfExit(earlierExits, exits, package, observedPid)) {
        return ProbeResult(check, ProbeStatus.blocked, processOnly: true,
            evidence: 'Android recorded that the observed app process exited on its own after the condition.');
      }
    }
    final started = appStarted(logs, package, pid: pid);
    return ProbeResult(check, ProbeStatus.inconclusive,
        evidence: death
            ? 'app crashed or was killed'
            : alive
                ? 'app process stayed alive'
                : 'app process unavailable',
        note: detail ?? (started
            ? 'The app exit could not be attributed to the tested condition.'
            : 'No app process was observed under the tested condition.'));
  }

  Future<String?> _install(ProbeDevice device, List<String> apks) =>
      apks.length == 1 ? device.install(apks.single) : device.installApks(apks);

  Future<ProbeResult> _repackage(
      ProbeCheck check, List<String> apks, String package, String workDir) async {
    final ks = '$workDir/aegis-probe.jks';
    final resigned = <String>[];
    for (final apk in apks) {
      final out = '$workDir/aegis-resigned-${resigned.length}.apk';
      final signErr = await dev.resignWithNewKey(apk, out, ks);
      if (signErr != null) {
        return ProbeResult(check, ProbeStatus.inconclusive, note: signErr);
      }
      resigned.add(out);
    }
    await dev.uninstall(package);
    final installErr = await _install(dev, resigned);
    if (installErr != null) {
      return ProbeResult(check, ProbeStatus.inconclusive,
          note: 'could not install the re-signed build: $installErr');
    }
    return _observe(dev, check, package);
  }

  static String _short(String s, {int max = 200}) {
    final one = s.replaceAll(RegExp(r'\s+'), ' ').trim();
    return one.length > max ? '${one.substring(0, max)}…' : one;
  }

  /// The last few non-empty lines of [logcat], for a failure note.
  static String _tail(String logcat, {int lines = 8}) {
    final ls = logcat
        .split('\n')
        .map((l) => l.trimRight())
        .where((l) => l.isNotEmpty)
        .toList();
    return (ls.length > lines ? ls.sublist(ls.length - lines) : ls).join('\n');
  }
}
