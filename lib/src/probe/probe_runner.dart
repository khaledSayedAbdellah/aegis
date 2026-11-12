/// Orchestrates `aegis probe` (doc/plans/probe.md §2–3): boot, baseline gate,
/// then each resilience check, each judged only from what was observed.
///
/// Pure orchestration over the [ProbeDevice] seam and [observation.dart], so
/// it runs against a fake device in tests. It applies the standard MASTG
/// condition for each check on the developer's own app and reads the app's
/// reaction; it never tries to defeat a protection.
library;

import 'device.dart';
import '../l10n/messages.g.dart';
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
            {String? noteAr,
            bool baselineAlive = false,
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
                ProbeResult(c, ProbeStatus.inconclusive,
                    note: note, noteAr: noteAr),
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
        return allInconclusive(En.androidControlStopped,
            noteAr: Ar.androidControlStopped,
            baselineNote: '${launchOut.trim()}\n${_tail(baselineLog)}');
      }

      Map<String, Object?> platformObservations = {};
      // Recorded before each observer starts, so a failed observer (no facts)
      // is distinguishable from one that never ran.
      final observerAttempts = <String>{};
      if (dev case final PlatformObserver observer) {
        try {
          emit('platform: inspecting the control application launch UI…');
          observerAttempts.add('control');
          platformObservations =
              await observer.platformObservation(package, pid);
        } catch (_) {
          emit(
              'platform: automatic observation unavailable; coverage remains partial.');
        }
      }
      final results = <ProbeResult>[
        ProbeResult(checkById('baseline'), ProbeStatus.notBlocked,
            evidence: En.androidBaselineAlive(seconds: wait.inSeconds),
            evidenceAr: Ar.androidBaselineAlive(seconds: wait.inSeconds),
            note: baselineRoot ? En.androidControlRoot : null,
            noteAr: baselineRoot ? Ar.androidControlRoot : null),
      ];

      Future<void> check(
          String id, Future<ProbeResult> Function(ProbeCheck) run) async {
        if (only != null && !only.contains(id)) return;
        final check = checkById(id);
        emit('check: ${check.title}…');
        try {
          if (appProbeVerdict(baselineLog, package, id, pid: pid) != null) {
            results.add(ProbeResult(check, ProbeStatus.inconclusive,
                note: En.androidControlVerdict,
                noteAr: Ar.androidControlVerdict));
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
              note: En.androidControlRoot, noteAr: Ar.androidControlRoot);
        }
        final rooted = rootDevice;
        if (rooted == null) {
          return ProbeResult(check, ProbeStatus.inconclusive,
              note: En.androidRootDeviceMissing,
              noteAr: Ar.androidRootDeviceMissing);
        }
        final boot = await rooted.bootEmulator(
            log: emit, logPath: '$workDir/root-emulator.log');
        if (boot != null) {
          return ProbeResult(check, ProbeStatus.inconclusive, note: boot);
        }
        if (!await rooted.rootAvailable()) {
          return ProbeResult(check, ProbeStatus.inconclusive,
              note: En.androidRootUnverified, noteAr: Ar.androidRootUnverified);
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
              applicable: false,
              note: En.androidNotDebuggable,
              noteAr: Ar.androidNotDebuggable);
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
          final observed = await _observe(fridaDevice, check, package,
              verifyBeforeAttach: separate,
              apply: () async =>
                  await fridaDevice.startFridaServer() ??
                  await fridaDevice.fridaAttach(package, wait),
              settleAfterApply: false);
          // Only an app still running under Frida can be observed with it. An
          // app that exited (its protection worked) or an inconclusive check
          // never makes this observation possible, so it is not requested.
          if (fridaDevice case final PlatformObserver observer
              when observed.status == ProbeStatus.notBlocked) {
            try {
              observerAttempts.add('instrumented');
              final extra =
                  await observer.instrumentedPlatformObservation(package);
              if (extra['verified'] == true) {
                // Preserve the stock launch facts separately from instrumented facts.
                platformObservations = {
                  ...extra,
                  'control': platformObservations
                };
              }
            } catch (_) {
              emit('platform: instrumented observation unavailable.');
            }
          }
          return observed;
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
              note: En.androidControlRestoreFailed,
              noteAr: Ar.androidControlRestoreFailed);
        }
        return _repackage(check, controlApks, package, workDir);
      });
      return ProbeReport(
          app: appLabel ?? appPath,
          apkIdentity: apkIdentity,
          baselineAlive: true,
          results: results,
          platformObservations: platformObservations,
          platformObserverAttempts: observerAttempts);
    } catch (e) {
      return allInconclusive(En.androidSetupFailed(error: e),
          noteAr: Ar.androidSetupFailed(error: e), emulatorError: '$e');
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
            note: En.androidProcessUnavailable(detail: _short(launch)),
            noteAr: Ar.androidProcessUnavailable(detail: _short(launch)));
      }
      if (verifyBeforeAttach) {
        await _sleep(wait);
        final logs = await dev.logcat();
        if (await dev.pidOf(package) != pid ||
            logcatShowsAppDeath(logs, pid: pid, package: package) ||
            appProbeVerdict(logs, package, check.id, pid: pid) != null) {
          return ProbeResult(check, ProbeStatus.inconclusive,
              note: En.androidFridaBaselineFailed,
              noteAr: Ar.androidFridaBaselineFailed);
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
          note: En.androidConflictingOutcomes,
          noteAr: Ar.androidConflictingOutcomes);
    }
    if (status != null && (status == ProbeStatus.blocked || alive && !death)) {
      final outcome = status == ProbeStatus.blocked ? 'blocked' : 'not-blocked';
      return ProbeResult(check, status,
          evidence: 'AegisProbe: ${check.id} $outcome');
    }
    if (status == null && alive && !death) {
      return ProbeResult(check, ProbeStatus.notBlocked,
          processOnly: true,
          evidence: En.androidProcessAliveVerified,
          evidenceAr: Ar.androidProcessAliveVerified);
    }

    String? detail;
    String? detailAr;
    var boundService = false;
    if (check.id == 'repackage' && (death || !alive)) {
      final cause = classifyRepackageReaction(logs, package: package, pid: pid);
      if (cause == CrashCause.boundService) {
        boundService = true;
        detail = En.androidBoundServiceFailed;
        detailAr = Ar.androidBoundServiceFailed;
      }
      if (cause == CrashCause.integrityCheck) {
        detail = En.androidIntegrityMentioned;
        detailAr = Ar.androidIntegrityMentioned;
      }
    }
    final observedPid = pid ?? appPids(logs, package).singleOrNull;
    if (status == null &&
        currentPid == null &&
        !boundService &&
        earlierExits != null &&
        observedPid != null) {
      final exits = await dev.exitInfo(package);
      if (exits != null &&
          observedSelfExit(earlierExits, exits, package, observedPid)) {
        return ProbeResult(check, ProbeStatus.blocked,
            processOnly: true,
            evidence: En.androidSelfExitVerified,
            evidenceAr: Ar.androidSelfExitVerified);
      }
    }
    final started = appStarted(logs, package, pid: pid);
    return ProbeResult(check, ProbeStatus.inconclusive,
        evidence: death
            ? En.androidAppCrashed
            : alive
                ? En.androidProcessStayedAlive
                : En.androidProcessMissing,
        evidenceAr: death
            ? Ar.androidAppCrashed
            : alive
                ? Ar.androidProcessStayedAlive
                : Ar.androidProcessMissing,
        noteAr: detailAr ??
            (started
                ? Ar.androidExitUnattributed
                : Ar.androidProcessNotObserved),
        note: detail ??
            (started
                ? En.androidExitUnattributed
                : En.androidProcessNotObserved));
  }

  Future<String?> _install(ProbeDevice device, List<String> apks) =>
      apks.length == 1 ? device.install(apks.single) : device.installApks(apks);

  Future<ProbeResult> _repackage(ProbeCheck check, List<String> apks,
      String package, String workDir) async {
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
          note: En.androidResignedInstallFailed(error: installErr),
          noteAr: Ar.androidResignedInstallFailed(error: installErr));
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
