/// Resilience probes against explicitly selected iOS targets.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as p;

import '../binary/ios_signature.dart';
import '../binary/ipa.dart';
import '../l10n/messages.g.dart';
import 'ios_device.dart';
import 'ios_simulator_build.dart';
import 'ios_simulator_partial.dart';
import 'probe_model.dart';
import 'toolchain.dart';

const iosProbeChecks = [
  ProbeCheck('jailbreak', En.checkJailbreak, masvs: 'MASVS-RESILIENCE-1'),
  ProbeCheck('ios-debugger', En.checkIosDebugger,
      masvs: 'MASVS-RESILIENCE-4'),
  ProbeCheck('ios-hooking', En.checkIosHooking,
      masvs: 'MASVS-RESILIENCE-4'),
  ProbeCheck('ios-repackage', En.checkIosRepackage,
      masvs: 'MASVS-RESILIENCE-2'),
];

typedef _Launched = ({
  IosDevice target,
  IosCommand console,
  String app,
  String bundle,
  String executable,
});

typedef _SimulatorGadget = ({String library, bool Function(int) verify});

class IosProbeRunner {
  IosProbeRunner({this.wait = const Duration(seconds: 8)});

  final Duration wait;

  Future<ProbeOutcome> run(
    String path, {
    String? controlId,
    String? jailbreakId,
    String? resignedIpa,
    String? simulatorId,
    String? simulatorApp,
    String? projectRoot,
    String? simulatorFlavor,
    String? simulatorTarget,
    Set<String>? only,
    void Function(String)? log,
  }) async {
    if (!Platform.isMacOS) {
      return const ProbeOutcome.skipped(
          En.iosRequiresXcode, skippedAr: Ar.iosRequiresXcode);
    }
    if (only != null && only.contains('root')) {
      return const ProbeOutcome.skipped(En.iosOnlyJailbreak, skippedAr: Ar.iosOnlyJailbreak);
    }
    final requested = iosProbeChecks
        .where((check) =>
            only == null || only.contains(check.id.replaceFirst('ios-', '')))
        .toList();
    final simulator = simulatorId != null || simulatorApp != null;
    if (simulator &&
        (simulatorId == null ||
            (simulatorApp == null && projectRoot == null) ||
            controlId != null ||
            jailbreakId != null ||
            resignedIpa != null)) {
      return const ProbeOutcome.skipped(
          En.iosSimulatorConfig, skippedAr: Ar.iosSimulatorConfig);
    }
    final selected = simulator ? simulatorId : controlId;
    if (selected == null) {
      return const ProbeOutcome.skipped(
          En.iosControlMissing, skippedAr: Ar.iosControlMissing);
    }
    final work = Directory.systemTemp.createTempSync('aegis-ios-probe-');
    RandomAccessFile? lock;
    try {
      lock = File(p.join(Directory.systemTemp.path, 'aegis-ios-probe.lock'))
          .openSync(mode: FileMode.append);
      try {
        lock.lockSync(FileLock.exclusive);
      } on FileSystemException {
        return const ProbeOutcome.skipped(
            En.iosProbeBusy, skippedAr: Ar.iosProbeBusy);
      }
      final original = IpaContext.load(path);
      final matchedSimulatorApp = simulator
          ? await IosSimulatorBuilder().ensure(original,
              project: projectRoot,
              app: simulatorApp,
              flavor: simulatorFlavor,
              target: simulatorTarget,
              log: log)
          : null;
      final debuggable = original.machO
          .any((slice) => slice.entitlements?['get-task-allow'] == true);
      if (!simulator &&
          jailbreakId == null &&
          !debuggable &&
          requested.length == 1 &&
          requested.single.id == 'ios-hooking') {
        return const ProbeOutcome.skipped(En.iosFridaNeedsDevelopment, skippedAr: Ar.iosFridaNeedsDevelopment);
      }
      final control = IosDevice(selected, work, simulator: simulator);
      final controlUdid = await control.verifyTarget();
      final root = jailbreakId == null ? null : IosDevice(jailbreakId, work);
      String? rootUdid;
      String? rootError;
      if (root != null &&
          requested.any((c) => c.id == 'jailbreak' || c.id == 'ios-hooking')) {
        try {
          rootUdid = await root.verifyTarget();
          if (rootUdid.toLowerCase() == controlUdid.toLowerCase()) {
            throw StateError('Use different stock and jailbroken devices.');
          }
        } catch (e) {
          rootUdid = null;
          rootError = '$e';
        }
      }
      final app =
          matchedSimulatorApp ?? original.stage(_folder(work, 'original'));
      final signature = simulator
          ? null
          : await verifyIosSignature(app, _folder(work, 'signature'));
      if (!simulator && signature?.valid != true) {
        return const ProbeOutcome.skipped(
            En.iosSignatureRequired, skippedAr: Ar.iosSignatureRequired);
      }

      final installed = <IosDevice>{};
      final results = <ProbeResult>[];
      var baselineAlive = false;
      String? baselineNote;
      String? baselineNoteAr;
      try {
        log?.call('iOS: installing the control build…');
        await _install(control, app, original.bundleId, installed);
        await _withLaunch(control, original, (launch, pid) async {
          if (pid != null) {
            await Future<void>.delayed(wait);
            baselineAlive = await _sameProcess(launch, pid);
          }
          if (!baselineAlive) {
            baselineNote = [
              En.probeControlDead,
              ...launch.console.errors,
            ].join('\n');
          }
          if (!baselineAlive) baselineNoteAr = [Ar.probeControlDead, ...launch.console.errors].join('\n');
          for (final check in requested) {
            if (_verdict(launch.console, check, 0) != null) {
              results.add(_unknown(check,
                  En.iosControlReported, messageAr: Ar.iosControlReported));
            }
          }
        });
        if (!baselineAlive) {
          results
            ..clear()
            ..addAll(requested.map((check) =>
                _unknown(check, En.iosControlStopped, messageAr: Ar.iosControlStopped)));
        } else {
          results.insert(
              0,
              ProbeResult(checkById('baseline'), ProbeStatus.notBlocked,
                  evidence:
                      En.iosAlive(seconds: wait.inSeconds),
                  evidenceAr: Ar.iosAlive(seconds: wait.inSeconds),
                  note: simulator
                      ? En.iosSimulatorBuild : En.iosStockDevice,
                  noteAr: simulator ? Ar.iosSimulatorBuild : Ar.iosStockDevice));
          String? rootInstallError;
          for (final check in requested) {
            if (results.any((r) => r.check.id == check.id)) continue;
            log?.call('iOS: ${check.title}…');
            try {
              if (simulator && check.id == 'ios-hooking') {
                final tools = Toolchain(control.host);
                if (!tools.checkIosGadget(simulator: true).ok) {
                  results.add(_unknown(check,
                      En.iosInstallSimulatorGadget, messageAr: Ar.iosInstallSimulatorGadget));
                  continue;
                }
                final gadget = await _prepareSimulatorFrida(
                    control, original.bundleId, tools.iosSimulatorGadgetPath);
                results.add(await _observe(control, original, check,
                    gadget: gadget,
                    condition:
                        En.iosGadgetVerified, conditionAr: Ar.iosGadgetVerified));
              } else if (simulator && check.id == 'jailbreak') {
                results
                    .add(await _simulatorJailbreak(control, original, check));
              } else if (simulator && check.id == 'ios-repackage') {
                final modified = await prepareSimulatorResign(control, app);
                await control.uninstall(original.bundleId);
                installed.remove(control);
                await _install(
                    control, modified.app, original.bundleId, installed);
                final installedPath =
                    await control.installedApp(original.bundleId);
                if (installedPath == null ||
                    (await simulatorSignature(control, installedPath)) !=
                        modified.after) {
                  throw StateError(
                      'The installed Simulator signature does not match the prepared copy.');
                }
                final observed = await _observe(control, original, check,
                    condition: En.iosSignatureChanged(beforeId: modified.before.identifier, beforeHash: modified.before.hash, afterId: modified.after.identifier, afterHash: modified.after.hash),
                    conditionAr: Ar.iosSignatureChanged(beforeId: modified.before.identifier, beforeHash: modified.before.hash, afterId: modified.after.identifier, afterHash: modified.after.hash));
                results.add(_partial(observed));
              } else if (check.id == 'ios-hooking' && root == null) {
                if (!debuggable) {
                  results.add(_unknown(check, En.iosFridaNeedsDevelopment, messageAr: Ar.iosFridaNeedsDevelopment));
                  continue;
                }
                final tools = Toolchain(control.host);
                if (!(await tools.checkFrida()).ok ||
                    !tools.checkIosGadget().ok) {
                  results.add(_unknown(check,
                      En.iosInstallFrida, messageAr: Ar.iosInstallFrida));
                  continue;
                }
                results.add(await _observe(control, original, check,
                    attach: (pid) => attachIosFrida(
                        tools.venvExe('python'), controlUdid, pid,
                        gadgetCache: tools.iosFridaCache),
                    attachTimeout: const Duration(seconds: 30),
                    proof: (pid) => 'AEGIS_IOS_FRIDA_$pid',
                    condition:
                        En.iosStockFridaVerified, conditionAr: Ar.iosStockFridaVerified));
              } else if (check.id == 'jailbreak' || check.id == 'ios-hooking') {
                final udid = rootUdid;
                if (root == null || udid == null) {
                  results.add(_unknown(
                      check,
                      rootError ??
                          En.iosJailbreakDeviceMissing, messageAr: rootError ?? Ar.iosJailbreakDeviceMissing));
                  continue;
                }
                if (!await verifyIosJailbreak(udid, root.host)) {
                  results.add(_unknown(check,
                      En.iosRootUnverified, messageAr: Ar.iosRootUnverified));
                  continue;
                }
                if (!installed.contains(root) && rootInstallError == null) {
                  try {
                    await _install(root, app, original.bundleId, installed);
                  } catch (e) {
                    rootInstallError = '$e';
                  }
                }
                if (rootInstallError != null) {
                  results.add(_unknown(check, rootInstallError));
                  continue;
                }
                results.add(check.id == 'jailbreak'
                    ? await _observe(root, original, check,
                        condition:
                            En.iosRootVerified, conditionAr: Ar.iosRootVerified)
                    : await _observe(root, original, check,
                        attach: (pid) =>
                            attachIosFrida(_fridaPython(), udid, pid),
                        proof: (pid) => 'AEGIS_IOS_FRIDA_$pid',
                        condition:
                            En.iosFridaVerified, conditionAr: Ar.iosFridaVerified));
              } else if (check.id == 'ios-debugger') {
                if (!simulator &&
                    original.machO.every((slice) =>
                        slice.entitlements != null &&
                        slice.entitlements!['get-task-allow'] != true)) {
                  results.add(_unknown(check,
                      En.iosDebuggerNeedsDevelopment, messageAr: Ar.iosDebuggerNeedsDevelopment));
                  continue;
                }
                results.add(await _observe(control, original, check,
                    attach: control.debugger,
                    proof: (pid) => 'AEGIS_IOS_DEBUG_$pid',
                    condition:
                        En.iosDebuggerVerified, conditionAr: Ar.iosDebuggerVerified));
              } else {
                if (resignedIpa == null) {
                  results.add(_unknown(check,
                      En.iosResignedMissing, messageAr: Ar.iosResignedMissing));
                  continue;
                }
                final alternative = IpaContext.load(resignedIpa);
                final alternateApp = await _verifyResigned(
                    original, app, signature!, alternative, work);
                await control.uninstall(original.bundleId);
                installed.remove(control);
                await _install(
                    control, alternateApp, original.bundleId, installed);
                results.add(await _observe(control, alternative, check,
                    condition:
                        En.iosCertificateChanged, conditionAr: Ar.iosCertificateChanged));
              }
            } catch (e) {
              final unknown = _unknown(check, '$e');
              results.add(simulator &&
                      (check.id == 'jailbreak' || check.id == 'ios-repackage')
                  ? _partial(unknown)
                  : unknown);
            }
          }
        }
      } finally {
        for (final target in installed) {
          try {
            await target.uninstall(original.bundleId);
          } catch (e) {
            log?.call(
                'iOS: could not remove the test install from ${target.id}: $e');
          }
        }
      }
      return ProbeOutcome.ran(ProbeReport(
        app: matchedSimulatorApp ?? path,
        baselineAlive: baselineAlive,
        baselineNote: baselineNote,
        baselineNoteAr: baselineNoteAr,
        platform: simulator ? 'ios-simulator' : 'ios',
        results: results,
      ));
    } on Exception catch (e) {
      return ProbeOutcome.skipped('$e');
    } on StateError catch (e) {
      return ProbeOutcome.skipped(e.message);
    } finally {
      lock?.closeSync();
      work.deleteSync(recursive: true);
    }
  }

  Future<ProbeResult> _simulatorJailbreak(
      IosDevice target, IpaContext ipa, ProbeCheck check) async {
    final helper = await SimulatorIndicators.prepare(target, ipa.bundleId);
    final control = helper.session(enabled: false);
    final clean = await _withLaunch(target, ipa, (launch, pid) async {
      await Future<void>.delayed(wait);
      return pid != null &&
          control.events(pid).contains('ready') &&
          await _sameProcess(launch, pid) &&
          _verdict(launch.console, check, 0) == null;
    },
        simulatorLibrary: helper.library,
        simulatorEnvironment: control.environment);
    if (!clean) {
      return _partial(_unknown(check,
          En.iosIndicatorControlFailed, messageAr: Ar.iosIndicatorControlFailed));
    }
    final injected = helper.session(enabled: true);
    return _withLaunch(target, ipa, (launch, pid) async {
      await Future<void>.delayed(wait);
      if (pid == null) {
        return _partial(
            _unknown(check, En.iosIndicatorPidMissing, messageAr: Ar.iosIndicatorPidMissing));
      }
      final events = injected.events(pid);
      if (!events.contains('ready') || events.contains('failed')) {
        return _partial(_unknown(check,
            En.iosIndicatorProofMissing, messageAr: Ar.iosIndicatorProofMissing));
      }
      final queries = events.where((e) => e.startsWith('query:')).toSet();
      final alive = await _sameProcess(launch, pid);
      final verdict = _verdict(launch.console, check, 0);
      final queryList = queries.isEmpty ? '' : ' (${queries.join(', ')})';
      final evidence = En.iosIndicatorsVerified(pid: pid, count: queries.length, queries: queryList);
      final evidenceAr = Ar.iosIndicatorsVerified(pid: pid, count: queries.length, queries: queryList);
      if (verdict == ProbeStatus.blocked ||
          verdict == null &&
              !alive &&
              queries.isNotEmpty &&
              events.contains('normal-exit')) {
        return _partial(ProbeResult(check, ProbeStatus.blocked,
            processOnly: verdict == null,
            evidence:
                '$evidence${verdict == null ? En.iosIndicatorExit : En.iosReportedBlock}',
            evidenceAr: '$evidenceAr${verdict == null ? Ar.iosIndicatorExit : Ar.iosReportedBlock}'));
      }
      if (verdict != ProbeStatus.inconclusive && alive) {
        return _partial(ProbeResult(check, ProbeStatus.notBlocked,
            processOnly: verdict == null,
            evidence:
                '$evidence${En.iosAlive(seconds: wait.inSeconds)} ${queries.isEmpty ? En.iosNoIndicatorQuery : ''}',
            evidenceAr: '$evidenceAr${Ar.iosAlive(seconds: wait.inSeconds)} ${queries.isEmpty ? Ar.iosNoIndicatorQuery : ''}'));
      }
      return _partial(ProbeResult(check, ProbeStatus.inconclusive,
          evidence:
              '$evidence${En.iosAmbiguousOutcome}',
          evidenceAr: '$evidenceAr${Ar.iosAmbiguousOutcome}'));
    },
        simulatorLibrary: helper.library,
        simulatorEnvironment: injected.environment);
  }

  Future<void> _install(IosDevice target, String app, String bundle,
      Set<IosDevice> installed) async {
    if (await target.installedApp(bundle) != null) {
      throw StateError(
          'The target already contains $bundle. Use a dedicated device without this app installed.');
    }
    await target.install(app);
    installed.add(target);
  }

  Future<T> _withLaunch<T>(
      IosDevice target, IpaContext ipa, Future<T> Function(_Launched, int?) run,
      {String? simulatorLibrary,
      Map<String, String> simulatorEnvironment = const {}}) async {
    final app = await target.installedApp(ipa.bundleId);
    if (app == null || app.isEmpty) {
      throw StateError('Xcode did not provide the installed application path.');
    }
    final previous = await target.pid(app, ipa.executable);
    final console = await target.launch(ipa.bundleId,
        simulatorLibrary: simulatorLibrary,
        simulatorEnvironment: simulatorEnvironment);
    final session = (
      target: target,
      console: console,
      app: app,
      bundle: ipa.bundleId,
      executable: ipa.executable
    );
    int? pid;
    try {
      final clock = Stopwatch()..start();
      while (clock.elapsed < const Duration(seconds: 15) &&
          console.exitCode == null) {
        final observed = await target.pid(app, ipa.executable);
        if (observed != null && observed != previous) {
          pid = observed;
          break;
        }
        await Future<void>.delayed(const Duration(milliseconds: 250));
      }
      return await run(session, pid);
    } finally {
      try {
        if (target.simulator ||
            pid != null && await _sameProcess(session, pid)) {
          await target.terminate(ipa.bundleId, pid);
        }
      } on StateError {
        // The process may have exited between the identity check and terminate.
      } finally {
        await console.close();
      }
    }
  }

  Future<bool> _sameProcess(_Launched launch, int pid) async =>
      await launch.target.pid(launch.app, launch.executable, previous: pid) ==
      pid;

  Future<ProbeResult> _observe(
    IosDevice target,
    IpaContext ipa,
    ProbeCheck check, {
    required String condition,
    required String conditionAr,
    Future<IosCommand> Function(int)? attach,
    Duration attachTimeout = const Duration(seconds: 15),
    String Function(int)? proof,
    _SimulatorGadget? gadget,
  }) =>
      _withLaunch(target, ipa, (launch, pid) async {
        IosCommand? tool;
        var after = 0;
        try {
          if (attach != null) {
            if (pid == null) {
              return _unknown(
                  check, En.iosAttachPidMissing, messageAr: Ar.iosAttachPidMissing);
            }
            await Future<void>.delayed(wait);
            if (!await _sameProcess(launch, pid) ||
                _verdict(launch.console, check, 0) != null) {
              return _unknown(check,
                  En.iosAttachBaselineFailed, messageAr: Ar.iosAttachBaselineFailed);
            }
            after = launch.console.position;
            tool = await attach(pid);
            if (!await tool.ready(proof!(pid), timeout: attachTimeout)) {
              final error =
                  tool.errors.where((line) => line.isNotEmpty).lastOrNull;
              return _unknown(
                  check,
                  En.iosAttachmentFailed(error: error == null ? '' : ' $error'),
                  messageAr: Ar.iosAttachmentFailed(error: error == null ? '' : ' $error'));
            }
          }
          await Future<void>.delayed(wait);
          if (gadget != null && (pid == null || !gadget.verify(pid))) {
            return _unknown(check,
                En.iosGadgetProofMissing, messageAr: Ar.iosGadgetProofMissing);
          }
          final outcome = _verdict(launch.console, check, after);
          if (outcome == ProbeStatus.inconclusive) {
            return _unknown(check, En.iosConflictingOutcomes, messageAr: Ar.iosConflictingOutcomes);
          }
          if (outcome == ProbeStatus.blocked) {
            return ProbeResult(check, ProbeStatus.blocked,
                evidence: En.iosAppBlocked(condition: condition),
                evidenceAr: Ar.iosAppBlocked(condition: conditionAr));
          }
          if (outcome == null &&
              check.id == 'ios-debugger' &&
              pid != null &&
              tool?.saw('AEGIS_IOS_DEBUG_EXIT_$pid') == true &&
              !await _sameProcess(launch, pid)) {
            return ProbeResult(check, ProbeStatus.blocked,
                processOnly: true,
                evidence: En.iosNormalExit(condition: condition),
                evidenceAr: Ar.iosNormalExit(condition: conditionAr));
          }
          final alive = pid != null && await _sameProcess(launch, pid);
          if (alive && (tool == null || tool.exitCode == null)) {
            return ProbeResult(check, ProbeStatus.notBlocked,
                processOnly: outcome == null,
                evidence: outcome == null
                    ? En.iosContinued(condition: condition) : En.iosOperationContinued(condition: condition),
                evidenceAr: outcome == null
                    ? Ar.iosContinued(condition: conditionAr) : Ar.iosOperationContinued(condition: conditionAr));
          }
          return _unknown(
              check, En.iosNoOutcome(condition: condition), messageAr: Ar.iosNoOutcome(condition: conditionAr));
        } finally {
          await tool?.close();
        }
      }, simulatorLibrary: gadget?.library);
}

Future<_SimulatorGadget> _prepareSimulatorFrida(
    IosDevice target, String bundle, String gadgetPath) async {
  final scratch = _folder(target.work, 'frida-simulator');
  final gadget =
      File(gadgetPath).copySync(p.join(scratch.path, 'FridaGadget.dylib'));
  final signed = await target.host.run(
      '/usr/bin/codesign', ['-s', '-', '-f', gadget.path],
      timeout: const Duration(seconds: 20));
  if (signed?.ok != true) {
    throw StateError(
        'Could not sign the temporary Simulator Gadget. ${signed?.text ?? ''}');
  }
  final random = Random.secure();
  final nonce =
      base64UrlEncode(List<int>.generate(24, (_) => random.nextInt(256)));
  final data = await target.simulatorDataPath(bundle);
  final proof = File(p.join(data, 'tmp', 'aegis-frida-$nonce'));
  final script = File(p.join(scratch.path, 'proof.js'))..writeAsStringSync('''
rpc.exports = {
  init(stage, options) {
    const proof = new File(options.path, 'w');
    proof.write(options.nonce + ':' + Process.id);
    proof.close();
  }
};
''');
  File(p.join(scratch.path, 'FridaGadget.config'))
      .writeAsStringSync(jsonEncode({
    'interaction': {
      'type': 'script',
      'path': script.path,
      'parameters': {'path': proof.path, 'nonce': nonce},
    },
    'runtime': 'qjs',
    'code_signing': 'required',
  }));
  return (
    library: gadget.path,
    verify: (int pid) {
      final expected = '$nonce:$pid';
      return FileSystemEntity.typeSync(proof.path, followLinks: false) ==
              FileSystemEntityType.file &&
          proof.lengthSync() == expected.length &&
          proof.readAsStringSync() == expected;
    },
  );
}

ProbeResult _partial(ProbeResult observation) {
  final jailbreak = observation.check.id == 'jailbreak';
  return ProbeResult.partial(observation.check,
      observation: observation.status,
      evidence: observation.evidence.isEmpty
          ? (observation.note ?? '')
          : observation.evidence,
      evidenceAr: observation.evidence.isEmpty ? observation.noteAr : observation.evidenceAr,
      processOnly: observation.processOnly,
      note: jailbreak ? jailbreakLimit : signingLimit,
      noteAr: jailbreak ? jailbreakLimitAr : signingLimitAr);
}

ProbeResult _unknown(ProbeCheck check, String message, {String? messageAr}) =>
    ProbeResult(check, ProbeStatus.inconclusive, note: message, noteAr: messageAr);

ProbeStatus? _verdict(IosCommand console, ProbeCheck check, int after) {
  final prefix = 'AegisProbe ${check.id.replaceFirst('ios-', '')} ';
  final lines = console.linesAfter(after).toSet();
  final blocked = lines.contains('${prefix}blocked');
  final continued = lines.contains('${prefix}not-blocked');
  return blocked && continued
      ? ProbeStatus.inconclusive
      : blocked
          ? ProbeStatus.blocked
          : continued
              ? ProbeStatus.notBlocked
              : null;
}

Directory _folder(Directory parent, String name) =>
    Directory(p.join(parent.path, name))..createSync();

String _fridaPython() {
  final home = Platform.environment['HOME'];
  final installed =
      home == null ? null : p.join(home, '.aegis', 'venv', 'bin', 'python');
  return installed != null && File(installed).existsSync()
      ? installed
      : 'python3';
}

Future<String> _verifyResigned(IpaContext original, String originalApp,
    IosSignature signature, IpaContext alternate, Directory work) async {
  if (original.bundleId != alternate.bundleId ||
      original.executable != alternate.executable ||
      original.build == null ||
      original.build != alternate.build ||
      original.version != alternate.version ||
      original.encrypted ||
      alternate.encrypted) {
    throw const FormatException(
        'The re-signed IPA must be the same unencrypted app and build.');
  }
  final app = alternate.stage(_folder(work, 'resigned'));
  final b = await verifyIosSignature(app, _folder(work, 'resigned-cert'));
  if (signature.valid != true ||
      b.valid != true ||
      signature.certificate == null ||
      b.certificate == null ||
      sha256.convert(signature.certificate!) ==
          sha256.convert(b.certificate!)) {
    throw const FormatException(
        'The two IPAs must have valid Apple signatures with different leaf certificates.');
  }
  final scratch = _folder(work, 'unsigned-payload');
  final before = await iosUnsignedPayload(originalApp, scratch);
  final after = await iosUnsignedPayload(app, scratch);
  if (before.length != after.length ||
      before.entries.any((entry) => after[entry.key] != entry.value)) {
    throw const FormatException(
        'Payload files differ beyond signing or provisioning.');
  }
  return app;
}
