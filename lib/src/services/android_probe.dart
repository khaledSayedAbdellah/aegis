import 'dart:io';

import 'package:path/path.dart' as p;

import '../binary/apk.dart';
import '../config.dart';
import '../l10n/messages.g.dart';
import '../probe/apk_identity.dart';
import '../probe/apk_set.dart';
import '../probe/device.dart';
import '../probe/host.dart';
import '../probe/pins.dart' show avdName;
import '../probe/probe_model.dart';
import '../probe/probe_runner.dart';
import '../probe/toolchain.dart';
import '../project.dart' show androidAttr;

/// Runs the probe on an installable APK with its original signing identity.
Future<ProbeOutcome> runAndroidProbe(
  String appPath, {
  void Function(String)? log,
  void Function(String package, String controlName)? onRunning,
  required AegisConfig config,
  required String projectRoot,
  Set<String>? only,
  String? signedApk,
  String? expectedSigner,
  String? rootAvd,
  String? controlAvd,
}) async {
  String? expectedDigest;
  late final ApkContext input;
  ApkContext? companion;
  var useApkArchive = false;
  var useApkDirectory = false;
  try {
    input = ApkContext.load(appPath);
    if (input.isBundle) {
      signedApk ??= AegisConfig.resolve(projectRoot, config.probeApk);
      expectedSigner ??= config.probeCertSha256;
      if (expectedSigner != null) {
        expectedDigest = normalizeCertificateSha256(expectedSigner);
        if (expectedDigest == null) {
          return const ProbeOutcome.skipped(En.aabSignerFingerprintInvalid,
              skippedAr: Ar.aabSignerFingerprintInvalid);
        }
      }
      if (signedApk == null) {
        return const ProbeOutcome.skipped(En.aabCompanionRequired,
            skippedAr: Ar.aabCompanionRequired);
      }
      useApkDirectory = Directory(signedApk).existsSync();
      useApkArchive =
          !useApkDirectory && signedApk.toLowerCase().endsWith('.apks');
      if (!useApkArchive && !useApkDirectory) {
        final apk = ApkContext.load(signedApk);
        if (apk.isBundle ||
            apk.packageName != input.packageName ||
            apk.versionCode == null ||
            apk.versionCode != input.versionCode ||
            apk.manifest!.rootElement.getAttribute('split')?.isNotEmpty ==
                true) {
          return const ProbeOutcome.skipped(En.aabCompanionMismatch,
              skippedAr: Ar.aabCompanionMismatch);
        }
        companion = apk;
      }
    } else {
      if (signedApk != null || expectedSigner != null) {
        return const ProbeOutcome.skipped(En.aabOptionsOnly,
            skippedAr: Ar.aabOptionsOnly);
      }
    }
  } on FileSystemException catch (e) {
    return ProbeOutcome.skipped('${e.message}: ${e.path}');
  } on FormatException catch (e) {
    return ProbeOutcome.skipped(e.message);
  }
  final dedicatedName = RegExp(r'^aegis-probe(?:-[\w-]+)?$');
  if ([rootAvd, controlAvd]
          .whereType<String>()
          .any((name) => !dedicatedName.hasMatch(name)) ||
      rootAvd == (controlAvd ?? avdName)) {
    return const ProbeOutcome.skipped(En.androidDedicatedAvdsRequired,
        skippedAr: Ar.androidDedicatedAvdsRequired);
  }

  final host = SystemHost();
  final toolchain = Toolchain(host);
  final tools = await ProbeTools.resolve(host, toolchain);
  final missing = tools.missing(only: only);
  if (signedApk != null &&
      tools.apksigner == null &&
      !missing.contains('apksigner')) {
    missing.add('apksigner');
  }
  if (useApkArchive && !host.fileExists(toolchain.bundletoolPath)) {
    missing.add('bundletool');
  }
  if (useApkArchive && tools.javaHome == null) missing.add('Java');
  if (missing.isNotEmpty) {
    return ProbeOutcome.skipped(
        En.aegisMissingRunAegisSetup(
            value1: missing.join(', '), value2: ' --android'),
        skippedAr: Ar.aegisMissingRunAegisSetup(
            value1: missing.join('، '), value2: ' --android'));
  }

  final work = Directory.systemTemp.createTempSync('aegis-probe-');
  final lock = File(p.join(toolchain.aegisDir, 'probe.lock'));
  RandomAccessFile? guard;
  try {
    lock.parent.createSync(recursive: true);
    guard = lock.openSync(mode: FileMode.append);
    guard.lockSync(FileLock.exclusive);
  } on FileSystemException {
    guard?.closeSync();
    work.deleteSync(recursive: true);
    return const ProbeOutcome.skipped(En.androidProbeLockUnavailable,
        skippedAr: Ar.androidProbeLockUnavailable);
  }
  try {
    final device = Device(host, tools, avdName: controlAvd);
    final rootDevice =
        rootAvd == null ? null : Device(host, tools, avdName: rootAvd);
    ProbeApkIdentity? apkIdentity;
    var installed = companion ?? input;
    var runtimePath = installed.path;
    var splits = const <String>[];
    List<String>? rootedApks;
    if (signedApk != null) {
      try {
        if (useApkArchive || useApkDirectory) {
          final bundletool = useApkArchive ? toolchain.bundletoolPath : null;
          final staged = useApkArchive
              ? File(signedApk)
                  .copySync(p.join(work.path, 'verified.apks'))
                  .path
              : stageSelectedApks(
                  signedApk, p.join(work.path, 'verified-apks'));
          final control = await prepareProbeApkSet(
              device, staged, p.join(work.path, 'control-apks'),
              bundle: input,
              bundletool: bundletool,
              expectedSigner: expectedDigest,
              log: log);
          installed = control.base;
          runtimePath = installed.path;
          splits = control.splits;
          if (rootDevice != null &&
              (only == null ||
                  only.contains('root') ||
                  only.contains('hooking'))) {
            final rooted = await prepareProbeApkSet(
                rootDevice, staged, p.join(work.path, 'rooted-apks'),
                bundle: input,
                bundletool: bundletool,
                expectedSigner: expectedDigest,
                log: log);
            if (!sameApkSigners(control.identity, rooted.identity)) {
              return const ProbeOutcome.skipped(En.androidApkSetSignersDiffer,
                  skippedAr: Ar.androidApkSetSignersDiffer);
            }
            rootedApks = [rooted.base.path, ...rooted.splits];
          }
          apkIdentity = ProbeApkIdentity(
            signerSha256: control.identity.signerSha256,
            expectedSignerSha256: expectedDigest,
            controlApks: [p.basename(runtimePath), ...splits.map(p.basename)],
            rootedApks: rootedApks?.map(p.basename).toList() ?? const [],
          );
        } else {
          // Verify and install the same bytes even if a build replaces the input.
          runtimePath = p.join(work.path, 'verified.apk');
          File(runtimePath).writeAsBytesSync(installed.archive.bytes);
          apkIdentity = await verifyProbeApk(
              host, tools.apksigner!, runtimePath,
              expectedCertificateSha256: expectedDigest,
              javaHome: tools.javaHome);
        }
      } on FormatException catch (e) {
        return ProbeOutcome.skipped(e.message);
      } on FileSystemException catch (e) {
        return ProbeOutcome.skipped(En.androidStageApksFailed(error: e.message),
            skippedAr: Ar.androidStageApksFailed(error: e.message));
      } on StateError catch (e) {
        return ProbeOutcome.skipped(e.message);
      }
    }
    final package = installed.packageName!;
    final controlName = controlAvd ?? tools.avdName;
    onRunning?.call(package, controlName);
    final app = installed.application;
    final report = await ProbeRunner(device, rootDevice: rootDevice).run(
        appPath: runtimePath,
        appLabel: useApkDirectory
            ? p.normalize(p.absolute(signedApk!))
            : signedApk ?? installed.path,
        apkIdentity: apkIdentity,
        splits: splits,
        rootedApks: rootedApks,
        package: package,
        workDir: work.path,
        only: only,
        debuggable: app != null && androidAttr(app, 'debuggable') == 'true',
        log: log);
    return ProbeOutcome.ran(report);
  } finally {
    guard.closeSync();
    try {
      work.deleteSync(recursive: true);
    } catch (_) {}
  }
}
