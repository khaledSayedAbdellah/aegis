/// Selects and verifies the installable APKs for one probe emulator.
library;

import 'dart:io';

import 'package:path/path.dart' as p;

import '../binary/apk.dart';
import 'apk_identity.dart';
import 'device.dart';
import 'probe_model.dart';

typedef VerifiedApkSet = ({
  ApkContext base,
  List<String> splits,
  ProbeApkIdentity identity,
});

Future<VerifiedApkSet> prepareProbeApkSet(
    Device device, String source, String directory,
    {required ApkContext bundle,
    String? bundletool,
    String? expectedSigner,
    void Function(String)? log}) async {
  final bootError =
      await device.bootEmulator(log: log, logPath: '$directory.log');
  if (bootError != null) throw FormatException(bootError);
  if (bundletool != null) {
    await device.extractApkSet(bundletool, source, directory);
  }
  final sdk = await device.sdkVersion();
  final files = _apksIn(bundletool == null ? source : directory);
  ApkContext? base;
  final splits = <String>[];
  ProbeApkIdentity? identity;
  final splitNames = <String>{};
  for (final file in files) {
    final path = file.path;
    final apk = ApkContext.load(path);
    if (apk.isBundle ||
        apk.packageName != bundle.packageName ||
        apk.versionCode == null ||
        apk.versionCode != bundle.versionCode) {
      throw FormatException(
          '${p.basename(path)} must have the same package name and version code as the AAB.');
    }
    final splitName = apk.manifest!.rootElement.getAttribute('split');
    if (splitName == null || splitName.isEmpty) {
      if (base != null) {
        throw const FormatException(
            'The selected APKs contain multiple base APKs.');
      }
      base = apk;
    } else {
      if (!splitNames.add(splitName)) {
        throw FormatException('Duplicate APK split $splitName.');
      }
      splits.add(path);
    }

    final verified = await verifyProbeApk(
        device.host, device.tools.apksigner!, path,
        expectedCertificateSha256: expectedSigner,
        javaHome: device.tools.javaHome,
        sdkVersion: sdk);
    if (identity != null && !sameApkSigners(identity, verified)) {
      throw const FormatException(
          'The selected APKs have different signing certificates.');
    }
    identity ??= verified;
  }
  if (base == null || identity == null) {
    throw const FormatException(
        'The selected APKs are missing their base APK.');
  }
  return (base: base, splits: splits, identity: identity);
}

List<File> _apksIn(String directory) => Directory(directory)
    .listSync(followLinks: false)
    .whereType<File>()
    .where((file) => p.extension(file.path).toLowerCase() == '.apk')
    .toList()
  ..sort((a, b) => a.path.compareTo(b.path));

/// Copies a single, preselected device set so verification and install use
/// the same bytes. Metadata-bearing archives are selected by bundletool.
String stageSelectedApks(String source, String destination) {
  Directory(destination).createSync();
  for (final file in _apksIn(source)) {
    file.copySync(p.join(destination, p.basename(file.path)));
  }
  return destination;
}

bool sameApkSigners(ProbeApkIdentity a, ProbeApkIdentity b) =>
    a.signerSha256.length == b.signerSha256.length &&
    a.signerSha256.every(b.signerSha256.contains);
