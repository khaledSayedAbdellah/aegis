/// Verifies the APK supplied as the executable companion to an AAB.
library;

import 'host.dart';
import 'probe_model.dart';

String? normalizeCertificateSha256(String value) {
  final hex = value.trim().toLowerCase();
  if (RegExp(r'^[0-9a-f]{64}$').hasMatch(hex)) return hex;
  if (RegExp(r'^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$').hasMatch(hex)) {
    return hex.replaceAll(':', '');
  }
  return null;
}

Future<ProbeApkIdentity> verifyProbeApk(
  Host host,
  String apksigner,
  String path, {
  String? expectedCertificateSha256,
  String? javaHome,
  int? sdkVersion,
}) async {
  final result = await host.run(
    apksigner,
    [
      'verify',
      '--print-certs',
      if (sdkVersion != null) ...[
        '--min-sdk-version',
        '$sdkVersion',
        '--max-sdk-version',
        '$sdkVersion',
      ],
      path,
    ],
    environment: javaHome == null ? null : {'JAVA_HOME': javaHome},
    timeout: const Duration(seconds: 60),
  );
  if (result?.ok != true) {
    throw FormatException(
        'APK signature verification failed: ${result?.text ?? 'apksigner could not run'}');
  }
  final signers = RegExp(
    r'^Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F]{64})[ \t]*\r?$',
    multiLine: true,
  ).allMatches(result!.stdout).map((m) => m[1]!.toLowerCase()).toSet();
  if (signers.isEmpty) {
    throw const FormatException(
        'apksigner did not report a verified APK signer.');
  }
  if (expectedCertificateSha256 != null &&
      (signers.length != 1 || !signers.contains(expectedCertificateSha256))) {
    throw FormatException(
        'APK signer SHA-256 does not match --probe-cert-sha256 '
        '(expected $expectedCertificateSha256, verified ${signers.join(', ')}).');
  }
  return ProbeApkIdentity(
    signerSha256: List.unmodifiable(signers),
    expectedSignerSha256: expectedCertificateSha256,
  );
}
