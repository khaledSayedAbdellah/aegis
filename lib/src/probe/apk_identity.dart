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

/// The app signer certificates in `apksigner verify --print-certs` output.
///
/// Recognized line prefixes, each followed by `certificate SHA-256 digest:`:
/// * `Signer #1` (build-tools up to 36)
/// * `V2 Signer:`, `V3.0 Signer:` (build-tools 37)
/// * either form with `(minSdkVersion=A, maxSdkVersion=B)`, printed for a
///   rotated signing key; only the signer whose range holds [sdkVersion] is
///   kept when it is known.
///
/// The match is anchored to the start of the line, so the `Source Stamp
/// Signer` certificate is never taken for the app's signer.
Set<String> verifiedSigners(String output, {int? sdkVersion}) {
  final line = RegExp(
    r'^(?:V\d+(?:\.\d+)? Signer(?: #\d+)?:|Signer(?: #\d+)?)[ \t]*'
    r'(?:\(minSdkVersion=(\d+), maxSdkVersion=(\d+)\)[ \t]*)?'
    r'certificate SHA-256 digest:[ \t]*([0-9a-fA-F]{64})[ \t]*\r?$',
    multiLine: true,
  );
  return {
    for (final m in line.allMatches(output))
      if (sdkVersion == null ||
          m[1] == null ||
          int.parse(m[1]!) <= sdkVersion && sdkVersion <= int.parse(m[2]!))
        m[3]!.toLowerCase(),
  };
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
  final signers = verifiedSigners(result!.stdout, sdkVersion: sdkVersion);
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
