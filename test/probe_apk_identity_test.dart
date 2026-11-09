import 'package:aegis/src/probe/apk_identity.dart';
import 'package:test/test.dart';

import 'support/fake_host.dart';

void main() {
  const verifier = '/sdk/apksigner';
  const apk = '/work/verified.apk';
  const args = ['verify', '--print-certs', apk];
  final fingerprint = List.filled(32, 'ab').join();
  final other = List.filled(32, 'cd').join();

  test('normalizes plain hex and Play Console fingerprints', () {
    expect(normalizeCertificateSha256(fingerprint.toUpperCase()), fingerprint);
    expect(normalizeCertificateSha256(List.filled(32, 'AB').join(':')),
        fingerprint);
    expect(normalizeCertificateSha256(':$fingerprint'), isNull);
  });

  test('a certificate printed by a failed verification is rejected', () async {
    final host = FakeHost()
      ..answer(verifier, args,
          stdout: 'Signer #1 certificate SHA-256 digest: $fingerprint',
          stderr: 'DOES NOT VERIFY',
          code: 1);
    await expectLater(
        verifyProbeApk(host, verifier, apk), throwsA(isA<FormatException>()));
  });

  test('a split is verified against the emulator SDK level', () async {
    final host = FakeHost()
      ..answer(
          verifier,
          [
            'verify',
            '--print-certs',
            '--min-sdk-version',
            '34',
            '--max-sdk-version',
            '34',
            apk,
          ],
          stdout: 'Signer #1 certificate SHA-256 digest: $fingerprint');
    final verified = await verifyProbeApk(host, verifier, apk, sdkVersion: 34);
    expect(verified.signerSha256, [fingerprint]);
  });

  test('a verified signer is recorded and the expected signer must match',
      () async {
    final host = FakeHost()
      ..answer(verifier, args,
          stdout: 'Signer #1 certificate SHA-256 digest: $fingerprint\n'
              'Source Stamp Signer certificate SHA-256 digest: $other\n');
    final verified = await verifyProbeApk(host, verifier, apk,
        expectedCertificateSha256: fingerprint);
    expect(verified.signerSha256, [fingerprint]);
    expect(verified.expectedSignerSha256, fingerprint);
    final unpinned = await verifyProbeApk(host, verifier, apk);
    expect(unpinned.expectedSignerSha256, isNull);
    await expectLater(
        verifyProbeApk(host, verifier, apk, expectedCertificateSha256: other),
        throwsA(isA<FormatException>()));
  });
}
