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

  group('apksigner output formats', () {
    // Captured from apksigner (build-tools 36.0.0 and 37.0.0) on a bundletool
    // split and on an APK whose signing key was rotated at SDK 33.
    test('build-tools 37 prefixes the scheme instead of the signer number', () {
      expect(
          verifiedSigners('V3.0 Signer: certificate DN: CN=smoke\n'
              'V3.0 Signer: certificate SHA-256 digest: $fingerprint\n'
              'V3.0 Signer: certificate SHA-1 digest: ${'a' * 40}\n'),
          {fingerprint});
      expect(
          verifiedSigners(
              'V2 Signer: certificate SHA-256 digest: ${fingerprint.toUpperCase()}'),
          {fingerprint});
    });

    test('a rotated key keeps only the signer for the device SDK', () {
      for (final (prefix, sep) in [('Signer', ''), ('V3.1 Signer', ':')]) {
        final older = prefix.replaceFirst('3.1', '3.0');
        final output =
            '$prefix$sep (minSdkVersion=33, maxSdkVersion=2147483647)'
            ' certificate SHA-256 digest: $other\n'
            '$older$sep (minSdkVersion=24, maxSdkVersion=32)'
            ' certificate SHA-256 digest: $fingerprint\n';
        expect(verifiedSigners(output, sdkVersion: 34), {other},
            reason: prefix);
        expect(verifiedSigners(output, sdkVersion: 30), {fingerprint},
            reason: prefix);
        expect(verifiedSigners(output, sdkVersion: 21), isEmpty,
            reason: prefix);
        expect(verifiedSigners(output), {other, fingerprint}, reason: prefix);
      }
    });

    test('only signer lines count, at the start of the line', () {
      for (final line in [
        'Source Stamp Signer certificate SHA-256 digest: $other',
        'V3.0 Source Stamp Signer: certificate SHA-256 digest: $other',
        'note: Signer #1 certificate SHA-256 digest: $other',
        'Signer #1 certificate SHA-1 digest: ${'a' * 40}',
        'Signer #1 certificate SHA-256 digest: ${'a' * 63}',
      ]) {
        expect(verifiedSigners(line), isEmpty, reason: line);
      }
    });

    test('a build-tools 37 split verifies against the emulator SDK level',
        () async {
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
            stdout: 'V3.0 Signer: certificate SHA-256 digest: $fingerprint\n');
      final verified = await verifyProbeApk(host, verifier, apk,
          expectedCertificateSha256: fingerprint, sdkVersion: 34);
      expect(verified.signerSha256, [fingerprint]);
    });
  });
}
