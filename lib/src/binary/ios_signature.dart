/// Verification of iOS code signatures using Apple's macOS verifier.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as p;

import '../probe/host.dart';
import '../l10n/messages.g.dart';
import 'ipa.dart';

typedef IosSignature = ({bool? valid, String evidence, String? evidenceAr, Uint8List? certificate});

Future<IosSignature> verifyIosSignature(String app, Directory scratch) async {
  final host = SystemHost();
  if (host.os != 'macos') {
    return (
      valid: null,
      evidence: En.signatureMacOnly,
      evidenceAr: Ar.signatureMacOnly,
      certificate: null
    );
  }
  final verify = await host.run('/usr/bin/codesign',
      ['--verify', '--deep', '--strict', '-R=anchor apple generic', app],
      timeout: const Duration(minutes: 2));
  if (verify == null || verify.exitCode == 124 || verify.exitCode < 0) {
    return (
      valid: null,
      evidence: verify?.text ?? En.signatureCouldNotRun,
      evidenceAr: verify == null ? Ar.signatureCouldNotRun : null,
      certificate: null
    );
  }
  if (!verify.ok) {
    return (valid: false, evidence: verify.text, evidenceAr: null, certificate: null);
  }
  final prefix = p.join(scratch.path, 'signer-');
  final extracted = await host.run('/usr/bin/codesign',
      ['--display', '--extract-certificates=$prefix', app]);
  final leaf = File('${prefix}0');
  if (extracted?.ok != true || !leaf.existsSync()) {
    return (
      valid: null,
      evidence: En.signatureCertificateUnavailable,
      evidenceAr: Ar.signatureCertificateUnavailable,
      certificate: null
    );
  }
  return (
    valid: true,
    evidence: En.signatureVerified,
      evidenceAr: Ar.signatureVerified,
    certificate: leaf.readAsBytesSync()
  );
}

/// Hash the complete payload after stripping code signatures in a scratch
/// copy. Provisioning and the code signature resource envelopes may change.
Future<Map<String, String>> iosUnsignedPayload(
    String app, Directory scratch) async {
  final files = <String, String>{};
  final host = SystemHost();
  for (final file in Directory(app)
      .listSync(recursive: true, followLinks: false)
      .whereType<File>()) {
    final relative = p.relative(file.path, from: app);
    final parts = p.split(relative);
    if (parts.contains('_CodeSignature') ||
        parts.last == 'embedded.mobileprovision' ||
        parts.last == 'CodeResources' && parts.length == 1) {
      continue;
    }
    final fd = file.openSync();
    final magic = fd.readSync(4);
    fd.closeSync();
    final isMachO = magic.length == 4 &&
        const {
          0xcffaedfe,
          0xcefaedfe,
          0xcafebabe,
          0xcafebabf,
        }.contains(ByteData.sublistView(magic).getUint32(0));
    var input = file;
    if (isMachO && inspectMachO(file.readAsBytesSync()).isNotEmpty) {
      input = file.copySync(p.join(scratch.path, 'unsigned'));
      final removed = await host
          .run('/usr/bin/codesign', ['--remove-signature', input.path]);
      if (removed?.ok != true) {
        throw FormatException(
            'Could not isolate the signature in $relative: ${removed?.text ?? ''}');
      }
    }
    files[relative] = (await sha256.bind(input.openRead()).first).toString();
  }
  return files;
}
