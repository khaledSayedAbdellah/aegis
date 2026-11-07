/// Reads the signing certificates of an APK (v1 JAR signatures and the
/// v2/v3 APK Signature Scheme block). Signatures are not verified: aegis only
/// needs the certificates to identify the signer and compute hashes.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'zip.dart';

class SigningCert {
  SigningCert(this.der, this.scheme);

  /// DER-encoded X.509 certificate.
  final Uint8List der;

  /// `v1`, `v2` or `v3`.
  final String scheme;

  late final List<int> _sha256 = sha256.convert(der).bytes;

  /// Base64 of the SHA-256 digest: the format freeRASP expects in
  /// `signingCertHashes`.
  String get sha256Base64 => base64.encode(_sha256);

  /// `AB:CD:...` form, as shown by keytool and the Play Console.
  String get sha256Hex => _sha256
      .map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase())
      .join(':');

  /// Common name of the subject, e.g. `Android Debug`.
  late final String? commonName = _subjectCommonName(der);

  bool get isAndroidDebug => commonName == 'Android Debug';
}

/// All distinct signing certificates found in [zip].
List<SigningCert> readSigningCerts(ZipReader zip) {
  final out = <SigningCert>[];
  final seen = <String>{};
  void add(Uint8List der, String scheme) {
    final c = SigningCert(der, scheme);
    if (seen.add(c.sha256Base64)) out.add(c);
  }

  for (final (der, scheme) in _signingBlockCerts(zip)) {
    add(der, scheme);
  }
  for (final e in zip.entries.values) {
    final n = e.name.toUpperCase();
    if (!n.startsWith('META-INF/')) continue;
    if (!(n.endsWith('.RSA') || n.endsWith('.DSA') || n.endsWith('.EC'))) continue;
    try {
      final der = _certFromPkcs7(zip.readEntry(e));
      if (der != null) add(der, 'v1');
    } catch (_) {
      // Malformed signature file: ignore, other schemes may still work.
    }
  }
  return out;
}

/// Certificates from the APK Signing Block (v2 id 0x7109871a, v3 0xf05368c0).
List<(Uint8List, String)> _signingBlockCerts(ZipReader zip) {
  final b = zip.bytes;
  final cd = zip.centralDirectoryOffset;
  final out = <(Uint8List, String)>[];
  if (cd < 32 || cd > b.length) return out;
  final magic = ascii.decode(Uint8List.sublistView(b, cd - 16, cd), allowInvalid: true);
  if (magic != 'APK Sig Block 42') return out;
  final d = ByteData.sublistView(b);
  final blockSize = d.getUint64(cd - 24, Endian.little);
  final start = cd - blockSize - 8;
  if (start < 0) return out;
  try {
    var p = start + 8;
    final end = cd - 24;
    while (p + 12 <= end) {
      final len = d.getUint64(p, Endian.little);
      final id = d.getUint32(p + 8, Endian.little);
      final valueStart = p + 12;
      final valueEnd = p + 8 + len;
      if (valueEnd > end || len < 4) break;
      if (id == 0x7109871a || id == 0xf05368c0) {
        final scheme = id == 0x7109871a ? 'v2' : 'v3';
        for (final der in _certsFromSigners(d, valueStart, valueEnd)) {
          out.add((der, scheme));
        }
      }
      p = valueEnd;
    }
  } catch (_) {
    // Malformed block: return what was read so far.
  }
  return out;
}

List<Uint8List> _certsFromSigners(ByteData d, int start, int end) {
  final b = d.buffer.asUint8List(d.offsetInBytes, d.lengthInBytes);
  int u32(int o) => d.getUint32(o, Endian.little);
  final out = <Uint8List>[];
  var q = start;
  final signersEnd = q + 4 + u32(q);
  q += 4;
  while (q + 4 <= signersEnd && signersEnd <= end) {
    final signerEnd = q + 4 + u32(q);
    q += 4;
    // signed data
    var s = q + 4;
    final signedDataEnd = s + u32(q);
    // digests
    s += 4 + u32(s);
    // certificates
    final certsEnd = s + 4 + u32(s);
    s += 4;
    while (s + 4 <= certsEnd && certsEnd <= signedDataEnd) {
      final len = u32(s);
      s += 4;
      if (s + len > certsEnd) break;
      out.add(Uint8List.fromList(b.sublist(s, s + len)));
      s += len;
    }
    q = signerEnd;
  }
  return out;
}

class _Tlv {
  _Tlv(this.tag, this.start, this.valueStart, this.end);
  final int tag;
  final int start;
  final int valueStart;
  final int end;
}

_Tlv? _readTlv(Uint8List b, int p, [int? limit]) {
  final max = limit ?? b.length;
  if (p + 2 > max) return null;
  final tag = b[p];
  final first = b[p + 1];
  var q = p + 2;
  var len = 0;
  if (first < 0x80) {
    len = first;
  } else {
    final n = first & 0x7f;
    if (n == 0 || n > 4 || q + n > max) return null;
    for (var k = 0; k < n; k++) {
      len = (len << 8) | b[q++];
    }
  }
  final end = q + len;
  if (end > max) return null;
  return _Tlv(tag, p, q, end);
}

List<_Tlv> _children(Uint8List b, _Tlv t) {
  final out = <_Tlv>[];
  var p = t.valueStart;
  while (p < t.end) {
    final c = _readTlv(b, p, t.end);
    if (c == null) break;
    out.add(c);
    p = c.end;
  }
  return out;
}

/// First certificate of a PKCS#7 SignedData (META-INF/*.RSA).
Uint8List? _certFromPkcs7(Uint8List b) {
  final root = _readTlv(b, 0);
  if (root == null || root.tag != 0x30) return null;
  final ci = _children(b, root);
  if (ci.length < 2 || ci[1].tag != 0xA0) return null;
  final inner = _children(b, ci[1]);
  if (inner.isEmpty || inner.first.tag != 0x30) return null;
  for (final c in _children(b, inner.first)) {
    if (c.tag == 0xA0) {
      final certs = _children(b, c);
      if (certs.isEmpty) return null;
      return Uint8List.fromList(b.sublist(certs.first.start, certs.first.end));
    }
  }
  return null;
}

/// The last commonName (OID 2.5.4.3) in the certificate: for the usual
/// issuer-then-subject order that is the subject's CN.
String? _subjectCommonName(Uint8List der) {
  String? cn;
  for (var i = 0; i + 5 < der.length; i++) {
    if (der[i] == 0x06 &&
        der[i + 1] == 0x03 &&
        der[i + 2] == 0x55 &&
        der[i + 3] == 0x04 &&
        der[i + 4] == 0x03) {
      final v = _readTlv(der, i + 5);
      if (v != null) {
        cn = utf8.decode(der.sublist(v.valueStart, v.end), allowMalformed: true);
      }
    }
  }
  return cn;
}
