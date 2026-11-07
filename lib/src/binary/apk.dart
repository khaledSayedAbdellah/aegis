/// Everything aegis reads from a compiled APK.
library;

import 'dart:typed_data';

import 'package:path/path.dart' as p;
import 'package:xml/xml.dart';

import '../project.dart' show androidAttr, firstElement;
import 'axml.dart';
import 'signing.dart';
import 'zip.dart';

const _abiPreference = ['arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86'];

class ApkContext {
  ApkContext._(this.path, this.zip);

  /// Opens the APK at [path]. Throws [FormatException] when it is not a
  /// readable APK.
  static ApkContext load(String path) {
    final lower = path.toLowerCase();
    if (lower.endsWith('.aab')) {
      throw const FormatException(
          'App bundles (.aab) store the manifest as protobuf and are not supported yet. '
          'Build an APK (flutter build apk --release) or convert with '
          'bundletool build-apks --mode=universal.');
    }
    if (lower.endsWith('.ipa')) {
      throw const FormatException('IPA scanning is not supported yet.');
    }
    final zip = ZipReader.file(path);
    if (!zip.contains('AndroidManifest.xml')) {
      throw const FormatException('No AndroidManifest.xml: this is not an APK.');
    }
    return ApkContext._(path, zip);
  }

  final String path;
  final ZipReader zip;

  String get fileName => p.basename(path);

  /// Label used as the "file" of findings, e.g. `app-release.apk!/AndroidManifest.xml`.
  String location(String entry) => '$fileName!/$entry';

  /// The final, merged manifest as XML text.
  late final String? manifestText = _decode('AndroidManifest.xml');

  late final XmlDocument? manifest = _parse(manifestText);

  late final XmlElement? application =
      manifest == null ? null : firstElement(manifest!, 'application');

  String? get packageName => manifest?.rootElement.getAttribute('package');

  String? get versionName =>
      manifest == null ? null : androidAttr(manifest!.rootElement, 'versionName');

  String? get versionCode =>
      manifest == null ? null : androidAttr(manifest!.rootElement, 'versionCode');

  XmlElement? get _usesSdk =>
      manifest == null ? null : firstElement(manifest!, 'uses-sdk');

  int? get minSdk => int.tryParse(
      (_usesSdk == null ? null : androidAttr(_usesSdk!, 'minSdkVersion')) ?? '');

  int? get targetSdk => int.tryParse(
      (_usesSdk == null ? null : androidAttr(_usesSdk!, 'targetSdkVersion')) ?? '');

  /// The network security config, found by decoding res/**/*.xml files and
  /// looking for a `<network-security-config>` root (resource names may be
  /// obfuscated, so the manifest reference cannot be followed by name).
  late final (String, XmlDocument)? networkSecurityConfig = _findNsc();

  (String, XmlDocument)? _findNsc() {
    for (final e in zip.entries.values) {
      if (!e.name.startsWith('res/') || !e.name.endsWith('.xml')) continue;
      if (e.size > 64 * 1024) continue;
      final text = _decode(e.name);
      if (text == null || !text.contains('network-security-config')) continue;
      final doc = _parse(text);
      if (doc != null && doc.rootElement.name.local == 'network-security-config') {
        return (e.name, doc);
      }
    }
    return null;
  }

  bool get isFlutter =>
      zip.entries.keys.any((n) => n.startsWith('assets/flutter_assets/')) ||
      zip.entries.keys.any((n) => n.endsWith('/libflutter.so'));

  /// Debug (JIT) Flutter builds ship the Dart kernel instead of AOT code.
  bool get isDebugFlutterBuild =>
      zip.contains('assets/flutter_assets/kernel_blob.bin');

  List<String> get abis => {
        for (final n in zip.entries.keys)
          if (n.startsWith('lib/') && n.split('/').length == 3) n.split('/')[1]
      }.toList()
        ..sort();

  /// Path of the AOT-compiled Dart code, preferring arm64.
  String? get libappEntry {
    for (final abi in _abiPreference) {
      final n = 'lib/$abi/libapp.so';
      if (zip.contains(n)) return n;
    }
    for (final n in zip.entries.keys) {
      if (n.endsWith('/libapp.so')) return n;
    }
    return null;
  }

  /// Printable strings of libapp.so (the compiled Dart program).
  late final List<String> libappStrings =
      libappEntry == null ? const [] : printableStrings(zip.read(libappEntry!)!);

  /// Entries under assets/flutter_assets/.
  List<String> get flutterAssets => [
        for (final n in zip.entries.keys)
          if (n.startsWith('assets/flutter_assets/') && !n.endsWith('/')) n
      ];

  late final List<SigningCert> certificates = readSigningCerts(zip);

  int get sizeBytes => zip.bytes.length;

  String? _decode(String entry) {
    try {
      final bytes = zip.read(entry);
      if (bytes == null || !isBinaryXml(bytes)) return null;
      return decodeBinaryXml(bytes);
    } catch (_) {
      return null;
    }
  }

  static XmlDocument? _parse(String? text) {
    if (text == null) return null;
    try {
      return XmlDocument.parse(text);
    } catch (_) {
      return null;
    }
  }
}

/// Runs of printable ASCII of at least [min] characters, like `strings`.
List<String> printableStrings(Uint8List b, {int min = 6}) {
  final out = <String>[];
  var start = -1;
  for (var i = 0; i < b.length; i++) {
    final c = b[i];
    final printable = c >= 0x20 && c < 0x7f;
    if (printable) {
      if (start < 0) start = i;
    } else if (start >= 0) {
      if (i - start >= min) out.add(String.fromCharCodes(b, start, i));
      start = -1;
    }
  }
  if (start >= 0 && b.length - start >= min) {
    out.add(String.fromCharCodes(b, start, b.length));
  }
  return out;
}
