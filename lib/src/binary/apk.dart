/// Everything aegis reads from a compiled APK or Android App Bundle (AAB).
///
/// An AAB is read through an APK-shaped view of its base module
/// (`base/manifest/AndroidManifest.xml` -> `AndroidManifest.xml`,
/// `base/dex/classes.dex` -> `classes.dex`, ...), so the binary rules work on
/// both. Its XML files are protobuf instead of binary XML.
library;

import 'dart:typed_data';

import 'package:path/path.dart' as p;
import 'package:xml/xml.dart';

import '../project.dart' show androidAttr, firstElement;
import 'axml.dart';
import 'proto_xml.dart';
import 'signing.dart';
import 'resources.dart';
import 'zip.dart';

const _abiPreference = ['arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86'];

class ApkContext {
  ApkContext._(this.path, this.zip, this.archive, {this.isBundle = false});

  /// Opens the APK or AAB at [path]. Throws [FormatException] when it is not
  /// a readable APK or app bundle.
  static ApkContext load(String path) {
    final lower = path.toLowerCase();
    if (lower.endsWith('.ipa')) {
      throw const FormatException('Use --ipa to audit an iOS application archive.');
    }
    final archive = ZipReader.file(path);
    if (archive.contains('base/manifest/AndroidManifest.xml')) {
      return _validated(ApkContext._(path, archive.renamed(bundleView(archive.entries.keys)), archive,
          isBundle: true));
    }
    if (lower.endsWith('.aab')) {
      throw const FormatException(
          'No base/manifest/AndroidManifest.xml: this is not an Android App Bundle.');
    }
    if (!archive.contains('AndroidManifest.xml')) {
      throw const FormatException('No AndroidManifest.xml: this is not an APK.');
    }
    return _validated(ApkContext._(path, archive, archive));
  }

  static ApkContext _validated(ApkContext apk) {
    if (apk.manifest?.rootElement.name.local != 'manifest' ||
        !RegExp(r'^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$')
            .hasMatch(apk.packageName ?? '')) {
      throw const FormatException('Could not read a valid AndroidManifest.xml.');
    }
    return apk;
  }

  /// Maps AAB entry names to the names they would have in an APK. The base
  /// module wins; files of feature modules are added when their name is
  /// free, and their dex files keep the module as a prefix.
  static Map<String, String> bundleView(Iterable<String> names) {
    final out = <String, String>{};
    final taken = <String>{};
    void add(String from, String to) {
      if (taken.add(to)) out[from] = to;
    }

    final sorted = names.toList()
      ..sort((a, b) {
        final ab = a.startsWith('base/') ? 0 : 1;
        final bb = b.startsWith('base/') ? 0 : 1;
        return ab != bb ? ab - bb : a.compareTo(b);
      });
    for (final n in sorted) {
      if (n.endsWith('/')) continue;
      final slash = n.indexOf('/');
      if (slash <= 0) continue; // BundleConfig.pb, signatures
      final module = n.substring(0, slash);
      if (module == 'META-INF' || module == 'BUNDLE-METADATA') continue;
      final rest = n.substring(slash + 1);
      final base = module == 'base';
      if (rest == 'manifest/AndroidManifest.xml') {
        if (base) add(n, 'AndroidManifest.xml');
      } else if (rest.startsWith('dex/')) {
        add(n, base ? rest.substring(4) : '$module/${rest.substring(4)}');
      } else if (rest.startsWith('lib/') || rest.startsWith('assets/') || rest.startsWith('res/')) {
        add(n, rest);
      } else if (rest.startsWith('root/')) {
        if (base) add(n, rest.substring(5));
      } else if (rest == 'resources.pb') {
        if (base) add(n, 'resources.pb');
      }
    }
    return out;
  }

  final String path;

  /// The entries, named as in an APK.
  final ZipReader zip;

  /// The file as it is on disk (the AAB itself for a bundle).
  final ZipReader archive;

  /// An Android App Bundle rather than an APK.
  final bool isBundle;

  /// `AAB` or `APK`.
  String get kind => isBundle ? 'AAB' : 'APK';

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

  String? get networkSecurityConfigReference =>
      application == null ? null : androidAttr(application!, 'networkSecurityConfig');

  /// First resolved variant, for callers that only need one document.
  (String, XmlDocument)? get networkSecurityConfig => networkSecurityConfigs.firstOrNull;

  /// All variants of the resource referenced by the manifest.
  late final List<(String, XmlDocument)> networkSecurityConfigs = _findNsc();

  List<(String, XmlDocument)> _findNsc() {
    final reference = networkSecurityConfigReference;
    if (reference == null || reference == '@null') return const [];
    final numeric = RegExp(r'^@0x([0-9a-fA-F]+)$').firstMatch(reference);
    final named = RegExp(r'^@(?:([\w.]+):)?xml/([\w.]+)$').firstMatch(reference);
    final id = numeric == null ? null : int.tryParse(numeric[1]!, radix: 16);
    final name = named?[2];
    final resourcePackage = named?[1] ?? packageName;
    final paths = <String>{};
    if (id != null || name != null) {
      if (isBundle && zip.contains('resources.pb')) {
        paths.addAll(protoResourceFiles(zip.read('resources.pb')!, id: id, name: name, packageName: resourcePackage));
      } else if (!isBundle && id != null && zip.contains('resources.arsc')) {
        paths.addAll(androidResourceFiles(zip.read('resources.arsc')!, id));
      } else if (name != null && resourcePackage == packageName) {
        final path = RegExp('^res/xml(?:-[^/]+)?/${RegExp.escape(name)}\\.xml\$');
        paths.addAll(zip.entries.keys.where(path.hasMatch));
      }
    }
    if (paths.isEmpty) throw FormatException('Cannot resolve network security config $reference');
    return [
      for (final path in paths)
        (path, _readNsc(path)),
    ];
  }

  XmlDocument _readNsc(String path) {
    final doc = _parse(isBundle ? _decode('base/$path', from: archive) : _decode(path));
    if (doc == null || doc.rootElement.name.local != 'network-security-config') {
      throw FormatException('Cannot decode network security config $path');
    }
    return doc;
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

  /// Certificates that signed the file. For an AAB this is the upload key:
  /// Google Play re-signs the APKs it serves with the app signing key.
  late final List<SigningCert> certificates = readSigningCerts(archive);

  int get sizeBytes => archive.bytes.length;

  String? _decode(String entry, {ZipReader? from}) {
    try {
      final bytes = (from ?? zip).read(entry);
      if (bytes == null) return null;
      if (isBinaryXml(bytes)) return decodeBinaryXml(bytes);
      if (isBundle && isProtoXml(bytes)) return decodeProtoXml(bytes);
      return null;
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
