import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:aegis/src/rules/native_library_rules.dart';
import 'package:archive/archive.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'support/macho_security_fixture.dart';

void main() {
  test('version strings and the advisory table', () {
    final found = findLibraryVersions(
            'x OpenSSL 1.1.1k  25 Mar 2021 y deflate 1.2.11 Copyright 1995 '
                'libpng version 1.6.43 libcurl/8.4.0 OpenSSL 3.5.1 1 Jul 2025',
            'lib.so')
        .toList();
    expect([
      for (final v in found) '${v.library} ${v.version}'
    ], [
      'OpenSSL 1.1.1k',
      'OpenSSL 3.5.1',
      'zlib 1.2.11',
      'libpng 1.6.43',
      'libcurl 8.4.0'
    ]);
    expect([
      for (final v in found)
        vulnerability(v)?.$1 ?? (vulnerability(v) == null ? 'ok' : 'eol')
    ], [
      'eol',
      'ok',
      '1.2.13',
      'ok',
      'ok'
    ]);
  });

  late Directory dir;
  setUp(() {
    dir = Directory.systemTemp.createTempSync('aegis-oldlib-');
    addTearDown(() => dir.deleteSync(recursive: true));
  });

  test('AEG-B14 reads native libraries of one ABI, not libflutter.so',
      () async {
    final source = ZipDecoder()
        .decodeBytes(File('test/fixtures/apk/secure.apk').readAsBytesSync());
    final archive = Archive();
    for (final f in source.files) {
      archive.addFile(ArchiveFile.bytes(f.name, f.content as List<int>));
    }
    archive
      ..addFile(ArchiveFile.bytes('lib/arm64-v8a/libcrypto.so',
          latin1.encode('\x00OpenSSL 1.0.2u  20 Dec 2019\x00')))
      ..addFile(ArchiveFile.bytes('lib/arm64-v8a/libz2.so',
          latin1.encode('\x00 deflate 1.2.11 Copyright 1995-2017 \x00')));
    final apk = p.join(dir.path, 'app.apk');
    File(apk).writeAsBytesSync(ZipEncoder().encode(archive));
    final r = await runAudit(dir.path,
        apkPath: apk,
        config: AegisConfig(profile: ProfileSet.tryParse('l2')!),
        offline: true);
    final b14 = r.results.singleWhere((x) => x.meta.id == 'AEG-B14');
    expect(b14.findings.map((f) => f.message), [
      'OpenSSL 1.0.2u is inside the APK: that branch is past its end of life and gets no security fixes.',
      'zlib 1.2.11 is inside the APK; versions before 1.2.13 have known vulnerabilities (CVE-2022-37434, CVE-2018-25032).',
    ]);
    expect(b14.findings.first.file, 'app.apk!/lib/arm64-v8a/libcrypto.so');
  });

  test('AEG-I13 reads IPA binaries', () async {
    const app = 'Payload/Test.app';
    final archive = Archive()
      ..addFile(ArchiveFile.bytes(
          '$app/Info.plist',
          utf8.encode('<plist><dict><key>CFBundleIdentifier</key>'
              '<string>org.aegis.test</string><key>CFBundleExecutable</key>'
              '<string>Test</string></dict></plist>')))
      ..addFile(
          ArchiveFile.bytes('$app/Test', securityMachO(strings: ['hello'])))
      ..addFile(ArchiveFile.bytes('$app/Frameworks/Net.framework/Net',
          securityMachO(fileType: 6, strings: ['libcurl/7.88.1'])));
    final ipa = p.join(dir.path, 'app.ipa');
    File(ipa).writeAsBytesSync(ZipEncoder().encode(archive));
    final r = await runAudit(dir.path,
        ipaPath: ipa,
        config: AegisConfig(profile: ProfileSet.tryParse('l2')!),
        offline: true);
    final i13 = r.results.singleWhere((x) => x.meta.id == 'AEG-I13');
    expect(i13.findings.single.message,
        'libcurl 7.88.1 is inside the IPA; versions before 8.4.0 have known vulnerabilities (CVE-2023-38545).');
  });
}
