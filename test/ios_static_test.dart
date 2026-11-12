import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:aegis/aegis.dart';
import 'package:aegis/src/binary/ios_static.dart';
import 'package:aegis/src/binary/macho_security.dart';
import 'package:aegis/src/binary/zip.dart';
import 'package:aegis/src/l10n/messages.g.dart';
import 'package:aegis/src/project.dart';
import 'package:aegis/src/reporters/ios_static_view.dart';
import 'package:aegis/src/rules/ipa_hardening_rules.dart';
import 'package:archive/archive.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'support/macho_security_fixture.dart';

const app = 'Payload/Test.app';
const plist =
    '<plist><dict><key>CFBundleIdentifier</key><string>org.aegis.test</string>'
    '<key>CFBundleExecutable</key><string>Test</string></dict></plist>';
Uint8List ipaBytes(Uint8List main, [Map<String, List<int>> extras = const {}]) {
  final archive = Archive()
    ..addFile(ArchiveFile.bytes('$app/Info.plist', utf8.encode(plist)))
    ..addFile(ArchiveFile.bytes('$app/Test', main));
  for (final e in extras.entries) {
    archive.addFile(ArchiveFile.bytes('$app/${e.key}', e.value));
  }
  return Uint8List.fromList(ZipEncoder().encode(archive));
}

void main() {
  test('32-bit and big-endian thin headers preserve their flags', () {
    for (final endian in [Endian.big, Endian.little]) {
      for (final wide in [false, true]) {
        final bytes = Uint8List(wide ? 32 : 28);
        final data = ByteData.sublistView(bytes);
        data.setUint32(0, wide ? 0xfeedfacf : 0xfeedface, endian);
        data.setUint32(4, wide ? 0x0100000c : 12, endian);
        data.setUint32(12, 2, endian);
        data.setUint32(24, 0x200000, endian);
        final slice = inspectMachSecurity(bytes).single;
        expect(slice.pie, isTrue);
        expect(slice.architecture, wide ? 'arm64' : 'arm');
      }
    }
  });

  test('oversized strings are reported as limited, not negative evidence', () {
    final analysis = analyzeIpaStatic(
        ZipReader(ipaBytes(securityMachO(strings: ['x' * 4097]))), app, 'Test');
    expect(analysis.complete, isTrue);
    expect(analysis.limited, isTrue);
    expect(analysis.signals.first.status, 'unavailable');
  });

  test('literal function names do not imply ARC or canary symbol references',
      () {
    final analysis = analyzeIpaStatic(
        ZipReader(ipaBytes(
            securityMachO(strings: ['___stack_chk_fail', '_objc_release']))),
        app,
        'Test');
    for (final signal in analysis.signals
        .where((s) => s.id == 'arc' || s.id == 'stack_canary')) {
      expect(signal.status, 'not_observed');
    }
  });

  test('Mach-O flags use initial protections and distinguish dylibs', () {
    final facts = inspectMachSecurity(securityMachO(maxProtection: 7)).single;
    expect(facts.pie, isTrue);
    expect(facts.writableExecutableSegments, isEmpty);
    expect(facts.executableStackRequested, isFalse);
    final risky =
        inspectMachSecurity(securityMachO(flags: 0x20000, initialProtection: 7))
            .single;
    expect(risky.pie, isFalse);
    expect(risky.executableStackRequested, isTrue);
    expect(risky.writableExecutableSegments, ['__TEXT']);
    expect(
        inspectMachSecurity(securityMachO(fileType: 6, flags: 0))
            .single
            .fileType,
        6);
  });

  test('debug entries use N_STAB, not normal exports or strip marker', () {
    final plain = inspectMachSecurity(securityMachO(symbols: [
      ('_ordinaryExport', 0x0f),
      ('radr://5614542', 0x3c),
    ])).single;
    expect(plain.debugSymbols, 0);
    final debug = inspectMachSecurity(
        securityMachO(symbols: [('_main', 0x0f), ('file.m', 0x64)])).single;
    expect(debug.debugSymbols, 1);
    expect(debug.symbols, {'_main'});
  });

  test('all fat slices and swapped fat headers are inspected', () {
    for (final wide in [false, true]) {
      for (final swapped in [false, true]) {
        final slices = inspectMachSecurity(fatSecurityMachO([
          securityMachO(),
          securityMachO(flags: 0),
        ], wide: wide, swapped: swapped));
        expect(slices.map((s) => s.pie), [true, false]);
      }
    }
  });

  test(
      'invalid commands, symbol ranges, sections and overlapping slices reject',
      () {
    for (final mutation in <void Function(ByteData)>[
      (d) => d.setUint32(36, 4, Endian.little),
      (d) => d.setUint32(20, 0xffffffff, Endian.little),
      (d) => d.setUint32(216, 0xffffffff, Endian.little),
      (d) => d.setUint32(56 + 72 + 48, 0xffffffff, Endian.little),
    ]) {
      final bytes = securityMachO(symbols: [('_ptrace', 1)]);
      mutation(ByteData.sublistView(bytes));
      expect(() => inspectMachSecurity(bytes), throwsFormatException);
    }
    final fat = fatSecurityMachO([securityMachO(), securityMachO()]);
    final data = ByteData.sublistView(fat);
    data.setUint32(36, data.getUint32(16));
    expect(() => inspectMachSecurity(fat), throwsFormatException);
    expect(
        () => inspectMachSecurity(Uint8List.fromList([0xcf, 0xfa, 0xed, 0xfe])),
        throwsFormatException);
  });

  test('encrypted cstrings do not become positive or negative protection proof',
      () {
    final bytes = ipaBytes(
        securityMachO(encrypted: true, strings: ['isJailbroken', 'frida']));
    final analysis = analyzeIpaStatic(ZipReader(bytes), app, 'Test');
    expect(analysis.limited, isTrue);
    expect(analysis.signals.every((s) => s.status == 'unavailable'), isTrue);
    expect(analysis.toJson()['runtimeVerified'], isFalse);
  });

  test(
      'framework references are found; resource text is not executable evidence',
      () {
    final bytes = ipaBytes(securityMachO(), {
      'note.txt': utf8.encode('isJailbroken frida SecCodeCheckValidity'),
      'Frameworks/Guard.framework/README': utf8.encode('isJailbroken'),
      'Frameworks/Guard.framework/Guard':
          securityMachO(fileType: 6, flags: 0, symbols: [
        ('_ptrace', 1),
        ('_SecCodeCheckValidity', 1),
        ('___stack_chk_fail', 1),
        ('_objc_release', 1)
      ], strings: [
        'isJailbroken',
        'frida-server'
      ]),
    });
    final analysis = analyzeIpaStatic(ZipReader(bytes), app, 'Test');
    expect(analysis.complete, isTrue);
    expect(analysis.binaries, hasLength(2));
    expect(analysis.signals.every((s) => s.status == 'observed'), isTrue);
    expect(
        analysis.signals
            .expand((s) => s.evidence)
            .every((e) => e.file.endsWith('/Guard')),
        isTrue);
  });

  test('unreadable framework and absent symbol tables remain incomplete', () {
    final analysis = analyzeIpaStatic(
        ZipReader(ipaBytes(securityMachO(symbolTable: false), {
          'Frameworks/Bad.framework/Bad': [1, 2, 3],
        })),
        app,
        'Test');
    expect(analysis.complete, isFalse);
    expect(analysis.limited, isTrue);
    expect(analysis.signals.every((s) => s.status == 'unavailable'), isTrue);
  });

  test('absence of signatures is not absence of runtime protection', () {
    final analysis =
        analyzeIpaStatic(ZipReader(ipaBytes(securityMachO())), app, 'Test');
    expect(analysis.signals.every((s) => s.status == 'not_observed'), isTrue);
    final json = analysis.toJson();
    expect(json['runtimeVerified'], isFalse);
    final en = IosStaticView(analysis, 'en').html();
    final ar = IosStaticView(analysis, 'ar').html();
    expect(en, contains(En.iosStaticCaveat));
    expect(ar, contains(Ar.iosStaticCaveat));
    expect(ar, isNot(contains(En.iosStaticHeading)));
    expect(ar, contains('PIE'));
  });

  test('report renderers escape untrusted binary paths', () {
    final analysis = IosStaticAnalysis([
      IosStaticBinary('<script>alert(1)</script>', const [], issue: 'invalid')
    ]);
    final view = IosStaticView(analysis, 'en');
    expect(view.html(), isNot(contains('<script>')));
    expect(view.markdown(), isNot(contains('<script>')));
    expect(view.html(), contains('&lt;script&gt;'));
  });

  test('hardening rules preserve findings when another binary is unreadable',
      () async {
    final dir = Directory.systemTemp.createTempSync('aegis-ios-static-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final file = File(p.join(dir.path, 'test.ipa'))
      ..writeAsBytesSync(ipaBytes(
        securityMachO(flags: 0x20000, symbols: [('source.m', 0x64)]),
        {
          'Frameworks/Bad.framework/Bad': [1]
        },
      ));
    final ipa = IpaContext.load(file.path);
    final project = Project.ipaOnly(dir.path, ipa)..ipa = ipa;
    for (final rule in ipaHardeningRules) {
      final check = await rule.check(project, ProfileSet.tryParse('l2+r')!);
      expect(check.isIncomplete, isTrue);
      expect(check.findings, isNotEmpty);
    }
  });

  test('normal dylib PIE and normal exports do not produce findings', () async {
    final dir = Directory.systemTemp.createTempSync('aegis-ios-static-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final file = File(p.join(dir.path, 'test.ipa'))
      ..writeAsBytesSync(ipaBytes(
        securityMachO(symbols: [('_main', 0x0f)]),
        {'Frameworks/SDK.framework/SDK': securityMachO(fileType: 6, flags: 0)},
      ));
    final ipa = IpaContext.load(file.path);
    final project = Project.ipaOnly(dir.path, ipa)..ipa = ipa;
    for (final rule in ipaHardeningRules) {
      final check = await rule.check(project, ProfileSet.tryParse('l2+r')!);
      expect(check.isIncomplete, isFalse);
      expect(check.findings, isEmpty);
    }
  });

  test('run --mode ipa --no-probe produces static evidence without a target',
      () async {
    final dir = Directory.systemTemp.createTempSync('aegis-ios-static-cli-');
    addTearDown(() => dir.deleteSync(recursive: true));
    File(p.join(dir.path, 'test.ipa'))
        .writeAsBytesSync(ipaBytes(securityMachO(strings: ['isJailbroken'])));
    File(p.join(dir.path, 'aegis.yaml'))
        .writeAsStringSync('ipa: test.ipa\nlang: ar\nprofile: l2+r\n');
    final result = await Process.run(Platform.resolvedExecutable, [
      p.absolute('bin/aegis.dart'),
      'run',
      dir.path,
      '--mode',
      'ipa',
      '--no-probe',
      '--offline',
      '--no-open',
      '-f',
      'console,html,md,json,sarif',
    ]);
    final report = jsonDecode(File(p.join(dir.path, 'build/aegis-report.json'))
        .readAsStringSync()) as Map;
    expect(report['iosStaticAnalysis']['runtimeVerified'], isFalse);
    expect(report['iosStaticAnalysis']['signals'][0]['status'], 'observed');
    expect(report['probe']['ran'], isFalse);
    expect(result.stdout, contains(En.iosStaticHeading));
    expect(result.stdout, isNot(contains(Ar.iosStaticHeading)));
    for (final ext in ['html', 'md']) {
      expect(
          File(p.join(dir.path, 'build/aegis-report.$ext')).readAsStringSync(),
          contains(Ar.iosStaticHeading));
    }
    final runtime = (report['rules'] as List)
        .cast<Map>()
        .where((r) => r['id'].startsWith('AEG-R'));
    expect(runtime.any((r) => r['status'] == 'passed'), isFalse);
  });
}
