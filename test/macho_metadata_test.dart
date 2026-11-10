import 'dart:typed_data';

import 'package:aegis/src/binary/ios_static.dart';
import 'package:aegis/src/binary/macho_metadata.dart';
import 'package:aegis/src/binary/macho_security.dart';
import 'package:aegis/src/reporters/ios_static_view.dart';
import 'package:test/test.dart';

import 'support/macho_metadata_fixture.dart';
import 'support/macho_security_fixture.dart';

void main() {
  for (final wide in [false, true]) {
    for (final endian in [Endian.big, Endian.little]) {
      test('metadata relationships ${wide ? 64 : 32} bit $endian', () {
        final s = inspectMachSecurity(metadataMachO(wide: wide, endian: endian))
            .single;
        expect(s.metadata.limitations, isEmpty);
        final entries = s.metadata.entries;
        expect(entries.where((e) => e.kind == 'objc-class').single.name,
            'GuardClass');
        expect(
            entries.any((e) =>
                e.kind == 'objc-instance-method' &&
                e.owner == 'GuardClass' &&
                e.name == 'isJailbroken'),
            isTrue);
        expect(
            entries.any((e) =>
                e.kind == 'objc-class-method' &&
                e.owner == 'GuardClass' &&
                e.name == 'verifyAppSignature'),
            isTrue);
        expect(
            entries.any((e) =>
                e.kind == 'objc-adopted-protocol' &&
                e.owner == 'GuardClass' &&
                e.name == 'SecurityProtocol'),
            isTrue);
        expect(entries.any((e) => e.owner == 'GuardClass(Extras)'), isTrue);
        expect(
            entries.any((e) =>
                e.kind == 'swift-class' &&
                e.qualifiedName == 'Security.JailbreakDetector'),
            isTrue);
        expect(
            entries.any((e) =>
                e.kind == 'swift-protocol' &&
                e.qualifiedName == 'Security.IntegrityChecking'),
            isTrue);
        expect(
            entries.where((e) => e.kind == 'swift-type-reference').single.raw,
            '<ref>C');
      });
    }
  }
  test('relative selectors direct and indirect', () {
    for (final indirect in [false, true]) {
      final m = inspectMachSecurity(
              metadataMachO(smallMethods: true, indirectMethods: indirect))
          .single
          .metadata;
      expect(m.limitations, isEmpty);
      expect(
          m.entries
              .any((e) => e.owner == 'GuardClass' && e.name == 'isJailbroken'),
          isTrue);
    }
  });
  test('chained rebase format 2 and fat slices preserve metadata', () {
    final slices = inspectMachSecurity(fatSecurityMachO([
      metadataMachO(chained: true, chainFormat: 2),
      metadataMachO(wide: false, endian: Endian.big),
    ]));
    for (final slice in slices) {
      expect(slice.metadata.limitations, isEmpty);
      expect(
          slice.metadata.entries
              .where((e) => e.kind == 'objc-class')
              .single
              .name,
          'GuardClass');
    }
  });
  test('Swift type-record tags and descriptor versions are not guessed', () {
    for (final mutate in <void Function(ByteData)>[
      (d) => d.setInt32(2100, 3520 - 2100 + 2, Endian.little),
      (d) => d.setUint32(3520, 0x110, Endian.little),
    ]) {
      final bytes = metadataMachO();
      mutate(ByteData.sublistView(bytes));
      expect(inspectMachSecurity(bytes).single.metadata.limited, isTrue);
    }
  });
  test('all truncations fail safely or retain bounded partial metadata', () {
    final bytes = metadataMachO(chained: true);
    for (var end = 0; end < bytes.length; end += 127) {
      try {
        final result =
            inspectMachSecurity(Uint8List.sublistView(bytes, 0, end));
        expect(result.every((s) => s.metadata.entries.length <= 30000), isTrue);
      } on FormatException {
        // A rejected/truncated container must not escape as RangeError.
      }
    }
  });
  test(
      'tagged chained pointers retain high bits without invalidating other chains',
      () {
    final bytes = metadataMachO(chained: true);
    final d = ByteData.sublistView(bytes);
    d.setUint64(
        2048, d.getUint64(2048, Endian.little) | (17 << 36), Endian.little);
    final m = inspectMachSecurity(bytes).single.metadata;
    expect(m.limitations, contains('unresolved'));
    expect(m.limitations, isNot(contains('fixups')));
    expect(m.entries.where((e) => e.kind == 'objc-class'), isEmpty);
    expect(m.entries.where((e) => e.kind == 'objc-protocol'), isNotEmpty);
  });
  test('chained rebase format 6 resolves relationships', () {
    final m = inspectMachSecurity(metadataMachO(chained: true)).single.metadata;
    expect(m.limitations, isEmpty);
    expect(
        m.entries
            .any((e) => e.owner == 'GuardClass' && e.name == 'isJailbroken'),
        isTrue);
  });
  test(
      'unsupported chains preserve relative Swift but never guess ObjC pointers',
      () {
    final bytes = metadataMachO(chained: true);
    ByteData.sublistView(bytes).setUint16(7042, 12, Endian.little);
    final m = inspectMachSecurity(bytes).single.metadata;
    expect(m.limitations, contains('fixups'));
    expect(m.entries.where((e) => e.kind == 'objc-class'), isEmpty);
    expect(m.entries.where((e) => e.kind == 'swift-class'), isNotEmpty);
  });
  test('invalid pointers, counts, cyclic parents and typerefs are limited', () {
    for (final mutate in <void Function(ByteData)>[
      (d) => d.setUint64(2048, 0xffffffffffff, Endian.little),
      (d) => d.setUint32(3004, 0xffffffff, Endian.little),
      (d) => d.setInt32(3504, 3520 - 3504, Endian.little),
      (d) => d.setUint8(2125, 1), // Truncated symbolic reference at end.
    ]) {
      final bytes = metadataMachO();
      mutate(ByteData.sublistView(bytes));
      expect(inspectMachSecurity(bytes).single.metadata.limited, isTrue);
    }
  });
  test(
      'structured evidence keeps binary, architecture, owner, source and offset',
      () {
    final s = inspectMachSecurity(metadataMachO()).single;
    final analysis = IosStaticAnalysis([
      IosStaticBinary('Payload/Test.app/Test', [s])
    ]);
    final signal = analysis.signals.firstWhere((s) => s.id == 'jailbreak');
    final e = signal.evidence.firstWhere((e) => e.owner == 'GuardClass');
    expect(e.toJson(), containsPair('sliceOffset', 3008));
    expect(e.source, '__DATA,__objc_classlist');
    expect(e.architecture, 'arm64');
    expect(e.token, 'isJailbroken');
    expect(signal.status, 'observed');
    expect(analysis.toJson()['runtimeVerified'], isFalse);
    expect(IosStaticView(analysis, 'ar').html(), contains('GuardClass'));
    expect(IosStaticView(analysis, 'ar').html(),
        isNot(contains('Built-in Objective-C')));
    expect(IosStaticView(analysis, 'en').markdown(),
        contains('methods &#47; requirements'));
  });
  test('nominal Swift demangling refuses complex and malformed symbols', () {
    expect(nominalSwiftName(r'_$s8Security5GuardCMn'), 'Security.Guard');
    expect(nominalSwiftName('8Security5GuardC'), 'Security.Guard');
    for (final value in [
      r'$s99NoC',
      r'$s8Security5GuardCyyF',
      r'$sSi',
      'notSwift',
      '01A1BC'
    ]) {
      expect(nominalSwiftName(value), isNull);
    }
  });
  test('name refs are not definitions; encrypted metadata is unavailable', () {
    final s = inspectMachSecurity(
            securityMachO(strings: ['JailbreakDetector', 'SecurityProtocol']))
        .single;
    expect(s.metadata.entries, isEmpty);
    final encrypted =
        inspectMachSecurity(securityMachO(encrypted: true)).single;
    expect(encrypted.metadata.entries, isEmpty);
    expect(encrypted.metadata.limitations, contains('encrypted'));
  });
  test('positive and negative expanded indicators are separate from verdicts',
      () {
    IosStaticAnalysis analyze(List<String> strings) => IosStaticAnalysis([
          IosStaticBinary(
              'Test', inspectMachSecurity(securityMachO(strings: strings)))
        ]);
    for (final token in [
      'amIJailbroken',
      '/Applications/Sileo.app',
      '/etc/apt/',
      'cydia://package'
    ]) {
      expect(
          analyze([token])
              .signals
              .firstWhere((s) => s.id == 'jailbreak')
              .status,
          'observed');
    }
    expect(
        analyze(['jailbirds', 'aptitude', 'ordinarySignature', 'isPirated'])
            .signals
            .every((s) => s.status == 'not_observed'),
        isTrue);
    expect(
        analyze(['verifyAppSignature'])
            .signals
            .firstWhere((s) => s.id == 'signing')
            .status,
        'observed');
  });
  test('metadata output cannot inject HTML or Markdown', () {
    final bytes = metadataMachO();
    bytes.setRange(4000, 4010, '<script>x>'.codeUnits);
    final analysis = IosStaticAnalysis(
        [IosStaticBinary('Test', inspectMachSecurity(bytes))]);
    final view = IosStaticView(analysis, 'en');
    expect(view.html(), isNot(contains('<script>')));
    expect(view.markdown(), isNot(contains('<script>')));
    expect(view.html(), contains('&lt;script&gt;'));
  });
}
