import 'dart:typed_data';

import 'package:aegis/src/binary/arm64_strings.dart';
import 'package:aegis/src/binary/macho_security.dart';
import 'package:test/test.dart';

import 'support/macho_security_fixture.dart';

/// MOVZ/MOVK, 64-bit (Xd) or 32-bit (Wd).
int movz(int rd, int imm, int hw, {bool x = true}) =>
    (x ? 0xd2800000 : 0x52800000) | hw << 21 | imm << 5 | rd;
int movk(int rd, int imm, int hw, {bool x = true}) =>
    (x ? 0xf2800000 : 0x72800000) | hw << 21 | imm << 5 | rd;
const nop = 0xd503201f;
const ret = 0xd65f03c0;

/// How Swift's compiler builds an ASCII literal of up to 15 bytes: the
/// first word in [low], the second (with `0xE0 | length` on top) in [high],
/// skipping half-words that are zero.
List<int> swiftLiteral(String s, {int low = 0, int high = 1}) {
  final bytes = s.codeUnits;
  var first = 0, second = 0;
  for (var i = 0; i < bytes.length; i++) {
    if (i < 8) {
      first |= bytes[i] << (8 * i);
    } else {
      second |= bytes[i] << (8 * (i - 8));
    }
  }
  second |= (0xe0 | s.length) << 56;
  List<int> build(int rd, int value, {bool x = true}) {
    final out = <int>[];
    for (var hw = 0; hw < (x ? 4 : 2); hw++) {
      final half = (value >> (16 * hw)) & 0xffff;
      if (half == 0) continue;
      out.add(
          out.isEmpty ? movz(rd, half, hw, x: x) : movk(rd, half, hw, x: x));
    }
    return out;
  }

  return [
    ...build(low, first, x: first >> 32 != 0),
    ...build(high, second),
  ];
}

Uint8List words(List<int> code) {
  final data = ByteData(code.length * 4);
  for (var i = 0; i < code.length; i++) {
    data.setUint32(i * 4, code[i], Endian.little);
  }
  return data.buffer.asUint8List();
}

void main() {
  test('recovers short and long inline literals', () {
    final code = [
      ...swiftLiteral('FridaGadget'),
      nop,
      ...swiftLiteral('frida'), // first word built with 32-bit MOVZ/MOVK
      ret,
      ...swiftLiteral('/etc/apt', low: 8, high: 9),
      ...swiftLiteral('cydia://package', low: 2, high: 3),
    ];
    expect(arm64SmallStrings(words(code)),
        {'FridaGadget', 'frida', '/etc/apt', 'cydia://package'});
  });

  test('the second word may come first', () {
    final literal = swiftLiteral('/var/jb');
    final split = literal.indexWhere((w) => w & 31 == 1);
    final code = [...literal.sublist(split), ...literal.sublist(0, split)];
    expect(arm64SmallStrings(words(code)), {'/var/jb'});
  });

  test('ordinary constants are not taken for strings', () {
    final code = [
      movz(0, 0x1234, 0), movk(0, 0xffff, 3), // not a literal
      movz(1, 0xe500, 3), // a length-5 marker without a printable first word
      movz(2, 0x0001, 0), movk(2, 0x0203, 1),
      ...swiftLiteral('abc'), // shorter than 4
    ];
    expect(arm64SmallStrings(words(code)), isEmpty);
  });

  test('a first word far from its marker is not paired', () {
    final literal = swiftLiteral('cynject');
    final split = literal.indexWhere((w) => w & 31 == 1);
    final code = [
      ...literal.sublist(0, split),
      for (var i = 0; i < 20; i++) nop,
      ...literal.sublist(split),
    ];
    expect(arm64SmallStrings(words(code)), isEmpty);
  });

  test('the Mach-O reader adds literals from arm64 __text to its strings', () {
    final slice = inspectMachSecurity(securityMachO(
        strings: ['/Applications/Cydia.app'],
        code: [...swiftLiteral('FridaGadget'), ret])).single;
    expect(
        slice.strings, containsAll(['/Applications/Cydia.app', 'FridaGadget']));

    final encrypted = inspectMachSecurity(securityMachO(
        encrypted: true, code: [...swiftLiteral('FridaGadget'), ret])).single;
    expect(encrypted.strings, isEmpty);
  });
}
