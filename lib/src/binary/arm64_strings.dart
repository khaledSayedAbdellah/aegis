/// Recovers Swift's inline string literals from arm64 code.
///
/// Swift stores an ASCII string literal of up to 15 bytes inside the string
/// value itself instead of in `__cstring`: two 64-bit words, the bytes in
/// order and, in the top byte of the second word, `0xE0` plus the length. On
/// arm64 the compiler builds both words with MOVZ/MOVK instructions, so tools
/// that read only string sections never see literals such as "frida" or
/// "/etc/apt". This reads those instruction sequences back.
library;

import 'dart:typed_data';

/// Inline string literals of at least [minLength] bytes found in the arm64
/// instructions of [code] (a `__text` section).
Set<String> arm64SmallStrings(Uint8List code,
    {int minLength = 4, int maxStrings = 50000}) {
  final data = ByteData.sublistView(code);
  final out = <String>{};
  // Register -> value being built and the index of its last instruction.
  final building = <int, (int, int)>{};
  // Finished 64-bit values: (instruction index, register, value).
  final done = <(int, int, int)>[];

  void finish(int register) {
    final value = building.remove(register);
    if (value != null) done.add((value.$2, register, value.$1));
  }

  final count = code.length ~/ 4;
  for (var i = 0; i < count; i++) {
    final ins = data.getUint32(i * 4, Endian.little);
    final rd = ins & 31;
    final hw = (ins >> 21) & 3;
    final imm = (ins >> 5) & 0xffff;
    // MOVZ starts a new value; the 32-bit form (Wd) also clears the upper
    // half, which is how short first words are built.
    final opcode = ins & 0xff800000;
    if (opcode == 0xd2800000 || opcode == 0x52800000) {
      finish(rd);
      building[rd] = (imm << (16 * hw), i);
    } else if (opcode == 0xf2800000 || opcode == 0x72800000) {
      // MOVK: replaces one 16-bit half-word of the value being built.
      final current = building[rd];
      if (current == null || i - current.$2 > 4) continue;
      final shift = 16 * hw;
      building[rd] = ((current.$1 & ~(0xffff << shift)) | (imm << shift), i);
    } else if (rd != 31 && _writesRegister(ins)) {
      finish(rd);
    }
    // Values not touched for a few instructions are complete.
    if (i % 8 == 7) {
      for (final r in building.keys.toList()) {
        if (i - building[r]!.$2 > 4) finish(r);
      }
    }
    if (done.length > 64) {
      _pair(done, minLength, out);
      done.removeRange(0, done.length - 16);
      if (out.length >= maxStrings) return out;
    }
  }
  for (final r in building.keys.toList()) {
    finish(r);
  }
  _pair(done, minLength, out);
  return out;
}

/// Data-processing instructions that overwrite their destination register;
/// a value being built in it is over (or was never a string).
bool _writesRegister(int ins) =>
    // ADD/SUB (immediate), logical (immediate), ADR/ADRP, MOVN.
    ins & 0x1f000000 == 0x11000000 ||
    ins & 0x1f800000 == 0x12000000 ||
    ins & 0x1f000000 == 0x10000000 ||
    ins & 0x7f800000 == 0x12800000;

/// Matches each second word (`0xE0 | length` in its top byte) with a nearby
/// first word in another register and adds the decoded literal to [out].
void _pair(List<(int, int, int)> done, int minLength, Set<String> out) {
  for (final (index, register, high) in done) {
    final top = (high >> 56) & 0xff;
    if (top & 0xf0 != 0xe0) continue;
    final length = top & 0x0f;
    if (length < minLength) continue;
    // Bytes of the second word beyond the literal must be zero.
    final tail = length > 8 ? length - 8 : 0;
    final unused = 0x00ffffffffffffff & ~((1 << (8 * tail)) - 1);
    if (high & unused != 0) continue;
    if (!_printable(high, tail)) continue;
    final head = length < 8 ? length : 8;
    String? best;
    var distance = 9;
    for (final (other, otherRegister, low) in done) {
      if (otherRegister == register) continue;
      final d = (other - index).abs();
      if (d >= distance) continue;
      if (!_printable(low, head)) continue;
      if (head < 8 && low >> (8 * head) != 0) continue;
      distance = d;
      best = _bytes(low, head) + _bytes(high, tail);
    }
    if (best != null) out.add(best);
  }
}

bool _printable(int word, int bytes) {
  for (var b = 0; b < bytes; b++) {
    final c = (word >> (8 * b)) & 0xff;
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

String _bytes(int word, int bytes) => String.fromCharCodes(
    [for (var b = 0; b < bytes; b++) (word >> (8 * b)) & 0xff]);
