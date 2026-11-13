/// A bounded DEX reader that answers one question: which class's code uses a
/// given string constant or calls a method with a given name. Follows the
/// Dalvik executable format; anything out of range ends the scan.
library;

import 'dart:convert';
import 'dart:typed_data';

class DexUsage {
  DexUsage(this.classes, this.users, {required this.complete});

  /// Every class defined or referenced, as `com.example.Name`.
  final Set<String> classes;

  /// Class -> the labels of the strings and method names its code uses.
  final Map<String, Set<String>> users;

  /// False when the file could not be read to the end.
  final bool complete;
}

/// Reads [bytes] as a DEX file. [labels] names what a string or a method name
/// stands for (empty when it is not interesting).
DexUsage readDexUsage(Uint8List bytes, Set<String> Function(String) labels) {
  final classes = <String>{};
  final users = <String, Set<String>>{};
  try {
    _Dex(bytes, labels, classes, users).read();
    return DexUsage(classes, users, complete: true);
  } on RangeError {
    return DexUsage(classes, users, complete: false);
  } on FormatException {
    return DexUsage(classes, users, complete: false);
  }
}

/// Instruction sizes in 16-bit code units, by opcode.
final List<int> _widths = () {
  final w = List<int>.filled(256, 1);
  void set(int from, int to, int n) {
    for (var i = from; i <= to; i++) {
      w[i] = n;
    }
  }

  for (final op in const [0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19]) {
    w[op] = 2;
  }
  for (final op in const [0x1a, 0x1c, 0x1f, 0x20, 0x22, 0x23, 0x29]) {
    w[op] = 2;
  }
  for (final op in const [0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x2a]) {
    w[op] = 3;
  }
  w[0x18] = 5;
  set(0x24, 0x26, 3);
  set(0x2b, 0x2c, 3);
  set(0x2d, 0x3d, 2);
  set(0x44, 0x6d, 2);
  set(0x6e, 0x72, 3);
  set(0x74, 0x78, 3);
  set(0x90, 0xaf, 2);
  set(0xd0, 0xe2, 2);
  set(0xfa, 0xfb, 4);
  set(0xfc, 0xfd, 3);
  set(0xfe, 0xff, 2);
  return w;
}();

class _Dex {
  _Dex(this.bytes, this.labels, this.classes, this.users)
      : data = ByteData.sublistView(bytes);

  final Uint8List bytes;
  final ByteData data;
  final Set<String> Function(String) labels;
  final Set<String> classes;
  final Map<String, Set<String>> users;

  /// String index -> labels, for the interesting strings only.
  final wanted = <int, Set<String>>{};

  /// Method index -> labels of its name.
  final wantedMethods = <int, Set<String>>{};

  int u16(int o) => data.getUint16(o, Endian.little);
  int u32(int o) => data.getUint32(o, Endian.little);

  /// Read position for [leb].
  var at = 0;

  /// The unsigned LEB128 number at [at]; moves past it.
  int leb() {
    var result = 0;
    var shift = 0;
    while (true) {
      final b = bytes[at++];
      result |= (b & 0x7f) << shift;
      if (b & 0x80 == 0) return result;
      shift += 7;
      if (shift > 35) throw const FormatException('Bad LEB128.');
    }
  }

  void read() {
    if (bytes.length < 0x70 ||
        bytes[0] != 0x64 ||
        bytes[1] != 0x65 ||
        bytes[2] != 0x78) {
      throw const FormatException('Not a DEX file.');
    }
    final stringCount = u32(0x38), stringOff = u32(0x3c);
    final typeCount = u32(0x40), typeOff = u32(0x44);
    final methodCount = u32(0x58), methodOff = u32(0x5c);
    final classCount = u32(0x60), classOff = u32(0x64);
    if (stringCount > 4000000 || typeCount > 1000000 || classCount > 1000000) {
      throw const FormatException('DEX tables exceed the analysis limit.');
    }

    final typeStrings = <int>{
      for (var i = 0; i < typeCount; i++) u32(typeOff + 4 * i)
    };
    final descriptors = <int, String>{};
    for (var i = 0; i < stringCount; i++) {
      at = u32(stringOff + 4 * i);
      leb();
      final o = at;
      var end = o;
      while (bytes[end] != 0) {
        end++;
      }
      final text = utf8.decode(Uint8List.sublistView(bytes, o, end),
          allowMalformed: true);
      if (typeStrings.contains(i)) descriptors[i] = text;
      final found = labels(text);
      if (found.isNotEmpty) wanted[i] = found;
    }
    String? className(int typeIndex) {
      final d = descriptors[u32(typeOff + 4 * typeIndex)];
      if (d == null || !d.startsWith('L') || !d.endsWith(';')) return null;
      return d.substring(1, d.length - 1).replaceAll('/', '.');
    }

    for (var i = 0; i < typeCount; i++) {
      final name = className(i);
      if (name != null) classes.add(name);
    }
    if (wanted.isEmpty) return;
    for (var i = 0; i < methodCount; i++) {
      final found = wanted[u32(methodOff + 8 * i + 4)];
      if (found != null) wantedMethods[i] = found;
    }

    for (var i = 0; i < classCount; i++) {
      final def = classOff + 32 * i;
      final name = className(u32(def));
      final dataOff = u32(def + 24);
      if (name == null || dataOff == 0) continue;
      at = dataOff;
      final fields = leb() + leb();
      final methods = leb() + leb();
      if (fields > 1000000 || methods > 1000000) {
        throw const FormatException('Class data exceeds the analysis limit.');
      }
      for (var f = 0; f < fields; f++) {
        leb();
        leb();
      }
      for (var m = 0; m < methods; m++) {
        leb();
        leb();
        final codeOff = leb();
        if (codeOff != 0) _code(name, codeOff);
      }
    }
  }

  void _code(String owner, int codeOff) {
    final units = u32(codeOff + 12);
    final start = codeOff + 16;
    final end = start + units * 2;
    if (end > bytes.length) throw RangeError('Code item out of range.');
    void use(Set<String>? found) {
      if (found != null) (users[owner] ??= {}).addAll(found);
    }

    var o = start;
    while (o < end) {
      final unit = u16(o);
      final op = unit & 0xff;
      if (op == 0 && unit != 0) {
        // Switch and array payloads follow the code and are not instructions.
        final int size;
        switch (unit) {
          case 0x0100:
            size = 4 + u16(o + 2) * 2;
          case 0x0200:
            size = 2 + u16(o + 2) * 4;
          case 0x0300:
            size = 4 + (u16(o + 2) * u32(o + 4) + 1) ~/ 2;
          default:
            size = 1;
        }
        o += size * 2;
        continue;
      }
      if (op == 0x1a) {
        use(wanted[u16(o + 2)]);
      } else if (op == 0x1b) {
        use(wanted[u32(o + 2)]);
      } else if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
        use(wantedMethods[u16(o + 2)]);
      }
      o += _widths[op] * 2;
    }
  }
}
