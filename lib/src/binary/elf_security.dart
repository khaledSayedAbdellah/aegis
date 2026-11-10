import 'dart:convert';
import 'dart:typed_data';

/// Bounded ELF header/program/section/dynamic-table inspection. No execution.
class ElfSecurity {
  ElfSecurity(this.bits, this.type);
  final int bits, type;
  bool stackHeader = false,
      executableStack = false,
      wx = false,
      relro = false,
      bindNow = false,
      dynamic = false;
  bool? canary, fortify;
  final List<String> debugSections = [], paths = [];
  Map<String, Object?> toJson() => {
        'bits': bits,
        'type': type,
        'executableStack': stackHeader ? executableStack : null,
        'writableExecutableLoad': wx,
        'relro': !dynamic
            ? 'not_applicable'
            : relro
                ? (bindNow ? 'full' : 'partial')
                : 'none',
        'positionIndependent': type == 3,
        'stackCanaryReference': canary,
        'fortifyReference': fortify,
        'debugSections': debugSections,
        'searchPaths': paths
      };
}

ElfSecurity inspectElf(Uint8List bytes) {
  if (bytes.length < 52 ||
      bytes[0] != 127 ||
      ascii.decode(bytes.sublist(1, 4)) != 'ELF' ||
      ![1, 2].contains(bytes[4]) ||
      ![1, 2].contains(bytes[5])) {
    throw const FormatException('Invalid ELF');
  }
  final wide = bytes[4] == 2;
  final endian = bytes[5] == 1 ? Endian.little : Endian.big;
  final d = ByteData.sublistView(bytes);
  void range(int o, int n) {
    if (o < 0 || n < 0 || o > bytes.length - n) {
      throw const FormatException('Truncated ELF');
    }
  }

  int u16(int o) {
    range(o, 2);
    return d.getUint16(o, endian);
  }

  int u32(int o) {
    range(o, 4);
    return d.getUint32(o, endian);
  }

  int word(int o) {
    range(o, wide ? 8 : 4);
    return wide ? d.getUint64(o, endian) : d.getUint32(o, endian);
  }

  String string(int o, int end) {
    range(o, 0);
    range(end, 0);
    final b = <int>[];
    while (o < end && bytes[o] != 0 && b.length < 4096) {
      b.add(bytes[o++]);
    }
    if (o >= end || bytes[o] != 0) {
      throw const FormatException('ELF string limit');
    }
    return utf8.decode(b, allowMalformed: true);
  }

  final result = ElfSecurity(wide ? 64 : 32, u16(16));
  final ph = word(wide ? 32 : 28), sh = word(wide ? 40 : 32);
  final ps = u16(wide ? 54 : 42),
      pn = u16(wide ? 56 : 44),
      ss = u16(wide ? 58 : 46),
      sn = u16(wide ? 60 : 48),
      ni = u16(wide ? 62 : 50);
  if (pn == 65535 ||
      ni == 65535 ||
      sn == 0 && sh != 0 ||
      pn > 4096 ||
      sn > 16384 ||
      pn > 0 && ps < (wide ? 56 : 32) ||
      sn > 0 && ss < (wide ? 64 : 40)) {
    throw const FormatException('Unsupported ELF table');
  }
  final loads = <(int, int, int)>[];
  final dyn = <(int, int)>[];
  range(ph, ps * pn);
  range(sh, ss * sn);
  for (var i = 0; i < pn; i++) {
    final o = ph + i * ps,
        type = u32(o),
        flags = u32(o + (wide ? 4 : 24)),
        off = word(o + (wide ? 8 : 4)),
        addr = word(o + (wide ? 16 : 8)),
        size = word(o + (wide ? 32 : 16));
    range(off, size);
    if (type == 1) {
      loads.add((addr, off, size));
      result.wx |= (flags & 3) == 3;
    }
    if (type == 0x6474e551) {
      result.stackHeader = true;
      result.executableStack |= (flags & 1) != 0;
    }
    if (type == 0x6474e552) result.relro = true;
    if (type == 2) {
      result.dynamic = true;
      dyn.add((off, size));
    }
  }
  int? strings, stringsSize;
  final pathOffsets = <int>[];
  for (final table in dyn) {
    final step = wide ? 16 : 8;
    if (table.$2 > 4 * 1024 * 1024) {
      throw const FormatException('ELF dynamic limit');
    }
    for (var o = table.$1; o + step <= table.$1 + table.$2; o += step) {
      final tag = word(o), value = word(o + (wide ? 8 : 4));
      if (tag == 0) break;
      if (tag == 5) strings = value;
      if (tag == 10) stringsSize = value;
      if (tag == 15 || tag == 29) pathOffsets.add(value);
      if (tag == 24 ||
          tag == 30 && value & 8 != 0 ||
          tag == 0x6ffffffb && value & 1 != 0) {
        result.bindNow = true;
      }
    }
  }
  if (pathOffsets.isNotEmpty) {
    if (strings == null || stringsSize == null) {
      throw const FormatException('Missing dynamic strings');
    }
    final address = strings, stringLength = stringsSize;
    final load = loads
        .where((l) => address >= l.$1 && address + stringLength <= l.$1 + l.$3)
        .firstOrNull;
    if (load == null) throw const FormatException('Invalid dynamic strings');
    final start = load.$2 + strings - load.$1;
    for (final off in pathOffsets) {
      if (off >= stringsSize) {
        throw const FormatException('Invalid path offset');
      }
      result.paths.addAll(string(start + off, start + stringsSize).split(':'));
    }
  }
  int? names;
  int namesSize = 0;
  if (sn > 0) {
    if (ni >= sn) throw const FormatException('Invalid names index');
    final o = sh + ni * ss;
    names = word(o + (wide ? 24 : 16));
    namesSize = word(o + (wide ? 32 : 20));
    range(names, namesSize);
  }
  for (var i = 0; i < sn; i++) {
    final o = sh + i * ss,
        type = u32(o + 4),
        off = word(o + (wide ? 24 : 16)),
        size = word(o + (wide ? 32 : 20));
    if (type != 8) range(off, size);
    final nameOffset = u32(o);
    if (nameOffset >= namesSize && namesSize > 0) {
      throw const FormatException('Invalid section name');
    }
    final name =
        namesSize == 0 ? '' : string(names! + nameOffset, names + namesSize);
    if (name.startsWith('.debug_') || name.startsWith('.zdebug_')) {
      result.debugSections.add(name);
    }
    if (type == 2 || type == 11) {
      final link = u32(o + (wide ? 40 : 24)), step = word(o + (wide ? 56 : 36));
      if (link >= sn || step < (wide ? 24 : 16) || size ~/ step > 1000000) {
        throw const FormatException('Invalid symbols');
      }
      final so = sh + link * ss,
          base = word(so + (wide ? 24 : 16)),
          length = word(so + (wide ? 32 : 20));
      range(base, length);
      result.canary ??= false;
      result.fortify ??= false;
      for (var x = off; x + step <= off + size; x += step) {
        final index = u32(x);
        if (index >= length) {
          throw const FormatException('Symbol string offset');
        }
        final symbol = string(base + index, base + length);
        if (symbol == '__stack_chk_fail' || symbol == '__stack_chk_guard') {
          result.canary = true;
        }
        if (RegExp(r'^__\w+_chk$').hasMatch(symbol)) result.fortify = true;
      }
    }
  }
  return result;
}
