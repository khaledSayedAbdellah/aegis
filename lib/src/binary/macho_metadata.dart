/// Bounded, offline metadata reader. Independently implements the layouts in
/// Apple's objc-runtime-new.h / fixup-chains.h and Swift ABI Metadata.h.
/// Never loads the image or invokes code from an artifact.
library;

import 'dart:convert';
import 'dart:typed_data';

class MachSegment {
  const MachSegment(this.address, this.fileOffset, this.fileSize);
  final int address, fileOffset, fileSize;
}

class MachSection {
  const MachSection(
      this.segment, this.name, this.address, this.offset, this.size);
  final String segment, name;
  final int address, offset, size;
}

class MetadataEntry {
  const MetadataEntry(this.kind, this.name, this.source, this.offset,
      {this.owner, this.raw});
  final String kind, name, source;
  final int offset;
  final String? owner, raw;
  String get qualifiedName => owner == null ? name : '$owner.$name';
  Map<String, Object?> toJson() => {
        'kind': kind,
        'name': name,
        'source': source,
        if (offset >= 0) 'sliceOffset': offset,
        if (owner != null) 'owner': owner,
        if (raw != null) 'raw': raw,
      };
}

class MachMetadata {
  const MachMetadata(this.entries, this.limitations);
  final List<MetadataEntry> entries;
  // Stable machine-readable reasons. Human reports localize them.
  final Set<String> limitations;
  bool get limited => limitations.isNotEmpty;
  Map<String, Object?> toJson() => {
        'reader': 'builtin',
        'runtimeVerified': false,
        'limited': limited,
        'limitations': limitations.toList()..sort(),
        'entries': entries.map((e) => e.toJson()).toList(),
      };
}

MachMetadata inspectMachMetadata(Uint8List bytes, Endian endian, bool wide,
    List<MachSegment> segments, List<MachSection> sections, Set<String> symbols,
    {required bool encrypted, (int, int)? fixups}) {
  if (encrypted) return const MachMetadata([], {'encrypted'});
  return _Reader(bytes, endian, wide, segments, sections).read(symbols, fixups);
}

class _Reader {
  _Reader(this.bytes, this.endian, this.wide, this.segments, this.sections)
      : data = ByteData.sublistView(bytes);
  final Uint8List bytes;
  final ByteData data;
  final Endian endian;
  final bool wide;
  final List<MachSegment> segments;
  final List<MachSection> sections;
  final entries = <MetadataEntry>[];
  final limitations = <String>{};
  final seen = <String>{};
  final pointers = <int, int?>{};
  var operations = 0;
  var chainFailure = false;
  int get width => wide ? 8 : 4;
  Never invalid() => throw const FormatException('Invalid metadata range.');
  void budget() {
    if (++operations > 2000000) {
      limitations.add('budget');
      invalid();
    }
  }

  void bounds(int o, int n) {
    if (o < 0 || n < 0 || o > bytes.length - n) invalid();
  }

  int u32(int o) {
    bounds(o, 4);
    return data.getUint32(o, endian);
  }

  int u16(int o) {
    bounds(o, 2);
    return data.getUint16(o, endian);
  }

  int rawPointer(int o) {
    bounds(o, width);
    return wide ? data.getUint64(o, endian) : u32(o);
  }

  int pointer(int o) {
    if (chainFailure) invalid(); // Never reinterpret encoded pointers as VAs.
    if (pointers.containsKey(o)) {
      return pointers[o] ?? (throw const FormatException('External binding.'));
    }
    return rawPointer(o);
  }

  int offset(int address, [int size = 1]) {
    budget();
    final matches = segments
        .where((s) =>
            address >= s.address && address - s.address <= s.fileSize - size)
        .toList();
    if (matches.length != 1) invalid();
    final o = matches.single.fileOffset + address - matches.single.address;
    bounds(o, size);
    return o;
  }

  int va(int o) {
    final matches = segments
        .where((s) => o >= s.fileOffset && o < s.fileOffset + s.fileSize)
        .toList();
    if (matches.length != 1) invalid();
    return matches.single.address + o - matches.single.fileOffset;
  }

  int relative(int o, {bool indirect = false}) {
    bounds(o, 4);
    final delta = data.getInt32(o, endian);
    if (delta == 0) invalid();
    final target = offset(va(o) + (indirect ? delta & ~1 : delta));
    return indirect && delta & 1 != 0 ? offset(pointer(target)) : target;
  }

  String string(int o) {
    final start = o;
    final containing = segments
        .where((s) => o >= s.fileOffset && o < s.fileOffset + s.fileSize)
        .toList();
    if (containing.length != 1) invalid();
    final end = containing.single.fileOffset + containing.single.fileSize;
    // Strings may not run out of their file-backed segment.
    while (o < end && o - start <= 4096) {
      budget();
      if (bytes[o] == 0) {
        if (o == start) invalid();
        final value = utf8.decode(Uint8List.sublistView(bytes, start, o));
        if (value.contains(RegExp(r'[\x00-\x1f\x7f]'))) invalid();
        return value;
      }
      o++;
    }
    invalid();
  }

  void add(String kind, String name, String source, int o,
      {String? owner, String? raw}) {
    budget();
    if (entries.length >= 30000) {
      limitations.add('budget');
      return;
    }
    if (seen.add('$kind:$o:$owner:$name')) {
      entries.add(MetadataEntry(kind, name, source, o, owner: owner, raw: raw));
    }
  }

  void attempt(void Function() action) {
    if (operations > 2000000) return;
    try {
      budget();
      action();
    } on FormatException {
      limitations.add('unresolved');
    } on RangeError {
      limitations.add('unresolved');
    }
  }

  MachMetadata read(Set<String> symbols, (int, int)? fixups) {
    if (fixups != null) {
      try {
        chains(fixups.$1, fixups.$2);
      } on FormatException {
        chainFailure = true;
        limitations.add('fixups');
      } on RangeError {
        chainFailure = true;
        limitations.add('fixups');
      }
    }
    for (final section in sections) {
      if (operations > 2000000) break;
      final source = '${section.segment},${section.name}';
      if (const {
        '__objc_classlist',
        '__objc_nlclslist',
        '__objc_protolist',
        '__objc_catlist',
        '__objc_nlcatlist'
      }.contains(section.name)) {
        if (section.size % width != 0) limitations.add('unresolved');
        for (var o = section.offset;
            o + width <= section.offset + section.size && operations <= 2000000;
            o += width) {
          attempt(() {
            final target = offset(pointer(o));
            if (section.name.contains('cls') ||
                section.name == '__objc_classlist') {
              objcClass(target, source);
            } else if (section.name == '__objc_protolist') {
              protocol(target, source);
            } else {
              category(target, source);
            }
          });
        }
      } else if (section.name == '__swift5_types' ||
          section.name == '__swift5_protos') {
        if (section.size % 4 != 0) limitations.add('unresolved');
        for (var o = section.offset;
            o + 4 <= section.offset + section.size && operations <= 2000000;
            o += 4) {
          attempt(() {
            if (section.name == '__swift5_types' && (u32(o) & 3) > 1) {
              invalid(); // Objective-C type records aren't Swift descriptors.
            }
            context(relative(o, indirect: section.name == '__swift5_types'),
                source, <int>{});
          });
        }
      } else if (section.name == '__swift5_typeref') {
        attempt(() => typeRefs(section, source));
      } else if (const {
        '__objc_classname',
        '__objc_methname',
        '__swift5_reflstr'
      }.contains(section.name)) {
        // These are references, not class/method definitions or relationships.
        attempt(() {
          var start = section.offset;
          for (var o = start; o < section.offset + section.size; o++) {
            budget();
            if (bytes[o] != 0) continue;
            if (o > start) {
              final at = start;
              attempt(() => add('name-reference', string(at), source, at));
            }
            start = o + 1;
          }
          if (start != section.offset + section.size) invalid();
        });
      }
    }
    for (final symbol in symbols) {
      if (operations > 2000000) break;
      if (symbol.startsWith(r'_OBJC_CLASS_$_') ||
          symbol.startsWith(r'_OBJC_PROTOCOL_$_')) {
        final marker = symbol.indexOf(r'$_');
        attempt(() => add(
            'symbol-reference', symbol.substring(marker + 2), 'symbol', -1,
            raw: symbol));
      } else if (RegExp(r'^_?\$[sS]').hasMatch(symbol)) {
        final demangled = nominalSwiftName(symbol);
        if (demangled != null) {
          attempt(() => add('swift-nominal-symbol', demangled, 'symbol', -1,
              raw: symbol));
        } else {
          limitations.add('swift-mangling');
        }
      }
    }
    return MachMetadata(
        List.unmodifiable(entries), Set.unmodifiable(limitations));
  }

  String className(int o) {
    offset(va(o), 5 * width);
    final ro = offset(pointer(o + width * 4) & ~(wide ? 7 : 3), wide ? 48 : 28);
    return string(offset(pointer(ro + (wide ? 24 : 16))));
  }

  void objcClass(int o, String source) {
    final name = className(o);
    add('objc-class', name, source, o);
    final ro = offset(pointer(o + width * 4) & ~(wide ? 7 : 3), wide ? 48 : 28);
    attempt(() => methods(pointer(ro + (wide ? 32 : 20)), name, source, false));
    attempt(() => adopted(pointer(ro + (wide ? 40 : 24)), name, source));
    attempt(() {
      final meta = pointer(o);
      if (meta == 0) return;
      final metaRo = offset(
          pointer(offset(meta, 5 * width) + width * 4) & ~(wide ? 7 : 3),
          wide ? 48 : 28);
      methods(pointer(metaRo + (wide ? 32 : 20)), name, source, true);
    });
  }

  void methods(int address, String owner, String source, bool isClass,
      {bool requirement = false}) {
    if (address == 0) return;
    final o = offset(address, 8), flags = u32(o), count = u32(o + 4);
    final small = flags & 0x80000000 != 0;
    final direct = flags & 0x40000000 != 0;
    final stride = flags & 0xffff & ~3;
    if (count > 30000 || stride < (small ? 12 : width * 3)) invalid();
    offset(address, 8 + stride * count);
    for (var i = 0; i < count; i++) {
      budget();
      final m = o + 8 + stride * i;
      attempt(() {
        var target = small ? relative(m) : offset(pointer(m));
        if (small && !direct) target = offset(pointer(target));
        add(
            requirement
                ? (isClass
                    ? 'objc-class-requirement'
                    : 'objc-instance-requirement')
                : (isClass ? 'objc-class-method' : 'objc-instance-method'),
            string(target),
            source,
            m,
            owner: owner);
      });
    }
  }

  String protocol(int o, String source, {String? owner}) {
    offset(va(o), 7 * width);
    final name = string(offset(pointer(o + width)));
    add('objc-protocol', name, source, o);
    if (owner != null) {
      add('objc-adopted-protocol', name, source, o, owner: owner);
    }
    // Protocol requirements use the same method list layout, but aren't bodies.
    for (var i = 3; i <= 6; i++) {
      attempt(() => methods(
          pointer(o + width * i), 'protocol:$name', source, i == 4 || i == 6,
          requirement: true));
    }
    return name;
  }

  void adopted(int address, String owner, String source) {
    if (address == 0) return;
    final o = offset(address, width), count = rawPointer(o);
    if (count > 4096) invalid();
    offset(address, width * (count + 1));
    for (var i = 0; i < count; i++) {
      budget();
      attempt(() =>
          protocol(offset(pointer(o + width * (i + 1))), source, owner: owner));
    }
  }

  void category(int o, String source) {
    offset(va(o), 5 * width);
    final name = string(offset(pointer(o)));
    add('objc-category', name, source, o);
    String? owner;
    attempt(() => owner = className(offset(pointer(o + width))));
    final qualified = owner == null ? 'category:$name' : '$owner($name)';
    attempt(() => methods(pointer(o + 2 * width), qualified, source, false));
    attempt(() => methods(pointer(o + 3 * width), qualified, source, true));
    attempt(() => adopted(pointer(o + 4 * width), qualified, source));
  }

  String context(int o, String source, Set<int> visited) {
    offset(va(o), 12);
    budget();
    if (visited.length >= 32 || !visited.add(o)) invalid();
    final flags = u32(o), kind = flags & 31;
    if ((flags >> 8) & 255 != 0 || !{0, 3, 16, 17, 18}.contains(kind)) {
      invalid();
    }
    final name = string(relative(o + 8));
    String? owner;
    if (u32(o + 4) != 0) {
      owner = context(relative(o + 4, indirect: true), source, visited);
    }
    final label = switch (kind) {
      0 => 'swift-module',
      3 => 'swift-protocol',
      16 => 'swift-class',
      17 => 'swift-struct',
      _ => 'swift-enum',
    };
    add(label, name, source, o, owner: owner);
    return owner == null ? name : '$owner.$name';
  }

  void typeRefs(MachSection s, String source) {
    var o = s.offset;
    final end = o + s.size;
    while (o < end) {
      budget();
      final start = o;
      final printable = StringBuffer();
      while (o < end && bytes[o] != 0) {
        budget();
        final tag = bytes[o++];
        if (tag >= 1 && tag <= 31) {
          final size = tag <= 0x17 ? 4 : width;
          if (o > end - size) invalid();
          final at = o;
          if (tag == 1 || tag == 2) {
            attempt(() {
              final target = relative(at);
              context(
                  tag == 1 ? target : offset(pointer(target)), source, <int>{});
            });
          } else {
            limitations.add('swift-symbolic-reference');
          }
          o += size; // Embedded zeroes are payload bytes, not terminators.
          printable.write('<ref>');
        } else {
          if (tag < 32 || tag > 126 || o - start > 4096) invalid();
          printable.writeCharCode(tag);
        }
      }
      if (o == end) invalid();
      o++;
      if (printable.isNotEmpty) {
        final raw = printable.toString();
        add('swift-type-reference', nominalSwiftName(raw) ?? raw, source, start,
            raw: raw);
      }
    }
  }

  void chains(int o, int size) {
    bounds(o, size);
    final end = o + size;
    void within(int p, int n) {
      if (p < o || p > end - n) invalid();
    }

    within(o, 28);
    if (!wide || endian != Endian.little || u32(o) != 0) invalid();
    final bases =
        segments.where((s) => s.fileOffset == 0 && s.fileSize > 0).toList();
    if (bases.length != 1) invalid();
    final base = bases.single.address;
    final starts = o + u32(o + 4);
    within(starts, 4);
    final count = u32(starts);
    if (count > 256) invalid();
    within(starts + 4, count * 4);
    for (var i = 0; i < count; i++) {
      budget();
      final delta = u32(starts + 4 + i * 4);
      if (delta == 0) continue;
      final s = starts + delta;
      within(s, 22);
      final structSize = u32(s),
          pageSize = u16(s + 4),
          format = u16(s + 6),
          pages = u16(s + 20);
      within(s, structSize);
      if (structSize < 22 + 2 * pages ||
          !{4096, 16384}.contains(pageSize) ||
          !{2, 6}.contains(format)) {
        invalid();
      }
      final segmentAddress = base + data.getUint64(s + 8, endian);
      for (var page = 0; page < pages; page++) {
        budget();
        final start = u16(s + 22 + 2 * page);
        if (start == 0xffff) continue;
        if (start & 0x8000 != 0 || start >= pageSize) invalid();
        var current = start;
        while (true) {
          budget();
          if (current > pageSize - 8) invalid();
          final p = offset(segmentAddress + page * pageSize + current, 8);
          final value = rawPointer(p);
          if (pointers.containsKey(p)) invalid();
          final next = (value >>> 51) & 0xfff;
          if (value >>> 63 != 0) {
            pointers[p] = null; // External bindings have no local definition.
          } else {
            final low = value & 0xfffffffff, high = (value >>> 36) & 255;
            if (((value >>> 44) & 127) != 0) {
              invalid();
            }
            final target = low | (high << 56);
            pointers[p] = format == 6 ? base + target : target;
          }
          if (next == 0) break;
          current += next * 4;
        }
      }
    }
  }
}

/// Conservative demangling of simple Swift nominal type names only. Refuse
/// substitutions, generics, operators and function signatures rather than guess.
String? nominalSwiftName(String raw) {
  var value = raw.replaceFirst(RegExp(r'^_?\$[sS]'), '');
  final parts = <String>[];
  var o = 0;
  for (var i = 0; i < 2; i++) {
    final match = RegExp(r'^[1-9][0-9]{0,3}').firstMatch(value.substring(o));
    if (match == null) return null;
    final length = int.parse(match[0]!);
    o += match[0]!.length;
    if (o > value.length - length) return null;
    final name = value.substring(o, o + length);
    if (!RegExp(r'^[A-Za-z_][A-Za-z0-9_]*$').hasMatch(name)) return null;
    parts.add(name);
    o += length;
  }
  if (!RegExp(r'^[CVOP](?:N|Ma|Mn|Mp)?$').hasMatch(value.substring(o))) {
    return null;
  }
  return parts.join('.');
}
