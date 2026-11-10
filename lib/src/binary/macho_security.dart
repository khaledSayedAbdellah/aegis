/// Device-independent Mach-O facts. Uses Apple's loader.h / nlist.h layout.
/// These facts describe packaged bytes, not observed runtime enforcement.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'macho_metadata.dart';

class MachSecurity {
  MachSecurity(
      {required this.architecture,
      required this.fileType,
      required this.flags,
      required this.encrypted,
      required this.signatureBlob,
      required this.symbolTable,
      required this.stringsLimited,
      required this.debugSymbols,
      required this.writableExecutableSegments,
      required this.symbols,
      required this.strings,
      required this.rpaths,
      required this.metadata});

  final MachMetadata metadata;
  final String architecture;
  final int fileType, flags, debugSymbols;
  final bool encrypted, signatureBlob, symbolTable, stringsLimited;
  final List<String> writableExecutableSegments, rpaths;
  final Set<String> symbols, strings;
  bool get pie => flags & 0x200000 != 0;
  bool get executableStackRequested => flags & 0x20000 != 0;
}

bool isMachO(Uint8List bytes) =>
    bytes.length >= 4 &&
    const {
      0xfeedface,
      0xfeedfacf,
      0xcefaedfe,
      0xcffaedfe,
      0xcafebabe,
      0xcafebabf,
      0xbebafeca,
      0xbfbafeca,
    }.contains(ByteData.sublistView(bytes).getUint32(0));

List<MachSecurity> inspectMachSecurity(Uint8List bytes) {
  if (!isMachO(bytes)) throw const FormatException('Not a Mach-O binary.');
  final data = ByteData.sublistView(bytes);
  final magic = data.getUint32(0);
  if (const {0xcafebabe, 0xcafebabf, 0xbebafeca, 0xbfbafeca}.contains(magic)) {
    if (bytes.length < 8) throw const FormatException('Truncated fat header.');
    final endian =
        magic == 0xbebafeca || magic == 0xbfbafeca ? Endian.little : Endian.big;
    final wide = magic == 0xcafebabf || magic == 0xbfbafeca;
    final count = data.getUint32(4, endian), stride = wide ? 32 : 20;
    final headerEnd = 8 + count * stride;
    if (count == 0 || count > 32 || headerEnd > bytes.length) {
      throw const FormatException('Invalid fat architecture table.');
    }
    final ranges = <(int, int)>[];
    for (var i = 0; i < count; i++) {
      final pos = 8 + i * stride;
      final offset = wide
          ? data.getUint64(pos + 8, endian)
          : data.getUint32(pos + 8, endian);
      final size = wide
          ? data.getUint64(pos + 16, endian)
          : data.getUint32(pos + 12, endian);
      if (offset < headerEnd ||
          size < 28 ||
          offset > bytes.length - size ||
          ranges.any((r) => offset < r.$1 + r.$2 && r.$1 < offset + size)) {
        throw const FormatException('Invalid or overlapping Mach-O slices.');
      }
      ranges.add((offset, size));
    }
    return [
      for (final r in ranges)
        _inspect(Uint8List.sublistView(bytes, r.$1, r.$1 + r.$2))
    ];
  }
  return [_inspect(bytes)];
}

MachSecurity _inspect(Uint8List bytes) {
  final data = ByteData.sublistView(bytes);
  void bounds(int offset, int size) {
    if (offset < 0 || size < 0 || offset > bytes.length - size) {
      throw const FormatException('Mach-O range exceeds slice.');
    }
  }

  bounds(0, 28);
  final magic = data.getUint32(0);
  final wide = magic == 0xfeedfacf || magic == 0xcffaedfe;
  final endian =
      magic == 0xcefaedfe || magic == 0xcffaedfe ? Endian.little : Endian.big;
  if (!const {0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe}.contains(magic)) {
    throw const FormatException('Unsupported Mach-O slice.');
  }
  int word(int offset) => data.getUint32(offset, endian);
  int address(int offset) =>
      wide ? data.getUint64(offset, endian) : word(offset);
  final header = wide ? 32 : 28;
  bounds(0, header);
  final cpu = word(4);
  final architecture = switch (cpu) {
    0x0100000c => word(8) & 0xff == 2 ? 'arm64e' : 'arm64',
    0x01000007 => 'x86_64',
    12 => 'arm',
    7 => 'i386',
    _ => 'cpu-$cpu',
  };
  final count = word(16), size = word(20), end = header + size;
  bounds(header, size);
  if (count > size ~/ 8) {
    throw const FormatException('Invalid load command count.');
  }
  var pos = header, encrypted = false, signature = false;
  (int, int, int, int)? symtab;
  final stringRanges = <(int, int)>[];
  final segments = <MachSegment>[];
  final metadataSections = <MachSection>[];
  (int, int)? fixups;
  final wx = <String>[], rpaths = <String>[];
  String fixed(int start, int length) => ascii.decode(
      bytes.sublist(start, start + length).takeWhile((b) => b != 0).toList(),
      allowInvalid: true);
  String terminated(int start, int limit) {
    var end = start;
    while (end < limit && bytes[end] != 0 && end - start <= 4096) {
      end++;
    }
    if (end == limit || end - start > 4096) {
      throw const FormatException('Invalid Mach-O string.');
    }
    return utf8.decode(Uint8List.sublistView(bytes, start, end),
        allowMalformed: true);
  }

  for (var i = 0; i < count; i++) {
    if (pos + 8 > end) throw const FormatException('Truncated load command.');
    final cmd = word(pos), length = word(pos + 4);
    if (length < 8 || length % 4 != 0 || length > end - pos) {
      throw const FormatException('Invalid load command size.');
    }
    void minimum(int n) {
      if (length < n) throw const FormatException('Short load command.');
    }

    if (cmd == 2) {
      minimum(24);
      if (symtab != null) {
        throw const FormatException('Duplicate symbol table.');
      }
      symtab = (word(pos + 8), word(pos + 12), word(pos + 16), word(pos + 20));
    } else if (cmd == 0x21 || cmd == 0x2c) {
      minimum(cmd == 0x2c ? 24 : 20);
      bounds(word(pos + 8), word(pos + 12));
      encrypted |= word(pos + 16) != 0;
    } else if (cmd == 0x80000034) {
      minimum(16);
      bounds(word(pos + 8), word(pos + 12));
      if (fixups != null) throw const FormatException('Duplicate fixups.');
      fixups = (word(pos + 8), word(pos + 12));
    } else if (cmd == 0x1d) {
      minimum(16);
      bounds(word(pos + 8), word(pos + 12));
      signature = word(pos + 12) > 0;
    } else if (cmd == 0x8000001c) {
      minimum(12);
      final start = word(pos + 8);
      if (start < 12 || start >= length) {
        throw const FormatException('Invalid runpath.');
      }
      rpaths.add(terminated(pos + start, pos + length));
    } else if (cmd == 1 || cmd == 0x19) {
      final segment64 = cmd == 0x19;
      if (segment64 != wide) {
        throw const FormatException('Segment width mismatch.');
      }
      final segmentSize = wide ? 72 : 56, sectionSize = wide ? 80 : 68;
      minimum(segmentSize);
      final sections = word(pos + (wide ? 64 : 48));
      if (sections > (length - segmentSize) ~/ sectionSize) {
        throw const FormatException('Invalid section table.');
      }
      final fileOffset = address(pos + (wide ? 40 : 32));
      final fileSize = address(pos + (wide ? 48 : 36));
      bounds(fileOffset, fileSize);
      if (segments.length >= 256) {
        throw const FormatException('Too many segments.');
      }
      segments.add(MachSegment(address(pos + 24), fileOffset, fileSize));
      final protection = word(pos + (wide ? 60 : 44));
      if (address(pos + (wide ? 32 : 28)) > 0 && protection & 6 == 6) {
        wx.add(fixed(pos + 8, 16));
      }
      for (var j = 0; j < sections; j++) {
        final section = pos + segmentSize + j * sectionSize;
        final name = fixed(section, 16);
        final flags = word(section + (wide ? 64 : 56));
        if (name.startsWith('__objc_') || name.startsWith('__swift5_')) {
          final offset = word(section + (wide ? 48 : 40));
          final length = address(section + (wide ? 40 : 36));
          bounds(offset, length);
          if (offset < fileOffset ||
              offset + length > fileOffset + fileSize ||
              const {1, 12, 18}.contains(flags & 0xff) ||
              address(section + 32) !=
                  address(pos + 24) + offset - fileOffset) {
            throw const FormatException('Metadata section exceeds segment.');
          }
          if (metadataSections.length >= 4096) {
            throw const FormatException('Too many metadata sections.');
          }
          metadataSections.add(MachSection(fixed(section + 16, 16), name,
              address(section + 32), offset, length));
        }
        if (flags & 0xff == 2 ||
            const {
              '__cstring',
              '__objc_classname',
              '__objc_methname',
              '__swift5_reflstr'
            }.contains(name)) {
          final offset = word(section + (wide ? 48 : 40));
          final length = address(section + (wide ? 40 : 36));
          bounds(offset, length);
          if (offset < fileOffset || offset + length > fileOffset + fileSize) {
            throw const FormatException('String section exceeds segment.');
          }
          stringRanges.add((offset, length));
        }
      }
    }
    pos += length;
  }
  if (pos != end) {
    throw const FormatException('Load command sizes do not match header.');
  }
  final symbols = <String>{}, strings = <String>{};
  var debugSymbols = 0;
  var stringsLimited = false;
  if (symtab case final table?) {
    final (offset, count, strOffset, strSize) = table;
    bounds(offset, count * (wide ? 16 : 12));
    bounds(strOffset, strSize);
    if (count > 1000000 || strSize > 64 * 1024 * 1024) {
      throw const FormatException('Symbol table exceeds analysis limit.');
    }
    for (var i = 0; i < count; i++) {
      final pos = offset + i * (wide ? 16 : 12), index = word(pos);
      if (index >= strSize && index != 0) {
        throw const FormatException('Invalid symbol string index.');
      }
      final name =
          index == 0 ? '' : terminated(strOffset + index, strOffset + strSize);
      if (data.getUint8(pos + 4) & 0xe0 != 0) {
        // strip(1)'s N_OPT marker is not retained source debug information.
        if (data.getUint8(pos + 4) != 0x3c || name != 'radr://5614542') {
          debugSymbols++;
        }
      } else if (name.isNotEmpty) {
        symbols.add(name);
      }
    }
  }
  // FairPlay ciphertext must never be interpreted as absence of indicators.
  if (!encrypted) {
    var scanned = 0;
    for (final (offset, length) in stringRanges) {
      scanned += length;
      if (scanned > 32 * 1024 * 1024) {
        throw const FormatException('String sections exceed analysis limit.');
      }
      var start = offset;
      for (var i = offset; i < offset + length; i++) {
        if (bytes[i] != 0) continue;
        if (i - start >= 4 && i - start <= 4096) {
          strings.add(utf8.decode(Uint8List.sublistView(bytes, start, i),
              allowMalformed: true));
        }
        if (i - start > 4096) stringsLimited = true;
        start = i + 1;
      }
      if (start != offset + length) stringsLimited = true;
      if (strings.length > 200000) {
        throw const FormatException('Too many Mach-O strings.');
      }
    }
  }
  return MachSecurity(
      metadata: inspectMachMetadata(
          bytes, endian, wide, segments, metadataSections, symbols,
          encrypted: encrypted, fixups: fixups),
      architecture: architecture,
      fileType: word(12),
      flags: word(24),
      encrypted: encrypted,
      signatureBlob: signature,
      symbolTable: symtab != null,
      stringsLimited: stringsLimited,
      debugSymbols: debugSymbols,
      writableExecutableSegments: wx,
      symbols: symbols,
      strings: strings,
      rpaths: rpaths);
}
