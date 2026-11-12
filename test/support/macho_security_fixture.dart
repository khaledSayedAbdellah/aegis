import 'dart:convert';
import 'dart:typed_data';

/// A structured Mach-O with real section/symbol offsets, not arbitrary strings.
Uint8List securityMachO({
  int flags = 0x200000,
  int fileType = 2,
  int initialProtection = 5,
  int maxProtection = 7,
  bool encrypted = false,
  bool symbolTable = true,
  List<(String, int)> symbols = const [],
  List<String> strings = const [],
}) {
  const segmentSize = 152;
  final commandsSize = 24 + segmentSize + (symbolTable ? 24 : 0) + 24 + 16;
  final text = utf8.encode('${strings.join('\x00')}\x00');
  final stringOffset = 32 + commandsSize;
  final symbolOffset = (stringOffset + text.length + 7) & ~7;
  final names = <int>[0];
  final nameOffsets = <int>[];
  for (final (name, _) in symbols) {
    nameOffsets.add(names.length);
    names.addAll([...utf8.encode(name), 0]);
  }
  final nameOffset = symbolOffset + (symbolTable ? symbols.length * 16 : 0);
  final signatureOffset = nameOffset + names.length;
  final bytes = Uint8List(signatureOffset + 8);
  final data = ByteData.sublistView(bytes);
  void word(int offset, int value) =>
      data.setUint32(offset, value, Endian.little);
  void wide(int offset, int value) =>
      data.setUint64(offset, value, Endian.little);
  void name(int offset, String value) =>
      bytes.setRange(offset, offset + value.length, ascii.encode(value));
  word(0, 0xfeedfacf);
  word(4, 0x0100000c);
  word(12, fileType);
  word(16, symbolTable ? 5 : 4);
  word(20, commandsSize);
  word(24, flags);
  var pos = 32;
  word(pos, 0x32);
  word(pos + 4, 24);
  word(pos + 8, 2);
  pos += 24;
  word(pos, 0x19);
  word(pos + 4, segmentSize);
  name(pos + 8, '__TEXT');
  wide(pos + 24, 0x1000);
  wide(pos + 32, bytes.length);
  wide(pos + 40, 0);
  wide(pos + 48, bytes.length);
  word(pos + 56, maxProtection);
  word(pos + 60, initialProtection);
  word(pos + 64, 1);
  final section = pos + 72;
  name(section, '__cstring');
  name(section + 16, '__TEXT');
  wide(section + 32, 0x1000 + stringOffset);
  wide(section + 40, text.length);
  word(section + 48, stringOffset);
  word(section + 64, 2);
  pos += segmentSize;
  if (symbolTable) {
    word(pos, 2);
    word(pos + 4, 24);
    word(pos + 8, symbolOffset);
    word(pos + 12, symbols.length);
    word(pos + 16, nameOffset);
    word(pos + 20, names.length);
    pos += 24;
  }
  word(pos, 0x2c);
  word(pos + 4, 24);
  word(pos + 8, stringOffset);
  word(pos + 12, text.length);
  word(pos + 16, encrypted ? 1 : 0);
  pos += 24;
  word(pos, 0x1d);
  word(pos + 4, 16);
  word(pos + 8, signatureOffset);
  word(pos + 12, 8);
  bytes.setRange(stringOffset, stringOffset + text.length, text);
  if (symbolTable) {
    for (var i = 0; i < symbols.length; i++) {
      word(symbolOffset + i * 16, nameOffsets[i]);
      bytes[symbolOffset + i * 16 + 4] = symbols[i].$2;
    }
  }
  bytes.setRange(nameOffset, nameOffset + names.length, names);
  return bytes;
}

Uint8List fatSecurityMachO(List<Uint8List> slices,
    {bool wide = false, bool swapped = false}) {
  final stride = wide ? 32 : 20, header = 8 + slices.length * (wide ? 32 : 20);
  final bytes = Uint8List(header + slices.fold<int>(0, (s, b) => s + b.length));
  final data = ByteData.sublistView(bytes);
  final endian = swapped ? Endian.little : Endian.big;
  data.setUint32(0, wide ? 0xcafebabf : 0xcafebabe, endian);
  data.setUint32(4, slices.length, endian);
  var offset = header;
  for (var i = 0; i < slices.length; i++) {
    final pos = 8 + stride * i;
    data.setUint32(pos, 0x0100000c, endian);
    if (wide) {
      data.setUint64(pos + 8, offset, endian);
      data.setUint64(pos + 16, slices[i].length, endian);
    } else {
      data.setUint32(pos + 8, offset, endian);
      data.setUint32(pos + 12, slices[i].length, endian);
    }
    bytes.setRange(offset, offset + slices[i].length, slices[i]);
    offset += slices[i].length;
  }
  return bytes;
}
