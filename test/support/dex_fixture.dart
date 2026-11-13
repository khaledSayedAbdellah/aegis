import 'dart:convert';
import 'dart:typed_data';

/// A structured DEX file: real string, type, method and class tables, and one
/// method per class whose code loads the class's strings.
///
/// [classes] maps `com.example.Name` to what its code uses: a plain entry is
/// a string constant, `call:name` invokes a method called `name`. Classes in
/// [referenced] are in the type table without a definition.
Uint8List dexFile(Map<String, List<String>> classes,
    {List<String> referenced = const []}) {
  String descriptor(String name) => 'L${name.replaceAll('.', '/')};';
  final calls = <String>{
    for (final uses in classes.values)
      for (final use in uses)
        if (use.startsWith('call:')) use.substring(5)
  }.toList()
    ..sort();
  final strings = <String>{
    ...classes.keys.map(descriptor),
    ...referenced.map(descriptor),
    ...calls,
    for (final uses in classes.values)
      for (final use in uses)
        if (!use.startsWith('call:')) use
  }.toList()
    ..sort();
  final types = [...classes.keys, ...referenced].map(descriptor).toList()
    ..sort();

  const header = 0x70;
  final stringIds = header;
  final typeIds = stringIds + 4 * strings.length;
  final methodIds = typeIds + 4 * types.length;
  final classDefs = methodIds + 8 * calls.length;
  final out = BytesBuilder();
  var offset = classDefs + 32 * classes.length;

  List<int> leb(int value) {
    final bytes = <int>[];
    do {
      var b = value & 0x7f;
      value >>= 7;
      if (value != 0) b |= 0x80;
      bytes.add(b);
    } while (value != 0);
    return bytes;
  }

  void emit(List<int> bytes) {
    out.add(bytes);
    offset += bytes.length;
  }

  void align() {
    while (offset % 4 != 0) {
      emit([0]);
    }
  }

  final stringOffsets = <int>[];
  for (final s in strings) {
    stringOffsets.add(offset);
    emit([...leb(s.length), ...utf8.encode(s), 0]);
  }

  final classData = <int>[];
  var index = 0;
  for (final uses in classes.values) {
    final units = <int>[0x0018, 1, 2, 3, 4]; // const-wide: five units
    for (final use in uses) {
      if (use.startsWith('call:')) {
        units.addAll([0x0071, calls.indexOf(use.substring(5)), 0]);
      } else {
        final id = strings.indexOf(use);
        // Alternate between const-string and const-string/jumbo.
        units.addAll(index.isEven ? [0x001a, id] : [0x001b, id, 0]);
        index++;
      }
    }
    units.add(0x000e); // return-void
    // fill-array-data payload: three one-byte elements.
    units.addAll([0x0300, 1, 3, 0, 0x0201, 0x0003]);
    align();
    final code = offset;
    final item = ByteData(16 + units.length * 2)
      ..setUint16(0, 2, Endian.little)
      ..setUint32(12, units.length, Endian.little);
    for (var i = 0; i < units.length; i++) {
      item.setUint16(16 + i * 2, units[i], Endian.little);
    }
    emit(item.buffer.asUint8List());
    classData.add(offset);
    emit([...leb(0), ...leb(0), ...leb(1), ...leb(0)]);
    emit([...leb(0), ...leb(9), ...leb(code)]);
  }

  final tables = ByteData(classDefs + 32 * classes.length);
  const magic = 'dex\n035\x00';
  for (var i = 0; i < magic.length; i++) {
    tables.setUint8(i, magic.codeUnitAt(i));
  }
  void word(int at, int value) => tables.setUint32(at, value, Endian.little);
  word(0x20, offset);
  word(0x24, header);
  word(0x28, 0x12345678);
  word(0x38, strings.length);
  word(0x3c, stringIds);
  word(0x40, types.length);
  word(0x44, typeIds);
  word(0x58, calls.length);
  word(0x5c, methodIds);
  word(0x60, classes.length);
  word(0x64, classDefs);
  for (var i = 0; i < strings.length; i++) {
    word(stringIds + 4 * i, stringOffsets[i]);
  }
  for (var i = 0; i < types.length; i++) {
    word(typeIds + 4 * i, strings.indexOf(types[i]));
  }
  for (var i = 0; i < calls.length; i++) {
    word(methodIds + 8 * i + 4, strings.indexOf(calls[i]));
  }
  var c = 0;
  for (final name in classes.keys) {
    final def = classDefs + 32 * c;
    word(def, types.indexOf(descriptor(name)));
    word(def + 24, classData[c]);
    c++;
  }
  return Uint8List.fromList(
      [...tables.buffer.asUint8List(), ...out.takeBytes()]);
}
