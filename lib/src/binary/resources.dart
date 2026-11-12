/// Resolves file references in Android's compiled resource table.
library;

import 'dart:typed_data';

import 'axml.dart' show readAndroidStringPool;

Set<String> androidResourceFiles(Uint8List bytes, int id) {
  final data = ByteData.sublistView(bytes);
  int u16(int at) => data.getUint16(at, Endian.little);
  int u32(int at) => data.getUint32(at, Endian.little);
  Iterable<int> chunks(int start, int end) sync* {
    for (var at = start; at < end;) {
      if (at + 8 > end) throw const FormatException('Truncated resource chunk');
      final size = u32(at + 4);
      if (u16(at + 2) < 8 || size < u16(at + 2) || at + size > end) {
        throw const FormatException('Invalid resource chunk size');
      }
      yield at;
      at += size;
    }
  }

  if (bytes.length < 12 || u16(0) != 2 || u32(4) > bytes.length) {
    throw const FormatException('Invalid Android resource table');
  }
  final children = chunks(u16(2), u32(4)).toList();
  final pool = children.firstWhere((at) => u16(at) == 1);
  final strings = readAndroidStringPool(bytes, pool);
  final visiting = <int>{};
  final resolved = <int, Set<String>>{};
  Set<String> resolve(int id) {
    final cached = resolved[id];
    if (cached != null) return cached;
    if (visiting.length >= 32 || !visiting.add(id)) {
      throw const FormatException(
          'Cyclic or excessive Android resource aliases');
    }
    final files = <String>{};
    final target = id & 0xffff;
    for (final package in children.where((at) => u16(at) == 0x200)) {
      final header = u16(package + 2);
      if (header < 284) {
        throw const FormatException('Invalid resource package header');
      }
      if (u32(package + 8) != id >> 24) continue;
      final typeOffset = header >= 288 ? u32(package + 284) : 0;
      for (final type in chunks(package + header, package + u32(package + 4))) {
        if (u16(type) != 0x201) continue;
        if (u16(type + 2) < 24) {
          throw const FormatException('Invalid resource type header');
        }
        if (bytes[type + 8] + typeOffset != (id >> 16 & 0xff)) continue;
        final flags = bytes[type + 9];
        final count = u32(type + 12);
        final values = type + u32(type + 16);
        final index = type + u16(type + 2);
        final end = type + u32(type + 4);
        final width = flags & 1 != 0 || flags & 2 == 0 ? 4 : 2;
        if (index + count * width > values || values > end) {
          throw const FormatException('Invalid resource entry offsets');
        }

        int? offset;
        if (flags & 1 != 0) {
          for (var i = 0; i < count; i++) {
            final at = index + i * 4;
            if (u16(at) == target) {
              offset = u16(at + 2) * 4;
              break;
            }
          }
        } else if (target < count) {
          final at = index + target * width;
          if (width == 2) {
            if (u16(at) != 0xffff) offset = u16(at) * 4;
          } else if (u32(at) != 0xffffffff) {
            offset = u32(at);
          }
        }
        if (offset == null) continue;
        final entry = values + offset;
        if (entry + 8 > end) {
          throw const FormatException('Truncated resource entry');
        }
        final entryFlags = u16(entry + 2);
        if (entryFlags & 1 != 0) {
          throw const FormatException('Expected a file resource');
        }
        final compact = entryFlags & 8 != 0;
        final value = compact ? entry : entry + u16(entry);
        if (value + 8 > end) {
          throw const FormatException('Truncated resource value');
        }
        final valueType = compact ? entryFlags >> 8 : bytes[value + 3];
        final contents = u32(value + 4);
        if (valueType == 1) {
          files.addAll(resolve(contents));
        } else if (valueType == 3) {
          files.add(strings[contents]);
        } else {
          throw const FormatException('Expected a resource file path');
        }
      }
    }
    visiting.remove(id);
    if (files.isEmpty) {
      throw const FormatException('Android resource has no file variants');
    }
    return resolved[id] = files;
  }

  return resolve(id);
}
