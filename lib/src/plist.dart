/// Minimal XML property-list parser (Info.plist, *.entitlements).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:xml/xml.dart';

/// Parses an XML plist into Dart values: Map, List, String, bool, int,
/// double. Returns null if [text] is not a valid XML plist.
Map<String, Object?>? parsePlist(String text) {
  try {
    final doc = XmlDocument.parse(text);
    final plist = doc.findAllElements('plist').cast<XmlElement?>().firstWhere(
          (_) => true,
          orElse: () => null,
        );
    if (plist == null) return null;
    final root = plist.childElements.cast<XmlElement?>().firstWhere(
          (_) => true,
          orElse: () => null,
        );
    if (root == null) return null;
    final v = _value(root);
    return v is Map<String, Object?> ? v : null;
  } catch (_) {
    return null;
  }
}

Object? _value(XmlElement e) {
  switch (e.name.local) {
    case 'dict':
      final map = <String, Object?>{};
      String? key;
      for (final c in e.childElements) {
        if (c.name.local == 'key') {
          key = c.innerText.trim();
        } else if (key != null) {
          map[key] = _value(c);
          key = null;
        }
      }
      return map;
    case 'array':
      return e.childElements.map(_value).toList();
    case 'true':
      return true;
    case 'false':
      return false;
    case 'integer':
      return int.tryParse(e.innerText.trim());
    case 'real':
      return double.tryParse(e.innerText.trim());
    default:
      return e.innerText;
  }
}

/// Parses either XML or the binary plist used by compiled Apple applications.
Map<String, Object?>? decodeApplePlist(Uint8List bytes) {
  if (bytes.length < 8 ||
      ascii.decode(bytes.sublist(0, 8), allowInvalid: true) != 'bplist00') {
    return parsePlist(utf8.decode(bytes, allowMalformed: true));
  }
  try {
    final value = _BinaryPlist(bytes).read();
    return value is Map<String, Object?> ? value : null;
  } on FormatException {
    return null;
  } on RangeError {
    return null;
  }
}

class _BinaryPlist {
  _BinaryPlist(this.bytes) : data = ByteData.sublistView(bytes);

  final Uint8List bytes;
  final ByteData data;
  late int offsets;
  late int offsetWidth;
  late int referenceWidth;
  late int count;
  final cache = <int, Object?>{};
  final visiting = <int>{};

  int number(int offset, int width, int limit) {
    if (width < 1 || width > 8 || offset < 0 || offset + width > limit) {
      throw const FormatException('Invalid binary plist number.');
    }
    var value = 0;
    for (var i = 0; i < width; i++) {
      value = (value << 8) | bytes[offset + i];
    }
    return value;
  }

  Object? read() {
    if (bytes.length < 40) {
      throw const FormatException('Truncated binary plist.');
    }
    final end = bytes.length - 32;
    offsetWidth = bytes[end + 6];
    referenceWidth = bytes[end + 7];
    count = data.getUint64(end + 8);
    final root = data.getUint64(end + 16);
    offsets = data.getUint64(end + 24);
    if (offsets < 8 ||
        offsets > end ||
        offsetWidth < 1 ||
        offsetWidth > 8 ||
        referenceWidth < 1 ||
        referenceWidth > 8 ||
        count < 1 ||
        count > (end - offsets) ~/ offsetWidth) {
      throw const FormatException('Invalid binary plist offset table.');
    }
    return object(root);
  }

  Object? object(int id) {
    if (cache.containsKey(id)) return cache[id];
    if (id < 0 || id >= count || visiting.length >= 64 || !visiting.add(id)) {
      throw const FormatException('Invalid binary plist reference.');
    }
    final start =
        number(offsets + id * offsetWidth, offsetWidth, bytes.length - 32);
    if (start < 8 || start >= offsets) {
      throw const FormatException('Invalid binary plist object offset.');
    }
    final value = _valueAt(start);
    visiting.remove(id);
    return cache[id] = value;
  }

  Object? _valueAt(int start) {
    final marker = bytes[start];
    final type = marker >> 4;
    var length = marker & 15;
    var offset = start + 1;
    switch (type) {
      case 0:
        return switch (marker) { 8 => false, 9 => true, _ => null };
      case 1:
        return number(offset, 1 << length, offsets);
      case 2:
        return switch (length) {
          2 when offset + 4 <= offsets => data.getFloat32(offset),
          3 when offset + 8 <= offsets => data.getFloat64(offset),
          _ => null,
        };
      case 3:
      case 8:
        return null;
    }
    if (length == 15) {
      final size = number(offset++, 1, offsets);
      if (size >> 4 != 1) {
        throw const FormatException('Invalid binary plist count.');
      }
      final width = 1 << (size & 15);
      length = number(offset, width, offsets);
      offset += width;
    }
    final width = switch (type) {
      6 => 2,
      10 || 12 => referenceWidth,
      13 => referenceWidth * 2,
      _ => 1,
    };
    if (width < 1 || length < 0 || length > (offsets - offset) ~/ width) {
      throw const FormatException('Truncated binary plist value.');
    }
    int ref(int i) =>
        number(offset + i * referenceWidth, referenceWidth, offsets);
    if (type == 13) {
      final values = <String, Object?>{};
      for (var i = 0; i < length; i++) {
        final key = object(ref(i));
        if (key is! String || values.containsKey(key)) {
          throw const FormatException('Invalid binary plist dictionary key.');
        }
        values[key] = object(ref(i + length));
      }
      return values;
    }
    return switch (type) {
      4 => Uint8List.sublistView(bytes, offset, offset + length),
      5 || 7 => utf8.decode(bytes.sublist(offset, offset + length),
          allowMalformed: true),
      6 => String.fromCharCodes(
          [for (var i = 0; i < length; i++) data.getUint16(offset + i * 2)]),
      10 || 12 => [for (var i = 0; i < length; i++) object(ref(i))],
      _ => null,
    };
  }
}
