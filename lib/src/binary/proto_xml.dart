/// Decoder for the protobuf XML that Android App Bundles use for
/// AndroidManifest.xml and res/xml files (aapt2 `aapt.pb.XmlNode`).
///
/// Only the protobuf wire format and the handful of messages below are
/// needed, so this is a small hand-written reader instead of generated code:
///
///   XmlNode      { XmlElement element = 1; string text = 2; }
///   XmlElement   { repeated XmlNamespace namespace_declaration = 1;
///                  string namespace_uri = 2; string name = 3;
///                  repeated XmlAttribute attribute = 4;
///                  repeated XmlNode child = 5; }
///   XmlNamespace { string prefix = 1; string uri = 2; }
///   XmlAttribute { string namespace_uri = 1; string name = 2;
///                  string value = 3; uint32 resource_id = 5;
///                  Item compiled_item = 6; }
///   Item         { Reference ref = 1; String str = 2; RawString raw_str = 3;
///                  FileReference file = 5; Primitive prim = 7; }
///
/// Field numbers are from frameworks/base/tools/aapt2/Resources.proto.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'axml.dart' show androidAttrIds;

const _androidUri = 'http://schemas.android.com/apk/res/android';

/// A decoded protobuf field: either a varint/fixed number or bytes.
class _Field {
  _Field(this.number, this.wireType, {this.value = 0, this.bytes});
  final int number;
  final int wireType;
  final int value;
  final Uint8List? bytes;

  String get string => utf8.decode(bytes ?? Uint8List(0), allowMalformed: true);
}

/// Splits a protobuf message into its fields. Throws [FormatException] on
/// malformed input.
List<_Field> _fields(Uint8List b) {
  final out = <_Field>[];
  var p = 0;
  int varint() {
    var result = 0;
    var shift = 0;
    while (true) {
      if (p >= b.length) throw const FormatException('Truncated varint.');
      final byte = b[p++];
      if (shift < 63) result |= (byte & 0x7f) << shift;
      if (byte & 0x80 == 0) return result;
      shift += 7;
      if (shift > 70) throw const FormatException('Varint too long.');
    }
  }

  while (p < b.length) {
    final key = varint();
    final number = key >> 3;
    final wire = key & 7;
    if (number == 0) throw const FormatException('Field number 0.');
    switch (wire) {
      case 0:
        out.add(_Field(number, wire, value: varint()));
      case 1:
        if (p + 8 > b.length) throw const FormatException('Truncated fixed64.');
        out.add(_Field(number, wire,
            value:
                ByteData.sublistView(b, p, p + 8).getUint64(0, Endian.little)));
        p += 8;
      case 2:
        final len = varint();
        if (len < 0 || p + len > b.length) {
          throw const FormatException('Truncated length-delimited field.');
        }
        out.add(
            _Field(number, wire, bytes: Uint8List.sublistView(b, p, p + len)));
        p += len;
      case 5:
        if (p + 4 > b.length) throw const FormatException('Truncated fixed32.');
        out.add(_Field(number, wire,
            value:
                ByteData.sublistView(b, p, p + 4).getUint32(0, Endian.little)));
        p += 4;
      default:
        throw FormatException('Unsupported wire type $wire.');
    }
  }
  return out;
}

String _stringField(List<_Field> fields, int number) {
  for (final f in fields) {
    if (f.number == number && f.wireType == 2) return f.string;
  }
  return '';
}

int? _intField(List<_Field> fields, int number) {
  for (final f in fields) {
    if (f.number == number && f.wireType != 2) return f.value;
  }
  return null;
}

Uint8List? _messageField(List<_Field> fields, int number) {
  for (final f in fields) {
    if (f.number == number && f.wireType == 2) return f.bytes;
  }
  return null;
}

/// Whether [bytes] looks like a protobuf XmlNode holding an element (the
/// first field is `element`, length-delimited) rather than binary XML or
/// plain text.
bool isProtoXml(Uint8List bytes) {
  if (bytes.length < 4 || bytes[0] != 0x0a) return false;
  try {
    final fields = _fields(bytes);
    final element = _messageField(fields, 1);
    return element != null && _stringField(_fields(element), 3).isNotEmpty;
  } catch (_) {
    return false;
  }
}

/// Converts a protobuf XmlNode to XML text, with the same conventions as the
/// binary XML decoder (`android:` prefix, references as `@type/name` or
/// `@0x7f......`). Throws [FormatException] on malformed input.
String decodeProtoXml(Uint8List bytes) {
  final fields = _fields(bytes);
  final element = _messageField(fields, 1);
  if (element == null) throw const FormatException('Not a proto XML element.');
  final out = StringBuffer();
  final prefixes = <String, String>{_androidUri: 'android'};
  _writeElement(element, out, prefixes, root: true, depth: 0);
  return out.toString();
}

void _writeElement(
    Uint8List message, StringBuffer out, Map<String, String> prefixes,
    {required bool root, required int depth}) {
  if (depth > 256) throw const FormatException('XML nested too deeply.');
  final fields = _fields(message);
  final declared = <String, String>{};
  for (final f in fields.where((f) => f.number == 1 && f.wireType == 2)) {
    final ns = _fields(f.bytes!);
    final uri = _stringField(ns, 2);
    if (uri.isEmpty) continue;
    final prefix =
        uri == _androidUri ? 'android' : _xmlName(_stringField(ns, 1));
    if (prefixes[uri] != prefix) declared[uri] = prefix;
    prefixes[uri] = prefix;
  }

  String qualify(String uri, String name) {
    if (uri.isEmpty) return name;
    final prefix = prefixes.putIfAbsent(uri, () {
      final p = 'ns${prefixes.length}';
      declared[uri] = p;
      return p;
    });
    return '$prefix:$name';
  }

  final name = _xmlName(_stringField(fields, 3));
  final qname = qualify(_stringField(fields, 2), name);

  final attrs = StringBuffer();
  final seen = <String>{};
  for (final f in fields.where((f) => f.number == 4 && f.wireType == 2)) {
    final a = _fields(f.bytes!);
    var uri = _stringField(a, 1);
    var attrName = _stringField(a, 2);
    final id = _intField(a, 5);
    if (attrName.isEmpty && id != null) {
      attrName = androidAttrIds[id] ?? 'attr_0x${id.toRadixString(16)}';
    }
    if (attrName.isEmpty) continue;
    if (uri.isEmpty && id != null && id >> 24 == 0x01) uri = _androidUri;
    final q = qualify(uri, _xmlName(attrName));
    if (!seen.add(q)) continue;
    var value = _stringField(a, 3);
    if (value.isEmpty) {
      final item = _messageField(a, 6);
      if (item != null) value = _itemValue(item);
    }
    attrs.write(' $q="${_escape(value)}"');
  }

  out.write('<$qname');
  if (root) {
    // Declare every prefix in use on the root, like the binary decoder.
    declared.addAll({for (final e in prefixes.entries) e.key: e.value});
  }
  declared
      .forEach((uri, prefix) => out.write(' xmlns:$prefix="${_escape(uri)}"'));
  out.write(attrs);
  out.write('>');

  for (final f in fields.where((f) => f.number == 5 && f.wireType == 2)) {
    final node = _fields(f.bytes!);
    final child = _messageField(node, 1);
    if (child != null) {
      _writeElement(child, out, prefixes, root: false, depth: depth + 1);
    } else {
      final text = _stringField(node, 2);
      if (text.isNotEmpty) out.write(_escape(text));
    }
  }
  out.write('</$qname>');
}

/// The value of a compiled `Item` when the raw `value` string is empty.
String _itemValue(Uint8List item) {
  final fields = _fields(item);
  final ref = _messageField(fields, 1);
  if (ref != null) {
    final r = _fields(ref);
    final sigil = _intField(r, 1) == 1 ? '?' : '@';
    final name = _stringField(r, 3);
    if (name.isNotEmpty) return '$sigil$name';
    final id = _intField(r, 2) ?? 0;
    return '${sigil}0x${id.toRadixString(16).padLeft(8, '0')}';
  }
  for (final n in [2, 3]) {
    final s = _messageField(fields, n);
    if (s != null) return _stringField(_fields(s), 1);
  }
  final file = _messageField(fields, 5);
  if (file != null) return _stringField(_fields(file), 1);
  final prim = _messageField(fields, 7);
  if (prim != null) return _primitiveValue(_fields(prim));
  return '';
}

String _primitiveValue(List<_Field> p) {
  for (final f in p) {
    switch (f.number) {
      case 8:
        return f.value != 0 ? 'true' : 'false';
      case 6:
        return f.value.toSigned(32).toString();
      case 7:
      case 9:
      case 10:
      case 11:
      case 12:
      case 13:
      case 14:
        return '0x${f.value.toRadixString(16)}';
      case 3:
        final d = ByteData(4)..setUint32(0, f.value);
        return d.getFloat32(0).toString();
    }
  }
  return '';
}

String _xmlName(String s) {
  final cleaned = s.replaceAll(RegExp(r'[^A-Za-z0-9_.\-]'), '_');
  if (cleaned.isEmpty) return '_';
  return RegExp(r'^[A-Za-z_]').hasMatch(cleaned) ? cleaned : '_$cleaned';
}

String _escape(String s) => s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');

/// Resolves the file values of a compiled bundle resource.
Set<String> protoResourceFiles(Uint8List bytes,
    {int? id, String? name, String? packageName}) {
  Iterable<List<_Field>> messages(List<_Field> fields, int number) => fields
      .where((f) => f.number == number && f.bytes != null)
      .map((f) => _fields(f.bytes!));
  int? resourceId(List<_Field> fields) =>
      messages(fields, 1).map((m) => _intField(m, 1) ?? 0).firstOrNull;

  final packages = messages(_fields(bytes), 2).toList();
  final visiting = <(int?, String?, String?)>{};
  final resolved = <(int?, String?, String?), Set<String>>{};
  Set<String> resolve(int? id, String? name, String? packageName) {
    final key = (id, name, packageName);
    final cached = resolved[key];
    if (cached != null) return cached;
    if (visiting.length >= 32 || !visiting.add(key)) {
      throw const FormatException(
          'Cyclic or excessive bundle resource aliases');
    }

    final paths = <String>{};
    for (final package in packages) {
      final packageLabel = _stringField(package, 2);
      if (id != null
          ? resourceId(package) != id >> 24
          : packageName != packageLabel) {
        continue;
      }
      for (final type in messages(package, 3)) {
        if (id != null
            ? resourceId(type) != (id >> 16 & 0xff)
            : _stringField(type, 2) != 'xml') {
          continue;
        }
        for (final entry in messages(type, 3)) {
          if (id != null
              ? resourceId(entry) != (id & 0xffff)
              : _stringField(entry, 2) != name) {
            continue;
          }
          for (final config in messages(entry, 6)) {
            final item =
                messages(config, 2).expand((v) => messages(v, 4)).firstOrNull;
            final file = item == null ? null : messages(item, 5).firstOrNull;
            if (file != null && _stringField(file, 1).isNotEmpty) {
              paths.add(_stringField(file, 1));
              continue;
            }
            final ref = item == null ? null : messages(item, 1).firstOrNull;
            final refId = ref == null ? null : _intField(ref, 2);
            final refName = RegExp(r'^(?:([\w.]+):)?xml/([\w.]+)$')
                .firstMatch(ref == null ? '' : _stringField(ref, 3));
            if ((refId == null || refId == 0) && refName == null) {
              throw const FormatException(
                  'Expected a bundle resource file path or alias');
            }
            paths.addAll(resolve(refId == 0 ? null : refId, refName?[2],
                refName?[1] ?? packageLabel));
          }
        }
      }
    }
    visiting.remove(key);
    if (paths.isEmpty) {
      throw const FormatException('Bundle resource has no file variants');
    }
    return resolved[key] = paths;
  }

  return resolve(id, name, packageName);
}
