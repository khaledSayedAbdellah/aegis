/// Decoder for Android binary XML (AXML), the format of AndroidManifest.xml
/// and res/xml/*.xml inside an APK. The result is plain XML text so the same
/// parsing code works for source and compiled manifests.
library;

import 'dart:convert';
import 'dart:typed_data';

const _androidUri = 'http://schemas.android.com/apk/res/android';
const _none = 0xFFFFFFFF;

/// Resource ids of `android:` attributes, used when attribute names have
/// been stripped from the string pool (some obfuscators do this).
const Map<int, String> androidAttrIds = {
  0x01010003: 'name',
  0x01010006: 'permission',
  0x0101000f: 'debuggable',
  0x01010010: 'exported',
  0x0101020c: 'minSdkVersion',
  0x0101021b: 'versionCode',
  0x0101021c: 'versionName',
  0x01010270: 'targetSdkVersion',
  0x01010271: 'maxSdkVersion',
  0x01010280: 'allowBackup',
  0x01010473: 'fullBackupContent',
  0x010104ec: 'usesCleartextTraffic',
  0x01010527: 'networkSecurityConfig',
};

/// Whether [bytes] starts with an AXML header.
bool isBinaryXml(Uint8List bytes) =>
    bytes.length >= 8 && bytes[0] == 0x03 && bytes[1] == 0x00;

/// Converts AXML [bytes] to XML text. Throws [FormatException] when the
/// data is not binary XML.
String decodeBinaryXml(Uint8List bytes) =>
    _AxmlDecoder(bytes).decode();

class _AxmlDecoder {
  _AxmlDecoder(this.b) : d = ByteData.sublistView(b);

  final Uint8List b;
  final ByteData d;
  List<String> strings = const [];
  List<int> resIds = const [];
  final Map<String, String> prefixes = {}; // uri -> prefix
  final List<String> stack = [];
  final StringBuffer out = StringBuffer();
  bool rootWritten = false;

  int u16(int o) => d.getUint16(o, Endian.little);
  int u32(int o) => d.getUint32(o, Endian.little);

  String? str(int index) =>
      index == _none || index < 0 || index >= strings.length ? null : strings[index];

  String decode() {
    if (!isBinaryXml(b)) throw const FormatException('Not a binary XML file.');
    final total = u32(4) < b.length ? u32(4) : b.length;
    var p = u16(2);
    while (p + 8 <= total) {
      final type = u16(p);
      final headerSize = u16(p + 2);
      final size = u32(p + 4);
      if (size < 8 || p + size > b.length) break;
      switch (type) {
        case 0x0001:
          strings = readAndroidStringPool(b, p);
        case 0x0180:
          resIds = [
            for (var i = p + headerSize; i + 4 <= p + size; i += 4) u32(i)
          ];
        case 0x0100:
          _startNamespace(p);
        case 0x0102:
          _startElement(p + headerSize);
        case 0x0103:
          if (stack.isNotEmpty) out.write('</${stack.removeLast()}>');
        case 0x0104:
          _cdata(p + headerSize);
      }
      p += size;
    }
    while (stack.isNotEmpty) {
      out.write('</${stack.removeLast()}>');
    }
    return out.toString();
  }

  void _startNamespace(int p) {
    final prefix = str(u32(p + 16));
    final uri = str(u32(p + 20));
    if (uri != null) {
      prefixes[uri] = uri == _androidUri ? 'android' : (prefix ?? 'ns${prefixes.length}');
    }
  }

  void _cdata(int ext) {
    final text = str(u32(ext));
    if (text != null) out.write(_escape(text));
  }

  void _startElement(int e) {
    final nsIdx = u32(e);
    final name = _xmlName(str(u32(e + 4)) ?? 'element');
    final attrStart = u16(e + 8);
    final attrSize = u16(e + 10);
    final attrCount = u16(e + 12);
    final qname = _qualify(str(nsIdx), name);
    out.write('<$qname');
    if (!rootWritten) {
      rootWritten = true;
      prefixes.putIfAbsent(_androidUri, () => 'android');
      prefixes.forEach((uri, prefix) {
        out.write(' xmlns:$prefix="${_escape(uri)}"');
      });
    }
    // The attribute array starts relative to the extension start.
    final base = e + attrStart;
    final seen = <String>{};
    for (var i = 0; i < attrCount; i++) {
      final a = base + i * (attrSize == 0 ? 20 : attrSize);
      if (a + 20 > b.length) break;
      final attrNs = str(u32(a));
      final nameIdx = u32(a + 4);
      var attrName = str(nameIdx);
      if (attrName == null || attrName.isEmpty) {
        final id = nameIdx < resIds.length ? resIds[nameIdx] : null;
        attrName = id == null ? 'attr$i' : (androidAttrIds[id] ?? 'attr_0x${id.toRadixString(16)}');
      }
      var uri = attrNs;
      if (uri == null && nameIdx < resIds.length && resIds[nameIdx] >> 24 == 0x01) {
        uri = _androidUri; // framework attribute without a namespace entry
      }
      final q = _qualify(uri, _xmlName(attrName));
      if (!seen.add(q)) continue;
      final raw = str(u32(a + 8));
      final dataType = b[a + 15];
      final data = u32(a + 16);
      out.write(' $q="${_escape(_value(dataType, data, raw))}"');
    }
    out.write('>');
    stack.add(qname);
  }

  String _qualify(String? uri, String name) {
    if (uri == null || uri.isEmpty) return name;
    final prefix = prefixes.putIfAbsent(
        uri, () => uri == _androidUri ? 'android' : 'ns${prefixes.length}');
    return '$prefix:$name';
  }

  String _value(int type, int data, String? raw) {
    if (raw != null) return raw;
    switch (type) {
      case 0x03:
        return str(data) ?? '';
      case 0x12:
        return data != 0 ? 'true' : 'false';
      case 0x10:
        return data.toSigned(32).toString();
      case 0x11:
        return '0x${data.toRadixString(16)}';
      case 0x01:
        return '@0x${data.toRadixString(16).padLeft(8, '0')}';
      case 0x02:
        return '?0x${data.toRadixString(16).padLeft(8, '0')}';
      case 0x04:
        final f = ByteData(4)..setUint32(0, data);
        return f.getFloat32(0).toString();
      default:
        return '0x${data.toRadixString(16)}';
    }
  }

  static String _xmlName(String s) {
    final cleaned = s.replaceAll(RegExp(r'[^A-Za-z0-9_.\-]'), '_');
    if (cleaned.isEmpty) return '_';
    return RegExp(r'^[A-Za-z_]').hasMatch(cleaned) ? cleaned : '_$cleaned';
  }

  static String _escape(String s) => s
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;');
}

/// Reads the string pool shared by binary XML and the Android resource table.
List<String> readAndroidStringPool(Uint8List b, int p) {
    final data = ByteData.sublistView(b);
    int u16(int at) => data.getUint16(at, Endian.little);
    int u32(int at) => data.getUint32(at, Endian.little);
    final headerSize = u16(p + 2);
    final count = u32(p + 8);
    if (count > (u32(p + 4) - headerSize) ~/ 4) {
      throw const FormatException('Invalid Android string pool');
    }
    final flags = u32(p + 16);
    final stringsStart = u32(p + 20);
    final isUtf8 = (flags & 0x100) != 0;
    final base = p + stringsStart;
    final out = <String>[];
    for (var i = 0; i < count; i++) {
      try {
        var pos = base + u32(p + headerSize + i * 4);
        if (isUtf8) {
          // Length in UTF-16 units, then length in bytes (1 or 2 bytes each).
          pos += (b[pos] & 0x80) != 0 ? 2 : 1;
          var len = b[pos];
          if ((len & 0x80) != 0) {
            len = ((len & 0x7f) << 8) | b[pos + 1];
            pos += 2;
          } else {
            pos += 1;
          }
          out.add(utf8.decode(Uint8List.sublistView(b, pos, pos + len),
              allowMalformed: true));
        } else {
          var len = u16(pos);
          pos += 2;
          if ((len & 0x8000) != 0) {
            len = ((len & 0x7fff) << 16) | u16(pos);
            pos += 2;
          }
          out.add(String.fromCharCodes(
              [for (var k = 0; k < len; k++) u16(pos + k * 2)]));
        }
      } catch (_) {
        out.add('');
      }
    }
    return out;
  }
