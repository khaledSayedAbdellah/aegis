/// Minimal ZIP reader for APK files (stored and deflated entries).
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

class ZipEntry {
  ZipEntry(this.name, this.method, this.compressedSize, this.size,
      this.localHeaderOffset, {this.unixMode = 0});

  final String name;

  /// 0 = stored, 8 = deflate.
  final int method;
  final int compressedSize;
  final int size;
  final int localHeaderOffset;

  final int unixMode;
  bool get isSymlink => unixMode & 0xf000 == 0xa000;
  bool get executable => unixMode & 0x49 != 0;

  bool get isDirectory => name.endsWith('/');
}

class ZipReader {
  ZipReader(this.bytes) {
    _readCentralDirectory();
  }

  factory ZipReader.file(String path) => ZipReader(File(path).readAsBytesSync());

  ZipReader._view(this.bytes, this.centralDirectoryOffset, Map<String, ZipEntry> entries) {
    this.entries.addAll(entries);
  }

  /// The same archive with entries renamed by [names] (old name -> new
  /// name). Entries not in [names] are left out.
  ZipReader renamed(Map<String, String> names) => ZipReader._view(bytes, centralDirectoryOffset, {
        for (final e in names.entries)
          if (entries[e.key] case final entry?)
            e.value: ZipEntry(e.value, entry.method, entry.compressedSize, entry.size,
                entry.localHeaderOffset, unixMode: entry.unixMode)
      });

  final Uint8List bytes;
  late final ByteData _data = ByteData.sublistView(bytes);

  /// Entries by name, in central-directory order.
  final Map<String, ZipEntry> entries = {};

  /// Offset of the central directory. The APK Signing Block sits right
  /// before it.
  late final int centralDirectoryOffset;

  int _u16(int o) => _data.getUint16(o, Endian.little);
  int _u32(int o) => _data.getUint32(o, Endian.little);

  void _readCentralDirectory() {
    if (bytes.length < 22) {
      throw const FormatException('Not a zip file (too small).');
    }
    final minPos = bytes.length > 65557 ? bytes.length - 65557 : 0;
    var eocd = -1;
    for (var i = bytes.length - 22; i >= minPos; i--) {
      if (bytes[i] == 0x50 &&
          bytes[i + 1] == 0x4b &&
          bytes[i + 2] == 0x05 &&
          bytes[i + 3] == 0x06) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) {
      throw const FormatException('Not a zip file (no end of central directory).');
    }
    final count = _u16(eocd + 10);
    centralDirectoryOffset = _u32(eocd + 16);
    var p = centralDirectoryOffset;
    for (var i = 0; i < count; i++) {
      if (p + 46 > bytes.length || _u32(p) != 0x02014b50) {
        throw const FormatException('Corrupt zip central directory.');
      }
      final method = _u16(p + 10);
      final compressed = _u32(p + 20);
      final size = _u32(p + 24);
      final nameLen = _u16(p + 28);
      final extraLen = _u16(p + 30);
      final commentLen = _u16(p + 32);
      final local = _u32(p + 42);
      if (p + 46 + nameLen + extraLen + commentLen > bytes.length) {
        throw const FormatException('Truncated zip central directory entry.');
      }
      final name = utf8.decode(
          Uint8List.sublistView(bytes, p + 46, p + 46 + nameLen),
          allowMalformed: true);
      if (entries.containsKey(name)) {
        throw const FormatException('Duplicate zip entry.');
      }
      entries[name] = ZipEntry(name, method, compressed, size, local,
          unixMode: _u16(p + 4) >> 8 == 3 ? _u16(p + 40) : 0);
      p += 46 + nameLen + extraLen + commentLen;
    }
  }

  bool contains(String name) => entries.containsKey(name);

  /// Decompressed content of [name], or null when missing.
  Uint8List? read(String name) {
    final e = entries[name];
    return e == null ? null : readEntry(e);
  }

  Uint8List readEntry(ZipEntry e, {int? maxBytes}) {
    if (maxBytes != null && e.size > maxBytes) {
      throw const FormatException('ZIP entry exceeds inspection limit.');
    }
    final h = e.localHeaderOffset;
    if (h + 30 > bytes.length || _u32(h) != 0x04034b50) {
      throw FormatException('Bad zip local header for ${e.name}.');
    }
    final start = h + 30 + _u16(h + 26) + _u16(h + 28);
    final end = start + e.compressedSize;
    if (end > bytes.length) {
      throw FormatException('Truncated zip entry ${e.name}.');
    }
    final raw = Uint8List.sublistView(bytes, start, end);
    switch (e.method) {
      case 0:
        if (raw.length != e.size || maxBytes != null && raw.length > maxBytes) {
          throw const FormatException('ZIP size mismatch.');
        }
        return raw;
      case 8:
        final sink = _LimitedZipSink(maxBytes ?? e.size);
        final decoder = ZLibDecoder(raw: true).startChunkedConversion(sink);
        decoder.add(raw);
        decoder.close();
        final result = sink.bytes.takeBytes();
        if (result.length != e.size) throw const FormatException('ZIP size mismatch.');
        return result;
      default:
        throw FormatException(
            'Unsupported compression method ${e.method} for ${e.name}.');
    }
  }
}

class _LimitedZipSink extends ByteConversionSinkBase {
  _LimitedZipSink(this.limit);
  final int limit;
  final bytes = BytesBuilder(copy: false);
  @override void add(List<int> chunk) {
    if (bytes.length + chunk.length > limit) {
      throw const FormatException('ZIP entry exceeds inspection limit.');
    }
    bytes.add(chunk);
  }
  @override void close() {}
}
