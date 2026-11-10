/// Metadata and safe staging of an iOS application archive.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as p;

import '../plist.dart';
import 'zip.dart';

class IpaContext {
  IpaContext._(this.path, this.archive, this.appPath, this.info, this.machO);

  static IpaContext load(String path) {
    try {
      final zip = ZipReader.file(path);
      final apps = zip.entries.keys
          .where(RegExp(r'^Payload/[^/]+\.app/Info\.plist$').hasMatch);
      if (apps.length != 1) {
        throw const FormatException(
            'An IPA must contain one Payload application.');
      }
      final infoPath = apps.single;
      final info = decodeApplePlist(zip.read(infoPath)!);
      final app = p.posix.dirname(infoPath);
      final executable = info?['CFBundleExecutable'];
      final id = info?['CFBundleIdentifier'];
      if (info == null ||
          id is! String ||
          !RegExp(r'^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$').hasMatch(id) ||
          executable is! String ||
          !RegExp(r'^[a-zA-Z0-9_.+-]+$').hasMatch(executable) ||
          executable == '.' ||
          executable == '..') {
        throw const FormatException('Invalid IPA application Info.plist.');
      }
      final bytes = zip.read('$app/$executable');
      if (bytes == null) {
        throw const FormatException(
            'The IPA application executable is missing.');
      }
      final mach = inspectMachO(bytes);
      if (mach.isEmpty || mach.any((slice) => slice.platform != 2)) {
        throw const FormatException(
            'The IPA executable must target physical iOS.');
      }
      return IpaContext._(path, zip, app, info, mach);
    } on RangeError {
      throw const FormatException('Truncated IPA archive or executable.');
    }
  }

  final String path;
  final ZipReader archive;
  final String appPath;
  final Map<String, Object?> info;
  final List<MachSlice> machO;

  String get bundleId => info['CFBundleIdentifier'] as String;
  String get executable => info['CFBundleExecutable'] as String;
  String? get version => info['CFBundleShortVersionString']?.toString();
  String? get build => info['CFBundleVersion']?.toString();
  bool get isFlutter => archive.entries.keys
      .any((name) => name.startsWith('$appPath/Frameworks/Flutter.framework/'));
  bool get encrypted => machO.any((slice) => slice.encrypted);

  String get label => p.basename(path);

  /// Stage only the application in a private directory. IPA symlinks and
  /// ambiguous paths are rejected so they cannot escape the staging root.
  String stage(Directory directory) {
    final app = Directory(p.join(directory.path, p.posix.basename(appPath)))
      ..createSync(recursive: true);
    final used = <String>{};
    for (final entry in archive.entries.values) {
      if (!entry.name.startsWith('$appPath/')) continue;
      final relative = entry.name.substring(appPath.length + 1);
      if (relative.isEmpty) continue;
      final parts = relative.split('/');
      if (entry.isDirectory) parts.removeLast();
      if (parts.isEmpty ||
          parts.any((part) =>
              part.isEmpty ||
              part == '.' ||
              part == '..' ||
              part.contains(RegExp(r'[\\:\x00-\x1f]'))) ||
          entry.isSymlink ||
          !used.add(parts.join('/').toLowerCase())) {
        throw FormatException('Unsafe IPA entry ${entry.name}.');
      }
      final output = p.joinAll([app.path, ...parts]);
      if (entry.isDirectory) {
        Directory(output).createSync(recursive: true);
      } else {
        final file = File(output);
        file.parent.createSync(recursive: true);
        file.writeAsBytesSync(archive.readEntry(entry));
        if (entry.executable || relative == executable) {
          final chmod = Process.runSync('/bin/chmod', ['755', output]);
          if (chmod.exitCode != 0) {
            throw FileSystemException('Could not make executable', output);
          }
        }
      }
    }
    return app.path;
  }
}

typedef MachSlice = ({
  String architecture,
  int platform,
  bool encrypted,
  Map<String, Object?>? entitlements,
});

/// Reads load commands and embedded XML entitlements. The signature's
/// cryptographic validity is established separately by Apple's codesign.
List<MachSlice> inspectMachO(Uint8List bytes) {
  if (bytes.length < 4) return const [];
  final data = ByteData.sublistView(bytes);
  final magic = data.getUint32(0);
  if (magic == 0xcafebabe || magic == 0xcafebabf) {
    if (bytes.length < 8) {
      throw const FormatException('Truncated fat Mach-O header.');
    }
    final wide = magic == 0xcafebabf;
    final count = data.getUint32(4);
    final stride = wide ? 32 : 20;
    if (count == 0 || count > 32 || 8 + count * stride > bytes.length) {
      throw const FormatException('Invalid fat Mach-O header.');
    }
    return [
      for (var i = 0; i < count; i++)
        _machSlice(
            bytes,
            wide
                ? data.getUint64(16 + i * stride)
                : data.getUint32(16 + i * stride),
            wide
                ? data.getUint64(24 + i * stride)
                : data.getUint32(20 + i * stride)),
    ];
  }
  if (magic != 0xcffaedfe && magic != 0xcefaedfe) return const [];
  return [_machSlice(bytes, 0, bytes.length)];
}

MachSlice _machSlice(Uint8List bytes, int offset, int size) {
  if (offset < 0 || size < 28 || offset > bytes.length - size) {
    throw const FormatException('Invalid Mach-O slice bounds.');
  }
  final view = ByteData.sublistView(bytes, offset, offset + size);
  int word(int i) => view.getUint32(i, Endian.little);
  final magic = word(0);
  final wide = magic == 0xfeedfacf;
  if (!wide && magic != 0xfeedface) {
    throw const FormatException('Unsupported Mach-O slice.');
  }
  final cpu = word(4);
  final architecture = switch (cpu) {
    0x0100000c => word(8) & 0xff == 2 ? 'arm64e' : 'arm64',
    0x01000007 => 'x86_64',
    12 => 'arm',
    7 => 'i386',
    _ => 'cpu-$cpu',
  };
  var index = wide ? 32 : 28;
  final commands = word(16);
  final end = index + word(20);
  if (end > size || commands > (end - index) ~/ 8) {
    throw const FormatException('Invalid Mach-O load commands.');
  }
  var platform = 0;
  var encrypted = false;
  Map<String, Object?>? entitlements;
  for (var i = 0; i < commands; i++) {
    if (index + 8 > end) {
      throw const FormatException('Truncated Mach-O command.');
    }
    final command = word(index);
    final length = word(index + 4);
    if (length < 8 || index + length > end) {
      throw const FormatException('Invalid Mach-O command size.');
    }
    if (command == 0x32 && length >= 24) platform = word(index + 8);
    if (command == 0x25 && platform == 0) {
      platform = cpu == 7 || cpu == 0x01000007 ? 7 : 2;
    }
    if ((command == 0x21 || command == 0x2c) && length >= 20) {
      encrypted = word(index + 16) != 0;
    }
    if (command == 0x1d && length >= 16) {
      final start = word(index + 8);
      final length = word(index + 12);
      if (length > 0 && start <= size - length) {
        entitlements = _xmlEntitlements(ByteData.sublistView(
            bytes, offset + start, offset + start + length));
      }
    }
    index += length;
  }
  return (
    architecture: architecture,
    platform: platform,
    encrypted: encrypted,
    entitlements: entitlements
  );
}

Map<String, Object?>? _xmlEntitlements(ByteData blob) {
  if (blob.lengthInBytes < 12 || blob.getUint32(0) != 0xfade0cc0) return null;
  final size = blob.getUint32(4);
  final count = blob.getUint32(8);
  if (size > blob.lengthInBytes || 12 + count * 8 > size) return null;
  for (var i = 0; i < count; i++) {
    if (blob.getUint32(12 + i * 8) != 5) continue;
    final index = blob.getUint32(16 + i * 8);
    if (index > size - 8 || blob.getUint32(index) != 0xfade7171) return null;
    final length = blob.getUint32(index + 4);
    if (length < 8 || index + length > size) return null;
    return parsePlist(utf8.decode(
        blob.buffer.asUint8List(blob.offsetInBytes + index + 8, length - 8),
        allowMalformed: true));
  }
  return null;
}
