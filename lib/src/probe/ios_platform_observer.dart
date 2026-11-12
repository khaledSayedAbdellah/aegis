import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';
import 'package:path/path.dart' as p;
import 'ios_device.dart';

/// Compiles only the shipped observer, with Apple's Simulator SDK, in probe
/// scratch space. This does not alter macOS security or the app's disk binary.
class IosPlatformObserver {
  IosPlatformObserver(this.library, this.output, this.nonce);
  final String library, nonce;
  final File output;
  Map<String, String> get environment =>
      {'AEGIS_PLATFORM_OUTPUT': output.path, 'AEGIS_PLATFORM_NONCE': nonce};
  static Future<IosPlatformObserver> prepare(
      IosDevice device, String bundle) async {
    final uri = await Isolate.resolvePackageUri(
        Uri.parse('package:aegis/src/probe/ios_platform_observer.m'));
    if (uri == null) throw StateError('Observer source unavailable');
    final scratch = Directory(p.join(device.work.path, 'platform-observer'))
      ..createSync();
    final sdk = await device.host
        .run('xcrun', ['--sdk', 'iphonesimulator', '--show-sdk-path']);
    if (sdk?.ok != true) throw StateError('Simulator SDK unavailable');
    final library = p.join(scratch.path, 'observer.dylib');
    final arch = device.host.arch == 'arm64' ? 'arm64' : 'x86_64';
    final built = await device.host.run(
        'xcrun',
        [
          '--sdk',
          'iphonesimulator',
          'clang',
          '-dynamiclib',
          '-fobjc-arc',
          '-Wno-deprecated-declarations',
          '-target',
          '$arch-apple-ios13.0-simulator',
          '-isysroot',
          sdk!.out,
          '-framework',
          'Foundation',
          '-framework',
          'UIKit',
          '-framework',
          'WebKit',
          '-framework',
          'Security',
          uri.toFilePath(),
          '-o',
          library
        ],
        timeout: const Duration(seconds: 45));
    if (built?.ok != true) {
      throw StateError('Simulator observer compilation failed');
    }
    final signed = await device.host.run(
        '/usr/bin/codesign', ['-s', '-', '-f', library],
        timeout: const Duration(seconds: 15));
    if (signed?.ok != true) {
      throw StateError('Simulator observer signing failed');
    }
    final nonce =
        base64UrlEncode(List.generate(24, (_) => Random.secure().nextInt(256)));
    final data = await device.simulatorDataPath(bundle);
    return IosPlatformObserver(library,
        File(p.join(data, 'tmp', 'aegis-platform-$nonce.json')), nonce);
  }

  Map<String, Object?> read(String bundle, int pid) {
    if (FileSystemEntity.typeSync(output.path, followLinks: false) !=
            FileSystemEntityType.file ||
        output.lengthSync() > 1024 * 1024) {
      return {};
    }
    final data = jsonDecode(output.readAsStringSync());
    if (data is! Map<String, dynamic> ||
        data['nonce'] != nonce ||
        data['pid'] != pid ||
        data['bundle'] != bundle) {
      return {};
    }
    data.remove('nonce');
    return {
      ...data,
      'verified': true,
      'scope': 'launch-only',
      'instrumented': true
    };
  }
}
