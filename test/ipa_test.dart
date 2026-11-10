import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:aegis/aegis.dart';
import 'package:archive/archive.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

const _app = 'Payload/Probe.app';
const _plist =
    'YnBsaXN0MDDVAQIDBAUGBwgJCl8QEkNGQnVuZGxlRXhlY3V0YWJsZV8QEkNGQnVu'
    'ZGxlSWRlbnRpZmllcl8QGkNGQnVuZGxlU2hvcnRWZXJzaW9uU3RyaW5nXxAPQ0ZCdW5kbGVWZXJz'
    'aW9uXxAWTlNBcHBUcmFuc3BvcnRTZWN1cml0eVVQcm9iZV8QEW9yZy5hZWdpcy5maXh0dXJlUzEu'
    'MFEx0QsMXxAWTlNBbGxvd3NBcmJpdHJhcnlMb2FkcwkIEyg9WmyFi5+jpajBAAAAAAAAAQEAAAAA'
    'AAAADQAAAAAAAAAAAAAAAAAAAMI=';

Uint8List executable(int platform) {
  final bytes = Uint8List(56);
  final data = ByteData.sublistView(bytes);
  void word(int offset, int value) =>
      data.setUint32(offset, value, Endian.little);
  word(0, 0xfeedfacf);
  word(4, 0x0100000c);
  word(12, 2);
  word(16, 1);
  word(20, 24);
  word(32, 0x32);
  word(36, 24);
  word(40, platform);
  return bytes;
}

File fixture(Directory directory, {int platform = 2, bool unsafe = false}) {
  final zip = Archive()
    ..addFile(ArchiveFile.bytes('$_app/Info.plist', base64Decode(_plist)))
    ..addFile(ArchiveFile.bytes('$_app/Probe', executable(platform)))
    ..addFile(ArchiveFile.bytes('$_app/.env', utf8.encode('TOKEN=example')));
  if (unsafe) zip.addFile(ArchiveFile.bytes('$_app/../outside', [1]));
  return File(p.join(directory.path, 'probe.ipa'))
    ..writeAsBytesSync(ZipEncoder().encode(zip));
}

void main() {
  late Directory directory;
  setUp(() {
    directory = Directory.systemTemp.createTempSync('aegis-ipa-test');
    addTearDown(() => directory.deleteSync(recursive: true));
  });

  test('loads binary Info.plist and the physical Mach-O platform', () {
    final ipa = IpaContext.load(fixture(directory).path);
    expect(ipa.bundleId, 'org.aegis.fixture');
    expect(ipa.version, '1.0');
    expect(ipa.build, '1');
    expect(ipa.machO.single.architecture, 'arm64');
    expect(
        ipa.info['NSAppTransportSecurity'], {'NSAllowsArbitraryLoads': true});
  });

  test('rejects a Simulator executable presented as an IPA', () {
    expect(() => IpaContext.load(fixture(directory, platform: 7).path),
        throwsFormatException);
  });

  test('iOS targets and IPA paths survive CLI overrides', () {
    final config = AegisConfig.parse('''
ipa: dist/app.ipa
ios_control_device: 00001234-0001234A3C03401E
ios_jailbreak_device: 00001234-0001234A3C03401F
ios_resigned_ipa: dist/resigned.ipa
ios_simulator: A0000001-0000-0000-0000-000000000001
ios_simulator_app: build/ios/iphonesimulator/Runner.app
ios_simulator_flavor: prod
ios_simulator_target: lib/main_prod.dart
''').copyWith(lang: 'ar');
    expect(config.ipa, 'dist/app.ipa');
    expect(config.iosControlDevice, '00001234-0001234A3C03401E');
    expect(config.iosJailbreakDevice, '00001234-0001234A3C03401F');
    expect(config.iosResignedIpa, 'dist/resigned.ipa');
    expect(config.iosSimulator, 'A0000001-0000-0000-0000-000000000001');
    expect(config.iosSimulatorApp, 'build/ios/iphonesimulator/Runner.app');
    expect(config.iosSimulatorFlavor, 'prod');
    expect(config.iosSimulatorTarget, 'lib/main_prod.dart');
  });

  test('staging refuses to write outside the app', () {
    final ipa = IpaContext.load(fixture(directory, unsafe: true).path);
    expect(() => ipa.stage(directory), throwsFormatException);
    expect(File(p.join(directory.path, 'outside')).existsSync(), isFalse);
  }, skip: Platform.isWindows);

  test('a missing Simulator app points to the setting to fix', () async {
    final ipa = fixture(directory);
    final result = await Process.run(Platform.resolvedExecutable, [
      p.absolute('bin/aegis.dart'),
      'probe',
      ipa.path,
      '--ios-simulator',
      'A0000001-0000-0000-0000-000000000001',
      '--ios-simulator-app',
      p.join(directory.path, 'Missing.app'),
    ]);
    expect(result.exitCode, 2);
    expect(result.stderr, contains('ios_simulator_app'));
  }, skip: !Platform.isMacOS);

  test('strict run reports that a requested iOS probe could not start',
      () async {
    final ipa = fixture(directory);
    File(p.join(directory.path, 'aegis.yaml'))
        .writeAsStringSync('ipa: probe.ipa\n');
    final output = p.join(directory.path, 'report');
    final result = await Process.run(Platform.resolvedExecutable, [
      p.absolute('bin/aegis.dart'),
      'run',
      directory.path,
      '--mode',
      'ipa',
      '--strict',
      '--offline',
      '--lang',
      'en',
      '-f',
      'json',
      '-o',
      output,
    ]);
    expect(result.exitCode, 2, reason: '${result.stdout}\n${result.stderr}');
    final report = jsonDecode(File('$output.json').readAsStringSync()) as Map;
    expect(report['binary'], containsPair('kind', 'IPA'));
    expect(report['probe'], containsPair('ran', false));
    expect(report['complete'], isFalse);
    expect(IpaContext.load(ipa.path).label, 'probe.ipa');
  });
}
