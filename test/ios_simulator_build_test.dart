import 'dart:convert';
import 'dart:io';

import 'package:aegis/src/binary/ipa.dart';
import 'package:aegis/src/probe/ios_simulator_build.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'ipa_test.dart' show fixture, executable;

void main() {
  late Directory project;
  late IpaContext ipa;
  late String app;
  late int builds;
  late List<String> arguments;

  void writeApp(
      {String build = '1',
      String bundle = 'org.aegis.fixture',
      int platform = 7}) {
    Directory(app).createSync(recursive: true);
    File(p.join(app, 'Info.plist')).writeAsStringSync('''
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$bundle</string>
<key>CFBundleExecutable</key><string>Probe</string>
<key>CFBundleVersion</key><string>$build</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
</dict></plist>''');
    File(p.join(app, 'Probe')).writeAsBytesSync(executable(platform));
  }

  Future<int> build(String exe, List<String> args, String cwd, File output,
      void Function(String)? log) async {
    builds++;
    arguments = args;
    expect(cwd, project.path);
    writeApp();
    return 0;
  }

  setUp(() {
    project = Directory.systemTemp.createTempSync('aegis-simulator-build-');
    addTearDown(() => project.deleteSync(recursive: true));
    Directory(p.join(project.path, 'ios', 'Flutter'))
        .createSync(recursive: true);
    File(p.join(project.path, 'pubspec.yaml')).writeAsStringSync(
        'name: fixture\ndependencies:\n  flutter:\n    sdk: flutter\n');
    ipa = IpaContext.load(fixture(project).path);
    app = p.join(project.path, 'build', 'ios', 'iphonesimulator', 'Probe.app');
    builds = 0;
    arguments = [];
  });

  test('missing app builds in project with IPA version and is reused',
      () async {
    final builder = IosSimulatorBuilder(command: build);
    expect(await builder.ensure(ipa, project: project.path), app);
    expect(
        arguments,
        containsAll([
          '--simulator',
          '--debug',
          '--build-name=1.0',
          '--build-number=1'
        ]));
    expect(await builder.ensure(ipa, project: project.path), app);
    expect(builds, 1);
  });

  test('automatic products respect changed explicit target and flavor',
      () async {
    final builder = IosSimulatorBuilder(command: build);
    writeApp(); // A matching build without verified build inputs.
    await builder.ensure(ipa,
        project: project.path, target: 'lib/protected.dart');
    expect(builds, 1);
    expect(arguments, contains('--target=lib/protected.dart'));
    await builder.ensure(ipa,
        project: project.path, target: 'lib/protected.dart');
    expect(builds, 1);
    await builder.ensure(ipa, project: project.path, target: 'lib/other.dart');
    expect(builds, 2);
    await builder.ensure(ipa,
        project: project.path, target: 'lib/other.dart', flavor: 'prod');
    expect(builds, 3);
    expect(arguments, contains('--flavor=prod'));
    await builder.ensure(ipa,
        project: project.path, target: 'lib/other.dart', flavor: 'prod');
    expect(builds, 3);
  });

  test('external payload replacement invalidates an automatic build receipt',
      () async {
    final builder = IosSimulatorBuilder(command: build);
    await builder.ensure(ipa,
        project: project.path, target: 'lib/protected.dart');
    final payload = File(p.join(app, 'Frameworks', 'App.framework',
        'flutter_assets', 'kernel_blob.bin'));
    payload.parent.createSync(recursive: true);
    payload.writeAsStringSync('externally rebuilt Dart code');
    await builder.ensure(ipa,
        project: project.path, target: 'lib/protected.dart');
    expect(builds, 2);
    await builder.ensure(ipa,
        project: project.path, target: 'lib/protected.dart');
    expect(builds, 2);
  });

  test('explicit matching artifact remains authoritative with build overrides',
      () async {
    writeApp();
    expect(
        await IosSimulatorBuilder(command: build)
            .ensure(ipa, app: app, target: 'lib/custom.dart', flavor: 'prod'),
        app);
    expect(builds, 0);
  });

  test('failed automatic build invalidates previous input receipt', () async {
    final builder = IosSimulatorBuilder(command: build);
    await builder.ensure(ipa, project: project.path, target: 'lib/a.dart');
    final failed =
        IosSimulatorBuilder(command: (exe, args, cwd, output, log) async => 65);
    await expectLater(
        failed.ensure(ipa, project: project.path, target: 'lib/b.dart'),
        throwsStateError);
    await builder.ensure(ipa, project: project.path, target: 'lib/a.dart');
    expect(builds, 2);
  });

  test('different build and physical artifacts are rebuilt', () async {
    final builder = IosSimulatorBuilder(command: build);
    writeApp(build: '99');
    expect(await builder.ensure(ipa, project: project.path, app: app), app);
    writeApp(platform: 2);
    expect(await builder.ensure(ipa, project: project.path, app: app), app);
    expect(builds, 2);
  });

  test('existing matching custom app needs no source or Flutter', () async {
    writeApp();
    expect(
        await IosSimulatorBuilder(command: build).ensure(ipa, app: app), app);
    expect(builds, 0);
  });

  test('missing custom path can use generated product without building twice',
      () async {
    final builder = IosSimulatorBuilder(command: build);
    final custom = p.join(project.path, 'custom.app');
    expect(await builder.ensure(ipa, project: project.path, app: custom), app);
    expect(await builder.ensure(ipa, project: project.path, app: custom), app);
    expect(builds, 1);
  });

  test('preserves defines/target and explicit flavor without shell expansion',
      () async {
    File(p.join(project.path, 'ios', 'Flutter', 'Generated.xcconfig'))
        .writeAsStringSync(
            'FLUTTER_TARGET=lib/main staging.dart\nDART_DEFINES=${base64.encode(utf8.encode('VALUE=hello \$(whoami)'))}\n');
    await IosSimulatorBuilder(command: build)
        .ensure(ipa, project: project.path, flavor: 'prod');
    expect(
        arguments,
        containsAll([
          '--flavor=prod',
          '--target=lib/main staging.dart',
          '--dart-define=VALUE=hello \$(whoami)'
        ]));
    Directory(app).deleteSync(recursive: true);
    await IosSimulatorBuilder(command: build)
        .ensure(ipa, project: project.path, target: 'lib/custom.dart');
    expect(arguments, contains('--target=lib/custom.dart'));
  });

  test('infers flavor only from the matching archive version and build',
      () async {
    final file = File(p.join(project.path, 'build', 'ios', 'archive',
        'App.xcarchive', 'Info.plist'));
    file.parent.createSync(recursive: true);
    file.writeAsStringSync(
        '''<plist><dict><key>SchemeName</key><string>prod</string>
<key>ApplicationProperties</key><dict><key>CFBundleIdentifier</key><string>org.aegis.fixture</string>
<key>CFBundleShortVersionString</key><string>1.0</string><key>CFBundleVersion</key><string>1</string></dict></dict></plist>''');
    await IosSimulatorBuilder(command: build)
        .ensure(ipa, project: project.path);
    expect(arguments, contains('--flavor=prod'));
    Directory(app).deleteSync(recursive: true);
    file.writeAsStringSync(file
        .readAsStringSync()
        .replaceFirst('<string>1</string>', '<string>9</string>'));
    await IosSimulatorBuilder(command: build)
        .ensure(ipa, project: project.path);
    expect(arguments.any((a) => a.startsWith('--flavor=')), isFalse);
  });

  test('rebuild removes SDK-generated defines and restores the app flavor',
      () async {
    final values = [
      'FLUTTER_VERSION=3.41.9',
      'FLUTTER_CHANNEL=stable',
      'FLUTTER_GIT_URL=https://github.com/flutter/flutter.git',
      'FLUTTER_FRAMEWORK_REVISION=abc',
      'FLUTTER_ENGINE_REVISION=abc',
      'FLUTTER_DART_VERSION=3.11.5',
      'FLUTTER_ENABLED_FEATURE_FLAGS=',
      'FLUTTER_APP_FLAVOR=prod',
      'API_URL=https://example.test',
    ];
    File(p.join(project.path, 'ios', 'Flutter', 'Generated.xcconfig'))
        .writeAsStringSync(
            'DART_DEFINES=${values.map((v) => base64.encode(utf8.encode(v))).join(',')}\n');
    await IosSimulatorBuilder(command: build)
        .ensure(ipa, project: project.path);
    expect(arguments, contains('--flavor=prod'));
    expect(arguments.where((arg) => arg.startsWith('--dart-define=')),
        ['--dart-define=API_URL=https://example.test']);
    Directory(app).deleteSync(recursive: true);
    await IosSimulatorBuilder(command: build)
        .ensure(ipa, project: project.path, flavor: 'qa');
    expect(arguments, contains('--flavor=qa'));
    expect(arguments, isNot(contains('--flavor=prod')));
  });

  test('failed build does not accept a stale product', () async {
    writeApp(build: '99');
    final builder =
        IosSimulatorBuilder(command: (exe, args, cwd, output, log) async => 65);
    await expectLater(
        builder.ensure(ipa, project: project.path),
        throwsA(isA<StateError>()
            .having((e) => e.message, 'reason', contains('exit 65'))));
  });

  test('successful tool exit does not accept mismatched identity', () async {
    final builder =
        IosSimulatorBuilder(command: (exe, args, cwd, output, log) async {
      writeApp(bundle: 'org.some.other.app');
      return 0;
    });
    await expectLater(
        builder.ensure(ipa, project: project.path),
        throwsA(isA<StateError>().having((e) => e.message, 'reason',
            contains('no matching Simulator app'))));
  });

  test('IPA alone gives an actionable source requirement', () async {
    await expectLater(
        IosSimulatorBuilder(command: build).ensure(ipa),
        throwsA(isA<FormatException>()
            .having((e) => e.message, 'reason', contains('project source'))));
    expect(builds, 0);
  });
}
