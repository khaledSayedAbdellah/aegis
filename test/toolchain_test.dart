import 'dart:io';

import 'package:aegis/src/probe/toolchain.dart';
import 'package:test/test.dart';

import 'support/fake_host.dart';

const studioJbr = '/Applications/Android Studio.app/Contents/jbr/Contents/Home';
const sdk = '/Users/dev/Library/Android/sdk';

/// A Mac set up like the owner's: Flutter, Android Studio JBR, the SDK with
/// cmdline-tools and adb, and Python — but nothing aegis adds itself.
FakeHost studioMac() {
  final h = FakeHost();
  h.answer('flutter', ['--version', '--machine'],
      stdout: '{"frameworkVersion":"3.41.9","dartSdkVersion":"3.11.5"}');
  h.answer('flutter', ['config', '--machine'],
      stdout: '{"jdk-dir":"$studioJbr","android-sdk":"$sdk"}');
  h.addFile('$studioJbr/bin/java');
  h.answer('$studioJbr/bin/java', ['-version'],
      stderr: 'openjdk version "21.0.6" 2025-01-21\n');
  h.addDir(sdk);
  h.addFile('$sdk/cmdline-tools/latest/bin/sdkmanager');
  h.addFile('$sdk/platform-tools/adb');
  h.answer('python3', ['--version'], stdout: 'Python 3.12.4\n');
  h.installed.add('python3'); // `python3 -c import venv` succeeds
  return h;
}

ToolCheck pick(List<ToolCheck> cs, String id) =>
    cs.firstWhere((c) => c.id == id);

void main() {
  group('detection on a ready Mac', () {
    test('finds Flutter, Java (JBR), the SDK, adb, cmdline-tools, Python',
        () async {
      final checks = await Toolchain(studioMac()).checkAll();
      expect(pick(checks, 'flutter').version, '3.41.9');
      expect(pick(checks, 'java').ok, isTrue);
      expect(pick(checks, 'java').version, '21');
      expect(pick(checks, 'java').source, 'flutter config');
      expect(pick(checks, 'android-sdk').path, sdk);
      expect(pick(checks, 'android-sdk').source, 'flutter config');
      expect(pick(checks, 'cmdline-tools').ok, isTrue);
      expect(pick(checks, 'platform-tools').ok, isTrue);
      expect(pick(checks, 'python').version, '3.12');
    });

    test('what aegis will install is installable, bundletool optional',
        () async {
      final checks = await Toolchain(studioMac()).checkAll();
      for (final id in [
        'build-tools',
        'emulator',
        'system-image',
        'control-image',
        'avd',
        'control-avd',
        'frida',
        'frida-server'
      ]) {
        expect(pick(checks, id).state, ToolState.installable, reason: id);
      }
      expect(pick(checks, 'bundletool').state, ToolState.optional);
      expect(
          (await Toolchain(studioMac()).checkAll(aab: true))
              .firstWhere((c) => c.id == 'bundletool')
              .state,
          ToolState.installable);
    });

    test('flutter config answers, so flutter doctor never runs', () async {
      final h = studioMac();
      await Toolchain(h).checkAll();
      expect(h.ran.where((c) => c.contains('doctor')), isEmpty);
    });
  });

  group('SDK and Java resolution order', () {
    test('ANDROID_HOME is used when flutter config has no android-sdk',
        () async {
      final h = FakeHost(env: {'ANDROID_HOME': '/opt/sdk'})
        ..answer('flutter', ['config', '--machine'], stdout: '{}')
        ..addDir('/opt/sdk');
      final c = await Toolchain(h).checkAndroidSdk();
      expect(c.path, '/opt/sdk');
      expect(c.source, 'ANDROID_HOME');
    });

    test('falls back to flutter doctor output (unwrapped)', () async {
      final doctor = File('test/fixtures/toolchain/flutter-doctor-v.txt')
          .readAsStringSync();
      final h = FakeHost()
        ..answer('flutter', ['config', '--machine'], stdout: '{}')
        ..answer('flutter', ['--no-wrap', 'doctor', '-v'], stdout: doctor)
        ..addDir(sdk)
        // The JDK path as doctor prints it (lowercase Contents/home).
        ..addFile(
            '/Applications/Android Studio.app/Contents/jbr/Contents/home/bin/java')
        ..answer(
            '/Applications/Android Studio.app/Contents/jbr/Contents/home/bin/java',
            ['-version'],
            stderr: 'openjdk version "21.0.6"\n');
      final t = Toolchain(h);
      expect((await t.checkAndroidSdk()).path, sdk);
      final java = await t.checkJava();
      expect(java.ok, isTrue);
      expect(java.source, 'flutter doctor');
    });

    test('longestExisting drops the sentence glued after a path', () {
      const bin =
          '/Applications/Android Studio.app/Contents/jbr/Contents/home/bin/java';
      expect(
          Toolchain.longestExisting(
              '$bin This JDK is specified in your Flutter configuration.',
              (p) => p == bin),
          bin);
      expect(
          Toolchain.longestExisting('/nowhere at all', (_) => false), isNull);
    });

    test('unwrapDoctor rejoins a path wrapped across two lines', () {
      final wrapped = File('test/fixtures/toolchain/flutter-doctor-v.txt')
          .readAsStringSync();
      final joined = Toolchain.unwrapDoctor(wrapped);
      expect(
          joined,
          contains(
              'Java binary at: /Applications/Android Studio.app/Contents/jbr/Contents/home/bin/java'));
    });
  });

  group('versions and variants', () {
    test('Java 8 is too old', () async {
      final h = FakeHost()
        ..answer('flutter', ['config', '--machine'],
            stdout: '{"jdk-dir":"/jdk8"}')
        ..addFile('/jdk8/bin/java')
        ..answer('/jdk8/bin/java', ['-version'],
            stderr: 'java version "1.8.0_382"\n');
      final c = await Toolchain(h).checkJava();
      expect(c.state, ToolState.manual);
      expect(c.issue, Issue.javaOld);
      expect(c.detail['found'], '8');
    });

    test('parseJavaMajor reads old and new formats', () {
      expect(Toolchain.parseJavaMajor('java version "1.8.0_382"'), 8);
      expect(Toolchain.parseJavaMajor('openjdk version "21.0.6"'), 21);
      expect(Toolchain.parseJavaMajor('openjdk 17 2021-09-14'), 17);
    });

    test('an SDK without cmdline-tools needs the person', () async {
      final h = FakeHost()
        ..answer('flutter', ['config', '--machine'],
            stdout: '{"android-sdk":"$sdk"}')
        ..addDir(sdk);
      final c = await Toolchain(h).checkCmdlineTools(sdk);
      expect(c.state, ToolState.manual);
      expect(c.issue, Issue.cmdlineMissing);
    });

    test('newest build-tools with both apksigner and zipalign wins', () async {
      final h = FakeHost()..addDir(sdk);
      for (final v in ['33.0.1', '36.0.0']) {
        h.addFile('$sdk/build-tools/$v/apksigner');
        h.addFile('$sdk/build-tools/$v/zipalign');
      }
      // Newer, but no zipalign: must be skipped.
      h.addFile('$sdk/build-tools/37.0.0/apksigner');
      final c = await Toolchain(h).checkBuildTools(sdk);
      expect(c.path, '$sdk/build-tools/36.0.0');
      expect(c.version, '36.0.0');
    });

    test('frida of another version is installable', () async {
      final h = FakeHost()
        ..answer('/Users/dev/.aegis/venv/bin/frida', ['--version'],
            stdout: '16.4.0\n');
      final c = await Toolchain(h).checkFrida();
      expect(c.state, ToolState.installable);
      expect(c.issue, Issue.fridaOtherVersion);
      expect(c.detail['have'], '16.4.0');
    });

    test('frida-server presence is version-specific', () async {
      final t = Toolchain(FakeHost()
        ..addFile(
            '/Users/dev/.aegis/tools/frida-server-17.26.2-android-arm64'));
      expect((await t.checkFridaServer()).ok, isTrue);
      final other = Toolchain(FakeHost()
        ..addFile('/Users/dev/.aegis/tools/frida-server-16.4.0-android-arm64'));
      expect((await other.checkFridaServer()).state, ToolState.installable);
    });

    test('Intel machines get x86_64 image and frida-server', () {
      final t = Toolchain(FakeHost(arch: 'x86_64'));
      expect(t.abi, 'x86_64');
      expect(
          t.systemImagePackage, 'system-images;android-34;google_apis;x86_64');
      expect(t.fridaArch, 'x86_64');
    });
  });
}
