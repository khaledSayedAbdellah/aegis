import 'package:aegis/src/probe/device.dart';
import 'package:aegis/src/probe/toolchain.dart';
import 'package:test/test.dart';

import 'support/fake_host.dart';

const sdk = '/Users/dev/Library/Android/sdk';
const jbr = '/Applications/Android Studio.app/Contents/jbr/Contents/Home';

ProbeTools fakeTools() => ProbeTools(
      adb: '/adb',
      emulator: '/emu',
      apksigner: '/bt/apksigner',
      javaHome: '/jdk',
      keytool: '/jdk/bin/keytool',
      frida: '/venv/frida',
      fridaServer: '/tools/frida-server',
      avdName: 'aegis-probe',
    );

void main() {
  group('ProbeTools', () {
    test('missing() lists only tools needed for selected checks', () {
      final t = ProbeTools(adb: '/adb', avdName: 'x');
      expect(
          t.missing(),
          containsAll(
              ['emulator', 'apksigner', 'frida', 'frida-server', 'keytool']));
      expect(t.missing(), isNot(contains('adb')));
      expect(fakeTools().missing(), isEmpty);
      expect(t.missing(only: {'debugger'}), ['emulator']);
    });

    test('resolve finds the tools the setup installed', () async {
      final h = FakeHost()
        ..answer('flutter', ['config', '--machine'],
            stdout: '{"android-sdk":"$sdk","jdk-dir":"$jbr"}')
        ..addDir(sdk)
        ..addFile('$jbr/bin/java')
        ..addFile('$jbr/bin/keytool')
        ..addFile('$sdk/platform-tools/adb')
        ..addFile('$sdk/emulator/emulator')
        ..addFile('$sdk/build-tools/36.0.0/apksigner')
        ..addFile('$sdk/build-tools/36.0.0/zipalign')
        ..addFile('/Users/dev/.aegis/venv/bin/frida')
        ..addFile('/Users/dev/.aegis/tools/frida-server-17.26.2-android-arm64');
      final t = Toolchain(h);
      final tools = await ProbeTools.resolve(h, t);
      expect(tools.adb, '$sdk/platform-tools/adb');
      expect(tools.emulator, '$sdk/emulator/emulator');
      expect(tools.apksigner, '$sdk/build-tools/36.0.0/apksigner');
      expect(tools.keytool, '$jbr/bin/keytool');
      expect(tools.frida, '/Users/dev/.aegis/venv/bin/frida');
      expect(tools.fridaServer, t.fridaServerPath);
      expect(tools.missing(), isEmpty);
    });
  });

  group('Device command lines', () {
    late FakeHost h;
    late Device d;
    setUp(() async {
      h = FakeHost()
        ..installed.addAll([
          '/adb',
          '/venv/frida',
          '/jdk/bin/keytool',
          '/jdk/bin/java',
          '/bt/apksigner'
        ]);
      h.answer('/adb', ['devices'],
          stdout: 'List of devices attached\n'
              'physical-device\tdevice\nemulator-5554\tdevice\nemulator-5556\tdevice');
      h.answer('/adb', ['-s', 'emulator-5554', 'emu', 'avd', 'name'],
          stdout: 'other-avd\nOK');
      h.answer('/adb', ['-s', 'emulator-5556', 'emu', 'avd', 'name'],
          stdout: 'aegis-probe\nOK');
      h.answer('/adb',
          ['-s', 'emulator-5556', 'shell', 'getprop', 'sys.boot_completed'],
          stdout: '1');
      d = Device(h, fakeTools());
      expect(await d.bootEmulator(timeoutSeconds: 0), isNull);
    });

    test('install, launch, pidOf', () async {
      h.answer('/adb', ['-s', 'emulator-5556', 'shell', 'pidof', 'com.x'],
          stdout: '9123\n');
      expect(await d.install('app.apk'), isNull);
      await d.launch('com.x');
      expect(await d.pidOf('com.x'), 9123);
      expect(h.ran, contains('/adb -s emulator-5556 install -r -t app.apk'));
      expect(h.ran, contains('/adb -s emulator-5556 shell monkey -p com.x 1'));
    });

    test('install all splits together on the selected emulator', () async {
      expect(await d.installApks(['base.apk', 'config.en.apk']), isNull);
      expect(
          h.ran,
          contains(
              '/adb -s emulator-5556 install-multiple -r -t base.apk config.en.apk'));
    });

    test('bundletool gets the spec for the selected emulator only', () async {
      await d.extractApkSet('/bundletool.jar', '/app.apks', '/work/apks');
      expect(
          h.ran,
          containsAllInOrder([
            '/jdk/bin/java -jar /bundletool.jar get-device-spec --adb=/adb '
                '--device-id=emulator-5556 --output=/work/apks/device.json',
            '/jdk/bin/java -jar /bundletool.jar extract-apks --apks=/app.apks '
                '--device-spec=/work/apks/device.json --output-dir=/work/apks',
          ]));
    });

    test('startFridaServer pushes and backgrounds the server', () async {
      h.answer(
          '/adb', ['-s', 'emulator-5556', 'shell', 'pidof', 'frida-server'],
          stdout: '42');
      expect(await d.startFridaServer(), isNull);
      expect(
          h.ran,
          contains(
              '/adb -s emulator-5556 push /tools/frida-server /data/local/tmp/frida-server'));
      expect(h.ran.any((c) => c.contains('frida-server >/dev/null 2>&1 &')),
          isTrue);
    });

    test('stopFridaServer kills a running server', () async {
      await d.stopFridaServer();
      expect(
          h.ran, contains('/adb -s emulator-5556 shell pkill -x frida-server'));
    });

    test('fridaAttach runs a one-line session against the app', () async {
      h.answer('/adb', ['-s', 'emulator-5556', 'shell', 'pidof', 'com.x'],
          stdout: '9123');
      h.answer('/adb', ['-s', 'emulator-5556', 'forward', 'tcp:0', 'tcp:27042'],
          stdout: '12345');
      final args = [
        '-H',
        '127.0.0.1:12345',
        '-p',
        '9123',
        '-q',
        '-t',
        '1',
        '-e',
        'console.log("AEGIS_FRIDA_ATTACHED")'
      ];
      h.answer('/venv/frida', args, stderr: 'attachment failed', code: 1);
      expect(await d.fridaAttach('com.x', Duration.zero),
          contains('attachment failed'));
      h.answer('/venv/frida', args, stdout: 'AEGIS_FRIDA_ATTACHED');
      expect(await d.fridaAttach('com.x', Duration.zero), isNull);
    });

    test('resignWithNewKey makes the key, copies and signs', () async {
      h.addFile('app.apk', 'PK');
      expect(await d.resignWithNewKey('app.apk', 'out.apk', '/ks.jks'), isNull);
      expect(h.ran.any((c) => c.startsWith('/jdk/bin/keytool -genkeypair')),
          isTrue);
      expect(h.fileExists('out.apk'), isTrue);
      expect(
          h.ran.any((c) =>
              c.startsWith('/bt/apksigner sign') && c.endsWith('out.apk')),
          isTrue);
    });

    test('an existing keystore is reused', () async {
      h.addFile('app.apk', 'PK');
      h.addFile('/ks.jks', 'KS');
      await d.resignWithNewKey('app.apk', 'out.apk', '/ks.jks');
      expect(h.ran.any((c) => c.contains('genkeypair')), isFalse);
    });
  });
}
