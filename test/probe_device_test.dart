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
      zipalign: '/bt/zipalign',
      keytool: '/jdk/bin/keytool',
      frida: '/venv/frida',
      fridaServer: '/tools/frida-server',
      bundletool: '/tools/bundletool.jar',
      avdName: 'aegis-probe',
    );

void main() {
  group('ProbeTools', () {
    test('java is derived beside keytool', () {
      expect(ProbeTools(keytool: '/jdk/bin/keytool', avdName: 'x').java, '/jdk/bin/java');
      expect(ProbeTools(avdName: 'x').java, isNull);
    });

    test('missing() lists the gaps; bundletool only with --aab', () {
      final t = ProbeTools(adb: '/adb', avdName: 'x');
      expect(t.missing(), containsAll(['emulator', 'apksigner', 'frida', 'frida-server', 'keytool']));
      expect(t.missing(), isNot(contains('adb')));
      expect(fakeTools().missing(), isEmpty);
      expect(ProbeTools(adb: '/adb', emulator: '/e', apksigner: '/a', frida: '/f',
              fridaServer: '/fs', keytool: '/k', avdName: 'x')
          .missing(needsBundletool: true), ['bundletool']);
    });

    test('resolve finds the tools the setup installed', () async {
      final h = FakeHost()
        ..answer('flutter', ['config', '--machine'], stdout: '{"android-sdk":"$sdk","jdk-dir":"$jbr"}')
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
    setUp(() {
      h = FakeHost()..installed.addAll(['/adb', '/venv/frida', '/jdk/bin/keytool', '/bt/apksigner']);
      d = Device(h, fakeTools());
    });

    test('install, launch, pidOf', () async {
      h.answer('/adb', ['shell', 'pidof', 'com.x'], stdout: '9123\n');
      expect(await d.install('app.apk'), isNull);
      await d.launch('com.x');
      expect(await d.pidOf('com.x'), 9123);
      expect(h.ran, contains('/adb install -r -t app.apk'));
      expect(h.ran, contains('/adb shell monkey -p com.x -c android.intent.category.LAUNCHER 1'));
    });

    test('startFridaServer pushes and backgrounds the server', () async {
      expect(await d.startFridaServer(), isNull);
      expect(h.ran, contains('/adb push /tools/frida-server /data/local/tmp/frida-server'));
      expect(h.ran.any((c) => c.contains('frida-server >/dev/null 2>&1 &')), isTrue);
    });

    test('fridaAttach runs a one-line session against the app', () async {
      expect(await d.fridaAttach('com.x'), isNull);
      expect(h.ran, contains('/venv/frida -U -n com.x -q -e true'));
    });

    test('resignWithNewKey makes the key, copies and signs', () async {
      h.addFile('app.apk', 'PK');
      expect(await d.resignWithNewKey('app.apk', 'out.apk', '/ks.jks'), isNull);
      expect(h.ran.any((c) => c.startsWith('/jdk/bin/keytool -genkeypair')), isTrue);
      expect(h.fileExists('out.apk'), isTrue);
      expect(h.ran.any((c) => c.startsWith('/bt/apksigner sign') && c.endsWith('out.apk')), isTrue);
    });

    test('an existing keystore is reused', () async {
      h.addFile('app.apk', 'PK');
      h.addFile('/ks.jks', 'KS');
      await d.resignWithNewKey('app.apk', 'out.apk', '/ks.jks');
      expect(h.ran.any((c) => c.contains('genkeypair')), isFalse);
    });
  });
}
