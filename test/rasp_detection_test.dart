import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

const flutterPubspec =
    'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n';

void main() {
  late Directory root;
  void put(String path, String text) => File(p.join(root.path, path))
    ..parent.createSync(recursive: true)
    ..writeAsStringSync(text);

  Future<RuleResult> p01([Map<String, String> files = const {}]) async {
    files.forEach(put);
    final report = await runAudit(root.path,
        config: AegisConfig(profile: ProfileSet.tryParse('l2+r')!),
        offline: true);
    return report.results.singleWhere((r) => r.meta.id == 'AEG-P01');
  }

  List<String> messages(RuleResult r) =>
      r.findings.map((f) => f.message).toList();

  setUp(() {
    root = Directory.systemTemp.createTempSync('aegis-rasp-');
    addTearDown(() => root.deleteSync(recursive: true));
    put('pubspec.yaml', flutterPubspec);
    put('lib/main.dart', 'void main() {}');
    put('android/app/src/main/AndroidManifest.xml', '<manifest/>');
    put('ios/Runner/Info.plist', '<plist><dict/></plist>');
  });

  test('nothing found: both platforms are reported', () async {
    final r = await p01();
    expect(r.status, RuleStatus.failed);
    expect(messages(r), [
      startsWith('Android: no RASP package or SDK is used, and no root'),
      startsWith('iOS: no RASP package or SDK is used, and no jailbreak'),
    ]);
  });

  test('a RASP package must be imported, not only declared', () async {
    put('pubspec.yaml', '$flutterPubspec  safe_device: any\n');
    final unused = await p01();
    expect(messages(unused),
        contains(startsWith('safe_device is declared as a dependency')));

    put('lib/main.dart',
        "import 'package:safe_device/safe_device.dart';\nvoid main() {}");
    final used = await p01();
    expect(used.status, RuleStatus.passed);
  });

  test('packages are recognized by name when they are imported', () async {
    put('pubspec.yaml', '$flutterPubspec  acme_root_checker: any\n');
    put('lib/main.dart',
        "import 'package:acme_root_checker/acme_root_checker.dart';\nvoid main() {}");
    expect((await p01()).status, RuleStatus.passed);
  });

  test("a package counts when its own native code checks the device", () async {
    final plugin = Directory.systemTemp.createTempSync('aegis-rasp-plugin-');
    addTearDown(() => plugin.deleteSync(recursive: true));
    void plug(String path, String text) => File(p.join(plugin.path, path))
      ..parent.createSync(recursive: true)
      ..writeAsStringSync(text);
    plug('lib/guard.dart', 'class Guard {}');
    plug('android/src/main/kotlin/Guard.kt',
        'val paths = listOf("/system/xbin/su", "/sbin/su")');
    put('pubspec.yaml', '$flutterPubspec  guard:\n    path: ${plugin.path}\n');
    put('lib/main.dart', "import 'package:guard/guard.dart';\nvoid main() {}");
    put(
        '.dart_tool/package_config.json',
        jsonEncode({
          'configVersion': 2,
          'packages': [
            {
              'name': 'guard',
              'rootUri': Uri.directory(plugin.path).toString(),
              'packageUri': 'lib/'
            },
          ],
        }));
    // Android only: iOS still has nothing.
    final android = await p01();
    expect(messages(android), [startsWith('iOS: no RASP package')]);

    plug('ios/Classes/Guard.swift',
        'let jb = FileManager.default.fileExists(atPath: "/Applications/Cydia.app")');
    expect((await p01()).status, RuleStatus.passed);
  });

  test("a crash reporter's own device check is not protection", () async {
    final plugin = Directory.systemTemp.createTempSync('aegis-rasp-plugin-');
    addTearDown(() => plugin.deleteSync(recursive: true));
    File(p.join(plugin.path, 'android/src/main/kotlin/RootChecker.kt'))
      ..parent.createSync(recursive: true)
      ..writeAsStringSync('val paths = listOf("/system/xbin/su")');
    put('pubspec.yaml', '$flutterPubspec  sentry_flutter: any\n');
    put('lib/main.dart',
        "import 'package:sentry_flutter/sentry_flutter.dart';\nvoid main() {}");
    put(
        '.dart_tool/package_config.json',
        jsonEncode({
          'configVersion': 2,
          'packages': [
            {
              'name': 'sentry_flutter',
              'rootUri': Uri.directory(plugin.path).toString(),
              'packageUri': 'lib/'
            },
          ],
        }));
    final r = await p01();
    expect(messages(r), [
      startsWith('Android: the only root detection belongs to sentry_flutter.'),
      startsWith('iOS: no RASP package'),
    ]);
  });

  test('packages that are not resolved are named in the evidence', () async {
    put('pubspec.yaml', '$flutterPubspec  guard: any\n');
    put('lib/main.dart', "import 'package:guard/guard.dart';\nvoid main() {}");
    final report = await runAudit(root.path,
        config: AegisConfig(profile: ProfileSet.tryParse('l2+r')!),
        offline: true);
    expect(
        report.securityEvidence
            .where((e) => e.ruleId == 'AEG-P01')
            .map((e) => e.detail.en),
        [
          startsWith('The native code of guard was not read because the '
              'dependencies are not resolved.')
        ]);
  });

  test('native SDKs count when declared and used', () async {
    put('android/app/build.gradle',
        "dependencies { implementation 'com.scottyab:rootbeer-lib:0.1.0' }");
    put('ios/Podfile', "target 'Runner' do\n  pod 'IOSSecuritySuite'\nend\n");
    final declared = await p01();
    expect(messages(declared), [
      startsWith('Android: no RASP package'),
      startsWith('iOS: no RASP package'),
      startsWith('RootBeer is declared as a dependency'),
      startsWith('IOSSecuritySuite is declared as a dependency'),
    ]);

    put('android/app/src/main/kotlin/MainActivity.kt',
        'class MainActivity { fun rooted() = RootBeer(this).isRooted }');
    put('ios/Runner/AppDelegate.swift',
        'import IOSSecuritySuite\nlet jb = IOSSecuritySuite.amIJailbroken()');
    expect((await p01()).status, RuleStatus.passed);
  });

  test('custom checks: integrity alone is partial, all three pass', () async {
    put(
        'android/app/src/main/kotlin/Guard.kt',
        '// isDebuggerConnected and frida are only mentioned here\n'
            'val su = File("/system/bin/su").exists()');
    final partial = await p01();
    expect(messages(partial), [
      'Android: the app\'s own checks detect root but not debugger, '
          'hooking (Frida/Xposed). Add the missing checks or use a RASP SDK '
          'that covers all of them.',
      startsWith('iOS: no RASP package'),
    ]);

    put(
        'android/app/src/main/kotlin/Guard.kt',
        'val su = File("/system/bin/su").exists()\n'
            'val dbg = Debug.isDebuggerConnected()\n'
            'val hook = Socket("127.0.0.1", 27042)');
    put(
        'ios/Runner/Guard.swift',
        'let jb = FileManager.default.fileExists(atPath: "/var/jb")\n'
            'ptrace(PT_DENY_ATTACH, 0, nil, 0)\n'
            'let hooked = _dyld_get_image_name(i).contains("FridaGadget")');
    expect((await p01()).status, RuleStatus.passed);
  });

  test('custom checks in Dart cover the platforms they name', () async {
    put('lib/guard.dart', '''
import 'dart:io';
const rootPaths = ['/system/xbin/su', '/sbin/su'];
const jailbreakPaths = ['/Applications/Cydia.app', '/var/jb'];
bool traced() => File('/proc/self/status').readAsStringSync().contains('TracerPid:\\t0') == false;
bool frida() => File('/proc/self/maps').readAsStringSync().contains('frida');
''');
    final r = await p01();
    expect(r.status, RuleStatus.passed);
  });

  test('evidence says where protection comes from', () async {
    put('pubspec.yaml', '$flutterPubspec  freerasp: any\n');
    put('lib/main.dart',
        "import 'package:freerasp/freerasp.dart';\nvoid main() {}");
    final report = await runAudit(root.path,
        config: AegisConfig(profile: ProfileSet.tryParse('l2+r')!),
        offline: true);
    final evidence =
        report.securityEvidence.where((e) => e.ruleId == 'AEG-P01').single;
    expect(evidence.detail.en,
        'Runtime protection on Android, iOS: the freerasp package, imported in lib/main.dart.');
    expect(evidence.detail.ar, contains('freerasp'));
    expect(renderHtml(report), contains('Runtime protection (RASP)'));
  });

  test('native-only projects are checked too', () async {
    File(p.join(root.path, 'pubspec.yaml')).deleteSync();
    Directory(p.join(root.path, 'lib')).deleteSync(recursive: true);
    Directory(p.join(root.path, 'ios')).deleteSync(recursive: true);
    put('app/src/main/AndroidManifest.xml', '<manifest/>');
    put(
        'app/src/main/java/Guard.java',
        'boolean su = new File("/system/xbin/su").exists();\n'
            'boolean dbg = Debug.isDebuggerConnected();\n'
            'boolean xposed = Class.forName("de.robv.android.xposed.XposedBridge") != null;');
    final r = await p01();
    expect(r.status, RuleStatus.passed);
  });
}
