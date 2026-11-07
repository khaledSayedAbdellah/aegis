import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

/// Writes [files] into a temporary project and audits it offline.
Future<AuditReport> audit(Map<String, String> files, {String profile = 'l2+r'}) async {
  final dir = Directory.systemTemp.createTempSync('aegis_test_');
  addTearDown(() => dir.deleteSync(recursive: true));
  final all = {
    'pubspec.yaml': 'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n',
    ...files,
  };
  all.forEach((path, content) {
    final f = File(p.join(dir.path, path));
    f.parent.createSync(recursive: true);
    f.writeAsStringSync(content);
  });
  return runAudit(dir.path,
      config: AegisConfig(profile: ProfileSet.tryParse(profile)!), offline: true);
}

Set<String> failedIds(AuditReport r) => r.failed.map((x) => x.meta.id).toSet();

RuleResult result(AuditReport r, String id) =>
    r.results.firstWhere((x) => x.meta.id == id);

const manifestHeader =
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android">';

void main() {
  group('Android', () {
    test('debuggable, backup and cleartext', () async {
      final r = await audit({
        'android/app/src/main/AndroidManifest.xml': '''
$manifestHeader
  <application android:debuggable="true" android:usesCleartextTraffic="true">
  </application>
</manifest>''',
      });
      expect(failedIds(r), containsAll(['AEG-A01', 'AEG-A02', 'AEG-A03']));
      expect(result(r, 'AEG-A01').findings.single.line, 2);
    });

    test('a hardened manifest passes', () async {
      final r = await audit({
        'android/app/src/main/AndroidManifest.xml': '''
$manifestHeader
  <application android:allowBackup="false">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
  </application>
</manifest>''',
      });
      for (final id in ['AEG-A01', 'AEG-A02', 'AEG-A03', 'AEG-A06']) {
        expect(result(r, id).status, RuleStatus.passed, reason: id);
      }
    });

    test('release signed with the debug key (Kotlin DSL template)', () async {
      final r = await audit({
        'android/app/build.gradle.kts': '''
android {
    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}''',
      });
      expect(failedIds(r), contains('AEG-A08'));
    });

    test('release signing from key.properties is fine', () async {
      final r = await audit({
        'android/app/build.gradle': '''
android {
    signingConfigs {
        release {
            storePassword keystoreProperties['storePassword']
        }
    }
    buildTypes {
        release {
            signingConfig signingConfigs.release
        }
    }
}''',
      });
      expect(result(r, 'AEG-A08').status, RuleStatus.passed);
      expect(result(r, 'AEG-A09').status, RuleStatus.passed);
    });

    test('network security config trusting user CAs', () async {
      final r = await audit({
        'android/app/src/main/AndroidManifest.xml': '''
$manifestHeader
  <application android:allowBackup="false" android:networkSecurityConfig="@xml/nsc"></application>
</manifest>''',
        'android/app/src/main/res/xml/nsc.xml': '''
<network-security-config>
  <base-config><trust-anchors><certificates src="user"/></trust-anchors></base-config>
  <debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>
</network-security-config>''',
      });
      final res = result(r, 'AEG-A04');
      expect(res.status, RuleStatus.failed);
      expect(res.findings, hasLength(1), reason: 'debug-overrides is allowed');
    });
  });

  group('iOS', () {
    test('ATS disabled', () async {
      final r = await audit({
        'ios/Runner/Info.plist': '''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict><key>NSAllowsArbitraryLoads</key><true/></dict>
</dict></plist>''',
      });
      expect(failedIds(r), contains('AEG-I01'));
    });
  });

  group('Dart code', () {
    test('secrets, http and TLS bypass', () async {
      final r = await audit({
        'lib/a.dart': r'''
const apiKey = 'q8Zr2LwX9vT4mN7pK1sB';
const tokenKey = 'auth_token';
const url = 'http://api.example-shop.com';
const local = 'http://localhost:8080';
void f() {
  final c = HttpClient()..badCertificateCallback = (c, h, p) => true;
}
''',
      });
      final secrets = result(r, 'AEG-D01');
      expect(secrets.findings, hasLength(1), reason: 'tokenKey is a storage key name');
      expect(secrets.findings.single.snippet, isNot(contains('q8Zr2LwX9vT4mN7pK1sB')));
      expect(result(r, 'AEG-D02').findings, hasLength(1));
      expect(failedIds(r), contains('AEG-D03'));
    });

    test('pinning-style certificate callback is not a TLS bypass', () async {
      final r = await audit({
        'lib/a.dart': '''
void f() {
  client.badCertificateCallback = (cert, host, port) {
    return sha256.convert(cert.der).toString() == expected;
  };
}
''',
      });
      expect(result(r, 'AEG-D03').status, RuleStatus.passed);
    });

    test('tokens in SharedPreferences and logs', () async {
      final r = await audit({
        'lib/a.dart': r'''
Future<void> save(String token) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('auth_token', token);
  await prefs.setBool('onboarding_done', true);
  await prefs.setBool('remember_session', true);
  print('token is $token');
  if (kDebugMode) print('debug only $token');
}
''',
      });
      expect(result(r, 'AEG-D04').findings, hasLength(1));
      expect(result(r, 'AEG-D08').findings, hasLength(1));
    });

    test('inline suppression', () async {
      final r = await audit({
        'lib/a.dart': '''
// aegis:ignore AEG-D02
const url = 'http://intranet.corp/api';
''',
      });
      final res = result(r, 'AEG-D02');
      expect(res.status, RuleStatus.passed);
      expect(res.suppressed, 1);
    });
  });

  group('Protection correctness', () {
    const raspPubspec = 'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n  freerasp: ^7.0.0\n';

    test('freeRASP installed but never started', () async {
      final r = await audit({
        'pubspec.yaml': raspPubspec,
        'lib/main.dart': "import 'package:freerasp/freerasp.dart';\nvoid main() {}\n",
      });
      expect(result(r, 'AEG-P02').findings, hasLength(2));
    });

    test('freeRASP wired, configured and reacting', () async {
      final r = await audit({
        'pubspec.yaml': raspPubspec,
        'android/app/build.gradle.kts':
            'android { defaultConfig { applicationId = "com.acme.bank" } }',
        'lib/main.dart': '''
import 'package:freerasp/freerasp.dart';
Future<void> main() async {
  final config = TalsecConfig(
    androidConfig: AndroidConfig(
      packageName: 'com.acme.bank',
      signingCertHashes: ['mVr/qQLO8DKTwqlL+B1qigl9NoBnbiUs8b4c2Ewcz0k=', 'Zx9AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd='],
    ),
    isProd: kReleaseMode,
  );
  Talsec.instance.attachListener(ThreatCallback(
    onPrivilegedAccess: _lock,
    onHooks: () => _lock(),
    onAppIntegrity: () => exit(0),
    onDebug: () { secureStorage.deleteAll(); _lock(); },
    onSimulator: _lock,
    onUnofficialStore: _lock,
    onObfuscationIssues: _lock,
    onDeviceBinding: _lock,
  ));
  await Talsec.instance.start(config);
}
void _lock() { Navigator.of(ctx).pushReplacementNamed('/blocked'); }
''',
      });
      for (final id in ['AEG-P01', 'AEG-P02', 'AEG-P03', 'AEG-P04']) {
        expect(result(r, id).status, RuleStatus.passed, reason: id);
      }
    });

    test('freeRASP misconfigured and log-only callbacks', () async {
      final r = await audit({
        'pubspec.yaml': raspPubspec,
        'android/app/build.gradle.kts':
            'android { defaultConfig { applicationId = "com.acme.bank" } }',
        'lib/main.dart': '''
import 'package:freerasp/freerasp.dart';
Future<void> main() async {
  final config = TalsecConfig(
    androidConfig: AndroidConfig(packageName: 'com.acme.other', signingCertHashes: []),
    isProd: false,
  );
  Talsec.instance.attachListener(ThreatCallback(
    onPrivilegedAccess: () => print('root'),
    onHooks: () {},
    onAppIntegrity: _log,
    onDebug: () { debugPrint('dbg'); },
  ));
  await Talsec.instance.start(config);
}
void _log() { print('tampered'); }
''',
      });
      final cfg = result(r, 'AEG-P03');
      expect(cfg.findings.map((f) => f.message).join('\n'),
          allOf(contains('isProd'), contains('com.acme.other'), contains('empty')));
      final reaction = result(r, 'AEG-P04');
      expect(reaction.findings.last.message,
          allOf(contains('onPrivilegedAccess'), contains('onHooks'), contains('onAppIntegrity'), contains('onDebug')));
    });

    test('App Check debug provider must be guarded', () async {
      const pubspec = 'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n  firebase_core: any\n  firebase_app_check: any\n';
      final bad = await audit({
        'pubspec.yaml': pubspec,
        'lib/a.dart': 'f() => FirebaseAppCheck.instance.activate(androidProvider: AndroidProvider.debug);',
      });
      expect(failedIds(bad), contains('AEG-P06'));
      final good = await audit({
        'pubspec.yaml': pubspec,
        'lib/a.dart': '''
f() => FirebaseAppCheck.instance.activate(
  androidProvider: kDebugMode ? AndroidProvider.debug : AndroidProvider.playIntegrity,
);''',
      });
      expect(result(good, 'AEG-P06').status, RuleStatus.passed);
    });

    test('profile decides which rules run', () async {
      final l1 = await audit({'lib/a.dart': 'void f() {}'}, profile: 'l1');
      expect(result(l1, 'AEG-P01').status, RuleStatus.outOfProfile);
      final r = await audit({'lib/a.dart': 'void f() {}'}, profile: 'l1+r');
      expect(result(r, 'AEG-P01').status, RuleStatus.failed);
    });
  });

  group('Example app', () {
    test('every category fires on example/vulnerable_app', () async {
      final r = await runAudit('example/vulnerable_app', offline: true);
      final ids = failedIds(r);
      for (final id in [
        'AEG-A01', 'AEG-A02', 'AEG-A03', 'AEG-A04', 'AEG-A05', 'AEG-A06', //
        'AEG-A07', 'AEG-A08', 'AEG-A09', 'AEG-A10', //
        'AEG-I01', 'AEG-I02', 'AEG-I03', 'AEG-I04', //
        'AEG-D01', 'AEG-D02', 'AEG-D03', 'AEG-D04', 'AEG-D05', 'AEG-D06', //
        'AEG-D07', 'AEG-D08', 'AEG-D09', //
        'AEG-P02', 'AEG-P03', 'AEG-P04', 'AEG-P06', 'AEG-P07', 'AEG-P08', 'AEG-P09', 'AEG-P10', //
        'AEG-C02',
      ]) {
        expect(ids, contains(id), reason: id);
      }
      expect(r.score.value, lessThan(50));
      expect(r.score.grade, 'F');
    });
  });

  group('Real-world patterns', () {
    test('logging behind a config flag is not reported', () async {
      final r = await audit({
        'lib/a.dart': '''
Dio build(NetworkConfig config) {
  final dio = Dio();
  dio.interceptors.addAll([
    AuthInterceptor(),
    if (config.enableLogging)
      LogInterceptor(requestBody: true, responseBody: true),
  ]);
  return dio;
}
void push(String token) {
  if (!AppConfig.instance.enableLogging) return;
  debugPrint('push token \$token');
}
''',
      });
      expect(result(r, 'AEG-D08').status, RuleStatus.passed);
    });

    test('a PEM header alone is not a private key', () async {
      final r = await audit({
        'lib/pem.dart': r'''
const beginKey = '-----BEGIN PRIVATE KEY-----';
const endKey = '-----END PRIVATE KEY-----';
const realKey = '-----BEGIN PRIVATE KEY-----\nTHISISNOTAREALKEYTHISISNOTAREALKEYTHISISNOTAREALKEY0123456789ab\n-----END PRIVATE KEY-----';
const splitKey = '-----BEGIN PRIVATE KEY-----\n'
    'THISISNOTAREALKEYTHISISNOTAREALKEYTHISISNOTAREALKEY0123456789ab';
''',
      });
      final lines = result(r, 'AEG-D01').findings.map((f) => f.line).toList();
      expect(lines, [3, 4]);
    });

    test('local_auth without visible calls is not a pass', () async {
      final r = await audit({
        'pubspec.yaml': 'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n  local_auth: any\n',
        'lib/a.dart': 'void f() {}',
      });
      expect(result(r, 'AEG-P08').status, RuleStatus.notApplicable);
    });

    test('git and path dependencies are scanned, pub.dev packages are not', () async {
      final dir = Directory.systemTemp.createTempSync('aegis_pkgs_');
      addTearDown(() => dir.deleteSync(recursive: true));
      void write(String path, String content) {
        final f = File(p.join(dir.path, path));
        f.parent.createSync(recursive: true);
        f.writeAsStringSync(content);
      }

      write('app/pubspec.yaml', '''
name: app
dependencies:
  flutter:
    sdk: flutter
  erp_auth:
    path: ../erp_auth
  some_lib: ^1.0.0
''');
      write('app/pubspec.lock', '''
packages:
  erp_auth:
    dependency: "direct main"
    description:
      path: "../erp_auth"
      relative: true
    source: path
    version: "0.1.0"
  some_lib:
    dependency: "direct main"
    description:
      name: some_lib
      url: "https://pub.dev"
    source: hosted
    version: "1.0.0"
''');
      write('app/.dart_tool/package_config.json', '''
{"configVersion": 2, "packages": [
  {"name": "erp_auth", "rootUri": "../../erp_auth", "packageUri": "lib/", "languageVersion": "3.0"},
  {"name": "some_lib", "rootUri": "../../hosted/some_lib", "packageUri": "lib/", "languageVersion": "3.0"},
  {"name": "app", "rootUri": "../", "packageUri": "lib/", "languageVersion": "3.0"}
]}''');
      write('app/lib/main.dart', 'void main() {}');
      write('erp_auth/lib/src/vault.dart', '''
Future<bool> unlock() => LocalAuthentication().authenticate(localizedReason: 'x');
const apiKey = 'q8Zr2LwX9vT4mN7pK1sB';
''');
      write('hosted/some_lib/lib/x.dart', "const apiKey = 'Zx9AbCdEfGhIjKlMnOpQ';");

      final r = await runAudit(p.join(dir.path, 'app'),
          config: AegisConfig(profile: ProfileSet.tryParse('l2')!), offline: true);
      expect(r.scannedPackages, ['erp_auth']);
      final secrets = result(r, 'AEG-D01').findings;
      expect(secrets, hasLength(1));
      expect(secrets.single.file, 'package:erp_auth/src/vault.dart');
      expect(secrets.single.line, 2);

      final off = await runAudit(p.join(dir.path, 'app'),
          config: AegisConfig(scanPackages: false), offline: true);
      expect(off.scannedPackages, isEmpty);
      expect(result(off, 'AEG-D01').status, RuleStatus.passed);
    });
  });

  group('Rule metadata', () {
    test('every rule has a unique id and its own pass title', () {
      final ids = allRules.map((r) => r.meta.id).toList();
      expect(ids.toSet(), hasLength(ids.length));
      for (final r in allRules) {
        final m = r.meta;
        expect(m.passTitle.en, isNot(m.title.en), reason: '${m.id} has no pass title');
        expect(m.passTitle.ar, isNotEmpty, reason: m.id);
      }
    });
  });

  group('Reports', () {
    test('all formats render', () async {
      final r = await runAudit('example/vulnerable_app', offline: true);
      expect(renderJson(r), contains('"tool": "aegis"'));
      expect(renderSarif(r), contains('"version": "2.1.0"'));
      expect(renderMarkdown(r, lang: 'ar'), contains('dir="rtl"'));
      expect(renderHtml(r), contains('<!doctype html>'));
      expect(ConsoleReporter(color: false).render(r), contains('AEG-A01'));
      final passedLines = ConsoleReporter(color: false)
          .render(r)
          .split('\n')
          .where((l) => l.trimLeft().startsWith('✓ '));
      expect(passedLines.join('\n'), isNot(contains('No runtime protection')));
    });
  });
}
