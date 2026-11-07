import 'dart:convert';
import 'dart:io';

import 'package:aegis/aegis.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

/// Fixtures are built by tool/make_apk_fixtures.py and cross-checked with
/// androguard, an independent APK parser.
const fixtures = 'test/fixtures/apk';
final expected =
    jsonDecode(File('$fixtures/expected.json').readAsStringSync()) as Map<String, dynamic>;

final l2r = AegisConfig(profile: ProfileSet.tryParse('l2+r')!);

Future<AuditReport> apkOnly(String apk) =>
    runAudit(fixtures, apkPath: '$fixtures/$apk', config: l2r, offline: true);

RuleResult result(AuditReport r, String id) => r.results.firstWhere((x) => x.meta.id == id);
Set<String> failedIds(AuditReport r) => r.failed.map((x) => x.meta.id).toSet();
String messages(AuditReport r, String id) =>
    result(r, id).findings.map((f) => f.message).join('\n');

void main() {
  group('APK readers', () {
    test('manifest, network config, signing and libapp strings', () {
      final apk = ApkContext.load('$fixtures/vulnerable.apk');
      expect(apk.packageName, 'com.myshop.app');
      expect(apk.versionName, '1.2.0');
      expect(apk.versionCode, '7');
      expect(apk.minSdk, 21);
      expect(apk.targetSdk, 33);
      expect(apk.manifestText, contains('android:debuggable="true"'));
      expect(apk.isFlutter, isTrue);
      expect(apk.isDebugFlutterBuild, isFalse);
      expect(apk.libappEntry, 'lib/arm64-v8a/libapp.so');
      expect(apk.libappStrings, contains('_MaterialAppState'));

      final nsc = apk.networkSecurityConfig;
      expect(nsc, isNotNull);
      expect(nsc!.$1, 'res/xml/nsc.xml', reason: 'the UTF-8 layout file is skipped');

      // The v1 and v2 signatures carry the same certificate.
      expect(apk.certificates, hasLength(1));
      final cert = apk.certificates.single;
      expect(cert.sha256Base64, expected['vulnerable']['sha256Base64']);
      expect(cert.commonName, 'Android Debug');
      expect(cert.isAndroidDebug, isTrue);
      expect(cert.sha256Hex, matches(RegExp(r'^([0-9A-F]{2}:){31}[0-9A-F]{2}$')));
    });

    test('attribute names stripped from the string pool are recovered', () {
      final apk = ApkContext.load('$fixtures/secure.apk');
      expect(apk.minSdk, 24);
      expect(apk.targetSdk, 35);
      expect(androidAttrOf(apk, 'allowBackup'), 'false');
      expect(apk.certificates.single.commonName, 'Acme Release');
      expect(apk.certificates.single.sha256Base64, expected['secure']['sha256Base64']);
    });

    test('rejects non-APK files', () {
      expect(() => ApkContext.load('pubspec.yaml'), throwsFormatException);
    });
  });

  group('APK only', () {
    test('vulnerable APK', () async {
      final r = await apkOnly('vulnerable.apk');
      expect(r.binary!.packageName, 'com.myshop.app');
      expect(failedIds(r), containsAll([
        'AEG-B02', 'AEG-B03', 'AEG-B04', 'AEG-B05', 'AEG-B06', //
        'AEG-B07', 'AEG-B08', 'AEG-B09', 'AEG-B11',
      ]));
      expect(result(r, 'AEG-B01').status, RuleStatus.passed);
      expect(result(r, 'AEG-B10').status, RuleStatus.notApplicable);
      // Only APK rules run without a source project.
      expect(r.results.every((x) => x.meta.id.startsWith('AEG-B')), isTrue);

      final secrets = messages(r, 'AEG-B06');
      expect(secrets, contains('Supabase service_role key'));
      expect(secrets, contains('AWS access key'));
      expect(secrets, contains('Private key'));
      expect(result(r, 'AEG-B06').findings, hasLength(4),
          reason: 'service_role JWT, AWS key and PEM key in libapp.so, AWS key in config.json; anon JWT ignored');
      for (final f in result(r, 'AEG-B06').findings) {
        expect(f.snippet, isNot(contains('EXAMPLE')), reason: 'secrets are redacted');
      }

      final perms = messages(r, 'AEG-B05');
      expect(perms, allOf(contains('READ_SMS'), contains('QUERY_ALL_PACKAGES')));
      expect(perms, isNot(contains('INTERNET')));
      expect(perms, isNot(contains('WRITE_EXTERNAL_STORAGE')), reason: 'limited by maxSdkVersion');

      final exported = messages(r, 'AEG-B04');
      expect(exported, contains('SmsReceiver'));
      expect(exported, isNot(contains('FirebaseInstanceIdReceiver')), reason: 'protected by a permission');
      expect(exported, isNot(contains('MainActivity')), reason: 'launcher');

      expect(messages(r, 'AEG-B03'),
          allOf(contains('allowBackup'), contains('usesCleartextTraffic'), contains('user-installed')));
      expect(messages(r, 'AEG-B08'), contains('.env'));
      expect(messages(r, 'AEG-B11'), allOf(contains('targetSdk is 33'), contains('minSdk is 21')));
    });

    test('hardened APK passes', () async {
      final r = await apkOnly('secure.apk');
      for (final res in r.results) {
        if (res.meta.id == 'AEG-B10') {
          expect(res.status, RuleStatus.notApplicable);
        } else {
          expect(res.status, RuleStatus.passed, reason: '${res.meta.id}: ${res.findings.map((f) => f.message)}');
        }
      }
      expect(r.score.value, 100);
    });

    test('debug build is detected', () async {
      final r = await apkOnly('debug.apk');
      expect(result(r, 'AEG-B01').status, RuleStatus.failed);
      expect(result(r, 'AEG-B07').status, RuleStatus.notApplicable);
    });
  });

  group('Source + APK', () {
    test('problems already visible in source are not counted twice', () async {
      final r = await runAudit('example/vulnerable_app',
          apkPath: '$fixtures/vulnerable.apk', config: l2r, offline: true);

      expect(result(r, 'AEG-A01').status, RuleStatus.failed);
      expect(result(r, 'AEG-B02').status, RuleStatus.notApplicable);
      expect(result(r, 'AEG-B09').status, RuleStatus.notApplicable, reason: 'AEG-A08 reports it');

      // The AWS key is in the Dart source (AEG-D01); the service_role JWT is
      // only in the binary, so it was injected at build time.
      final secrets = result(r, 'AEG-B06').findings;
      expect(secrets.map((f) => f.message).join('\n'), contains('injected at build time'));
      expect(secrets.where((f) => f.snippet == 'AKIA…MPLE (20 chars)' && f.file!.endsWith('libapp.so')), isEmpty);

      // .SyncService is declared in the source manifest (AEG-A06).
      final exported = messages(r, 'AEG-B04');
      expect(exported, contains('SmsReceiver'));
      expect(exported, isNot(contains('SyncService')));

      // .env is reported by AEG-D09 from pubspec.yaml.
      expect(result(r, 'AEG-B08').status, RuleStatus.passed);

      // minSdk is reported by AEG-A10, targetSdk only shows in the APK.
      expect(messages(r, 'AEG-B11'), contains('targetSdk is 33'));
      expect(messages(r, 'AEG-B11'), isNot(contains('minSdk')));

      // B07 also checks the app's own class names when source is present.
      expect(result(r, 'AEG-B07').status, RuleStatus.failed);
      expect(r.manual.map((m) => m.id), isNot(contains('AEG-M05')));
    });

    test('freeRASP signing hash must match the APK certificate', () async {
      final hash = expected['vulnerable']['sha256Base64'] as String;
      Future<AuditReport> withHashes(String hashes) async {
        final dir = Directory.systemTemp.createTempSync('aegis_apk_');
        addTearDown(() => dir.deleteSync(recursive: true));
        File(p.join(dir.path, 'pubspec.yaml')).writeAsStringSync(
            'name: app\ndependencies:\n  flutter:\n    sdk: flutter\n  freerasp: ^7.0.0\n');
        final lib = Directory(p.join(dir.path, 'lib'))..createSync();
        File(p.join(lib.path, 'main.dart')).writeAsStringSync('''
final config = TalsecConfig(
  androidConfig: AndroidConfig(
    packageName: 'com.myshop.app',
    signingCertHashes: [$hashes],
  ),
);
''');
        return runAudit(dir.path, apkPath: '$fixtures/vulnerable.apk', config: l2r, offline: true);
      }

      final wrong = await withHashes("'mVr/qQLO8DKTwqlL+B1qigl9NoBnbiUs8b4c2Ewcz0k='");
      expect(result(wrong, 'AEG-B10').status, RuleStatus.failed);
      expect(messages(wrong, 'AEG-B10'), contains(hash));

      final right = await withHashes("'mVr/qQLO8DKTwqlL+B1qigl9NoBnbiUs8b4c2Ewcz0k=', '$hash'");
      expect(result(right, 'AEG-B10').status, RuleStatus.passed);
    });
  });

  group('Reports', () {
    test('APK facts and the freeRASP hash are shown', () async {
      final r = await apkOnly('vulnerable.apk');
      final hash = expected['vulnerable']['sha256Base64'] as String;
      expect(ConsoleReporter(color: false).render(r), contains(hash));
      final json = jsonDecode(renderJson(r)) as Map<String, dynamic>;
      expect(json['binary']['certificates'][0]['sha256Base64'], hash);
      expect(renderMarkdown(r), contains(hash));
      expect(renderHtml(r), contains(hash));
    });
  });
}

String? androidAttrOf(ApkContext apk, String name) {
  for (final a in apk.application!.attributes) {
    if (a.name.local == name) return a.value;
  }
  return null;
}
